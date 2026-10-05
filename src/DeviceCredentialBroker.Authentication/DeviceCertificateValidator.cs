using System.Security.Cryptography.X509Certificates;
using DeviceCredentialBroker.Domain;
using Microsoft.Extensions.Options;

namespace DeviceCredentialBroker.Authentication;

/// <summary>
/// Validates a client certificate against the active trust profile. Adapted from the
/// verified two-tier (Enterprise PKI / Intune enrollment) model in LogCollector's
/// ClientCertValidator — see docs/authentication.md for the full reuse analysis.
/// Only Root certificates become trust anchors; intermediates are used only as chain
/// path hints, never as anchors, so a compromised issuing CA cannot silently become
/// a root of trust.
/// </summary>
public sealed class DeviceCertificateValidator : IDeviceCertificateValidator
{
    private const string ClientAuthenticationEkuOid = "1.3.6.1.5.5.7.3.2";

    private readonly DeviceCertificateOptions _options;

    public DeviceCertificateValidator(IOptions<DeviceCertificateOptions> options)
    {
        _options = options.Value;
    }

    public CertificateValidationResult Validate(X509Certificate2 clientCertificate, X509Chain chain)
    {
        ArgumentNullException.ThrowIfNull(clientCertificate);
        ArgumentNullException.ThrowIfNull(chain);

        var now = DateTimeOffset.UtcNow;
        if (now < clientCertificate.NotBefore || now > clientCertificate.NotAfter)
        {
            return CertificateValidationResult.Deny("Certificate is outside its validity window.");
        }

        return _options.ActiveProfile switch
        {
            "IntuneEnrollment" => ValidateIntuneEnrollment(clientCertificate, chain),
            "CorporatePKI" => ValidateCorporatePki(clientCertificate, chain),
            _ => CertificateValidationResult.Deny($"Unknown certificate profile '{_options.ActiveProfile}'.")
        };
    }

    private CertificateValidationResult ValidateCorporatePki(X509Certificate2 cert, X509Chain chain)
    {
        var profile = _options.CorporatePKI;

        if (profile.RequireClientAuthenticationEku && !HasEku(cert, ClientAuthenticationEkuOid))
        {
            return CertificateValidationResult.Deny("Client Authentication EKU is missing.");
        }

        if (profile.TrustedRootThumbprints.Count == 0 && profile.TrustedRootSubjects.Count == 0)
        {
            // Fail closed: no trust anchor configured at all must never be treated as
            // "trust everything" (docs/authentication.md §2, verified LogCollector invariant).
            return CertificateValidationResult.Deny("No CorporatePKI trust anchor is configured.");
        }

        // Trust is decided explicitly below (root thumbprint/subject allow-list), not by
        // OS/machine trust-store membership — so a structurally valid chain whose root is
        // "unknown" to Windows must still be allowed to build; AllowUnknownCertificateAuthority
        // defers the actual trust decision to our own allow-list check, it does not bypass it.
        chain.ChainPolicy.VerificationFlags = System.Security.Cryptography.X509Certificates.X509VerificationFlags.AllowUnknownCertificateAuthority;
        chain.ChainPolicy.RevocationMode = profile.CheckRevocation
            ? System.Security.Cryptography.X509Certificates.X509RevocationMode.Online
            : System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;

        if (!chain.Build(cert))
        {
            return CertificateValidationResult.Deny("Certificate chain did not build successfully.");
        }

        var root = chain.ChainElements[^1].Certificate;
        var rootThumbprintMatches = profile.TrustedRootThumbprints.Count == 0
            || profile.TrustedRootThumbprints.Contains(root.Thumbprint, StringComparer.OrdinalIgnoreCase);
        var rootSubjectMatches = profile.TrustedRootSubjects.Count == 0
            || profile.TrustedRootSubjects.Contains(root.Subject, StringComparer.OrdinalIgnoreCase);

        if (!rootThumbprintMatches || !rootSubjectMatches)
        {
            return CertificateValidationResult.Deny("Certificate chain root is not a trusted anchor.");
        }

        return new CertificateValidationResult
        {
            IsValid = true,
            Profile = CertificateTrustProfile.CorporatePKI,
            CertificateDerivedClaims = BuildClaims(cert)
        };
    }

    private CertificateValidationResult ValidateIntuneEnrollment(X509Certificate2 cert, X509Chain chain)
    {
        var profile = _options.IntuneEnrollment;

        if (!HasOid(cert, profile.RequiredOid))
        {
            return CertificateValidationResult.Deny("Certificate does not carry the required Intune enrollment OID.");
        }

        if (profile.IssuerSubjectAllowList.Count == 0
            || !profile.IssuerSubjectAllowList.Contains(cert.Issuer, StringComparer.OrdinalIgnoreCase))
        {
            // The OID alone is a selection criterion, never proof of trust — the issuer
            // must also be on an explicit allow-list (docs/authentication.md §2).
            return CertificateValidationResult.Deny("Certificate issuer is not on the Intune allow-list.");
        }

        if (profile.TrustedRootThumbprints.Count == 0)
        {
            return CertificateValidationResult.Deny("No IntuneEnrollment trust anchor is configured.");
        }

        chain.ChainPolicy.VerificationFlags = System.Security.Cryptography.X509Certificates.X509VerificationFlags.AllowUnknownCertificateAuthority;
        chain.ChainPolicy.RevocationMode = profile.SkipRevocationCheck
            ? System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
            : System.Security.Cryptography.X509Certificates.X509RevocationMode.Online;

        if (!chain.Build(cert))
        {
            return CertificateValidationResult.Deny("Certificate chain did not build successfully.");
        }

        var root = chain.ChainElements[^1].Certificate;
        if (!profile.TrustedRootThumbprints.Contains(root.Thumbprint, StringComparer.OrdinalIgnoreCase))
        {
            return CertificateValidationResult.Deny("Certificate chain root is not a trusted Intune anchor.");
        }

        return new CertificateValidationResult
        {
            IsValid = true,
            Profile = CertificateTrustProfile.IntuneEnrollment,
            CertificateDerivedClaims = BuildClaims(cert)
        };
    }

    private static bool HasEku(X509Certificate2 cert, string oid)
    {
        foreach (var extension in cert.Extensions)
        {
            if (extension is X509EnhancedKeyUsageExtension eku)
            {
                foreach (var usage in eku.EnhancedKeyUsages)
                {
                    if (usage.Value == oid) return true;
                }
            }
        }
        return false;
    }

    private static bool HasOid(X509Certificate2 cert, string oid)
    {
        foreach (var extension in cert.Extensions)
        {
            if (extension.Oid?.Value == oid) return true;
        }
        return false;
    }

    private static IReadOnlyDictionary<string, string> BuildClaims(X509Certificate2 cert) =>
        new Dictionary<string, string>
        {
            ["Subject"] = cert.Subject,
            ["Issuer"] = cert.Issuer,
            ["Thumbprint"] = cert.Thumbprint,
            ["SerialNumber"] = cert.SerialNumber
        };
}
