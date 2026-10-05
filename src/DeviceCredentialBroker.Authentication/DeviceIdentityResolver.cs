using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using DeviceCredentialBroker.Domain;

namespace DeviceCredentialBroker.Authentication;

/// <summary>
/// Resolves <see cref="DeviceIdentity"/> from a validated certificate using strict
/// GUID-only extraction (SAN URI "urn:uuid:&lt;guid&gt;", SAN DNS "&lt;guid&gt;", or
/// Subject CN "&lt;guid&gt;" as the ENTIRE value). Substring/regex extraction is
/// deliberately rejected — it is the exact IDOR vector called out in prompt §11 and
/// verified as a hard requirement in LogCollector's docs/security.md §5.
/// </summary>
public sealed partial class DeviceIdentityResolver : IDeviceIdentityResolver
{
    [GeneratedRegex(@"^urn:uuid:([0-9a-fA-F\-]{36})$")]
    private static partial Regex SanUriPattern();

    public DeviceIdentity? Resolve(
        X509Certificate2 clientCertificate,
        CertificateValidationResult certificateValidation,
        string? clientReportedSerialNumber,
        string? clientReportedCurrentComputerName,
        out string? denyReason)
    {
        if (!certificateValidation.IsValid || certificateValidation.Profile is null)
        {
            denyReason = "Certificate validation did not succeed.";
            return null;
        }

        var deviceId = ExtractBoundDeviceId(clientCertificate);
        if (deviceId is null)
        {
            denyReason = "No strictly-bound device identifier (SAN URI/DNS/CN) was found on the certificate.";
            return null;
        }

        denyReason = null;
        var thumbprintHash = Convert.ToHexString(SHA256.HashData(clientCertificate.GetRawCertData()));

        return new DeviceIdentity
        {
            CertificateSubject = clientCertificate.Subject,
            CertificateIssuer = clientCertificate.Issuer,
            CertificateSan = GetSanUri(clientCertificate) ?? GetSanDns(clientCertificate),
            CertificateThumbprintHash = thumbprintHash,
            CertificateBoundDeviceId = deviceId.Value,
            TrustProfile = certificateValidation.Profile.Value,
            ClientReportedSerialNumber = clientReportedSerialNumber,
            ClientReportedCurrentComputerName = clientReportedCurrentComputerName
        };
    }

    private static Guid? ExtractBoundDeviceId(X509Certificate2 cert)
    {
        var sanUri = GetSanUri(cert);
        if (sanUri is not null)
        {
            var match = SanUriPattern().Match(sanUri);
            if (match.Success && Guid.TryParse(match.Groups[1].Value, out var fromUri))
            {
                return fromUri;
            }
        }

        var sanDns = GetSanDns(cert);
        if (sanDns is not null && Guid.TryParse(sanDns, out var fromDns))
        {
            return fromDns;
        }

        var cn = GetSubjectCommonName(cert);
        if (cn is not null && Guid.TryParse(cn, out var fromCn))
        {
            return fromCn;
        }

        return null;
    }

    private static string? GetSanUri(X509Certificate2 cert) =>
        GetSanValues(cert).FirstOrDefault(v => v.StartsWith("urn:uuid:", StringComparison.OrdinalIgnoreCase));

    private static string? GetSanDns(X509Certificate2 cert) =>
        GetSanValues(cert).FirstOrDefault(v => Guid.TryParse(v, out _));

    private static IEnumerable<string> GetSanValues(X509Certificate2 cert)
    {
        foreach (var extension in cert.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.17") // Subject Alternative Name
            {
                var formatted = extension.Format(false);
                foreach (var part in formatted.Split(new[] { ", ", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var idx = part.IndexOf('=');
                    yield return idx >= 0 ? part[(idx + 1)..].Trim() : part.Trim();
                }
            }
        }
    }

    private static string? GetSubjectCommonName(X509Certificate2 cert)
    {
        // Strict: the entire CN component must be the GUID. "CN=<guid>.attacker.example"
        // or "CN=device-<guid>-01" must NOT match (prompt §11).
        var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
        return cn;
    }
}
