using System.Security.Cryptography.X509Certificates;
using DeviceCredentialBroker.Domain;
using Microsoft.Extensions.Options;
using Xunit;

namespace DeviceCredentialBroker.Authentication.Tests;

public class DeviceCertificateValidatorTests
{
    private static DeviceCertificateValidator CreateValidator(DeviceCertificateOptions options) =>
        new(Options.Create(options));

    [Fact]
    public void Validate_CorporatePki_TrustedRootAndEku_Succeeds()
    {
        var (root, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid());
        var options = new DeviceCertificateOptions
        {
            ActiveProfile = "CorporatePKI",
            CorporatePKI = new CorporatePkiProfileOptions
            {
                TrustedRootThumbprints = [root.Thumbprint],
                RequireClientAuthenticationEku = true,
                CheckRevocation = false
            }
        };

        var validator = CreateValidator(options);
        using var chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.Add(root);
        var result = validator.Validate(leaf, chain);

        Assert.True(result.IsValid);
        Assert.Equal(CertificateTrustProfile.CorporatePKI, result.Profile);
    }

    [Fact]
    public void Validate_CorporatePki_UntrustedRoot_Denies()
    {
        var (_, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid());
        var (otherRoot, _) = TestCertificateFactory.CreateChain(Guid.NewGuid());
        var options = new DeviceCertificateOptions
        {
            ActiveProfile = "CorporatePKI",
            CorporatePKI = new CorporatePkiProfileOptions
            {
                // Configured anchor is a *different* root than the one that issued the leaf.
                TrustedRootThumbprints = [otherRoot.Thumbprint],
                CheckRevocation = false
            }
        };

        var validator = CreateValidator(options);
        using var chain = new X509Chain();
        var result = validator.Validate(leaf, chain);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_CorporatePki_NoTrustAnchorConfigured_FailsClosed()
    {
        var (_, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid());
        var options = new DeviceCertificateOptions { ActiveProfile = "CorporatePKI" };

        var validator = CreateValidator(options);
        using var chain = new X509Chain();
        var result = validator.Validate(leaf, chain);

        Assert.False(result.IsValid);
        Assert.Contains("No CorporatePKI trust anchor", result.DenyReason);
    }

    [Fact]
    public void Validate_CorporatePki_MissingClientAuthEku_Denies()
    {
        var (root, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid(), includeClientAuthEku: false);
        var options = new DeviceCertificateOptions
        {
            ActiveProfile = "CorporatePKI",
            CorporatePKI = new CorporatePkiProfileOptions
            {
                TrustedRootThumbprints = [root.Thumbprint],
                RequireClientAuthenticationEku = true,
                CheckRevocation = false
            }
        };

        var validator = CreateValidator(options);
        using var chain = new X509Chain();
        var result = validator.Validate(leaf, chain);

        Assert.False(result.IsValid);
        Assert.Contains("EKU", result.DenyReason);
    }

    [Fact]
    public void Validate_ExpiredCertificate_Denies()
    {
        var (root, leaf) = TestCertificateFactory.CreateChain(
            Guid.NewGuid(),
            notBefore: DateTimeOffset.UtcNow.AddDays(-30),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1));

        var options = new DeviceCertificateOptions
        {
            ActiveProfile = "CorporatePKI",
            CorporatePKI = new CorporatePkiProfileOptions
            {
                TrustedRootThumbprints = [root.Thumbprint],
                CheckRevocation = false
            }
        };

        var validator = CreateValidator(options);
        using var chain = new X509Chain();
        var result = validator.Validate(leaf, chain);

        Assert.False(result.IsValid);
        Assert.Contains("validity window", result.DenyReason);
    }

    [Fact]
    public void Validate_IntuneEnrollment_RequiredOidAndAllowListedIssuer_Succeeds()
    {
        const string oid = "1.2.840.113556.5.25";
        var (root, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid(), intuneEnrollmentOid: oid);

        var options = new DeviceCertificateOptions
        {
            ActiveProfile = "IntuneEnrollment",
            IntuneEnrollment = new IntuneEnrollmentProfileOptions
            {
                TrustedRootThumbprints = [root.Thumbprint],
                IssuerSubjectAllowList = [leaf.Issuer],
                RequiredOid = oid,
                SkipRevocationCheck = true
            }
        };

        var validator = CreateValidator(options);
        using var chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.Add(root);
        var result = validator.Validate(leaf, chain);

        Assert.True(result.IsValid);
        Assert.Equal(CertificateTrustProfile.IntuneEnrollment, result.Profile);
    }

    [Fact]
    public void Validate_IntuneEnrollment_MissingOid_Denies()
    {
        var (root, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid());

        var options = new DeviceCertificateOptions
        {
            ActiveProfile = "IntuneEnrollment",
            IntuneEnrollment = new IntuneEnrollmentProfileOptions
            {
                TrustedRootThumbprints = [root.Thumbprint],
                IssuerSubjectAllowList = [leaf.Issuer],
                SkipRevocationCheck = true
            }
        };

        var validator = CreateValidator(options);
        using var chain = new X509Chain();
        var result = validator.Validate(leaf, chain);

        Assert.False(result.IsValid);
        Assert.Contains("Intune enrollment OID", result.DenyReason);
    }

    [Fact]
    public void Validate_IntuneEnrollment_IssuerNotAllowListed_Denies()
    {
        const string oid = "1.2.840.113556.5.25";
        var (root, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid(), intuneEnrollmentOid: oid);

        var options = new DeviceCertificateOptions
        {
            ActiveProfile = "IntuneEnrollment",
            IntuneEnrollment = new IntuneEnrollmentProfileOptions
            {
                TrustedRootThumbprints = [root.Thumbprint],
                IssuerSubjectAllowList = ["CN=Some Other Issuer"],
                RequiredOid = oid,
                SkipRevocationCheck = true
            }
        };

        var validator = CreateValidator(options);
        using var chain = new X509Chain();
        var result = validator.Validate(leaf, chain);

        Assert.False(result.IsValid);
        Assert.Contains("allow-list", result.DenyReason);
    }
}
