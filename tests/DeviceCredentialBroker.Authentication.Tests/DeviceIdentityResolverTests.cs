using DeviceCredentialBroker.Domain;
using Xunit;

namespace DeviceCredentialBroker.Authentication.Tests;

public class DeviceIdentityResolverTests
{
    private static readonly CertificateValidationResult ValidResult = new()
    {
        IsValid = true,
        Profile = CertificateTrustProfile.CorporatePKI
    };

    [Fact]
    public void Resolve_SanUriGuid_BindsDeviceId()
    {
        var deviceId = Guid.NewGuid();
        var (_, leaf) = TestCertificateFactory.CreateChain(deviceId);
        var resolver = new DeviceIdentityResolver();

        var identity = resolver.Resolve(leaf, ValidResult, "SN123", "OLD-HOST", out var denyReason);

        Assert.NotNull(identity);
        Assert.Null(denyReason);
        Assert.Equal(deviceId, identity!.CertificateBoundDeviceId);
    }

    [Fact]
    public void Resolve_CertificateValidationFailed_ReturnsNull()
    {
        var (_, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid());
        var resolver = new DeviceIdentityResolver();

        var identity = resolver.Resolve(leaf, CertificateValidationResult.Deny("bad cert"), null, null, out var denyReason);

        Assert.Null(identity);
        Assert.NotNull(denyReason);
    }

    [Fact]
    public void Resolve_NoBoundIdentifier_ReturnsNull()
    {
        // A certificate whose CN is not a GUID and has no SAN device-id — must be
        // rejected, never partially matched (prompt §11 anti-IDOR control).
        using var key = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=not-a-guid-device", key, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var resolver = new DeviceIdentityResolver();
        var identity = resolver.Resolve(cert, ValidResult, null, null, out var denyReason);

        Assert.Null(identity);
        Assert.Contains("No strictly-bound device identifier", denyReason);
    }
}
