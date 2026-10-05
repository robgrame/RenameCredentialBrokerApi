using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DeviceCredentialBroker.Authentication.Tests;

/// <summary>
/// Builds throwaway self-signed root/leaf certificate pairs for tests only. Never used
/// outside the test suite; private keys are generated in memory and discarded.
/// </summary>
internal static class TestCertificateFactory
{
    public static (X509Certificate2 Root, X509Certificate2 Leaf) CreateChain(
        Guid deviceId,
        string? intuneEnrollmentOid = null,
        bool includeClientAuthEku = true,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest(
            "CN=Test Root CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        var root = rootRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddYears(5));

        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest(
            $"CN={deviceId:D}", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

        if (includeClientAuthEku)
        {
            leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new Oid("1.3.6.1.5.5.7.3.2")], false));
        }

        if (intuneEnrollmentOid is not null)
        {
            leafRequest.CertificateExtensions.Add(
                new X509Extension(new Oid(intuneEnrollmentOid), [0x05, 0x00], false));
        }

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri($"urn:uuid:{deviceId:D}"));
        leafRequest.CertificateExtensions.Add(sanBuilder.Build());

        var leafNotBefore = notBefore ?? DateTimeOffset.UtcNow.AddDays(-1);
        var leafNotAfter = notAfter ?? DateTimeOffset.UtcNow.AddYears(1);

        using var leafCert = leafRequest.Create(
            root, leafNotBefore, leafNotAfter, Guid.NewGuid().ToByteArray());

        var leafWithKey = leafCert.CopyWithPrivateKey(leafKey);

        return (
            X509CertificateLoader.LoadCertificate(root.Export(X509ContentType.Cert)),
            X509CertificateLoader.LoadPkcs12(leafWithKey.Export(X509ContentType.Pfx), null));
    }
}
