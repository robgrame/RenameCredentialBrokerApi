using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DeviceCredentialBroker.IntegrationTests;

/// <summary>
/// Builds throwaway self-signed root/leaf certificate pairs for integration tests only.
/// Duplicated (not shared) from DeviceCredentialBroker.Authentication.Tests deliberately,
/// to keep each test project's dependency graph independent.
/// </summary>
internal static class TestCertificateFactory
{
    public static (X509Certificate2 Root, X509Certificate2 Leaf) CreateChain(Guid deviceId)
    {
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest(
            "CN=Integration Test Root CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest(
            $"CN={deviceId:D}", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri($"urn:uuid:{deviceId:D}"));
        leafRequest.CertificateExtensions.Add(sanBuilder.Build());

        using var leafCert = leafRequest.Create(
            root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), Guid.NewGuid().ToByteArray());
        var leafWithKey = leafCert.CopyWithPrivateKey(leafKey);

        return (
            X509CertificateLoader.LoadCertificate(root.Export(X509ContentType.Cert)),
            X509CertificateLoader.LoadPkcs12(leafWithKey.Export(X509ContentType.Pfx), null));
    }
}
