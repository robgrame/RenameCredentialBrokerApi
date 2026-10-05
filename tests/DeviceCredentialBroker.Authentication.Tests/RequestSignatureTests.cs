using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;

namespace DeviceCredentialBroker.Authentication.Tests;

public class RequestSignatureTests
{
    [Fact]
    public void Verify_ValidRsaSignature_Succeeds()
    {
        var (_, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid());
        var body = Encoding.UTF8.GetBytes("""{"requestId":"abc"}""");
        var timestamp = DateTimeOffset.UtcNow;
        var nonce = Guid.NewGuid();

        var canonical = RequestSignature.BuildCanonicalRequest("POST", "/api/v1/device/operations/computer-rename/credential", timestamp, nonce, body);
        using var rsa = leaf.GetRSAPrivateKey()!;
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var verified = RequestSignature.Verify(
            leaf, "POST", "/api/v1/device/operations/computer-rename/credential", timestamp, nonce, body,
            RequestSignature.RsaAlgorithm, signature);

        Assert.True(verified);
    }

    [Fact]
    public void Verify_TamperedBody_Fails()
    {
        var (_, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid());
        var body = Encoding.UTF8.GetBytes("""{"requestId":"abc"}""");
        var tamperedBody = Encoding.UTF8.GetBytes("""{"requestId":"xyz"}""");
        var timestamp = DateTimeOffset.UtcNow;
        var nonce = Guid.NewGuid();

        var canonical = RequestSignature.BuildCanonicalRequest("POST", "/path", timestamp, nonce, body);
        using var rsa = leaf.GetRSAPrivateKey()!;
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var verified = RequestSignature.Verify(
            leaf, "POST", "/path", timestamp, nonce, tamperedBody, RequestSignature.RsaAlgorithm, signature);

        Assert.False(verified);
    }

    [Fact]
    public void Verify_UnknownAlgorithm_Fails()
    {
        var (_, leaf) = TestCertificateFactory.CreateChain(Guid.NewGuid());
        var body = Encoding.UTF8.GetBytes("{}");

        var verified = RequestSignature.Verify(
            leaf, "POST", "/path", DateTimeOffset.UtcNow, Guid.NewGuid(), body, "SOMETHING-ELSE", [1, 2, 3]);

        Assert.False(verified);
    }

    [Fact]
    public void BuildCanonicalRequest_IsDeterministic()
    {
        var timestamp = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var nonce = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var body = Encoding.UTF8.GetBytes("{}");

        var first = RequestSignature.BuildCanonicalRequest("post", "api/v1/x", timestamp, nonce, body);
        var second = RequestSignature.BuildCanonicalRequest("POST", "/api/v1/x", timestamp, nonce, body);

        Assert.Equal(first, second);
        Assert.StartsWith(RequestSignature.ProtocolVersion, first);
    }
}
