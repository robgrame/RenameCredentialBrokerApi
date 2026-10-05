using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DeviceCredentialBroker.Authentication;

/// <summary>
/// DCB-SIGNATURE-V1 — adapted from LogCollector's verified IDA-SIGNATURE-V1 scheme
/// (docs/authentication.md §3). Re-establishes, end to end, the binding between the
/// mTLS-authenticated certificate and the exact request body/method/path/timestamp/
/// nonce — because the platform (App Service) proves possession only to the edge,
/// not to the application. Protocol is renamed (not reused byte-for-byte) to avoid
/// cross-service replay between LogCollector and this Broker.
/// </summary>
public static class RequestSignature
{
    public const string ProtocolVersion = "DCB-SIGNATURE-V1";
    public const string RsaAlgorithm = "RSA-PKCS1-SHA256";
    public const string EcdsaAlgorithm = "ECDSA-SHA256";

    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>
    /// Builds the canonical six-line string that is signed and verified. MUST stay
    /// byte-identical between client and server — any change is a breaking protocol
    /// change requiring a new version token.
    /// </summary>
    public static string BuildCanonicalRequest(
        string method,
        string path,
        DateTimeOffset timestamp,
        Guid nonce,
        ReadOnlySpan<byte> bodyBytes)
    {
        var normalizedPath = path.Trim();
        if (normalizedPath.Length == 0) normalizedPath = "/";
        if (!normalizedPath.StartsWith('/')) normalizedPath = "/" + normalizedPath;

        var bodyHash = Convert.ToBase64String(SHA256.HashData(bodyBytes));

        return string.Join('\n',
        [
            ProtocolVersion,
            method.Trim().ToUpperInvariant(),
            normalizedPath,
            timestamp.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture),
            nonce.ToString("D").ToLowerInvariant(),
            bodyHash
        ]);
    }

    public static bool Verify(
        X509Certificate2 certificate,
        string method,
        string path,
        DateTimeOffset timestamp,
        Guid nonce,
        byte[] bodyBytes,
        string algorithm,
        byte[] signature)
    {
        var canonical = BuildCanonicalRequest(method, path, timestamp, nonce, bodyBytes);
        var canonicalBytes = Utf8NoBom.GetBytes(canonical);

        if (algorithm == RsaAlgorithm)
        {
            using var rsa = certificate.GetRSAPublicKey();
            return rsa is not null && rsa.VerifyData(
                canonicalBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        if (algorithm == EcdsaAlgorithm)
        {
            using var ecdsa = certificate.GetECDsaPublicKey();
            return ecdsa is not null && ecdsa.VerifyData(canonicalBytes, signature, HashAlgorithmName.SHA256);
        }

        return false;
    }
}
