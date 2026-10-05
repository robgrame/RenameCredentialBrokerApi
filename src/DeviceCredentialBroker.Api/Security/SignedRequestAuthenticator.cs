using System.Security.Cryptography.X509Certificates;
using DeviceCredentialBroker.Authentication;
using Microsoft.Extensions.Logging;

namespace DeviceCredentialBroker.Api.Security;

/// <summary>
/// Orchestrates the ordered, security-critical pipeline for a signed request: raw body
/// capture (before any deserialization) → timestamp freshness → signature verification
/// → nonce reservation. Order is a security property (docs/authentication.md §3,
/// verified LogCollector invariant): nonce reservation must never run before signature
/// verification, or unauthenticated traffic could pollute/exhaust the nonce store.
/// </summary>
public sealed class SignedRequestAuthenticator
{
    private readonly ReplayProtector _replayProtector;
    private readonly ILogger<SignedRequestAuthenticator> _logger;

    public SignedRequestAuthenticator(ReplayProtector replayProtector, ILogger<SignedRequestAuthenticator> logger)
    {
        _replayProtector = replayProtector;
        _logger = logger;
    }

    public async Task<SignedRequestAuthenticationResult> AuthenticateAsync(
        HttpRequest request,
        X509Certificate2 clientCertificate,
        string certificateThumbprintHash,
        byte[] bodyBytes,
        CancellationToken cancellationToken)
    {
        if (!request.Headers.TryGetValue("X-Request-Timestamp", out var timestampHeader)
            || !DateTimeOffset.TryParse(timestampHeader, out var timestamp))
        {
            return SignedRequestAuthenticationResult.Deny("Missing or invalid X-Request-Timestamp.");
        }

        if (!_replayProtector.ValidateFreshness(timestamp, DateTimeOffset.UtcNow))
        {
            return SignedRequestAuthenticationResult.Deny("Request timestamp is outside the allowed skew window.");
        }

        if (!request.Headers.TryGetValue("X-Request-Nonce", out var nonceHeader)
            || !Guid.TryParse(nonceHeader, out var nonce) || nonce == Guid.Empty)
        {
            return SignedRequestAuthenticationResult.Deny("Missing or invalid X-Request-Nonce.");
        }

        if (!request.Headers.TryGetValue("X-Request-Signature-Version", out var version)
            || version != RequestSignature.ProtocolVersion)
        {
            return SignedRequestAuthenticationResult.Deny("Unsupported or missing signature protocol version.");
        }

        if (!request.Headers.TryGetValue("X-Request-Signature-Algorithm", out var algorithm)
            || !request.Headers.TryGetValue("X-Request-Signature", out var signatureBase64))
        {
            return SignedRequestAuthenticationResult.Deny("Missing signature headers.");
        }

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(signatureBase64!);
        }
        catch (FormatException)
        {
            return SignedRequestAuthenticationResult.Deny("Signature is not valid Base64.");
        }

        var verified = RequestSignature.Verify(
            clientCertificate,
            request.Method,
            request.Path,
            timestamp,
            nonce,
            bodyBytes,
            algorithm!,
            signature);

        if (!verified)
        {
            return SignedRequestAuthenticationResult.Deny("Signature verification failed.");
        }

        // Only now — after cheap checks and cryptographic verification — may the nonce
        // be reserved, so unauthenticated traffic cannot inflate the nonce store.
        var reserved = await _replayProtector.ReserveAsync(certificateThumbprintHash, nonce, timestamp, cancellationToken);
        if (!reserved)
        {
            _logger.LogWarning("ReplayDetected: nonce {Nonce} already used for certificate {Thumbprint}.", nonce, certificateThumbprintHash);
            return SignedRequestAuthenticationResult.Deny("Replay detected: nonce already used.");
        }

        return SignedRequestAuthenticationResult.Allow();
    }
}

public sealed record SignedRequestAuthenticationResult
{
    public required bool Success { get; init; }
    public string? DenyReason { get; init; }

    public static SignedRequestAuthenticationResult Allow() => new() { Success = true };
    public static SignedRequestAuthenticationResult Deny(string reason) => new() { Success = false, DenyReason = reason };
}
