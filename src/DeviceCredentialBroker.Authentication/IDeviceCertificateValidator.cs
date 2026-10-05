using System.Security.Cryptography.X509Certificates;
using DeviceCredentialBroker.Domain;

namespace DeviceCredentialBroker.Authentication;

/// <summary>
/// Validates a device (mTLS) certificate against the configured trust profile(s)
/// (prompt §3, §29). Certificate selection and validation must never rely on
/// FriendlyName — only explicit chain, EKU, and profile-specific characteristics.
/// </summary>
public interface IDeviceCertificateValidator
{
    CertificateValidationResult Validate(X509Certificate2 clientCertificate, X509Chain chain);
}

/// <summary>
/// Resolves a strongly typed <see cref="DeviceIdentity"/> from a validated certificate
/// plus client-reported claims, applying strict GUID-only device-ID binding extraction
/// (SAN URI / SAN DNS / Subject CN as the entire value — never a substring).
/// </summary>
public interface IDeviceIdentityResolver
{
    DeviceIdentity? Resolve(
        X509Certificate2 clientCertificate,
        CertificateValidationResult certificateValidation,
        string? clientReportedSerialNumber,
        string? clientReportedCurrentComputerName,
        out string? denyReason);
}
