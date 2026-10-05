namespace DeviceCredentialBroker.Domain;

/// <summary>
/// Strongly typed device identity. Clearly distinguishes certificate-derived values
/// (established during mTLS/chain validation), server-derived values (established by
/// calling Microsoft Graph), and client-reported values (claims in the request body,
/// never trusted on their own merely because they arrived over an authenticated
/// TLS connection — see docs/authentication.md).
/// </summary>
public sealed record DeviceIdentity
{
    // --- Certificate-derived (established by IDeviceCertificateValidator) ---
    public required string CertificateSubject { get; init; }
    public required string CertificateIssuer { get; init; }
    public string? CertificateSan { get; init; }
    public required string CertificateThumbprintHash { get; init; }
    public string? CertificatePublicKeyIdentifier { get; init; }

    /// <summary>
    /// The device identifier bound to the certificate using strict GUID-only extraction
    /// (SAN URI / SAN DNS / Subject CN as the entire value — never a substring match).
    /// </summary>
    public required Guid CertificateBoundDeviceId { get; init; }

    public required CertificateTrustProfile TrustProfile { get; init; }

    // --- Server-derived (established by IDeviceDirectoryValidator via Microsoft Graph) ---
    public Guid? EntraDeviceId { get; init; }
    public string? IntuneManagedDeviceId { get; init; }
    public string? TenantId { get; init; }

    // --- Client-reported claims (untrusted until cross-validated) ---
    public string? ClientReportedSerialNumber { get; init; }
    public string? ClientReportedCurrentComputerName { get; init; }
}

public enum CertificateTrustProfile
{
    IntuneEnrollment,
    CorporatePKI
}
