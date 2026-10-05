namespace DeviceCredentialBroker.Domain;

/// <summary>
/// Result of server-side device validation against Microsoft Graph / Entra ID / Intune
/// (prompt §7). Attributes are independently togglable via policy — not every attribute
/// is automatically required.
/// </summary>
public sealed record DeviceDirectoryValidationResult
{
    public required bool IsValid { get; init; }
    public bool EntraDeviceFound { get; init; }
    public bool EntraDeviceEnabled { get; init; }
    public bool IntuneManaged { get; init; }
    public bool IntuneCompliant { get; init; }
    public string? DenyReason { get; init; }

    public static DeviceDirectoryValidationResult Deny(string reason) => new()
    {
        IsValid = false,
        DenyReason = reason
    };
}

/// <summary>
/// Result of certificate chain/profile validation (prompt §3, §5, §29).
/// </summary>
public sealed record CertificateValidationResult
{
    public required bool IsValid { get; init; }
    public CertificateTrustProfile? Profile { get; init; }
    public string? DenyReason { get; init; }
    public IReadOnlyDictionary<string, string> CertificateDerivedClaims { get; init; }
        = new Dictionary<string, string>();

    public static CertificateValidationResult Deny(string reason) => new()
    {
        IsValid = false,
        DenyReason = reason
    };
}

/// <summary>
/// Outcome of <see cref="DeviceOperation"/> authorization (prompt §9). The server-side
/// reason code is never exposed to the client — only a generic denial is returned over
/// the wire, to avoid leaking authorization internals to a potentially spoofing endpoint.
/// </summary>
public sealed record AuthorizationResult
{
    public required bool Authorized { get; init; }
    public string? DenyReasonCode { get; init; }

    public static AuthorizationResult Allow() => new() { Authorized = true };
    public static AuthorizationResult Deny(string reasonCode) => new()
    {
        Authorized = false,
        DenyReasonCode = reasonCode
    };
}
