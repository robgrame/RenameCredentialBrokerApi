namespace DeviceCredentialBroker.Api.Contracts;

/// <summary>
/// Conceptual request body (prompt §10). The TLS client certificate is the PRIMARY
/// authentication material — every value here is an identity CLAIM to be independently
/// cross-validated, never trusted automatically.
/// </summary>
public sealed record ComputerRenameCredentialRequest
{
    public Guid? EntraDeviceId { get; init; }
    public string? IntuneDeviceId { get; init; }
    public string? SerialNumber { get; init; }
    public string? CurrentComputerName { get; init; }
    public string? DesiredComputerName { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string RequestId { get; init; }
    public string? ClientVersion { get; init; }
}

/// <summary>
/// Minimal response (prompt §17) — never exposes CyberArk Safe/Object/AppID/server,
/// provider authentication information, or internal authorization data.
/// </summary>
public sealed record ComputerRenameCredentialResponse
{
    public required string Username { get; init; }
    public required string Password { get; init; }
    public required DateTimeOffset ExpiresUtc { get; init; }
    public required Guid CredentialLeaseId { get; init; }
    public required string CorrelationId { get; init; }
}

public sealed record ComputerRenameResultRequest
{
    public required Guid CredentialLeaseId { get; init; }
    public required string RequestId { get; init; }
    public string? PreviousComputerName { get; init; }
    public string? RequestedComputerName { get; init; }
    public required string Result { get; init; } // "Succeeded" | "Failed"
    public int? WindowsErrorCode { get; init; }
    public bool RebootRequired { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
}
