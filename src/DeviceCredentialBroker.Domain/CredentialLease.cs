namespace DeviceCredentialBroker.Domain;

public enum DeviceOperation
{
    ComputerRename
}

/// <summary>
/// Server-side audit relationship between a device request and the eventual rename
/// result — contains NO password (prompt §21). Provides: Device → Authorization →
/// CyberArk retrieval → Credential issuance → Rename result, without ever persisting
/// the credential itself.
/// </summary>
public sealed record CredentialLease
{
    public required Guid LeaseId { get; init; }
    public required string DeviceIdentityId { get; init; }
    public required DeviceOperation Operation { get; init; }
    public required DateTimeOffset IssuedUtc { get; init; }
    public required DateTimeOffset ExpiresUtc { get; init; }
    public required string RequestId { get; init; }
    public required string CorrelationId { get; init; }
    public required CredentialLeaseStatus Status { get; init; }
}

public enum CredentialLeaseStatus
{
    Issued,
    OperationReportedSucceeded,
    OperationReportedFailed,
    Expired,
    Suspicious
}

public enum CredentialPurpose
{
    ComputerRename
}

/// <summary>
/// The credential released to an authorized device. Deliberately minimal — never
/// includes CyberArk Safe/Object/AppID/server details (prompt §17).
/// </summary>
public sealed record IssuedCredential
{
    public required string Username { get; init; }
    public required string Password { get; init; }
    public required DateTimeOffset ExpiresUtc { get; init; }
    public required Guid CredentialLeaseId { get; init; }
    public required string CorrelationId { get; init; }
}
