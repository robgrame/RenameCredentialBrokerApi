using DeviceCredentialBroker.Domain;

namespace DeviceCredentialBroker.CyberArk;

/// <summary>
/// Application-facing credential abstraction (prompt §13, §30). The application layer
/// only ever calls <see cref="GetCredentialAsync"/> with a <see cref="CredentialPurpose"/>
/// — it has no knowledge of CyberArk Safes, Objects, or authentication details.
/// </summary>
public interface ICredentialProvider
{
    Task<IssuedCredential?> GetCredentialAsync(CredentialPurpose purpose, CancellationToken cancellationToken);
}

/// <summary>
/// Low-level CyberArk client abstraction (prompt §13). NOTE: no production
/// implementation exists in this repository — see docs/cyberark-integration.md and
/// ADR 0004. Only <see cref="MockCyberArkClient"/> (tests) and
/// <see cref="NotConfiguredCyberArkClient"/> (fail-closed default) are provided until
/// the CyberArk interface and authentication mechanism are confirmed with the customer.
/// </summary>
public interface ICyberArkClient
{
    Task<CyberArkCredentialResult> GetAccountCredentialAsync(
        string safe,
        string @object,
        string appId,
        CancellationToken cancellationToken);
}

public sealed record CyberArkCredentialResult
{
    public required bool Success { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
    public DateTimeOffset? NextRotationUtc { get; init; }
    public string? FailureReason { get; init; }

    public static CyberArkCredentialResult Failure(string reason) => new() { Success = false, FailureReason = reason };
}
