using DeviceCredentialBroker.Domain;

namespace DeviceCredentialBroker.Application;

/// <summary>
/// Authorizes a requested <see cref="DeviceOperation"/> (prompt §9). The client never
/// chooses which CyberArk account/Safe/Object/AppID to retrieve — it only asks
/// "authorize me for ComputerRename," never "give me the password for X."
/// </summary>
public interface IDeviceOperationAuthorizationService
{
    Task<AuthorizationResult> AuthorizeAsync(DeviceOperationRequest request, CancellationToken cancellationToken);
}

public sealed record DeviceOperationRequest
{
    public required DeviceIdentity Identity { get; init; }
    public required DeviceDirectoryValidationResult DirectoryValidation { get; init; }
    public required DeviceOperation Operation { get; init; }
    public required DateTimeOffset RequestTimestamp { get; init; }
    public required string CorrelationId { get; init; }
    public string? TargetComputerName { get; init; }
}
