using DeviceCredentialBroker.Domain;

namespace DeviceCredentialBroker.Graph;

/// <summary>
/// Server-side device verification against Microsoft Graph (prompt §7). Composed from
/// independently configurable checks — never automatically requiring every possible
/// attribute (see docs/device-validation.md).
/// </summary>
public interface IDeviceDirectoryValidator
{
    Task<DeviceDirectoryValidationResult> ValidateAsync(DeviceIdentity identity, CancellationToken cancellationToken);
}
