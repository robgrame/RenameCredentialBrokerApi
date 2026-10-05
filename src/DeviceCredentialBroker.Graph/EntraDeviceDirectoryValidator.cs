using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models.ODataErrors;

namespace DeviceCredentialBroker.Graph;

/// <summary>
/// Looks up a device in Microsoft Entra ID by its device GUID and reports whether it exists and
/// is enabled. Does not evaluate Intune management or compliance state — see
/// <see cref="IntuneManagedDeviceValidator"/> for that. Composed by
/// <see cref="CompositeDeviceDirectoryValidator"/>, which owns policy (whether this lookup is
/// mandatory) and fail-closed behavior at the orchestration level.
/// </summary>
public sealed class EntraDeviceDirectoryValidator
{
    private readonly ILogger<EntraDeviceDirectoryValidator> _logger;

    public EntraDeviceDirectoryValidator(ILogger<EntraDeviceDirectoryValidator> logger)
    {
        _logger = logger;
    }

    public async Task<EntraDeviceLookupResult> ValidateAsync(
        GraphServiceClient client,
        Guid entraDeviceId,
        CancellationToken cancellationToken)
    {
        try
        {
            var devices = await client.Devices.GetAsync(request =>
            {
                request.QueryParameters.Filter = $"deviceId eq '{entraDeviceId:D}'";
            }, cancellationToken);

            var device = devices?.Value?.FirstOrDefault();
            if (device is null)
            {
                _logger.LogWarning("GraphDeviceValidationFailed: device {DeviceId} not found in Entra ID.", entraDeviceId);
                return EntraDeviceLookupResult.NotFound();
            }

            return EntraDeviceLookupResult.Resolved(device.AccountEnabled ?? false);
        }
        catch (ODataError ex)
        {
            _logger.LogWarning(ex, "GraphDeviceValidationFailed: Entra device lookup failed for {DeviceId}.", entraDeviceId);
            return EntraDeviceLookupResult.LookupFailed();
        }
    }
}

/// <summary>
/// Result of an <see cref="EntraDeviceDirectoryValidator"/> lookup. <see cref="LookupError"/>
/// distinguishes "Graph call failed" from "device legitimately not found" so the composite
/// validator can apply the same fail-closed deny to both, with a more specific audit reason.
/// </summary>
public sealed record EntraDeviceLookupResult(bool Found, bool Enabled, bool LookupError)
{
    public static EntraDeviceLookupResult NotFound() => new(Found: false, Enabled: false, LookupError: false);

    public static EntraDeviceLookupResult LookupFailed() => new(Found: false, Enabled: false, LookupError: true);

    public static EntraDeviceLookupResult Resolved(bool enabled) => new(Found: true, Enabled: enabled, LookupError: false);
}
