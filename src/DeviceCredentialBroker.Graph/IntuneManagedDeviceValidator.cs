using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models.ODataErrors;

namespace DeviceCredentialBroker.Graph;

/// <summary>
/// Looks up a device's Intune managed-device record by its Entra device GUID and reports
/// whether it is managed and, if so, its compliance state. Composed by
/// <see cref="CompositeDeviceDirectoryValidator"/>, which owns policy (whether this lookup runs
/// at all, and whether compliance is enforced) and fail-closed behavior at the orchestration
/// level.
/// </summary>
public sealed class IntuneManagedDeviceValidator
{
    private readonly ILogger<IntuneManagedDeviceValidator> _logger;

    public IntuneManagedDeviceValidator(ILogger<IntuneManagedDeviceValidator> logger)
    {
        _logger = logger;
    }

    public async Task<IntuneDeviceLookupResult> ValidateAsync(
        GraphServiceClient client,
        Guid entraDeviceId,
        CancellationToken cancellationToken)
    {
        try
        {
            var managedDevices = await client.DeviceManagement.ManagedDevices.GetAsync(request =>
            {
                request.QueryParameters.Filter = $"azureADDeviceId eq '{entraDeviceId:D}'";
            }, cancellationToken);

            var managedDevice = managedDevices?.Value?.FirstOrDefault();
            if (managedDevice is null)
            {
                return IntuneDeviceLookupResult.NotFound();
            }

            var compliant = managedDevice.ComplianceState == Microsoft.Graph.Models.ComplianceState.Compliant;
            return IntuneDeviceLookupResult.Resolved(compliant);
        }
        catch (ODataError ex)
        {
            _logger.LogWarning(ex, "GraphDeviceValidationFailed: Intune managed-device lookup failed for {DeviceId}.", entraDeviceId);
            return IntuneDeviceLookupResult.LookupFailed();
        }
    }
}

/// <summary>
/// Result of an <see cref="IntuneManagedDeviceValidator"/> lookup. <see cref="LookupError"/>
/// distinguishes "Graph call failed" from "device legitimately not managed" so the composite
/// validator can apply the same fail-closed deny to both, with a more specific audit reason.
/// </summary>
public sealed record IntuneDeviceLookupResult(bool Managed, bool Compliant, bool LookupError)
{
    public static IntuneDeviceLookupResult NotFound() => new(Managed: false, Compliant: false, LookupError: false);

    public static IntuneDeviceLookupResult LookupFailed() => new(Managed: false, Compliant: false, LookupError: true);

    public static IntuneDeviceLookupResult Resolved(bool compliant) => new(Managed: true, Compliant: compliant, LookupError: false);
}
