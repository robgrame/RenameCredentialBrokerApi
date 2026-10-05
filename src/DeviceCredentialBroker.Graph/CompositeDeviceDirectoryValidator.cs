using DeviceCredentialBroker.Domain;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Graph;
using Microsoft.Graph.Models.ODataErrors;

namespace DeviceCredentialBroker.Graph;

/// <summary>
/// Composes <see cref="EntraDeviceDirectoryValidator"/> and
/// <see cref="IntuneManagedDeviceValidator"/> according to <see cref="DeviceValidationOptions"/>.
/// Fails closed in every case — a Graph outage or error is never converted into an
/// authorization success (prompt §8, §27 — VERIFIED REQUIREMENT).
/// </summary>
public sealed class CompositeDeviceDirectoryValidator : IDeviceDirectoryValidator
{
    private readonly IGraphClientFactory _graphClientFactory;
    private readonly DeviceValidationOptions _options;
    private readonly ILogger<CompositeDeviceDirectoryValidator> _logger;

    public CompositeDeviceDirectoryValidator(
        IGraphClientFactory graphClientFactory,
        IOptions<DeviceValidationOptions> options,
        ILogger<CompositeDeviceDirectoryValidator> logger)
    {
        _graphClientFactory = graphClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<DeviceDirectoryValidationResult> ValidateAsync(DeviceIdentity identity, CancellationToken cancellationToken)
    {
        if (identity.EntraDeviceId is null)
        {
            return DeviceDirectoryValidationResult.Deny("No Entra device id resolved for this certificate.");
        }

        var client = _graphClientFactory.CreateClient();
        var entraDeviceFound = false;
        var entraDeviceEnabled = false;
        var intuneManaged = false;
        var intuneCompliant = false;

        try
        {
            var devices = await client.Devices.GetAsync(request =>
            {
                request.QueryParameters.Filter = $"deviceId eq '{identity.EntraDeviceId:D}'";
            }, cancellationToken);

            var device = devices?.Value?.FirstOrDefault();
            if (device is null)
            {
                _logger.LogWarning("GraphDeviceValidationFailed: device {DeviceId} not found in Entra ID.", identity.EntraDeviceId);
                return DeviceDirectoryValidationResult.Deny("Device not found in Entra ID.");
            }

            entraDeviceFound = true;
            entraDeviceEnabled = device.AccountEnabled ?? false;

            // A device found in Entra ID but explicitly disabled must always be denied —
            // this is not conditional on RequireEntraDevice (which only toggles whether the
            // lookup itself is mandatory), matching prompt §27 "Device disabled → DENY" with
            // no configuration-driven bypass.
            if (!entraDeviceEnabled)
            {
                return DeviceDirectoryValidationResult.Deny("Device is disabled in Entra ID.");
            }
        }
        catch (ODataError ex)
        {
            _logger.LogWarning(ex, "GraphDeviceValidationFailed: Entra device lookup failed for {DeviceId}.", identity.EntraDeviceId);
            return DeviceDirectoryValidationResult.Deny("Entra ID device lookup failed.");
        }

        // The Intune lookup must run whenever either managed-state or compliance is a
        // configured requirement — otherwise RequireCompliantDevice=true combined with
        // RequireIntuneManagedDevice=false would silently skip the compliance check
        // entirely (fixed per rubber-duck review finding #4).
        if (_options.RequireIntuneManagedDevice || _options.RequireCompliantDevice)
        {
            try
            {
                var managedDevices = await client.DeviceManagement.ManagedDevices.GetAsync(request =>
                {
                    request.QueryParameters.Filter = $"azureADDeviceId eq '{identity.EntraDeviceId:D}'";
                }, cancellationToken);

                var managedDevice = managedDevices?.Value?.FirstOrDefault();
                if (managedDevice is null)
                {
                    return DeviceDirectoryValidationResult.Deny("Device is not a managed Intune device.");
                }

                intuneManaged = true;
                intuneCompliant = managedDevice.ComplianceState == Microsoft.Graph.Models.ComplianceState.Compliant;

                if (_options.RequireCompliantDevice && !intuneCompliant)
                {
                    return DeviceDirectoryValidationResult.Deny("Device is not compliant.");
                }
            }
            catch (ODataError ex)
            {
                _logger.LogWarning(ex, "GraphDeviceValidationFailed: Intune managed-device lookup failed for {DeviceId}.", identity.EntraDeviceId);
                return DeviceDirectoryValidationResult.Deny("Intune managed-device lookup failed.");
            }
        }

        return new DeviceDirectoryValidationResult
        {
            IsValid = true,
            EntraDeviceFound = entraDeviceFound,
            EntraDeviceEnabled = entraDeviceEnabled,
            IntuneManaged = intuneManaged,
            IntuneCompliant = intuneCompliant
        };
    }
}
