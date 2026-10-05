using DeviceCredentialBroker.Domain;
using Microsoft.Extensions.Options;

namespace DeviceCredentialBroker.Graph;

/// <summary>
/// Composes <see cref="EntraDeviceDirectoryValidator"/> and
/// <see cref="IntuneManagedDeviceValidator"/> according to <see cref="DeviceValidationOptions"/>.
/// Owns the ordering and fail-closed policy; the two composed validators own only the Graph
/// calls themselves and do not make authorization decisions. A Graph outage or error is never
/// converted into an authorization success (prompt §8, §27 — VERIFIED REQUIREMENT).
/// </summary>
public sealed class CompositeDeviceDirectoryValidator : IDeviceDirectoryValidator
{
    private readonly IGraphClientFactory _graphClientFactory;
    private readonly EntraDeviceDirectoryValidator _entraValidator;
    private readonly IntuneManagedDeviceValidator _intuneValidator;
    private readonly DeviceValidationOptions _options;

    public CompositeDeviceDirectoryValidator(
        IGraphClientFactory graphClientFactory,
        EntraDeviceDirectoryValidator entraValidator,
        IntuneManagedDeviceValidator intuneValidator,
        IOptions<DeviceValidationOptions> options)
    {
        _graphClientFactory = graphClientFactory;
        _entraValidator = entraValidator;
        _intuneValidator = intuneValidator;
        _options = options.Value;
    }

    public async Task<DeviceDirectoryValidationResult> ValidateAsync(DeviceIdentity identity, CancellationToken cancellationToken)
    {
        if (identity.EntraDeviceId is null)
        {
            return DeviceDirectoryValidationResult.Deny("No Entra device id resolved for this certificate.");
        }

        var client = _graphClientFactory.CreateClient();

        var entraResult = await _entraValidator.ValidateAsync(client, identity.EntraDeviceId.Value, cancellationToken);
        if (entraResult.LookupError)
        {
            return DeviceDirectoryValidationResult.Deny("Entra ID device lookup failed.");
        }

        if (!entraResult.Found)
        {
            return DeviceDirectoryValidationResult.Deny("Device not found in Entra ID.");
        }

        // A device found in Entra ID but explicitly disabled must always be denied —
        // this is not conditional on RequireEntraDevice (which only toggles whether the
        // lookup itself is mandatory), matching prompt §27 "Device disabled → DENY" with
        // no configuration-driven bypass.
        if (!entraResult.Enabled)
        {
            return DeviceDirectoryValidationResult.Deny("Device is disabled in Entra ID.");
        }

        var intuneManaged = false;
        var intuneCompliant = false;

        // The Intune lookup must run whenever either managed-state or compliance is a
        // configured requirement — otherwise RequireCompliantDevice=true combined with
        // RequireIntuneManagedDevice=false would silently skip the compliance check
        // entirely (fixed per rubber-duck review finding #4).
        if (_options.RequireIntuneManagedDevice || _options.RequireCompliantDevice)
        {
            var intuneResult = await _intuneValidator.ValidateAsync(client, identity.EntraDeviceId.Value, cancellationToken);
            if (intuneResult.LookupError)
            {
                return DeviceDirectoryValidationResult.Deny("Intune managed-device lookup failed.");
            }

            if (!intuneResult.Managed)
            {
                return DeviceDirectoryValidationResult.Deny("Device is not a managed Intune device.");
            }

            intuneManaged = true;
            intuneCompliant = intuneResult.Compliant;

            if (_options.RequireCompliantDevice && !intuneCompliant)
            {
                return DeviceDirectoryValidationResult.Deny("Device is not compliant.");
            }
        }

        return new DeviceDirectoryValidationResult
        {
            IsValid = true,
            EntraDeviceFound = true,
            EntraDeviceEnabled = true,
            IntuneManaged = intuneManaged,
            IntuneCompliant = intuneCompliant
        };
    }
}
