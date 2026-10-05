namespace DeviceCredentialBroker.Graph;

/// <summary>
/// Device validation policy — configuration-driven, per docs/device-validation.md.
/// None of these default to a state that silently weakens the ComputerRename gate;
/// the final production policy must be documented explicitly (prompt §7).
/// </summary>
public sealed class DeviceValidationOptions
{
    public const string SectionName = "DeviceValidation";

    public bool RequireEntraDevice { get; set; } = true;
    public bool RequireIntuneManagedDevice { get; set; } = true;
    public bool RequireCompliantDevice { get; set; }
    public int PositiveResultCacheSeconds { get; set; }
}
