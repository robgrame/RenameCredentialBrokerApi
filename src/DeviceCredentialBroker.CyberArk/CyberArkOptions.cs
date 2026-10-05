namespace DeviceCredentialBroker.CyberArk;

/// <summary>
/// Server-side-only mapping of CredentialPurpose → CyberArk Safe/Object/AppID
/// (prompt §14). Never derived from, or exposed to, the client.
/// </summary>
public sealed class CyberArkOptions
{
    public const string SectionName = "CyberArk";

    public string? BaseUrl { get; set; }
    public string? AuthenticationMode { get; set; }
    public int TimeoutSeconds { get; set; } = 10;
    public Dictionary<string, CyberArkPurposeMapping> PurposeMappings { get; set; } = [];
}

public sealed class CyberArkPurposeMapping
{
    public required string Safe { get; set; }
    public required string Object { get; set; }
    public required string AppId { get; set; }
}
