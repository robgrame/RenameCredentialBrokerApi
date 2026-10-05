namespace DeviceCredentialBroker.Authentication;

/// <summary>
/// Configuration for the two certificate trust profiles described in prompt §3 and
/// docs/certificate-options.md. Both profiles can be configured simultaneously;
/// <see cref="ActiveProfile"/> selects which one is enforced in a given environment
/// (ADR 0002 — OPEN DECISION, not hard-coded).
/// </summary>
public sealed class DeviceCertificateOptions
{
    public const string SectionName = "DeviceCertificate";

    public string ActiveProfile { get; set; } = "CorporatePKI";

    public CorporatePkiProfileOptions CorporatePKI { get; set; } = new();

    public IntuneEnrollmentProfileOptions IntuneEnrollment { get; set; } = new();
}

public sealed class CorporatePkiProfileOptions
{
    public List<string> TrustedRootThumbprints { get; set; } = [];
    public List<string> TrustedRootSubjects { get; set; } = [];
    public List<string> TrustedIntermediateThumbprints { get; set; } = [];
    public List<string> TrustedIntermediateSubjects { get; set; } = [];
    public bool RequireClientAuthenticationEku { get; set; } = true;
    public bool CheckRevocation { get; set; } = true;
}

public sealed class IntuneEnrollmentProfileOptions
{
    public List<string> TrustedRootThumbprints { get; set; } = [];

    /// <summary>
    /// Issuer subject DNs allowed to carry the Intune enrollment OID. Required in
    /// addition to the OID itself — the OID alone is a selection criterion, never
    /// proof of trust (docs/authentication.md §2, verified LogCollector pattern).
    /// </summary>
    public List<string> IssuerSubjectAllowList { get; set; } = [];

    public string RequiredOid { get; set; } = "1.2.840.113556.5.25";

    public bool SkipRevocationCheck { get; set; }
}
