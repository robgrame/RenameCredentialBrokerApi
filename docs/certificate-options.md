# Certificate options — Intune enrollment vs. corporate PKI

Companion to ADR 0002. This document captures the *characteristics* to verify (prompt §3) before
choosing `ActiveProfile`, and the design of `IDeviceCertificateValidator`.

## Option A — Intune enrollment certificate

| Characteristic | Value / status |
|---|---|
| Store | `LocalMachine\My` (typical for Intune device-enrollment certs) — **REQUIRES CUSTOMER VALIDATION** |
| Issuer | A Microsoft-operated, shared Intune CA (not customer-specific) |
| Subject | Typically a GUID distinct from the Entra device ID (verified behavior in LogCollector: "Intune puts a different GUID in the CN that is not the Entra device id") — **do not** bind device identity off the CN for this profile |
| SAN | Not reliably populated with the Entra device ID for this profile — **REQUIRES CUSTOMER VALIDATION** against the actual issued certificate |
| EKU | Client Authentication (`1.3.6.1.5.5.7.3.2`) expected — **REQUIRES CUSTOMER VALIDATION** |
| Unique correlating identifier | Custom OID `1.2.840.113556.5.25` — verified in LogCollector as the field carrying the Entra device ID for Intune enrollment certs. **This OID mapping is inherited from a reference implementation, not a universal guarantee** — LogCollector's own docs say to compare against `dsregcmd` output and the Entra device record during pilot, and fail closed if it doesn't match. The same caution applies here. |
| Private-key availability | Should be non-exportable; SYSTEM-accessible (required, since the rename script runs in SYSTEM context) — **REQUIRES CUSTOMER VALIDATION** |
| Lifetime / renewal | Managed automatically by Intune; thumbprint changes on renewal — do not pin solely by thumbprint for this profile; key off the OID-derived device ID instead |
| Chain | Root is a shared Microsoft/Intune root, not customer-specific — trust by issuer DN is insufficient alone; must combine with issuer-subject allow-listing AND a mandatory (never-optional, for this operation) Graph tenant-membership check |

## Option B — Corporate PKI machine certificate

| Characteristic | Value / status |
|---|---|
| Store | `LocalMachine\My` expected, same reasoning as Option A |
| Issuer | Customer-operated Root/SubCA — **REQUIRES CUSTOMER VALIDATION** of actual template(s) in use |
| Subject / SAN | Entirely dependent on the certificate template design — **REQUIRES CUSTOMER VALIDATION**. If the template can be extended, recommend a SAN URI of the form `urn:uuid:<entraDeviceId>` or SAN DNS of the bare device GUID, matching the strict-GUID-binding pattern already proven in LogCollector. |
| EKU | Client Authentication — should be enforceable via template design, confirm with PKI team |
| Private-key availability | Non-exportable template flag — **REQUIRES CUSTOMER VALIDATION** |
| Lifetime / renewal | Customer-controlled; typically longer-lived than Intune enrollment certs, but exact policy unknown — **REQUIRES CUSTOMER VALIDATION** |
| Chain | Customer Root + one or more SubCAs — all configurable as trust anchors per `docs/authentication.md` §6 configuration shape |

## Selection logic (do NOT use FriendlyName)

`IDeviceCertificateValidator` selects a *candidate* certificate from the store using **only**:

1. Presence of a private key accessible without a UI prompt (SYSTEM context).
2. Current validity window (`NotBefore`/`NotAfter`).
3. Required EKU present.
4. For the `IntuneEnrollment` profile: presence of OID `1.2.840.113556.5.25` **and** issuer subject
   DN matching the configured allow-list (mirrors LogCollector's two-condition requirement — OID
   alone is "a selection criterion, not proof").
5. For the `CorporatePKI` profile: chain validation against the configured Root/SubCA anchors.

No candidate is accepted on the strength of a `FriendlyName` string anywhere in this design, per the
explicit prohibition in prompt §3.

## Decision ownership

`docs/adr/0002-certificate-profile-selection.md` is the decision record. This document is the
factual input to that decision, to be completed once the PKI/Intune team answers the "REQUIRES
CUSTOMER VALIDATION" rows above.
