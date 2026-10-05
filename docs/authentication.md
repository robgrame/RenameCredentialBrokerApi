# Device authentication — design and LogCollector reuse analysis

This document fulfils prompt section 4 (reuse analysis) and section 5/6 (mTLS + device identity
design). Every behavior attributed to LogCollector below was verified by reading the actual source
in `C:\Users\robgrame\source\repos\LogCollector` (commit state as of this session) — nothing here is
assumed or invented.

## 1. What LogCollector already does (verified)

LogCollector (`robgrame/LogCollector`) is a telemetry-ingestion service that already solves
"authenticate a Windows device to an Azure-hosted API using a device certificate, with no shared
secret." Verified components:

| LogCollector artifact | Location | What it does |
|---|---|---|
| `RequestSigning.psm1` | `src/Client/RequestSigning.psm1` | Client-side: builds a 6-line canonical string (`IDA-SIGNATURE-V1`, method, path, UTC timestamp "O", lowercase nonce GUID "D", Base64(SHA-256(body))) and signs it with the device certificate's private key (RSA-PKCS1-SHA256 or ECDSA-SHA256). Emits `X-Request-Timestamp`, `X-Request-Nonce`, `X-Request-Signature-Version`, `X-Request-Signature-Algorithm`, `X-Request-Signature` headers. |
| `ClientCertValidator.cs` | `src/Shared/Security/ClientCertValidator.cs` | Server-side: validates validity window, Client Authentication EKU, optional leaf-thumbprint allow-list, then builds/validates the chain against two independent trust tiers (see below). |
| `RequestSignatureVerifier.cs` | `src/Shared/Security/` | Server-side: rebuilds the identical canonical string and verifies the signature against the public key in the `X-ARR-ClientCert` (App Service-injected) certificate, over the raw body bytes (verified **before** deserialization). |
| `ReplayProtector.cs` + `IReplayNonceStore` + `AzureTableReplayNonceStore.cs` | `src/Shared/Security/` | Server-side: rejects timestamps outside ±300s skew; reserves `(thumbprint, nonce)` via an **insert-only** Azure Table entity (atomic across scaled-out instances — a 409 means replay). |
| `GraphDeviceAuthorizer.cs` | `src/Shared/Security/` | Server-side: for certificates accepted via the *Intune* trust tier only, looks up `https://graph.microsoft.com/v1.0/devices(deviceId='<guid>')` using the frontend's managed identity; requires an existing, **enabled** device in the frontend's own tenant. Positive results cached in-memory (default 240 min); negative/failed results never cached. |
| `TelemetryRequestAuthenticator.cs` | `src/Shared/Security/` | Orchestrates the above as an ordered pipeline (see `docs/security.md` in LogCollector) — order is a security property: timestamp freshness → cert chain → body signature → nonce reservation → device-ID binding. |
| Device ↔ certificate binding | `docs/security.md` §5 | Strict GUID extraction only (SAN URI `urn:uuid:<guid>`, SAN DNS `<guid>`, or Subject CN `<guid>` as the **entire** value) — substring/regex extraction is explicitly rejected as an IDOR vector. |
| Two-tier certificate trust | `docs/pki-ca-policy.md`, `security.md` §2 | **Enterprise PKI tier**: configurable Root/SubCA thumbprint+subject allow-lists (`ClientCert:TrustedRootCertificates` as the only trust anchors; intermediates are path hints only, never anchors). **Intune tier**: reached only if enterprise tier rejects, fallback enabled, Intune anchors configured, cert carries OID `1.2.840.113556.5.25`, AND issuer DN is on an explicit allow-list — selection criterion only, never trust by itself. |
| Platform-level mTLS | App Service `clientCertMode: Required`, no exclusion paths | TLS termination at the edge; leaf cert forwarded via `X-ARR-ClientCert`, trusted only because the platform strips any client-supplied copy of that header. |

## 2. Why this cannot be reused unmodified for a credential broker

LogCollector's own docs are explicit that it is deliberately **not** designed for an operation whose
failure mode is "a reusable AD password is disclosed":

- LogCollector's worst case from a forged/compromised-device request is **false telemetry rows**
  attributed to a device. The Credential Broker's worst case is **disclosure of a domain-admin-light
  credential**. The security bar must be strictly higher.
- LogCollector accepts the Intune tier with only "device exists, is enabled, in our tenant." The
  Broker must additionally gate on **managed state** and, per policy, **compliance state** before
  ever contacting CyberArk (prompt §7) — this does not exist in LogCollector and must be added.
  **PROPOSED DESIGN.**
  Current LogCollector code only requires `EntraDeviceValidation__Enabled=true`
  and an enabled device; it does not inspect Intune managed-device or compliance attributes. This is
  the single biggest behavioral gap, not a one-line change — it is a new validator component.
- LogCollector has no concept of "authorization for a specific operation" beyond "accept the
  telemetry." The Broker requires `IDeviceOperationAuthorizationService` as a first-class step before
  any backend call (prompt §9) — **new component, not present in LogCollector.**
- LogCollector has no credential-issuance lifecycle; it has no equivalent of `CredentialLease`. **New
  component.**
- LogCollector's nonce store defends a single-shot anti-replay window; the Broker additionally needs
  abuse-detection/rate-limiting per device (prompt §23) and a result-reporting correlation step
  (prompt §22) that LogCollector has no equivalent of (telemetry is one-way).
- LogCollector's Intune-tier Graph check is *optional* (`EntraDeviceValidation__Enabled=false` is
  supported for customers who cannot grant Graph permission). For the Broker, the device-validation
  gate controlling release of a privileged credential **must not** have a silent "disable" switch
  that still allows credential release — if it is user-configurable at all, disabling it must also
  disable the entire certificate tier that depended on it, never reduce it to "accept without a
  check." **OPEN DECISION — recommend making `RequireEntraDeviceValidation` non-disable-able for the
  `ComputerRename` operation; configurability review required.**

## 3. Verified-reusable behavior (carried over with no semantic change)

These are adopted as-is because they are generic, cryptographically sound, already tested in
production code, and nothing about "credential broker vs. telemetry" changes their correctness:

1. **IDA-SIGNATURE-V1 canonical string and signing scheme** — reused verbatim (method, path,
   timestamp, nonce, body hash; RSA-PKCS1-SHA256 / ECDSA-SHA256). Renamed `DCB-SIGNATURE-V1` in this
   repository to avoid cross-protocol replay between the two services, while keeping the identical
   algorithm and canonicalization rules. **PROPOSED DESIGN.**
2. **Insert-only nonce reservation pattern** (`IReplayNonceStore`) — reused as an interface; backing
   store (Azure Table, same as LogCollector, vs. Redis) is an **OPEN DECISION** depending on where
   the Broker is hosted (§16).
3. **Strict GUID-only device-ID binding extraction** (no substrings) — reused verbatim; this is the
   anti-IDOR control the new prompt explicitly calls out in §11.
4. **Two-tier PKI/Intune certificate model with Root/SubCA-only trust anchors, intermediates as path
   hints** — reused as the starting point for `IDeviceCertificateValidator`'s `CorporatePKI` and
   `IntuneEnrollment` profiles (prompt §3, §29).
5. **`X-ARR-ClientCert` forwarded-header trust, conditioned on platform `clientCertMode: Required`
   with no exclusion paths** — reused as the App Service hosting assumption (subject to the Functions
   vs. App Service ADR).
6. **Ordered pipeline discipline** (cheap/stateless checks before expensive/stateful ones; nonce
   reservation only after signature verification) — reused as the overall request-processing order
   for the Broker, extended with the new authorization and CyberArk steps.

## 4. Behavior requiring modification

| LogCollector behavior | Required change for the Broker |
|---|---|
| `GraphDeviceAuthorizer` checks device exists + enabled only | Extend into `IDeviceDirectoryValidator` with separate `EntraDeviceDirectoryValidator` (exists/enabled/tenant) and `IntuneManagedDeviceValidator` (managed state, compliance) — each independently togglable via policy (`RequireEntraDevice`, `RequireIntuneManagedDevice`, `RequireCompliantDevice`), but **none** may default to "off" in a way that silently weakens the `ComputerRename` policy below what is documented in `docs/device-validation.md`. |
| Optional Graph validation (can be disabled) | For `ComputerRename`, Graph validation must be **mandatory** and fail-closed; Graph unavailable → deny (prompt §8, §27). No equivalent "disable" flag should exist for this operation. |
| One-way telemetry submission | Add a **second** endpoint + `CredentialLease` correlation for result reporting (prompt §22), with its own certificate-identity cross-check against the original request. |
| No operation-authorization concept | Add `IDeviceOperationAuthorizationService` as a mandatory step between device validation and any backend (CyberArk) call — LogCollector has no analogous gate because it never discloses secrets. |
| Nonce protects submission only | Extend anti-replay to also prevent **duplicate credential retrieval** for the same lease/operation (prompt §12, §23) — a new check, not present in LogCollector. |

## 5. Behavior NOT appropriate for the credential-broker scenario

- LogCollector's configurable **fallback that disables Graph validation** entirely
  (`EntraDeviceValidation__Enabled=false`) must **not** carry over for `ComputerRename`. Disclosing a
  privileged credential without a mandatory Graph check is unacceptable regardless of customer
  convenience. If a similar flag exists for operational flexibility in non-privileged future
  operations, it must be scoped per-operation, never global.
- LogCollector's **positive Graph cache (240 min)** is reasonable for telemetry throughput but is too
  coarse for a credential-granting decision: a device disabled in Entra/Intune 10 minutes after a
  positive cache entry would still receive a password. **OPEN DECISION**: either a much shorter cache
  TTL (e.g., 60s) or no caching at all for `ComputerRename` device-validation lookups, trading Graph
  throttling risk against freshness. Recommendation: no caching for this operation given its low
  expected request volume (one rename per device lifetime, not a telemetry firehose).
- LogCollector's security model explicitly states it "does not protect against a fully compromised
  device" — this residual risk is **inherited, not eliminated**, and is documented formally in §18 of
  the architecture doc and in the threat model, because here the asset at risk is a domain credential
  rather than telemetry rows.

## 6. `IDeviceCertificateValidator` design (building on the above)

```csharp
public interface IDeviceCertificateValidator
{
    Task<CertificateValidationResult> ValidateAsync(
        X509Certificate2 clientCertificate,
        CancellationToken cancellationToken);
}

public sealed record CertificateValidationResult(
    bool IsValid,
    CertificateTrustProfile? Profile,      // IntuneEnrollment | CorporatePKI
    string? DenyReason,
    IReadOnlyDictionary<string, string> CertificateDerivedClaims); // Subject, Issuer, SAN, thumbprint, etc.
```

Configuration (per environment, selectable profile — prompt §3):

```jsonc
{
  "DeviceCertificate": {
    "Profiles": {
      "CorporatePKI": {
        "TrustedRootThumbprints": [],
        "TrustedRootSubjects": [],
        "TrustedIntermediateThumbprints": [],
        "TrustedIntermediateSubjects": [],
        "RequireClientAuthenticationEku": true,
        "CheckRevocation": true
      },
      "IntuneEnrollment": {
        "TrustedRootThumbprints": [],
        "IssuerSubjectAllowList": [],
        "RequiredOid": "1.2.840.113556.5.25",
        "SkipRevocationCheck": false
      }
    },
    "ActiveProfile": "CorporatePKI"
  }
}
```

`ActiveProfile` is **OPEN DECISION / REQUIRES CUSTOMER VALIDATION** — see `docs/certificate-options.md`.

## 7. Certificate characteristics to document before selection (prompt §3)

Per profile, before writing selection logic, the following must be captured for the actual
certificates issued to Windows devices (Intune SCEP/PKCS profile, or corporate PKI template):

- Certificate store (expected: `LocalMachine\My`, accessible from SYSTEM — **REQUIRES CUSTOMER
  VALIDATION**, not yet confirmed which profile the-customer-organization devices actually receive).
- Issuer DN and chain depth (Root → [SubCA...] → leaf).
- Subject DN and SAN entries (URI/DNS/CN — matters for device-ID extraction, see §5 above).
- EKU list (must include Client Authentication `1.3.6.1.5.5.7.3.2`).
- Private-key exportability (must be non-exportable; **never** export it — prompt explicitly
  forbids this).
- SYSTEM-context accessibility (SYSTEM must be able to open the private key handle without
  elevation prompts — verified pattern in LogCollector's client module, to be re-validated for
  whichever certificate is actually deployed).
- Expected lifetime and renewal/re-enrollment behavior (affects nonce/lease validity windows and
  the "certificate renewal" threat-model entry).
- A stable, unique identifier correlatable to the device record (Entra device ID via SAN/OID, or an
  operator-maintained thumbprint↔device map, mirroring LogCollector's `ThumbprintToDeviceMap`).

**All of the above are REQUIRES CUSTOMER VALIDATION** until confirmed against the actual certificate
template(s) issued in the target environment. No certificate is selected by FriendlyName anywhere in
this design, per the explicit prohibition in prompt §3.
