# ADR 0002: Certificate profile selection — Intune enrollment vs. corporate PKI

## Status

OPEN DECISION / REQUIRES CUSTOMER VALIDATION (prompt §33.1). Not decided in this ADR. Both profiles
are implemented behind `IDeviceCertificateValidator` with a configurable `ActiveProfile` so the
decision can be made later, or changed per-environment, without touching any other layer (CyberArk,
Graph, authorization, rename logic, API contract — prompt §29).

## Context

Prompt §3 requires both `IntuneEnrollment` and `CorporatePKI` to exist as configuration profiles, and
explicitly forbids selecting either merely because it is architecturally convenient, or selecting a
certificate by FriendlyName. LogCollector's codebase (see `docs/authentication.md`) already
implements both tiers for a different use case and is the starting point for both implementations.

## Options

### Option A — Intune enrollment certificate

- Pros: already deployed to every Intune-managed Windows device; no new PKI issuance work; carries
  OID `1.2.840.113556.5.25` usable for device-ID correlation (verified pattern in LogCollector).
- Cons: issued by a **shared** Microsoft Intune CA, not customer-specific — trust by issuer alone is
  insufficient (LogCollector mitigates this with issuer-subject allow-listing + mandatory Graph
  tenant check — must carry over here, and in fact must be made *mandatory*, not optional, per
  `docs/authentication.md` §5).
- Renewal is managed by Intune automatically; thumbprint changes on renewal, so trust should key off
  the OID/Entra device ID, not a static thumbprint pin for this profile.

### Option B — Corporate PKI machine certificate

- Pros: customer-controlled CA, can enforce a dedicated certificate template limited to the
  rename-broker use case, supports Root/SubCA-only trust anchors with no reliance on a third-party
  shared CA.
- Cons: requires provisioning/distribution if not already deployed to all relevant machines (new PKI
  work, timeline unknown); device-ID binding depends entirely on how the template populates SAN/CN
  (unknown — REQUIRES CUSTOMER VALIDATION).

## Decision

Not made here. Recorded as OPEN. `docs/certificate-options.md` lists the exact facts about the actual
deployed certificate(s) that must be confirmed before either option can be selected as
`ActiveProfile` for a given environment.

## Consequences

- Both `IntuneTrustProfileValidator` and `CorporatePkiTrustProfileValidator` must be implemented and
  tested independently (prompt §31 test matrix covers both).
- Environment configuration (`DeviceCertificate:ActiveProfile`) determines which is active; a given
  deployment need not run both simultaneously, but the code must support either without a rebuild.
