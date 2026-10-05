# ADR 0004: CyberArk interface and authentication mechanism

## Status

OPEN DECISION / REQUIRES CUSTOMER VALIDATION (prompt §33.2, §33.3). Not decided. This ADR exists only
to record the abstraction boundary and the open questions; no production CyberArk connector is
implemented until these are answered, per explicit instruction in prompt §13/§15/§34.

## Context

Prompt §13 requires `ICredentialProvider` → `CyberArkCredentialProvider` → `ICyberArkClient`, with all
Safe/Object/AppID/authentication configuration kept strictly server-side and never assumed. Prompt
§15 lists the exact open questions that must be answered by the CyberArk team before implementation.

## Decision

Not made. `ICyberArkClient` is implemented in this repository only as an interface plus:

1. A **mock** implementation (`MockCyberArkClient`) used exclusively in unit/integration tests, which
   returns a fixed, clearly-fake credential and never calls any network endpoint.
2. A **not-configured** fail-closed implementation (`NotConfiguredCyberArkClient`), mirroring the
   `NotConfiguredServiceAccountCredentialProvider` pattern already used in the `RenameApiService`
   project for the same reason: calling it always throws/returns a denial rather than silently
   succeeding, so an incomplete deployment fails closed instead of behaving unpredictably.

No implementation targets a specific CyberArk product interface (e.g., Central Credential Provider
REST API) until the following are confirmed:

## Open questions (verbatim from prompt §15, tracked here for traceability)

- Which CyberArk product/interface is available (Central Credential Provider REST API, PVWA REST
  API, another approved mechanism)?
- Which authentication mechanisms are supported (client certificate, AppID + OS user, API key,
  other)?
- Can the Azure service authenticate using a certificate?
- Is an application identity/AppID required?
- Is source-IP restriction required?
- Is a CyberArk Credential Provider (CCP) component required on the Broker's host/network path?
- Is mutual TLS required between the Broker and CyberArk?
- Can the Azure workload reach CyberArk over the network at all today?
- Is private connectivity (VPN/ExpressRoute/Private Link) required or already available?
- Is CyberArk on-premises only?
- Which Safe contains the computer-rename service account?
- Which object identifies that account?
- What authorization is assigned to the Broker's application identity within CyberArk?
- How is password rotation exposed to consumers (push notification, pull-on-every-request, versioned
  object)?
- Is every credential retrieval already audited server-side by CyberArk, or must the Broker provide
  its own authoritative audit trail?

## Consequences

- `docs/cyberark-integration.md` tracks these same questions alongside the abstraction design.
- Implementation of `CyberArkCredentialProvider`'s real HTTP client is explicitly out of scope until
  this ADR is updated with confirmed answers.
