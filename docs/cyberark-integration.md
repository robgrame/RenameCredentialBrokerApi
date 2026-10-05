# CyberArk integration

See ADR 0004 for the decision status (OPEN / REQUIRES CUSTOMER VALIDATION). This document is the
design of the abstraction boundary and is implemented fully; the production connector behind
`ICyberArkClient` is not.

## Abstraction layers (prompt §13, §14, §30)

```text
Application layer
      │  GetCredentialAsync(CredentialPurpose.ComputerRename)
      ▼
ICredentialProvider  ──implemented by──▶  CyberArkCredentialProvider
                                               │  resolves purpose → Safe/Object/AppID
                                               │  (server configuration only, never from the client)
                                               ▼
                                          ICyberArkClient
                                               │  GetAccountCredentialAsync(safe, object, appId, ...)
                                               ▼
                                     [NOT IMPLEMENTED: real CyberArk product connector]
                                     MockCyberArkClient (tests only)
                                     NotConfiguredCyberArkClient (fail-closed default)
```

The application layer only ever calls `GetCredentialAsync(CredentialPurpose.ComputerRename)` — it has
no knowledge of Safe names, Object names, the CyberArk REST surface, or CyberArk authentication
details (prompt §14, §30 — VERIFIED REQUIREMENT).

## `CredentialPurpose → Safe/Object/AD account` mapping

Controlled entirely by server configuration (never by the client):

```jsonc
{
  "CyberArk": {
    "PurposeMappings": {
      "ComputerRename": {
        "Safe": "<configured per environment>",
        "Object": "<configured per environment>",
        "AppId": "<configured per environment>"
      }
    },
    "BaseUrl": "<configured per environment>",
    "AuthenticationMode": "<OPEN DECISION — see ADR 0004>",
    "TimeoutSeconds": 10
  }
}
```

No example values are invented here — they must come from the actual CyberArk configuration,
confirmed with the CyberArk team, per the explicit instruction not to invent the deploying
organization's real values.

## Open questions for the CyberArk team

(Also tracked in ADR 0004 and `docs/architecture.md` §16 for cross-reference.)

1. Which CyberArk product/interface is available: Central Credential Provider (CCP) REST API,
   Privileged Vault Web Access (PVWA) REST API, or another approved mechanism?
2. Which authentication mechanisms does that interface support for a calling application: client
   certificate, AppID + OS-user restriction, API key/token, or other?
3. Can the Azure-hosted Broker authenticate to CyberArk using a certificate?
4. Is a specific CyberArk Application Identity (AppID) required, and if so, how is it provisioned and
   rotated?
5. Is source-IP restriction enforced/required on the CyberArk side for this AppID?
6. Is an on-premises CyberArk Credential Provider (CCP) component required in the network path, or
   can the Broker call CyberArk's REST surface directly?
7. Is mutual TLS required between the Broker and CyberArk?
8. Can the Azure workload reach CyberArk over the network today (any connectivity at all), and if so,
   is it public, VPN, ExpressRoute, or Private Link?
9. Is CyberArk on-premises only, or is there a cloud-reachable component?
10. Which Safe contains (or should contain) the computer-rename service account?
11. Which Object within that Safe identifies the account?
12. What authorization/permissions must be assigned to the Broker's CyberArk application identity
    (retrieve-only, no list/manage permissions expected)?
13. How is password rotation exposed to consumers — is every retrieval guaranteed to return the
    current password (pull-based), or is there a push/notification mechanism the Broker should
    instead subscribe to?
14. Is every credential retrieval already audited on the CyberArk side (sufficient for compliance by
    itself), or must the Broker's own `CredentialLease` audit trail be treated as the authoritative
    record?

## Why production code is not written yet

Per prompt §15 and §34: "Do not fabricate answers," and "stop before implementing the production
CyberArk connector if the CyberArk interface and authentication mechanism have not yet been
confirmed. Mocks and interfaces may be created, but infrastructure-specific CyberArk code must only be
implemented once those details are known." This repository therefore contains `ICyberArkClient`,
`MockCyberArkClient`, and `NotConfiguredCyberArkClient` only.

## Fail-closed defaults (prompt §27)

| Condition | Result |
|---|---|
| CyberArk unavailable | No credential returned; `CyberArkCredentialFailed` event |
| CyberArk authentication failed | No credential returned |
| Credential retrieval failed / malformed response | No credential returned |
| `ICyberArkClient` not configured (default state of this repository until ADR 0004 is resolved) | `NotConfiguredCyberArkClient` always denies, by design |
