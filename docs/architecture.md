# Architecture — Secure Device Credential Broker

Status tags used throughout this document and the rest of `docs/`:

- **VERIFIED REQUIREMENT** — stated explicitly in the user's prompt or confirmed from inspected code.
- **PROPOSED DESIGN** — this team's recommendation; not yet confirmed by the customer.
- **OPEN DECISION** — intentionally left open per prompt §33; requires a decision before build-out.
- **REQUIRES CUSTOMER VALIDATION** — depends on facts about the deploying organization's
  environment not available to this design (CyberArk interface, PKI template, Graph tenant
  permissions, network connectivity).

## 1. Proposed architecture — **PROPOSED DESIGN**

```text
┌─────────────────────────┐        mTLS + DCB-SIGNATURE-V1        ┌──────────────────────────────┐
│   Windows Device         │ ─────────────────────────────────▶   │  Device Credential Broker     │
│  (Intune-managed,        │                                       │  (.NET 10, ASP.NET Core)       │
│   SYSTEM context)         │ ◀─────────────────────────────────   │                                │
└─────────────────────────┘        credential / deny / lease       └───────┬──────────┬────────────┘
                                                                              │          │
                                                       Managed Identity       │          │ server-to-server
                                                       (least privilege)      ▼          ▼ (private connectivity)
                                                                    ┌──────────────┐  ┌──────────────┐
                                                                    │ Microsoft     │  │   CyberArk    │
                                                                    │ Graph /       │  │  (authoritative│
                                                                    │ Entra ID /    │  │   credential   │
                                                                    │ Intune        │  │   store)       │
                                                                    └──────────────┘  └──────────────┘
```

Component responsibilities map 1:1 to prompt §1. The device **never** talks to CyberArk or to Graph
directly; only the Broker does, server-side, after every gate in §2 below passes.

## 2. Security gate chain — **VERIFIED REQUIREMENT** (prompt §2)

```text
Device certificate valid
        │
        ▼
Certificate trusted (chain + profile match)
        │
        ▼
Certificate mapped to a device identity (strict GUID binding, no substrings)
        │
        ▼
Device verified server-side (Entra device exists, enabled, correct tenant)
        │
        ▼
Device managed/compliant per policy (Intune state, if required)
        │
        ▼
Operation authorized (IDeviceOperationAuthorizationService → ComputerRename)
        │
        ▼
Anti-replay passed (timestamp fresh, nonce unused, request still valid)
        │
        ▼
 ──────────────────── ONLY NOW may CyberArk be contacted ────────────────────
        │
        ▼
CyberArk credential retrieved
        │
        ▼
CredentialLease issued, credential returned to device
```

Any gate failure stops the chain. No gate is skippable by configuration for the `ComputerRename`
operation (see `docs/authentication.md` §5 for why LogCollector's optional-Graph-validation pattern
is explicitly not carried over here).

## 3. Device → Broker sequence — **PROPOSED DESIGN**

```text
Device                                   Broker
  │  TLS handshake, presents device cert   │
  │ ───────────────────────────────────▶   │
  │                                        │  validate chain, profile, EKU, revocation
  │                                        │  (IDeviceCertificateValidator)
  │  POST /api/v1/device/operations/       │
  │  computer-rename/credential            │
  │  + DCB-SIGNATURE-V1 headers            │
  │  + JSON claims (entraDeviceId, etc.)   │
  │ ───────────────────────────────────▶   │  verify signature over raw body (pre-deserialize)
  │                                        │  reserve nonce (insert-only, atomic)
  │                                        │  resolve DeviceIdentity (cert-derived + claims)
  │                                        │  cross-validate cert-derived vs claimed values (anti-IDOR)
  │                                        │  ── see §4 for Graph call ──
  │                                        │  ── see §5 for CyberArk call ──
  │                                        │  issue CredentialLease (no password stored)
  │  200 OK { username, password,          │
  │   expiresUtc, credentialLeaseId }      │
  │ ◀───────────────────────────────────   │
  │  build PSCredential, Rename-Computer   │
  │  dispose credential references         │
  │                                        │
  │  POST .../computer-rename/result       │
  │  + DCB-SIGNATURE-V1 (same cert)        │
  │ ───────────────────────────────────▶   │  verify cert ↔ original request ↔ lease match
  │  200 OK                                │  update CredentialLease status
  │ ◀───────────────────────────────────   │
```

## 4. Broker → Microsoft Graph sequence — **PROPOSED DESIGN**

```text
Broker                                         Microsoft Graph
  │  acquire token via Managed Identity           │
  │  (IGraphClientFactory)                         │
  │ ─────────────────────────────────────────▶     │
  │  GET /v1.0/devices(deviceId='<guid>')          │
  │ ─────────────────────────────────────────▶     │
  │  200 { id, deviceId, accountEnabled, ... }     │
  │ ◀─────────────────────────────────────────     │
  │  (if RequireIntuneManagedDevice)               │
  │  GET /v1.0/deviceManagement/managedDevices?    │
  │      $filter=azureADDeviceId eq '<guid>'       │
  │ ─────────────────────────────────────────▶     │
  │  200 { ..., complianceState, managementState } │
  │ ◀─────────────────────────────────────────     │
  │  Graph unavailable/error at any step           │
  │  → DENY (fail closed, no caching for this op)  │
```

Graph permissions required, least privilege — **PROPOSED DESIGN, REQUIRES CUSTOMER VALIDATION** for
final tenant-admin consent:

| Permission | Type | Why |
|---|---|---|
| `Device.Read.All` | Application | Resolve Entra device by `deviceId`, check `accountEnabled`. |
| `DeviceManagementManagedDevices.Read.All` | Application | Resolve Intune managed-device record, check `managementState`/`complianceState`, only if `RequireIntuneManagedDevice`/`RequireCompliantDevice` are enabled. |

No `Directory.ReadWrite.All` or broader permission is required for this use case.

## 5. Broker → CyberArk sequence — **PROPOSED DESIGN** (interfaces only; see §6 for open questions)

```text
Broker                                          CyberArk
  │  (after ALL prior gates passed)                │
  │  ICredentialProvider.GetCredentialAsync(        │
  │     CredentialPurpose.ComputerRename)           │
  │                                                  │
  │  CyberArkCredentialProvider resolves purpose     │
  │  → Safe/Object/AppID mapping (server config only)│
  │                                                  │
  │  ICyberArkClient.GetAccountCredentialAsync(...)  │
  │ ──────────────────────────────────────────────▶  │  (exact protocol TBD —
  │                                                  │   REQUIRES CUSTOMER VALIDATION,
  │  { username, password, nextRotationUtc }        │   see docs/cyberark-integration.md)
  │ ◀──────────────────────────────────────────────  │
  │  CredentialLease issued; password returned once  │
  │  to the device and never persisted by the Broker │
```

This sequence is implemented against `ICyberArkClient` only. No concrete CyberArk product
integration is written until the open questions in `docs/cyberark-integration.md` §"Open questions
for the CyberArk team" are answered — per the explicit instruction not to fabricate the
deploying organization's infrastructure details.

## 6. Certificate trust model — see `docs/certificate-options.md`

## 7. Device identity binding strategy — see `docs/authentication.md` §6-§7

## 8. Graph verification strategy — see `docs/device-validation.md`

## 9. CyberArk abstraction — see `docs/cyberark-integration.md`

## 10. Authorization model — **PROPOSED DESIGN**

`IDeviceOperationAuthorizationService.AuthorizeAsync` receives the authenticated `DeviceIdentity`,
the `DeviceDirectoryValidationResult`, the requested `DeviceOperation` (initially only
`ComputerRename`), request timestamp, correlation ID, and optional target computer name. It returns
`Authorized` or `Denied(reasonCode)`. The client never supplies — and the service never accepts from
the client — a CyberArk Safe, Object, AppID, or account name (prompt §9, §14). The reason codes are
server-internal audit detail; the HTTP response to a denied device is a generic 403 with a
correlation ID, never the internal reason (avoids information leakage to a potentially compromised
or spoofing endpoint).

## 11. Network requirements — see `docs/network-connectivity.md`

## 12. Credential lifecycle — see `docs/security.md` §"Credential lifecycle"

## 13. Residual security risks — see `docs/security.md` §"Residual risk" and `docs/adr/0003-credential-exposure-vs-server-side-execution.md`

## 14. Threat model — see `docs/threat-model.md`

## 15. Open architecture decisions — see `docs/adr/` (index below)

| ADR | Decision | Status |
|---|---|---|
| [0001](adr/0001-hosting-model.md) | Azure Functions isolated worker vs. ASP.NET Core on App Service | PROPOSED DESIGN (App Service), confirmation OPEN |
| [0002](adr/0002-certificate-profile-selection.md) | Intune enrollment certificate vs. corporate PKI certificate | OPEN DECISION / REQUIRES CUSTOMER VALIDATION |
| [0003](adr/0003-credential-exposure-vs-server-side-execution.md) | Return password to endpoint (A) vs. server-side privileged execution (B) | A implemented now per requirement; B documented for future evaluation |
| [0004](adr/0004-cyberark-interface-and-auth.md) | Exact CyberArk interface + authentication mechanism | OPEN DECISION / REQUIRES CUSTOMER VALIDATION |

## 16. Exact questions requiring the deploying organization's team input

Consolidated list (detailed versions live alongside each relevant doc):

**CyberArk team** (full list in `docs/cyberark-integration.md`):
1. Which CyberArk interface is enabled (Central Credential Provider REST, PVWA REST, other)?
2. What authentication mechanism is supported for the Broker (client certificate, AppID+OS user,
   allowed machine/source-IP restriction)?
3. Can CyberArk be reached privately from Azure (VNet/ExpressRoute/VPN), or is it on-prem only
   behind a gateway the Broker must call instead?
4. Which Safe and Object identify the computer-rename service account?
5. Is password rotation push- or pull-based from the consumer's perspective?
6. Is every retrieval already audited on the CyberArk side, or must the Broker provide its own audit
   trail as the primary record?

**PKI / Intune team** (full list in `docs/certificate-options.md`):
1. Which certificate (Intune SCEP/PKCS device certificate vs. a separate corporate PKI machine
   certificate) is actually deployed and accessible from SYSTEM context on target devices today?
2. What is the full chain (Root/SubCA thumbprints and subjects) for that certificate?
3. Does it carry SAN entries usable for strict GUID device-ID binding, or only a CN?
4. What is the renewal/re-enrollment cadence, and does renewal change the thumbprint the Broker must
   trust?

**Entra / Intune (Graph) team**:
1. Can `Device.Read.All` and `DeviceManagementManagedDevices.Read.All` application permissions be
   granted to the Broker's managed identity?
2. Is compliance state a hard requirement for authorizing a rename, or informational only?

**Network team**:
1. Is there existing Azure-to-on-prem connectivity (VPN/ExpressRoute) that the Broker's hosting
   environment can use to reach CyberArk privately?
2. Are there firewall/proxy rules required for Broker → CyberArk and Broker → Graph egress?
