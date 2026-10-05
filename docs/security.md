# Security — credential lifecycle, residual risk, memory handling

## Credential lifecycle

```text
Issued ──▶ OperationReportedSucceeded
   │
   ├──▶ OperationReportedFailed
   │
   ├──▶ Expired            (no result reported within lease TTL)
   │
   └──▶ Suspicious         (e.g., certificate mismatch on result report,
                             duplicate retrieval attempt, replay detected)
```

`CredentialLease` (prompt §21) stores **no password** — only:

```csharp
public sealed record CredentialLease(
    Guid LeaseId,
    string DeviceIdentityId,
    DeviceOperation Operation,
    DateTimeOffset IssuedUtc,
    DateTimeOffset ExpiresUtc,
    string RequestId,
    string CorrelationId,
    CredentialLeaseStatus Status);
```

This gives an auditable relationship (Device → Authorization → CyberArk retrieval → Credential
issuance → Rename result) without ever persisting the credential itself — **VERIFIED REQUIREMENT**.

## Residual risk — stated plainly, not minimized

> Returning a reusable Active Directory password to the endpoint introduces residual risk.

Even with every control in this design (TLS, strong device-certificate authentication, Entra/Intune
validation, just-in-time CyberArk retrieval), **an attacker with sufficient SYSTEM-level control over
the endpoint could potentially capture the credential while it exists in process memory.** This
architecture does **not** claim to eliminate credential exposure — see ADR 0003 for the full
comparison against the server-side-execution alternative, which is documented but not implemented in
this phase.

Additional, non-exhaustive residual risks carried from the threat model (`docs/threat-model.md`):

- Broker compromise remains the single highest-value target (#9) — mitigated, not eliminated.
- A SYSTEM-level attacker on the legitimate device can request (and receive) a legitimate credential
  using the device's own real certificate (#3) — this is an accepted trade-off of Architecture A.
- Non-exportability of the device private key is a PKI/Intune configuration guarantee this Broker
  cannot itself verify remotely (#2).

## Sensitive memory handling (prompt §20 — VERIFIED REQUIREMENT)

The password must never be persisted to: filesystem, registry, PowerShell transcript, Windows event
log, Application Insights, Intune Management Extension logs, stdout, or stderr.

- The Broker minimizes plaintext lifetime: deserializes directly into the response DTO, serializes
  the HTTP response, and does not log, cache, or retain the plaintext beyond the single
  request/response cycle.
- The client (`client/Invoke-SecureComputerRename.ps1`) converts the returned password to a
  `SecureString` immediately upon receipt and constructs the `PSCredential` before doing anything
  else; all plaintext variable references are cleared/overwritten and the plaintext string is not
  reused after conversion.
- **Honest caveat, not a claim of completeness**: JSON deserialization in .NET necessarily creates a
  managed string containing the plaintext password at least transiently before any conversion can
  occur (prompt §20). `SecureString` reduces, but does not eliminate, the window in which plaintext
  exists in process memory — the .NET GC does not guarantee immediate zeroing or non-pageable memory
  for a managed `string`. Minimization (shortest possible lifetime, explicit dereferencing, process
  exit immediately after use for the client script) is the practical mitigation, not a guarantee of
  non-recoverability.

## Logging and telemetry (prompt §24)

Never logged, anywhere in this codebase: password, CyberArk credential content, `PSCredential`,
authentication secrets, private keys, `Authorization` headers, Graph access tokens, CyberArk
authentication material. This is enforced structurally (dedicated DTOs for log events that never
include these fields, not relying on convention alone) and verified by the test matrix (`docs/
architecture.md` §15, prompt §31 "Security" test category).

Structured events emitted (correlated by an end-to-end correlation ID):

```text
DeviceCertificateAccepted / DeviceCertificateRejected
DeviceIdentityResolved
GraphDeviceValidationSucceeded / GraphDeviceValidationFailed
OperationAuthorized / OperationDenied
CyberArkCredentialRequested / CyberArkCredentialRetrieved / CyberArkCredentialFailed
CredentialLeaseIssued
RenameSucceeded / RenameFailed
ReplayDetected
SuspiciousCredentialRequest
```
