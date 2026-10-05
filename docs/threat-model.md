# Threat model (STRIDE-oriented)

Scope: the Device Credential Broker end-to-end flow (device certificate → broker → Graph → CyberArk →
credential → rename → result reporting). Tags per `docs/architecture.md` header.

For each threat: Threat / Attack scenario / Asset / Impact / Prevention / Detection / Residual risk.

## 1. Forged certificate

- **Threat**: attacker presents a certificate not issued by a trusted chain.
- **Scenario**: self-signed or attacker-CA-issued certificate presented at TLS handshake.
- **Asset**: credential-issuance decision.
- **Impact**: none if prevention holds — full compromise (credential disclosure) if it fails.
- **Prevention**: `IDeviceCertificateValidator` chain validation against configured Root/SubCA
  anchors only (intermediates are path hints, never anchors) — **VERIFIED REQUIREMENT**, pattern
  verified in LogCollector `ClientCertValidator.cs`.
- **Detection**: `DeviceCertificateRejected` event with chain-failure reason, alertable.
- **Residual risk**: compromise of a trusted Root/SubCA's private key is outside this design's
  control (PKI team's responsibility).

## 2. Stolen device certificate (private key exfiltrated)

- **Threat**: attacker copies the private key off a device (e.g., exportable key, offline attack).
- **Scenario**: attacker with prior SYSTEM access extracts a private key and replays it from another
  host.
- **Asset**: the service-account credential.
- **Impact**: full impersonation of the legitimate device for `ComputerRename`.
- **Prevention**: require non-exportable keys at issuance (PKI/Intune template control — **REQUIRES
  CUSTOMER VALIDATION**, not enforceable by the Broker itself); device-ID binding plus Graph
  liveness check narrows (but does not eliminate) the blast radius to the one device whose identity
  is cloned.
- **Detection**: abuse-detection rules (§23) — multiple requests claiming the same device identity
  from different network contexts, used alongside Entra sign-in/device sign-al correlation if
  available (outside this design's direct scope).
- **Residual risk**: non-exportability is a PKI/Intune configuration guarantee, not something this
  Broker can verify remotely. **Documented, not eliminated.**

## 3. Compromised device / compromised SYSTEM context

- **Threat**: attacker already has SYSTEM on the legitimate device.
- **Scenario**: malware or an attacker with local admin escalates to SYSTEM, then requests a
  legitimate rename credential using the device's own real certificate.
- **Asset**: the service-account credential.
- **Impact**: the attacker obtains a valid, legitimately-issued credential for that one device/
  operation.
- **Prevention**: scope of damage is limited to a single short-lived credential for one operation
  (`ComputerRename`), not a standing admin credential — mitigated by least-privilege account design
  on the AD side (out of this Broker's control) and by the `CredentialLease` audit trail.
- **Detection**: abuse detection — unexpected rename requests outside maintenance windows, repeated
  requests, mismatched correlation with an actual Intune-driven rename task.
- **Residual risk**: **explicitly accepted, not eliminated** — inherited from LogCollector's own
  documented position ("does not protect against a fully compromised device") and carried forward
  per ADR 0003: a SYSTEM-level attacker can capture the credential from process memory during the
  narrow window before disposal.

## 4. Spoofed serial number / spoofed Entra device ID

- **Threat**: attacker-controlled device reports another device's serial number or Entra device ID in
  the JSON payload.
- **Asset**: credential issued for a device identity that is not the real requester.
- **Impact**: classic IDOR — Device A obtains a credential while claiming to be Device B.
- **Prevention**: §11's anti-IDOR correlation — certificate-derived identity is cross-validated
  against every client-reported claim; computer name is never primary identity (it is the value
  being changed); serial number alone is never authentication (prompt §11, §4).
- **Detection**: `SuspiciousCredentialRequest` event when cross-validation fails.
- **Residual risk**: none beyond certificate theft (threat #2), assuming strict GUID-only binding is
  implemented exactly as in LogCollector's verified pattern (no substring extraction).

## 5. Certificate/device mismatch

- **Threat**: a certificate validly chains but is bound (by SAN/CN/OID) to a device ID different from
  the one claimed in the request body.
- **Asset**: credential-issuance correctness.
- **Impact**: same as #4 if not caught.
- **Prevention**: mismatch → deny, fail closed (prompt §27).
- **Detection**: logged and alertable denial reason (never exposed to the client in the HTTP
  response).
- **Residual risk**: none identified beyond implementation correctness (covered by the test matrix in
  §31 / `docs/authentication.md`).

## 6. Replay attacks

- **Threat**: attacker captures a previously valid, signed request and resends it later.
- **Asset**: single-use credential issuance.
- **Impact**: without protection, could obtain a second credential issuance from one legitimate
  request.
- **Prevention**: timestamp freshness window + insert-only nonce reservation (verified pattern,
  LogCollector `ReplayProtector`/`IReplayNonceStore`), extended here to also block duplicate
  credential retrieval against the same `CredentialLease` (prompt §12, §23 — new vs. LogCollector).
- **Detection**: `ReplayDetected` event on nonce-reservation conflict.
- **Residual risk**: none within the freshness window if the nonce store is correctly atomic; a
  non-atomic backing store would reopen a race — tracked as an implementation-correctness
  requirement, not a residual design risk.

## 7. Graph compromise or outage

- **Threat**: Microsoft Graph is unavailable, throttled, or (low likelihood) compromised.
- **Asset**: device-validation gate.
- **Impact**: if treated as "allow," an attacker could exploit a Graph outage window to bypass device
  verification.
- **Prevention**: fail closed — Graph unavailable → device identity cannot be validated → credential
  denied (prompt §8, §27). No caching of negative results; short/no caching of positive results for
  this specific operation (see `docs/authentication.md` §5).
- **Detection**: `GraphDeviceValidationFailed` event, infrastructure alerting on Graph dependency
  health.
- **Residual risk**: legitimate renames are blocked during a genuine Graph outage — an availability
  trade-off accepted deliberately in favor of security (documented, not a bug).

## 8. CyberArk compromise

- **Threat**: CyberArk itself is compromised, or its response channel to the Broker is tampered with.
- **Asset**: the credential returned to the Broker.
- **Impact**: if CyberArk returns a tampered/incorrect credential, the Broker would unknowingly
  forward it.
- **Prevention**: out of this design's control — CyberArk's own integrity is the responsibility of its
  operators; the Broker treats CyberArk as authoritative by design (prompt §13).
- **Detection**: rename failures reported back via the result endpoint correlate against the
  `CredentialLease`, surfacing anomalies (e.g., `Rename-Computer` failing with an auth error despite
  a "successful" credential retrieval).
- **Residual risk**: **accepted** — this is a trust boundary, not a defensible attack surface for this
  component.

## 9. Broker compromise

- **Threat**: the Broker service itself is compromised (e.g., RCE, compromised Managed Identity).
- **Asset**: everything — Graph access, CyberArk access, all issued credentials.
- **Impact**: full compromise of the credential-issuance pipeline.
- **Prevention**: least-privilege Managed Identity (Graph read-only permissions, no write scopes);
  no secrets in source; Key Vault only where Managed Identity/cert-based auth is not possible;
  network isolation (VNet) for the Broker.
- **Detection**: Application Insights anomaly detection on CyberArk request volume, Graph query
  volume, and credential-issuance rate.
- **Residual risk**: **accepted and significant** — this is the single highest-value target in the
  architecture; mitigations reduce blast radius and improve detection but cannot reduce the risk to
  zero. Flagged for the customer's security team as the primary component requiring hardening review
  (patching, network segmentation, secrets-free operation, restricted deployment access).

## 10. Credential extraction from endpoint memory

- Covered in depth in ADR 0003. **Accepted residual risk of Architecture A**, documented, not
  eliminated.

## 11. Credential extraction from broker memory

- **Threat**: an attacker with code-execution on the Broker captures the plaintext credential while
  in memory between CyberArk retrieval and the HTTP response.
- **Asset**: the credential.
- **Impact**: same as #9 (broker compromise) — this is a consequence of that threat, not a separate
  attack surface.
- **Prevention**: minimize the plaintext lifetime server-side as well (no logging, no caching of the
  response body, release references immediately after serialization).
- **Detection**: see #9.
- **Residual risk**: same as #9 — accepted, mitigated by scope but not eliminated.

## 12. Credential leakage in telemetry

- **Threat**: a password, PSCredential, Graph token, Authorization header, or CyberArk auth material
  ends up in logs/Application Insights.
- **Asset**: the credential, and any secondary secrets (Graph tokens, CyberArk auth material).
- **Impact**: credential disclosure via a channel intended for operational diagnostics, often with
  weaker access controls than the primary data path.
- **Prevention**: explicit deny-list of fields that must never be logged (prompt §24); PII/secret
  redaction at the logging-sink/middleware level, not just by convention; code review checklist item
  (mirrors LogCollector's `docs/security.md` review-checklist discipline).
- **Detection**: periodic log-content audits; the test matrix (§31) includes explicit
  "password never appears in logs/telemetry" tests.
- **Residual risk**: human error in future code changes — mitigated by tests and review process, not
  eliminated structurally.

## 13. API enumeration / IDOR

- Covered under #4. Additional note: rate limiting (§23) also mitigates brute-force enumeration of
  device identities.

## 14. Denial of service

- **Threat**: flooding the credential or result endpoints.
- **Asset**: availability of the rename operation; secondarily, Graph/CyberArk rate limits being
  exhausted by the flood before it reaches legitimate requests.
- **Prevention**: per-device rate limiting (prompt §23) applied *before* Graph/CyberArk calls (cheap
  checks first, matching LogCollector's ordered-pipeline discipline); platform-level DDoS protection
  (Azure Front Door/App Service built-in protections) as infrastructure-level mitigation — **OPEN
  DECISION** on exact platform configuration.
- **Detection**: Application Insights request-rate anomaly alerts.
- **Residual risk**: distributed attacks using many distinct, otherwise-valid certificates are harder
  to rate-limit per-device; broader network-level protections are an infrastructure team
  responsibility.

## 15. CyberArk account enumeration

- **Threat**: a client attempts to discover or select CyberArk Safe/Object/account names.
- **Prevention**: the client-facing contract (prompt §10, §14) never accepts or exposes CyberArk
  identifiers; the request says "authorize me for ComputerRename," never "give me account X."
- **Residual risk**: none within this design's contract; depends on the contract never being relaxed
  (test matrix enforces this explicitly, §31 "client cannot select CyberArk Safe").

## 16. Unauthorized rename

- **Threat**: a legitimately authenticated device requests a rename it should not be allowed to
  perform (e.g., a device that is disabled, non-compliant, or out of policy scope).
- **Prevention**: `IDeviceOperationAuthorizationService` as a mandatory gate, configurable policy
  (`RequireEntraDevice`, `RequireIntuneManagedDevice`, `RequireCompliantDevice`).
- **Detection**: `OperationDenied` event with reason code.
- **Residual risk**: policy misconfiguration (e.g., all requirements set to `false`) would weaken
  this gate — documented as a deployment-configuration risk, mitigated by documenting the final
  production policy explicitly (prompt §7) rather than leaving defaults ambiguous.

## 17. Repeated credential retrieval

- **Threat**: a device (legitimately or maliciously) requests multiple credential issuances for the
  same conceptual rename.
- **Prevention**: `CredentialLease` state machine + duplicate-request-ID detection (prompt §12, §23).
- **Detection**: abuse-detection event for "credential retrieval with no corresponding result" and
  "multiple credential requests from one device."
- **Residual risk**: none beyond implementation correctness.

## 18. Certificate renewal / re-enrollment

- **Threat**: a legitimate device's certificate renews (new thumbprint) and the device is temporarily
  unrecognized, or conversely a window exists where both old and new certificates are simultaneously
  trusted.
- **Prevention**: device-ID binding should key off a stable identifier (Entra device ID via SAN/OID),
  not a static thumbprint pin, exactly as LogCollector does for its Intune tier — thumbprint pinning
  (`AllowedLeafThumbprints`) is an optional additional restriction, not the primary binding mechanism.
- **Detection**: a spike in `DeviceCertificateRejected` correlated with a known renewal campaign.
- **Residual risk**: a transition window exists during any CA rotation; must be handled operationally
  (both old and new CA trusted during transition, per LogCollector's own documented PKI-rotation
  guidance), not solved purely in code.

## 19. Retired Intune device / deleted Entra device

- **Threat**: a device retired from Intune or deleted from Entra still presents a certificate that has
  not yet expired.
- **Prevention**: mandatory, non-cached (or very short TTL) Graph validation for `ComputerRename`
  ensures a deleted/disabled device is denied promptly, unlike LogCollector's longer-lived cache.
- **Detection**: `GraphDeviceValidationFailed`/`OperationDenied` correlated with device-retirement
  events in the directory (outside this Broker's scope to correlate automatically).
- **Residual risk**: a brief window between retirement and certificate revocation/CA-side action
  remains if Graph is somehow still returning a stale "enabled" state — considered acceptable given
  fail-closed design and short/no caching.

## 20. Renamed device temporarily reporting old hostname

- **Threat**: after a successful rename, the device may still report its old `currentComputerName` in
  a subsequent, stale request (e.g., retried before a reboot completes).
- **Prevention**: computer name is never treated as identity (§11); the `CredentialLease` tracks
  `RequestId` and operation state so a stale retry maps to an already-resolved lease rather than
  issuing a fresh credential.
- **Detection**: duplicate-request-ID detection (#17) naturally covers this case.
- **Residual risk**: none beyond implementation correctness.
