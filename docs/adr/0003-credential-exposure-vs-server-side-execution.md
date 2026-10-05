# ADR 0003: Credential exposure to endpoint (A) vs. server-side privileged execution (B)

## Status

Architecture **A** (return password to endpoint) is implemented now, because it is the current
stated requirement (prompt §18, §19 — the user's requirement is specifically that the device performs
`Rename-Computer` itself using a received `PSCredential`). Architecture **B** is documented here for
future security evaluation, per explicit instruction, and is **not** implemented.

## Context

Returning a reusable Active Directory password to an endpoint — even one strongly authenticated via
device certificate, validated against Entra/Intune, and retrieved just-in-time from CyberArk —
introduces irreducible residual risk: a SYSTEM-level attacker on that specific endpoint can capture
the credential while it exists in process memory (as plaintext, at least transiently, since
`Rename-Computer -DomainCredential` requires a `PSCredential`/`SecureString`, and JSON deserialization
of the HTTP response necessarily creates a managed string before that conversion — prompt §20 is
explicit that this must be honestly documented, not minimized).

## Option A — Return the password to the endpoint (current requirement, implemented)

```text
Broker → CyberArk → password → HTTPS response → Device (plaintext briefly in memory)
                                                    → SecureString → PSCredential
                                                    → Rename-Computer -DomainCredential
                                                    → dispose references
```

- Pros: minimal change to the existing, unmodified PowerShell rename workflow (prompt §19 explicitly
  requires `Rename-Computer -DomainCredential $Credential` as the final call, with no rewrite of
  Hybrid Join detection, scheduled-task architecture, or reboot workflow).
- Cons: the credential — however briefly — exists as plaintext in the device's process memory and
  crosses the network (even over TLS, it is visible at both TLS endpoints). A sufficiently privileged
  local attacker (the same SYSTEM-level attacker who could otherwise already request the operation)
  could extract it via memory inspection in the narrow window before disposal. **This is not
  eliminated by any control in this design.**

## Option B — Server-side privileged execution without exposing the password (documented, NOT implemented)

```text
Broker → CyberArk → password (never leaves Broker memory)
       → Broker executes the privileged AD operation on the device's behalf
         (e.g., via a constrained remote-execution channel, analogous to the
         JEA/WinRM model built in the prior RenameApiService project)
       → Device receives only a result, never a credential
```

- Pros: the password never leaves server-side trust boundary; eliminates the device-side credential-
  in-memory exposure window entirely. This was in fact the architecture of this user's *prior*
  project phase (`RenameApiService`, JEA/WinRM-based), before the explicit pivot documented in this
  repository's README.
- Cons: requires either (a) the Broker to reach back into the device via WinRM/JEA (reintroducing the
  server→device remoting dependency this pivot was meant to remove), or (b) a different constrained
  execution surface; also does not fit the user's stated new requirement that the *device* performs
  the rename itself.

## Decision

Implement **A** now, as explicitly required. Treat **B** as a standing, documented alternative for a
future security re-evaluation — e.g., if a security review later determines the residual
memory-exposure risk in A is unacceptable for this environment. No code for B exists in this
repository; it is referenced only for traceability back to the prior `RenameApiService` project,
which already implements the relevant remote-execution mechanics should B ever be revisited.

## Consequences

- `docs/security.md` must carry an explicit, non-minimized statement of this residual risk — it must
  never be described as "eliminated" by TLS, certificate validation, Entra validation, or CyberArk's
  own security, because none of those address the device-local memory-exposure window.
- The PowerShell client (`client/Invoke-SecureComputerRename.ps1`) must minimize the plaintext
  lifetime as tightly as possible: convert to `SecureString`/`PSCredential` immediately, and release
  all plaintext references as soon as the conversion completes (prompt §20).
