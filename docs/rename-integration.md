# Rename integration — PowerShell client

The existing `Monitor-HybridJoin-RenameReboot.ps1` script is **not modified** in this phase (per the
user's explicit instruction). This document describes how a future, separately-approved change would
wire it to this Broker — the integration script itself (`client/Get-AuthorizedRenameCredential.ps1`,
`client/Invoke-SecureComputerRename.ps1`) is implemented in this repository, but calling it from the
existing script is intentionally out of scope until approved.

## Minimal integration point (prompt §19 — VERIFIED REQUIREMENT)

Immediately before the existing script's `Rename-Computer` call, insert a call to
`Get-AuthorizedRenameCredential`:

```powershell
# Conceptual integration — NOT applied to Monitor-HybridJoin-RenameReboot.ps1 in this phase.
$credential = Get-AuthorizedRenameCredential `
    -BrokerUri 'https://<broker-host>/api/v1/device/operations/computer-rename/credential' `
    -DesiredComputerName $NewComputerName

try {
    Rename-Computer -NewName $NewComputerName -DomainCredential $credential -Force
    Invoke-SecureComputerRenameResult -LeaseId $credential.LeaseId -Result 'Succeeded'
}
catch {
    Invoke-SecureComputerRenameResult -LeaseId $credential.LeaseId -Result 'Failed' -ErrorRecord $_
    throw
}
finally {
    Remove-Variable credential -ErrorAction SilentlyContinue
}
```

Explicitly **not** rewritten: Hybrid Join detection, Event ID detection, hostname retrieval,
scheduled-task architecture, user notification, existing reboot workflow (prompt §19).

## Client scripts in this repository

- `client/Get-AuthorizedRenameCredential.ps1` — selects the device certificate per the configured
  profile (`IntuneEnrollment`/`CorporatePKI`), signs the request (`DCB-SIGNATURE-V1`, adapted from
  LogCollector's `RequestSigning.psm1`), calls the Broker, and returns a `PSCredential` plus the
  `CredentialLeaseId` needed for result reporting.
- `client/Invoke-SecureComputerRename.ps1` — orchestrates: get credential → `Rename-Computer` →
  report result → dispose credential references. This script is the one intended to eventually be
  invoked by the existing monitor script, once that specific wiring change is separately approved.

See `docs/security.md` for the memory-handling requirements both scripts must satisfy.
