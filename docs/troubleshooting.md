# Troubleshooting

| Symptom | Likely cause | Where to look |
|---|---|---|
| `DeviceCertificateRejected` for a device expected to be valid | Wrong `ActiveProfile` configured, cert does not match configured trust anchors, or EKU missing | `docs/certificate-options.md`; confirm the actual deployed certificate's characteristics against the active profile's configuration |
| `GraphDeviceValidationFailed` for all requests | Managed Identity missing Graph permissions, or Graph outage | Verify `Device.Read.All` (+ `DeviceManagementManagedDevices.Read.All` if `RequireIntuneManagedDevice`) consent; check Graph service health |
| `OperationDenied` despite a seemingly valid device | Policy requires Intune-managed/compliant state the device does not currently have | Check `DeviceValidation` policy flags against the device's actual Intune state |
| `ReplayDetected` on a legitimate retry | Client reused a nonce/timestamp instead of regenerating per attempt | Client must call `New-SignedInventoryRequest`-equivalent logic fresh on every attempt (never cache a signed request) |
| `CyberArkCredentialFailed` | CyberArk unreachable, unconfigured (`NotConfiguredCyberArkClient` is the default until ADR 0004 is resolved), or authentication failure | Confirm `ICyberArkClient` is configured with a real implementation; check network path per `docs/network-connectivity.md` |
| Rename succeeds but result-report fails | Certificate/device mismatch between original request and result report, or lease already expired/consumed | Check `CredentialLease` status and correlation ID in Application Insights |
| Password visible in a log | **Treat as a critical finding** — stop and investigate immediately | Review the specific code path against `docs/security.md` "Logging and telemetry"; this should never happen given the structural design, so a report indicates a regression |
