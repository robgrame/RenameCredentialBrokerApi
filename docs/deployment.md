# Deployment

Status: **PROPOSED DESIGN**, pending confirmation of ADR 0001 (hosting model) and the network/
CyberArk open decisions.

## Target topology (per ADR 0001 recommendation)

- Azure App Service, Premium v3 plan, regional VNet Integration enabled.
- System- or user-assigned Managed Identity, granted `Device.Read.All` and
  `DeviceManagementManagedDevices.Read.All` (Microsoft Graph, application permissions) — see
  `docs/device-validation.md`.
- `clientCertEnabled: true`, `clientCertMode: Required`, no `clientCertExclusionPaths` (including
  health endpoints) — mirrors the verified-safe LogCollector configuration.
- Application Insights connected for structured logging/telemetry (prompt §24, §25).
- Outbound connectivity to CyberArk per whatever is confirmed in `docs/network-connectivity.md` /
  ADR 0004 — NAT Gateway or similar if a stable outbound IP is required for CyberArk source-IP
  restriction.
- No secrets in App Settings for Graph auth (Managed Identity only). Key Vault reserved for any
  CyberArk-side secret that cannot be replaced by certificate-based or Managed-Identity auth, once
  that mechanism is confirmed.

## `infra/` skeleton

`infra/main.bicep` provisions the App Service plan, app, Managed Identity, Application Insights, and
VNet integration wiring. `infra/modules/` holds per-resource modules; `infra/parameters/` holds
per-environment parameter files. Concrete CyberArk-reachability resources (VPN/ExpressRoute/Private
Link selection) are deliberately left as placeholders pending the open network decision.

## Deployment stages (recommended)

1. Dev/test with `MockCyberArkClient` and `NotConfiguredCyberArkClient` wired in by configuration —
   validates the full device→Broker→Graph pipeline without touching real CyberArk.
2. Confirm ADR 0004 (CyberArk interface/auth) with the CyberArk team; implement the real
   `ICyberArkClient`.
3. Pilot with a small number of devices, one certificate profile (per ADR 0002) confirmed with the
   PKI/Intune team.
4. Production rollout, after the standing review workflow (rubber-duck → security review → fix →
   post-fix review → final review) and successful test runs.
