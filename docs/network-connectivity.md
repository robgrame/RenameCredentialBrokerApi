# Network connectivity

## Path 1 — Device → Broker — **PROPOSED DESIGN**

```text
Windows Device (corporate network or internet, Intune-managed)
        │  HTTPS + mTLS (device certificate)
        ▼
Azure Application Gateway / App Service built-in TLS termination
   (clientCertMode: Required, no exclusion paths — verified pattern, LogCollector)
        │
        ▼
Device Credential Broker (App Service, VNet-integrated)
```

- Requires the device to reach the Broker's public (or privately-exposed, if an internet-facing
  endpoint is undesirable) endpoint — **OPEN DECISION** whether the Broker should be
  internet-accessible at all vs. reachable only via a private endpoint/VPN, given devices are not
  always on the corporate network (prompt §33.6).
- DNS: standard public DNS resolution if internet-facing; private DNS zone if exposed only via
  Private Link, which would then require devices to have connectivity to that private zone
  (VPN/Always-On VPN) — **REQUIRES CUSTOMER VALIDATION** of actual device network posture.
- TLS trust: devices must trust the Broker's server certificate chain (standard public CA chain
  recommended to avoid additional trust distribution if internet-facing).

## Path 2 — Broker → CyberArk — **OPEN DECISION / REQUIRES CUSTOMER VALIDATION**

```text
Device Credential Broker (VNet-integrated App Service)
        │  (connectivity mechanism TBD)
        ▼
CyberArk (on-premises, per prompt's assumption "CyberArk remains the authoritative
          credential-management system" — exact topology unconfirmed)
```

Evaluate, once the network/CyberArk teams respond (prompt §16):

| Option | Notes |
|---|---|
| VNet Integration (regional) on the App Service, paired with... | ...required to reach any private endpoint or on-prem network at all |
| VPN Gateway (site-to-site) | Lower cost, higher latency, simpler to provision if one already exists for other Azure↔on-prem traffic |
| ExpressRoute | Preferred if already available for other on-prem integrations (likely, given this is an enterprise environment) — reuse rather than provision new |
| Private Endpoint + Private DNS (if CyberArk exposes a privately-linkable endpoint) | Only applicable if CyberArk's interface supports Private Link, unlikely for a traditional on-prem CyberArk Vault — **REQUIRES CUSTOMER VALIDATION** |
| Public CyberArk exposure | Explicitly to be avoided per prompt §16 ("Do not require public CyberArk exposure. Prefer private connectivity when the environment supports it.") |

Also required, once confirmed:

- DNS resolution for the CyberArk hostname from within the Broker's VNet (conditional forwarder to
  on-prem DNS, or private DNS zone).
- Firewall rules permitting the Broker's VNet-integrated outbound IP range (or NAT gateway IP) to
  reach CyberArk's port(s) — exact ports depend on the interface confirmed in
  `docs/cyberark-integration.md`.
- Proxy requirements, if the environment mandates egress via a forward proxy for on-prem-bound
  traffic — **REQUIRES CUSTOMER VALIDATION**.
- TLS trust between the Broker and CyberArk (mutual TLS, if confirmed as required per ADR 0004).
- CyberArk-side source-IP restriction, if enforced, must allow the Broker's outbound IP(s) — stable
  outbound IP typically requires a NAT Gateway or similar fixed-egress mechanism on the VNet.

## Summary of what is NOT yet decided

Everything in Path 2 above is explicitly **OPEN DECISION / REQUIRES CUSTOMER VALIDATION** until the
network and CyberArk teams answer the questions consolidated in `docs/architecture.md` §16 and
`docs/cyberark-integration.md`.
