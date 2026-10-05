<div align="center">

# 🔐 Device Credential Broker

**A zero-trust, mutual-TLS .NET 10 broker that lets a Windows device safely rename itself —
without ever touching CyberArk, and without any human or script ever seeing a standing password.**

[![.NET](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![C#](https://img.shields.io/badge/C%23-13-239120?logo=csharp&logoColor=white)](https://learn.microsoft.com/dotnet/csharp/)
[![ASP.NET Core](https://img.shields.io/badge/ASP.NET%20Core-Minimal%20API-512BD4?logo=dotnet&logoColor=white)](https://learn.microsoft.com/aspnet/core/)
[![Azure](https://img.shields.io/badge/Azure-App%20Service-0078D4?logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-Entra%20ID%20%7C%20Intune-0078D4?logo=microsoft&logoColor=white)](https://learn.microsoft.com/graph/)
[![CyberArk](https://img.shields.io/badge/CyberArk-Credential%20Provider-DA291C?logo=cyberark&logoColor=white)](https://www.cyberark.com/)
[![Bicep](https://img.shields.io/badge/IaC-Bicep-0078D4?logo=microsoftazure&logoColor=white)](https://learn.microsoft.com/azure/azure-resource-manager/bicep/)
[![PowerShell](https://img.shields.io/badge/Client-PowerShell%207-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![xUnit](https://img.shields.io/badge/Tests-xUnit-5AA7E4?logo=nuget&logoColor=white)](https://xunit.net/)
[![mTLS](https://img.shields.io/badge/Auth-Mutual%20TLS-2E8B57)](#-trust-model)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 📖 Overview

Renaming a domain-joined Windows device normally requires a privileged domain credential —
which traditionally ends up embedded in a scheduled task, a GPO script, or a Group Policy
Preference, where it can be extracted, replayed, or quietly outlives its usefulness.

**Device Credential Broker** removes that problem entirely. Instead of distributing a standing
credential to every endpoint, the device proves *who it is* using a machine certificate,
a server-side broker independently re-verifies that identity against **Microsoft Entra ID /
Intune**, and only then — for one single, narrowly-scoped operation (`ComputerRename`) — does
the broker fetch a **short-lived credential from CyberArk** on the device's behalf and hand it
back. The device performs the rename locally with `Rename-Computer`, reports the result, and the
credential lease is closed out. **CyberArk is never reachable from the endpoint**, and the broker
itself never becomes a second, parallel password vault.

> 💡 This project was designed end-to-end from a single, extremely detailed architecture brief
> (34 sections) covering trust model, authentication, Graph-based device validation,
> anti-replay/anti-IDOR controls, CyberArk abstraction, threat modeling, and open
> architecture decisions — see [`docs/`](docs/) for the full design record, including every
> ADR and the STRIDE threat model.

## ✨ Key features

- 🪪 **Mutual TLS device authentication** — the device's machine certificate is the primary
  authentication material; JSON payload fields are treated as untrusted claims, never as identity.
- 🧭 **Independent server-side identity verification** via Microsoft Graph against Entra ID and
  Intune — configurable policy (`RequireEntraDevice`, `RequireIntuneManagedDevice`,
  `RequireCompliantDevice`), fails **closed** whenever Graph can't be reached.
- 🛂 **Narrow, operation-scoped authorization** — the client can only ever ask *"authorize me for
  ComputerRename"*, never *"give me the password for `DOMAIN\ServiceAccount`"*. CyberArk Safe/Object/
  AppID mapping lives entirely server-side.
- 🔁 **Anti-replay & anti-IDOR** — signed canonical requests (`DCB-SIGNATURE-V1`), single-use
  request IDs claimed atomically, short-lived nonces, and strict cross-correlation between
  certificate identity, Entra device ID, Intune device ID, and reported serial number.
- 🗄️ **CyberArk stays authoritative** — the broker never caches or stores a password; a
  `CredentialLease` tracks *who requested what, when, and with what result* without ever
  persisting the credential itself.
- 🧱 **Fail-closed by design** — every security gate (certificate, chain, Graph, authorization,
  replay, CyberArk) denies the request on *any* uncertainty; an infrastructure failure is never
  silently converted into an authorization success.
- ☁️ **Azure-ready** — Bicep IaC for App Service (mTLS `Required`, system-assigned Managed
  Identity, Application Insights, optional VNet integration), portable to on-prem hosting.
- 🖥️ **Minimal, auditable PowerShell client** — selects the certificate by verifiable
  characteristics (never by friendly name), signs the request, converts the credential straight
  to a `PSCredential`, and clears plaintext references immediately after use.

## 🧩 Trust model

```text
Windows Device
  → Device Certificate Authentication (mTLS)
  → Credential Broker
  → Device Validation (Microsoft Graph / Entra ID / Intune)
  → Request Authorization (ComputerRename)
  → CyberArk Credential Retrieval (server-to-server only)
  → Credential returned to the authorized device
  → PSCredential
  → Rename-Computer -DomainCredential
```

The device **never** talks to CyberArk. CyberArk credentials, API authentication information, and
infrastructure details remain server-side only.

## 🏗️ Repository layout

```text
src/
  DeviceCredentialBroker.Domain/           Device identity, operations, lease, result models
  DeviceCredentialBroker.Authentication/   Certificate validation, identity resolution, request signing, replay protection
  DeviceCredentialBroker.Graph/            Microsoft Graph client factory + Entra/Intune device directory validators
  DeviceCredentialBroker.CyberArk/         ICredentialProvider/ICyberArkClient abstraction (mock + fail-closed "not configured" implementations only)
  DeviceCredentialBroker.Application/      Authorization service, abuse detection, credential lease store
  DeviceCredentialBroker.Infrastructure/   In-memory store implementations (replace with durable stores for production)
  DeviceCredentialBroker.Api/              ASP.NET Core 10 minimal API, mTLS host, endpoints
tests/
  *.UnitTests, *.Authentication.Tests, *.CyberArk.Tests, *.Security.Tests, *.IntegrationTests
client/
  Get-AuthorizedRenameCredential.ps1       Certificate selection, request signing, credential retrieval
  Invoke-SecureComputerRename.ps1          Orchestrates credential retrieval → Rename-Computer → result reporting
infra/
  main.bicep, modules/, parameters/        App Service (mTLS, Managed Identity, App Insights, VNet integration)
docs/
  architecture.md, authentication.md, certificate-options.md, device-validation.md,
  cyberark-integration.md, network-connectivity.md, security.md, threat-model.md,
  rename-integration.md, deployment.md, troubleshooting.md, adr/
```

## 🚀 Getting started

```powershell
# Build
dotnet build DeviceCredentialBroker.slnx

# Run the full test suite (unit + integration + security invariant tests)
dotnet test DeviceCredentialBroker.slnx

# Validate the infrastructure templates
az bicep build --file infra/main.bicep
```

## 📊 Status

| Area | Status |
|---|---|
| Architecture, threat model (STRIDE), ADRs | ✅ Complete — see [`docs/`](docs/) |
| Domain / Authentication / Graph / Application / Api | ✅ Implemented, reviewed, tested |
| Test suite | ✅ 44/44 passing (unit, authentication, CyberArk, security, integration) |
| PowerShell client | ✅ Implemented, parse-verified |
| Azure infrastructure (Bicep) | ✅ Implemented, validated with `az bicep build` |
| Production CyberArk connector | ⏳ Intentionally **not implemented** — interface/auth mechanism must be confirmed with the CyberArk team first (see open decisions below) |
| Security review | ✅ Passed — no exploitable findings, no secrets in source |

## 🔓 Open decisions requiring customer/team validation

These are **intentionally left open** and documented as explicit questions in
`docs/cyberark-integration.md`, `docs/certificate-options.md`, and the ADRs under
[`docs/adr/`](docs/adr/):

1. Intune enrollment certificate vs. corporate PKI certificate ([ADR 0002](docs/adr/0002-certificate-profile-selection.md)).
2. Exact CyberArk interface and authentication mechanism ([ADR 0004](docs/adr/0004-cyberark-interface-and-auth.md)).
3. Whether Intune compliance is mandatory for authorization.
4. Azure Functions vs. App Service hosting ([ADR 0001](docs/adr/0001-hosting-model.md) recommends App Service; confirm before production deployment).
5. Internet-accessible broker vs. private-endpoint-only strategy.

**Mocks and interfaces are implemented; infrastructure-specific CyberArk code is deliberately
not implemented until the CyberArk interface and authentication mechanism are confirmed.**

## 📚 Documentation index

| Doc | Covers |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | End-to-end design, sequence diagrams, authorization model |
| [`docs/authentication.md`](docs/authentication.md) | Certificate profiles, selection criteria, mTLS validation |
| [`docs/certificate-options.md`](docs/certificate-options.md) | Intune enrollment vs. corporate PKI certificate comparison |
| [`docs/device-validation.md`](docs/device-validation.md) | Microsoft Graph / Entra ID / Intune validation strategy |
| [`docs/cyberark-integration.md`](docs/cyberark-integration.md) | CyberArk abstraction, open integration questions |
| [`docs/network-connectivity.md`](docs/network-connectivity.md) | Device↔broker and broker↔CyberArk network paths |
| [`docs/security.md`](docs/security.md) | Credential lifecycle, memory hygiene, residual risk |
| [`docs/threat-model.md`](docs/threat-model.md) | STRIDE-based threat model |
| [`docs/rename-integration.md`](docs/rename-integration.md) | How the broker plugs into an existing rename workflow |
| [`docs/deployment.md`](docs/deployment.md) | Hosting and deployment notes |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | Common issues |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records |

## 🤝 Contributing

Issues and pull requests are welcome. Please avoid including any real tenant IDs, certificate
material, CyberArk configuration, or other environment-specific secrets in contributions.

## 📄 License

[MIT](LICENSE)
