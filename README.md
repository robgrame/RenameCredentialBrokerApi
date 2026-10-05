# RenameCredentialBrokerApi — Device Credential Broker

A secure, mutual-TLS, .NET 10 broker that authorizes a Windows device to perform a
`Rename-Computer -DomainCredential` operation and retrieves the required service-account
credential from CyberArk on the device's behalf — **without the device ever contacting
CyberArk directly**, and without the broker ever becoming an alternative permanent
password store.

## Status

✅ Architecture, threat model, and ADRs complete. ✅ Domain/Authentication/Graph/CyberArk/
Application/Infrastructure/Api libraries implemented and unit/integration tested (42/42 tests
passing). ✅ PowerShell client scripts and Bicep infra skeleton implemented. ⏳ Production
`ICyberArkClient` connector intentionally **not implemented** — see "Open decisions" below.

## Background

This repository supersedes [`RenameApiService`](https://github.com/robgrame/RenameApiService),
which implemented a server-side remote-execution model (WinRM/JEA): a server would reach out
to the client machine and run the rename itself. This design inverts that responsibility: the
broker only authorizes the operation and brokers a short-lived credential; the device itself
performs `Rename-Computer`, using the brokered credential, directly on the local machine
(prompt §19, `docs/rename-integration.md`). `Monitor-HybridJoin-RenameReboot.ps1` is **not**
modified by this repository — see `docs/rename-integration.md` for the documented, not-yet-applied,
future integration point.

## Trust model

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

The device never talks to CyberArk. CyberArk credentials, API authentication information, and
infrastructure details remain server-side only (prompt §1–§2).

## Repository layout

```text
src/
  DeviceCredentialBroker.Domain/          Device identity, operations, lease, result models
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

## Building and testing

```powershell
dotnet build DeviceCredentialBroker.slnx
dotnet test DeviceCredentialBroker.slnx
```

## Open decisions requiring customer/team validation

These are **intentionally not decided** in this repository (prompt §33) and are documented as
open questions in `docs/cyberark-integration.md`, `docs/certificate-options.md`, and the ADRs
under `docs/adr/`:

1. Intune enrollment certificate vs. corporate PKI certificate (ADR 0002).
2. Exact CyberArk interface and authentication mechanism (ADR 0004).
3. Whether Intune compliance is mandatory for authorization.
4. Azure Functions vs. App Service hosting (ADR 0001 recommends App Service; confirm before
   production deployment).
5. Internet-accessible broker vs. private-endpoint-only strategy.

**Mocks and interfaces are implemented; infrastructure-specific CyberArk code is deliberately
not implemented until the CyberArk interface and authentication mechanism are confirmed**
(prompt, final instruction).
