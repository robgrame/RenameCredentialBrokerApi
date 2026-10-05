# ADR 0001: Hosting model — Azure Functions isolated worker vs. ASP.NET Core on App Service

## Status

PROPOSED DESIGN (recommendation: ASP.NET Core on App Service). The underlying choice is explicitly
listed in prompt §33 as an item that must remain an OPEN DECISION until confirmed — this ADR records
the trade-off analysis and a recommendation, not a locked-in final decision. Confirm before
production deployment.

## Context

The prompt requires (§25): client certificate authentication, VNet integration, Managed Identity,
Application Insights, rate limiting, private connectivity toward CyberArk. It also requires (§33.5)
that "Azure Functions vs. App Service" remain open pending further input.

## Options considered

| Criterion | Azure Functions (isolated worker) | ASP.NET Core on App Service |
|---|---|---|
| Client certificate (mTLS) support | Supported via host.json/App Service platform settings, but historically less first-class for isolated worker HTTP triggers; requires `X-ARR-ClientCert` forwarding same as App Service under the hood (Functions runs on App Service infrastructure for Premium/Dedicated plans). | First-class: `clientCertMode: Required` is a direct App Service site setting, already proven in LogCollector's Frontend Function App (which *is* an App Service-hosted Function — see below). |
| VNet integration / private CyberArk connectivity | Available on Premium (EP) or Dedicated plans only, not Consumption. | Available on Standard/Premium App Service plans. |
| Long-lived connections / fine control over Kestrel pipeline (needed for raw-body-before-deserialize signature verification) | Possible but the Functions HTTP trigger model adds an abstraction layer the LogCollector Frontend already works around. | Direct control via ASP.NET Core middleware — simpler to guarantee raw-body verification order. |
| Cost model | Pay-per-execution (Consumption) or fixed (Premium) — Premium is required anyway for VNet, so cost advantage over App Service is marginal here. | Fixed cost, predictable, already proven for `RenameApiService` (same user's prior project) and for LogCollector's own Frontend (hosted as a Function App on a Premium/VNet-integrated plan — effectively the same infrastructure tier as App Service). |
| Prior art in this environment | LogCollector's Frontend *is* an Azure Function, but on a plan tier that already requires VNet/Premium — so it does not actually exercise the Consumption-plan benefits Functions is usually chosen for. | `RenameApiService` (this user's prior project) is already an ASP.NET Core minimal API with mTLS middleware, directly reusable patterns. |
| Request volume shape | Rename is a rare, low-frequency event per device (once per lifecycle), not a high-throughput telemetry firehose — Functions' elastic-scale advantage (LogCollector's actual justification) does not apply here. | Low, steady request volume is a good fit for a fixed-size App Service plan. |

## Decision (proposed)

Recommend **ASP.NET Core 10 on Azure App Service**, Premium v3 plan with VNet integration, because:

1. The operation's request volume does not benefit from Functions' elastic/consumption scaling
   (unlike LogCollector's telemetry ingestion, which does).
2. Direct control of the request pipeline makes it straightforward to replicate the
   verify-raw-body-before-deserializing discipline that the security model depends on (prompt §10,
   `docs/authentication.md`).
3. Directly reuses patterns and middleware already built and reviewed in `RenameApiService`
   (same user, prior project in this session), reducing net-new security-critical code.
4. VNet integration + Managed Identity + Application Insights + mTLS are all mainstream,
   well-documented App Service features at the required plan tier.

## Consequences

- Requires a Premium v3 (or higher) App Service plan for VNet integration — not eligible for a
  Consumption/cheaper tier.
- If request volume ever grows dramatically (unlikely for a rename-only operation), revisit.

## Confirmation required

This remains open per prompt §33 until explicitly confirmed with the customer/infrastructure team —
track as **OPEN DECISION**.
