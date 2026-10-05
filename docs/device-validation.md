# Device validation — Microsoft Graph verification strategy

## `IDeviceDirectoryValidator`

```csharp
public interface IDeviceDirectoryValidator
{
    Task<DeviceDirectoryValidationResult> ValidateAsync(
        DeviceIdentity identity,
        CancellationToken cancellationToken);
}

public sealed record DeviceDirectoryValidationResult(
    bool IsValid,
    bool EntraDeviceFound,
    bool EntraDeviceEnabled,
    bool IntuneManaged,
    bool IntuneCompliant,
    string? DenyReason);
```

Two implementations, composed by policy (not a single monolithic validator — prompt §7 explicitly
says "do not automatically require every possible attribute," policy must be configuration-driven):

- `EntraDeviceDirectoryValidator` — calls `GET /v1.0/devices(deviceId='{id}')`; checks the device
  exists, is enabled, and belongs to the expected tenant (the Broker's own tenant, since app-only
  Graph calls are inherently tenant-scoped to the Managed Identity's home tenant). This is the direct
  equivalent of LogCollector's `GraphDeviceAuthorizer`, extended to be **mandatory** rather than an
  optional fallback check for `ComputerRename` (see `docs/authentication.md` §5 for why).
- `IntuneManagedDeviceValidator` — calls
  `GET /v1.0/deviceManagement/managedDevices?$filter=azureADDeviceId eq '{id}'`; checks
  `managementState` and, if `RequireCompliantDevice` is enabled, `complianceState`.

## Policy configuration (example only — prompt §7 explicitly marks these as examples)

```jsonc
{
  "DeviceValidation": {
    "RequireEntraDevice": true,
    "RequireIntuneManagedDevice": true,
    "RequireCompliantDevice": false,
    "PositiveResultCacheSeconds": 0
  }
}
```

- `RequireEntraDevice = true` — **PROPOSED DESIGN**, treated as effectively non-optional for
  `ComputerRename` regardless of the flag's presence (the flag exists for future lower-risk
  operations that might reuse this validator with relaxed policy).
- `RequireIntuneManagedDevice = true` — **PROPOSED DESIGN**; the use case is specifically an
  Intune-managed Hybrid Join rename workflow (per the original script's context), so requiring
  Intune management state is a reasonable default, but **OPEN DECISION / REQUIRES CUSTOMER
  VALIDATION** to confirm as final production policy.
- `RequireCompliantDevice = false` — **PROPOSED DESIGN** default (not required), because compliance
  state can lag for reasons unrelated to rename eligibility (e.g., a pending but unrelated compliance
  check); **OPEN DECISION** whether the customer wants this stricter.
- `PositiveResultCacheSeconds = 0` — no caching by default for this operation, diverging from
  LogCollector's 240-minute cache, because credential issuance demands fresher state than telemetry
  ingestion (`docs/authentication.md` §5). **PROPOSED DESIGN.**

## Fail-closed behavior (prompt §8, §27 — VERIFIED REQUIREMENT)

| Condition | Result |
|---|---|
| Graph unreachable/throttled/error | `IsValid = false`, deny, `GraphDeviceValidationFailed` event |
| Device not found in Entra | `IsValid = false`, deny |
| Device disabled | `IsValid = false`, deny |
| `RequireIntuneManagedDevice = true` and device not found in Intune | `IsValid = false`, deny |
| `RequireCompliantDevice = true` and device non-compliant | `IsValid = false`, deny |
| All required checks pass | `IsValid = true`, proceed to authorization |

An infrastructure failure is never converted into an authorization success — this is the single most
important invariant in this component (explicitly called out in prompt §8).

## Graph authentication — `IGraphClientFactory`

```csharp
public interface IGraphClientFactory
{
    GraphServiceClient CreateClient();
}
```

Implemented using `DefaultAzureCredential`/`ManagedIdentityCredential` exclusively — no client
secret, matching prompt §8/§26's explicit requirement and the Managed-Identity pattern already used
by LogCollector's Frontend for the same Graph call.

## Required Graph application permissions (least privilege)

| Permission | Type | Required for |
|---|---|---|
| `Device.Read.All` | Application | `EntraDeviceDirectoryValidator` |
| `DeviceManagementManagedDevices.Read.All` | Application | `IntuneManagedDeviceValidator`, only if `RequireIntuneManagedDevice` or `RequireCompliantDevice` is enabled |

No write permissions are required anywhere in this design.
