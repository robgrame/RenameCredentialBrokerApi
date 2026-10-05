namespace DeviceCredentialBroker.Infrastructure;

/// <summary>
/// Placeholder for production, shared/scaled-out backing-store implementations of
/// <c>IReplayNonceStore</c> and <c>ICredentialLeaseStore</c> (e.g., Azure Table,
/// matching the verified LogCollector AzureTableReplayNonceStore pattern — see
/// docs/authentication.md §3 and docs/network-connectivity.md).
///
/// The in-memory implementations in DeviceCredentialBroker.Authentication and
/// DeviceCredentialBroker.Application are suitable only for a single-instance
/// dev/test deployment. A horizontally-scaled production deployment MUST replace
/// them with an atomic, shared store here before go-live — tracked as an OPEN
/// DECISION pending the hosting-model confirmation in ADR 0001.
/// </summary>
public static class InfrastructurePlaceholder
{
    public const string Note =
        "Replace in-memory nonce/lease stores with a shared backing store before any multi-instance deployment.";
}
