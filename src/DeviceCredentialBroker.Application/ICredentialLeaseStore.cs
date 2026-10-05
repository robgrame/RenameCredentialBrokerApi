using DeviceCredentialBroker.Domain;

namespace DeviceCredentialBroker.Application;

/// <summary>
/// Manages the <see cref="CredentialLease"/> lifecycle (prompt §21, §22). Never stores
/// the credential itself — only the audit relationship between the request, the
/// operation, and its eventual reported result.
/// </summary>
public interface ICredentialLeaseStore
{
    Task<CredentialLease> IssueAsync(string deviceIdentityId, DeviceOperation operation, string requestId, string correlationId, TimeSpan leaseLifetime, CancellationToken cancellationToken);

    Task<CredentialLease?> GetAsync(Guid leaseId, CancellationToken cancellationToken);

    Task<bool> TryMarkResultAsync(Guid leaseId, string deviceIdentityId, bool succeeded, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically claims a request ID, returning true only for the first caller to claim
    /// it. Must be called — and its result checked — before any authorization/CyberArk
    /// work begins, so two concurrent requests sharing a (replayed or retried) request ID
    /// can never both reach credential issuance (prompt §12, §23; fixes the
    /// check-then-act race identified in rubber-duck review).
    /// </summary>
    Task<bool> TryClaimRequestIdAsync(string requestId, CancellationToken cancellationToken);

    /// <summary>
    /// Returns true if a request ID has already been used for a distinct lease —
    /// catches duplicate credential-retrieval attempts (prompt §12, §23) even when the
    /// anti-replay nonce differs (e.g., a stale client retry re-signing a new request
    /// for an operation already completed). Prefer <see cref="TryClaimRequestIdAsync"/>
    /// when the check must also prevent a concurrent race; this method is read-only.
    /// </summary>
    Task<bool> IsDuplicateRequestAsync(string requestId, CancellationToken cancellationToken);
}

public sealed class InMemoryCredentialLeaseStore : ICredentialLeaseStore
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, CredentialLease> _leases = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Guid> _requestIds = new();

    public Task<bool> TryClaimRequestIdAsync(string requestId, CancellationToken cancellationToken) =>
        Task.FromResult(_requestIds.TryAdd(requestId, Guid.Empty));

    public Task<CredentialLease> IssueAsync(string deviceIdentityId, DeviceOperation operation, string requestId, string correlationId, TimeSpan leaseLifetime, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var lease = new CredentialLease
        {
            LeaseId = Guid.NewGuid(),
            DeviceIdentityId = deviceIdentityId,
            Operation = operation,
            IssuedUtc = now,
            ExpiresUtc = now.Add(leaseLifetime),
            RequestId = requestId,
            CorrelationId = correlationId,
            Status = CredentialLeaseStatus.Issued
        };

        _leases[lease.LeaseId] = lease;
        // Finalizes the mapping reserved by TryClaimRequestIdAsync (or claims it directly,
        // for callers — e.g. existing unit tests — that issue without a separate claim step).
        _requestIds[requestId] = lease.LeaseId;
        return Task.FromResult(lease);
    }

    public Task<CredentialLease?> GetAsync(Guid leaseId, CancellationToken cancellationToken) =>
        Task.FromResult(_leases.TryGetValue(leaseId, out var lease) ? lease : null);

    public Task<bool> TryMarkResultAsync(Guid leaseId, string deviceIdentityId, bool succeeded, CancellationToken cancellationToken)
    {
        if (!_leases.TryGetValue(leaseId, out var lease) || lease.DeviceIdentityId != deviceIdentityId)
        {
            return Task.FromResult(false);
        }

        if (lease.Status != CredentialLeaseStatus.Issued)
        {
            // Already resolved — reporting a result twice is treated as suspicious,
            // not silently accepted (prompt §22, §23).
            return Task.FromResult(false);
        }

        if (DateTimeOffset.UtcNow > lease.ExpiresUtc)
        {
            // Expired leases can no longer be resolved by a result report; mark explicitly
            // so the audit trail reflects a timeout rather than a (possibly stale) report.
            _leases.TryUpdate(leaseId, lease with { Status = CredentialLeaseStatus.Expired }, lease);
            return Task.FromResult(false);
        }

        var updated = lease with
        {
            Status = succeeded ? CredentialLeaseStatus.OperationReportedSucceeded : CredentialLeaseStatus.OperationReportedFailed
        };

        // Compare-and-swap against the exact instance just read: concurrent result reports
        // for the same lease can both read "Issued", but only one TryUpdate can win.
        return Task.FromResult(_leases.TryUpdate(leaseId, updated, lease));
    }

    public Task<bool> IsDuplicateRequestAsync(string requestId, CancellationToken cancellationToken) =>
        Task.FromResult(_requestIds.ContainsKey(requestId));
}
