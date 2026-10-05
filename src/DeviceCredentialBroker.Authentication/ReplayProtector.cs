namespace DeviceCredentialBroker.Authentication;

/// <summary>
/// Insert-only nonce reservation, adapted from LogCollector's verified
/// IReplayNonceStore/AzureTableReplayNonceStore pattern (docs/authentication.md §3).
/// A reservation conflict means the (thumbprint, nonce) pair was already claimed —
/// i.e., a replay. Must be atomic across scaled-out instances.
/// </summary>
public interface IReplayNonceStore
{
    /// <summary>
    /// Attempts to reserve the given (thumbprint, nonce) pair. Returns false if it was
    /// already reserved (a replay).
    /// </summary>
    Task<bool> TryReserveAsync(string certificateThumbprintHash, Guid nonce, DateTimeOffset timestamp, CancellationToken cancellationToken);
}

/// <summary>
/// Validates timestamp freshness and delegates nonce reservation. Order matters:
/// freshness is checked first (cheapest), then the signature must already have been
/// verified by the caller before nonce reservation runs — reserving a nonce for
/// unauthenticated traffic would let an attacker exhaust/pollute the nonce store
/// (docs/authentication.md §3, verified LogCollector invariant).
/// </summary>
public sealed class ReplayProtector
{
    private readonly IReplayNonceStore _store;
    private readonly TimeSpan _maxSkew;

    public ReplayProtector(IReplayNonceStore store, TimeSpan? maxSkew = null)
    {
        _store = store;
        _maxSkew = maxSkew ?? TimeSpan.FromSeconds(300);
    }

    public bool ValidateFreshness(DateTimeOffset timestamp, DateTimeOffset now) =>
        (now - timestamp).Duration() <= _maxSkew;

    public Task<bool> ReserveAsync(string certificateThumbprintHash, Guid nonce, DateTimeOffset timestamp, CancellationToken cancellationToken) =>
        _store.TryReserveAsync(certificateThumbprintHash, nonce, timestamp, cancellationToken);
}

/// <summary>
/// In-memory nonce store — suitable for a single-instance dev/test deployment only.
/// Production, scaled-out deployments must use an atomic, shared backing store
/// (e.g., Azure Table insert-only, matching the verified LogCollector pattern) —
/// see docs/network-connectivity.md / docs/authentication.md §3, item 2 (OPEN DECISION).
/// </summary>
public sealed class InMemoryReplayNonceStore : IReplayNonceStore
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTimeOffset> _seen = new();
    private readonly TimeSpan _retention;
    private long _reservationCount;

    public InMemoryReplayNonceStore(TimeSpan? retention = null)
    {
        // Retains entries well beyond the signature freshness window (default 300s) so a
        // nonce can never be "forgotten" and accepted again while still within that window.
        _retention = retention ?? TimeSpan.FromMinutes(15);
    }

    public Task<bool> TryReserveAsync(string certificateThumbprintHash, Guid nonce, DateTimeOffset timestamp, CancellationToken cancellationToken)
    {
        var key = $"{certificateThumbprintHash}:{nonce:D}";
        var reserved = _seen.TryAdd(key, DateTimeOffset.UtcNow.Add(_retention));

        // Opportunistic, bounded cleanup: avoids unbounded growth from valid signed
        // requests without requiring a background timer (single-instance scope only —
        // see the OPEN DECISION above for the production, scaled-out replacement).
        if (System.Threading.Interlocked.Increment(ref _reservationCount) % 500 == 0)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var entry in _seen)
            {
                if (entry.Value <= now)
                {
                    _seen.TryRemove(entry.Key, out _);
                }
            }
        }

        return Task.FromResult(reserved);
    }
}
