using DeviceCredentialBroker.Domain;
using Xunit;

namespace DeviceCredentialBroker.Application.Tests;

public class InMemoryCredentialLeaseStoreTests
{
    [Fact]
    public async Task IssueAsync_ThenGetAsync_ReturnsIssuedLease()
    {
        var store = new InMemoryCredentialLeaseStore();

        var lease = await store.IssueAsync(
            "device-1", DeviceOperation.ComputerRename, "req-1", "corr-1", TimeSpan.FromMinutes(5), CancellationToken.None);
        var fetched = await store.GetAsync(lease.LeaseId, CancellationToken.None);

        Assert.NotNull(fetched);
        Assert.Equal(CredentialLeaseStatus.Issued, fetched!.Status);
    }

    [Fact]
    public async Task IsDuplicateRequestAsync_SameRequestIdTwice_ReturnsTrueOnSecondCheck()
    {
        var store = new InMemoryCredentialLeaseStore();

        var firstCheck = await store.IsDuplicateRequestAsync("req-dup", CancellationToken.None);
        await store.IssueAsync("device-1", DeviceOperation.ComputerRename, "req-dup", "corr-1", TimeSpan.FromMinutes(5), CancellationToken.None);
        var secondCheck = await store.IsDuplicateRequestAsync("req-dup", CancellationToken.None);

        Assert.False(firstCheck);
        Assert.True(secondCheck);
    }

    [Fact]
    public async Task TryClaimRequestIdAsync_SameRequestIdTwice_OnlyFirstClaimSucceeds()
    {
        var store = new InMemoryCredentialLeaseStore();

        var firstClaim = await store.TryClaimRequestIdAsync("req-claim", CancellationToken.None);
        var secondClaim = await store.TryClaimRequestIdAsync("req-claim", CancellationToken.None);

        Assert.True(firstClaim);
        Assert.False(secondClaim, "A concurrent duplicate RequestId claim must never both succeed.");
    }

    [Fact]
    public async Task TryClaimRequestIdAsync_ConcurrentSameRequestId_OnlyOneWinnerAcrossManyAttempts()
    {
        var store = new InMemoryCredentialLeaseStore();
        const string requestId = "req-concurrent";

        var tasks = Enumerable.Range(0, 50)
            .Select(_ => store.TryClaimRequestIdAsync(requestId, CancellationToken.None))
            .ToArray();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, results.Count(r => r));
    }

    [Fact]
    public async Task TryMarkResultAsync_FirstReport_Succeeds_SecondReport_Fails()
    {
        var store = new InMemoryCredentialLeaseStore();
        var lease = await store.IssueAsync(
            "device-1", DeviceOperation.ComputerRename, "req-1", "corr-1", TimeSpan.FromMinutes(5), CancellationToken.None);

        var first = await store.TryMarkResultAsync(lease.LeaseId, "device-1", succeeded: true, CancellationToken.None);
        var second = await store.TryMarkResultAsync(lease.LeaseId, "device-1", succeeded: true, CancellationToken.None);

        Assert.True(first);
        Assert.False(second, "A second result report for an already-resolved lease must be rejected (prompt §22/§23).");
    }

    [Fact]
    public async Task TryMarkResultAsync_MismatchedDeviceIdentity_Fails()
    {
        // Anti-IDOR on the result-reporting endpoint: a different device presenting a
        // valid lease id for someone else's lease must never be able to resolve it.
        var store = new InMemoryCredentialLeaseStore();
        var lease = await store.IssueAsync(
            "device-1", DeviceOperation.ComputerRename, "req-1", "corr-1", TimeSpan.FromMinutes(5), CancellationToken.None);

        var result = await store.TryMarkResultAsync(lease.LeaseId, "device-2", succeeded: true, CancellationToken.None);

        Assert.False(result);
    }

    [Fact]
    public async Task TryMarkResultAsync_UnknownLeaseId_Fails()
    {
        var store = new InMemoryCredentialLeaseStore();

        var result = await store.TryMarkResultAsync(Guid.NewGuid(), "device-1", succeeded: true, CancellationToken.None);

        Assert.False(result);
    }
}
