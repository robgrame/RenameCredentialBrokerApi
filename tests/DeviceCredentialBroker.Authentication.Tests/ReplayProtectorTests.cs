using Xunit;

namespace DeviceCredentialBroker.Authentication.Tests;

public class ReplayProtectorTests
{
    [Fact]
    public void ValidateFreshness_WithinSkew_ReturnsTrue()
    {
        var protector = new ReplayProtector(new InMemoryReplayNonceStore(), TimeSpan.FromSeconds(300));
        var now = DateTimeOffset.UtcNow;

        Assert.True(protector.ValidateFreshness(now.AddSeconds(-60), now));
    }

    [Fact]
    public void ValidateFreshness_OutsideSkew_ReturnsFalse()
    {
        var protector = new ReplayProtector(new InMemoryReplayNonceStore(), TimeSpan.FromSeconds(300));
        var now = DateTimeOffset.UtcNow;

        Assert.False(protector.ValidateFreshness(now.AddMinutes(-10), now));
    }

    [Fact]
    public async Task ReserveAsync_FirstUse_Succeeds_SecondUse_IsReplay()
    {
        var protector = new ReplayProtector(new InMemoryReplayNonceStore());
        var nonce = Guid.NewGuid();
        var thumbprintHash = "abc123";
        var timestamp = DateTimeOffset.UtcNow;

        var first = await protector.ReserveAsync(thumbprintHash, nonce, timestamp, CancellationToken.None);
        var second = await protector.ReserveAsync(thumbprintHash, nonce, timestamp, CancellationToken.None);

        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public async Task ReserveAsync_DifferentCertificates_SameNonce_BothSucceed()
    {
        // The reservation key is scoped per-certificate; two different devices
        // presenting the same nonce value independently must not collide.
        var protector = new ReplayProtector(new InMemoryReplayNonceStore());
        var nonce = Guid.NewGuid();
        var timestamp = DateTimeOffset.UtcNow;

        var first = await protector.ReserveAsync("device-a", nonce, timestamp, CancellationToken.None);
        var second = await protector.ReserveAsync("device-b", nonce, timestamp, CancellationToken.None);

        Assert.True(first);
        Assert.True(second);
    }
}
