using DeviceCredentialBroker.Domain;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DeviceCredentialBroker.Application.Tests;

public class DeviceOperationAuthorizationServiceTests
{
    private static DeviceIdentity CreateIdentity() => new()
    {
        CertificateSubject = "CN=" + Guid.NewGuid(),
        CertificateIssuer = "CN=Test Root CA",
        CertificateThumbprintHash = "hash",
        CertificateBoundDeviceId = Guid.NewGuid(),
        TrustProfile = CertificateTrustProfile.CorporatePKI
    };

    private static DeviceOperationRequest CreateRequest(DeviceIdentity identity, DeviceDirectoryValidationResult directoryValidation) => new()
    {
        Identity = identity,
        DirectoryValidation = directoryValidation,
        Operation = DeviceOperation.ComputerRename,
        RequestTimestamp = DateTimeOffset.UtcNow,
        CorrelationId = Guid.NewGuid().ToString("D")
    };

    private sealed class NeverSuspiciousAbuseDetector : IAbuseDetector
    {
        public Task<bool> IsSuspiciousAsync(DeviceIdentity identity, DeviceOperation operation, CancellationToken cancellationToken) =>
            Task.FromResult(false);
    }

    private sealed class AlwaysSuspiciousAbuseDetector : IAbuseDetector
    {
        public Task<bool> IsSuspiciousAsync(DeviceIdentity identity, DeviceOperation operation, CancellationToken cancellationToken) =>
            Task.FromResult(true);
    }

    [Fact]
    public async Task AuthorizeAsync_ValidDirectoryAndNotAbusive_Authorizes()
    {
        var service = new DeviceOperationAuthorizationService(
            new NeverSuspiciousAbuseDetector(), NullLogger<DeviceOperationAuthorizationService>.Instance);

        var result = await service.AuthorizeAsync(
            CreateRequest(CreateIdentity(), new DeviceDirectoryValidationResult { IsValid = true }),
            CancellationToken.None);

        Assert.True(result.Authorized);
    }

    [Fact]
    public async Task AuthorizeAsync_DirectoryValidationFailed_Denies()
    {
        var service = new DeviceOperationAuthorizationService(
            new NeverSuspiciousAbuseDetector(), NullLogger<DeviceOperationAuthorizationService>.Instance);

        var result = await service.AuthorizeAsync(
            CreateRequest(CreateIdentity(), DeviceDirectoryValidationResult.Deny("not found")),
            CancellationToken.None);

        Assert.False(result.Authorized);
        Assert.Equal("DirectoryValidationFailed", result.DenyReasonCode);
    }

    [Fact]
    public async Task AuthorizeAsync_AbuseDetected_Denies()
    {
        var service = new DeviceOperationAuthorizationService(
            new AlwaysSuspiciousAbuseDetector(), NullLogger<DeviceOperationAuthorizationService>.Instance);

        var result = await service.AuthorizeAsync(
            CreateRequest(CreateIdentity(), new DeviceDirectoryValidationResult { IsValid = true }),
            CancellationToken.None);

        Assert.False(result.Authorized);
        Assert.Equal("AbuseDetected", result.DenyReasonCode);
    }
}

public class InMemoryAbuseDetectorTests
{
    [Fact]
    public async Task IsSuspiciousAsync_ExceedsThreshold_ReturnsTrue()
    {
        var detector = new InMemoryAbuseDetector(maxRequestsPerWindow: 2, window: TimeSpan.FromMinutes(10));
        var identity = new DeviceIdentity
        {
            CertificateSubject = "CN=x",
            CertificateIssuer = "CN=y",
            CertificateThumbprintHash = "hash",
            CertificateBoundDeviceId = Guid.NewGuid(),
            TrustProfile = CertificateTrustProfile.CorporatePKI
        };

        await detector.IsSuspiciousAsync(identity, DeviceOperation.ComputerRename, CancellationToken.None);
        await detector.IsSuspiciousAsync(identity, DeviceOperation.ComputerRename, CancellationToken.None);
        var thirdResult = await detector.IsSuspiciousAsync(identity, DeviceOperation.ComputerRename, CancellationToken.None);

        Assert.True(thirdResult);
    }

    [Fact]
    public async Task IsSuspiciousAsync_DifferentDevices_DoNotShareQuota()
    {
        var detector = new InMemoryAbuseDetector(maxRequestsPerWindow: 1);
        var deviceA = new DeviceIdentity
        {
            CertificateSubject = "CN=a", CertificateIssuer = "CN=y", CertificateThumbprintHash = "a",
            CertificateBoundDeviceId = Guid.NewGuid(), TrustProfile = CertificateTrustProfile.CorporatePKI
        };
        var deviceB = new DeviceIdentity
        {
            CertificateSubject = "CN=b", CertificateIssuer = "CN=y", CertificateThumbprintHash = "b",
            CertificateBoundDeviceId = Guid.NewGuid(), TrustProfile = CertificateTrustProfile.CorporatePKI
        };

        await detector.IsSuspiciousAsync(deviceA, DeviceOperation.ComputerRename, CancellationToken.None);
        var resultForB = await detector.IsSuspiciousAsync(deviceB, DeviceOperation.ComputerRename, CancellationToken.None);

        Assert.False(resultForB);
    }
}
