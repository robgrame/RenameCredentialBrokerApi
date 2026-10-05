using DeviceCredentialBroker.Domain;
using Microsoft.Extensions.Logging;

namespace DeviceCredentialBroker.Application;

/// <summary>
/// Authorizes ComputerRename only, fail-closed on any missing/invalid directory
/// validation result or on abuse-detection signals. Reason codes are internal audit
/// detail only — never returned to the client (docs/architecture.md §10).
/// </summary>
public sealed class DeviceOperationAuthorizationService : IDeviceOperationAuthorizationService
{
    private readonly IAbuseDetector _abuseDetector;
    private readonly ILogger<DeviceOperationAuthorizationService> _logger;

    public DeviceOperationAuthorizationService(IAbuseDetector abuseDetector, ILogger<DeviceOperationAuthorizationService> logger)
    {
        _abuseDetector = abuseDetector;
        _logger = logger;
    }

    public async Task<AuthorizationResult> AuthorizeAsync(DeviceOperationRequest request, CancellationToken cancellationToken)
    {
        if (request.Operation != DeviceOperation.ComputerRename)
        {
            return Deny("UnsupportedOperation", request.CorrelationId);
        }

        if (!request.DirectoryValidation.IsValid)
        {
            return Deny("DirectoryValidationFailed", request.CorrelationId);
        }

        if (await _abuseDetector.IsSuspiciousAsync(request.Identity, request.Operation, cancellationToken))
        {
            return Deny("AbuseDetected", request.CorrelationId);
        }

        _logger.LogInformation(
            "OperationAuthorized: {Operation} for device {DeviceId}, correlation {CorrelationId}.",
            request.Operation, request.Identity.CertificateBoundDeviceId, request.CorrelationId);

        return AuthorizationResult.Allow();
    }

    private AuthorizationResult Deny(string reasonCode, string correlationId)
    {
        _logger.LogWarning("OperationDenied: {ReasonCode}, correlation {CorrelationId}.", reasonCode, correlationId);
        return AuthorizationResult.Deny(reasonCode);
    }
}

/// <summary>
/// Abuse detection (prompt §23): multiple credential requests from one device,
/// mismatched identity signals, replayed/duplicate activity. Rate limiting and
/// per-device thresholds are implementation-defined in the backing store.
/// </summary>
public interface IAbuseDetector
{
    Task<bool> IsSuspiciousAsync(DeviceIdentity identity, DeviceOperation operation, CancellationToken cancellationToken);
}

/// <summary>
/// In-memory, single-instance rate limiter — default of 3 requests per device per
/// 10-minute rolling window for ComputerRename. Production/scaled-out deployments
/// should back this with a shared store (see docs/network-connectivity.md).
/// </summary>
public sealed class InMemoryAbuseDetector : IAbuseDetector
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, List<DateTimeOffset>> _requestHistory = new();
    private readonly int _maxRequestsPerWindow;
    private readonly TimeSpan _window;

    public InMemoryAbuseDetector(int maxRequestsPerWindow = 3, TimeSpan? window = null)
    {
        _maxRequestsPerWindow = maxRequestsPerWindow;
        _window = window ?? TimeSpan.FromMinutes(10);
    }

    public Task<bool> IsSuspiciousAsync(DeviceIdentity identity, DeviceOperation operation, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var history = _requestHistory.GetOrAdd(identity.CertificateBoundDeviceId, _ => []);

        lock (history)
        {
            history.RemoveAll(ts => now - ts > _window);
            history.Add(now);
            return Task.FromResult(history.Count > _maxRequestsPerWindow);
        }
    }
}
