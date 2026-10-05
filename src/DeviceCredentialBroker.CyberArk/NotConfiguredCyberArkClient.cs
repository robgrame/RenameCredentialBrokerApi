namespace DeviceCredentialBroker.CyberArk;

/// <summary>
/// Fail-closed default <see cref="ICyberArkClient"/>. Mirrors the
/// NotConfiguredServiceAccountCredentialProvider pattern already used in the
/// RenameApiService project: calling it always denies, so an incomplete deployment
/// fails closed instead of behaving unpredictably. This is the default registration
/// until ADR 0004 (CyberArk interface/auth mechanism) is resolved with the customer.
/// </summary>
public sealed class NotConfiguredCyberArkClient : ICyberArkClient
{
    public Task<CyberArkCredentialResult> GetAccountCredentialAsync(
        string safe, string @object, string appId, CancellationToken cancellationToken) =>
        Task.FromResult(CyberArkCredentialResult.Failure(
            "CyberArk integration is not configured. See docs/cyberark-integration.md and ADR 0004 " +
            "— the CyberArk interface and authentication mechanism must be confirmed with the " +
            "customer before a production connector can be implemented."));
}

/// <summary>
/// Test-only mock. Returns a fixed, clearly-fake credential and never calls any
/// network endpoint — used in unit/integration tests only (prompt §15, §34).
/// </summary>
public sealed class MockCyberArkClient : ICyberArkClient
{
    public Task<CyberArkCredentialResult> GetAccountCredentialAsync(
        string safe, string @object, string appId, CancellationToken cancellationToken) =>
        Task.FromResult(new CyberArkCredentialResult
        {
            Success = true,
            Username = "CONTOSO\\mock-rename-svc",
            Password = "mock-password-for-tests-only",
            NextRotationUtc = DateTimeOffset.UtcNow.AddDays(30)
        });
}
