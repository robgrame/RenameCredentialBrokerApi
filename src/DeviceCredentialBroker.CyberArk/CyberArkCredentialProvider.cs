using DeviceCredentialBroker.Domain;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DeviceCredentialBroker.CyberArk;

/// <summary>
/// Translates an application-level <see cref="CredentialPurpose"/> into the
/// server-configured Safe/Object/AppID and delegates to <see cref="ICyberArkClient"/>.
/// The logical operation is GetCredentialForPurpose(ComputerRename), never
/// GetCredential(accountNameReceivedFromClient) (prompt §14 — VERIFIED REQUIREMENT).
/// </summary>
public sealed class CyberArkCredentialProvider : ICredentialProvider
{
    private readonly ICyberArkClient _client;
    private readonly CyberArkOptions _options;
    private readonly ILogger<CyberArkCredentialProvider> _logger;

    public CyberArkCredentialProvider(ICyberArkClient client, IOptions<CyberArkOptions> options, ILogger<CyberArkCredentialProvider> logger)
    {
        _client = client;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<IssuedCredential?> GetCredentialAsync(CredentialPurpose purpose, CancellationToken cancellationToken)
    {
        if (!_options.PurposeMappings.TryGetValue(purpose.ToString(), out var mapping))
        {
            _logger.LogWarning("CyberArkCredentialFailed: no Safe/Object/AppID mapping configured for purpose {Purpose}.", purpose);
            return null;
        }

        var result = await _client.GetAccountCredentialAsync(mapping.Safe, mapping.Object, mapping.AppId, cancellationToken);
        if (!result.Success || result.Username is null || result.Password is null)
        {
            _logger.LogWarning("CyberArkCredentialFailed: {Reason}", result.FailureReason);
            return null;
        }

        return new IssuedCredential
        {
            Username = result.Username,
            Password = result.Password,
            ExpiresUtc = result.NextRotationUtc ?? DateTimeOffset.UtcNow.AddMinutes(15),
            CredentialLeaseId = Guid.NewGuid(),
            CorrelationId = Guid.NewGuid().ToString("D")
        };
    }
}
