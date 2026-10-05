using System.Reflection;
using DeviceCredentialBroker.Domain;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace DeviceCredentialBroker.Security.Tests;

/// <summary>
/// Cross-cutting security invariants from prompt §31 "Security" test matrix. These are
/// intentionally structural/behavioral checks that do not belong to any single project.
/// </summary>
public class SecurityInvariantTests
{
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }

    [Fact]
    public async Task CyberArkCredentialProvider_NeverLogsThePassword()
    {
        var logger = new CapturingLogger<CyberArk.CyberArkCredentialProvider>();
        var options = Options.Create(new CyberArk.CyberArkOptions
        {
            PurposeMappings = new Dictionary<string, CyberArk.CyberArkPurposeMapping>
            {
                [CredentialPurpose.ComputerRename.ToString()] = new() { Safe = "S", Object = "O", AppId = "A" }
            }
        });

        const string secretPassword = "Sup3rSecretValue!!";
        var client = new FixedPasswordCyberArkClient(secretPassword);
        var provider = new CyberArk.CyberArkCredentialProvider(client, options, logger);

        var credential = await provider.GetCredentialAsync(CredentialPurpose.ComputerRename, CancellationToken.None);

        Assert.NotNull(credential);
        Assert.Equal(secretPassword, credential!.Password);
        Assert.DoesNotContain(logger.Messages, m => m.Contains(secretPassword));
    }

    private sealed class FixedPasswordCyberArkClient(string password) : CyberArk.ICyberArkClient
    {
        public Task<CyberArk.CyberArkCredentialResult> GetAccountCredentialAsync(string safe, string @object, string appId, CancellationToken cancellationToken) =>
            Task.FromResult(new CyberArk.CyberArkCredentialResult
            {
                Success = true,
                Username = "DOMAIN\\svc",
                Password = password,
                NextRotationUtc = DateTimeOffset.UtcNow.AddDays(1)
            });
    }

    [Fact]
    public void ICredentialProvider_HasNoClientSelectableAccountParameter()
    {
        // Structural anti-enumeration control (prompt §9, §14): the only input the
        // application layer can pass is the CredentialPurpose enum — there must be no
        // overload or parameter allowing a Safe/Object/AppID/account name to be supplied.
        var method = typeof(CyberArk.ICredentialProvider).GetMethod(nameof(CyberArk.ICredentialProvider.GetCredentialAsync))!;
        var parameters = method.GetParameters();

        Assert.Equal(2, parameters.Length);
        Assert.Equal(typeof(CredentialPurpose), parameters[0].ParameterType);
        Assert.Equal(typeof(CancellationToken), parameters[1].ParameterType);
    }

    [Fact]
    public void CyberArkOptions_PurposeMappingsAreServerSideConfigurationOnly()
    {
        // The mapping type carries no field that could be populated from an inbound
        // HTTP request model (no [FromBody]/JSON-request coupling) — it is a plain
        // configuration-bound POCO (prompt §13, §14).
        var mappingProperties = typeof(CyberArk.CyberArkPurposeMapping)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .OrderBy(n => n)
            .ToArray();

        Assert.Equal(["AppId", "Object", "Safe"], mappingProperties);
    }

    [Fact]
    public async Task DeviceOperationAuthorizationService_DoesNotAuthorizeUnsupportedOperations()
    {
        var service = new Application.DeviceOperationAuthorizationService(
            new AlwaysAllowAbuseDetector(), Microsoft.Extensions.Logging.Abstractions.NullLogger<Application.DeviceOperationAuthorizationService>.Instance);

        var request = new Application.DeviceOperationRequest
        {
            Identity = new DeviceIdentity
            {
                CertificateSubject = "CN=x",
                CertificateIssuer = "CN=y",
                CertificateThumbprintHash = "hash",
                CertificateBoundDeviceId = Guid.NewGuid(),
                TrustProfile = CertificateTrustProfile.CorporatePKI
            },
            DirectoryValidation = new DeviceDirectoryValidationResult { IsValid = true },
            Operation = (DeviceOperation)999, // not a real supported operation
            RequestTimestamp = DateTimeOffset.UtcNow,
            CorrelationId = "corr"
        };

        var result = await service.AuthorizeAsync(request, CancellationToken.None);

        Assert.False(result.Authorized);
    }

    private sealed class AlwaysAllowAbuseDetector : Application.IAbuseDetector
    {
        public Task<bool> IsSuspiciousAsync(DeviceIdentity identity, DeviceOperation operation, CancellationToken cancellationToken) =>
            Task.FromResult(false);
    }
}
