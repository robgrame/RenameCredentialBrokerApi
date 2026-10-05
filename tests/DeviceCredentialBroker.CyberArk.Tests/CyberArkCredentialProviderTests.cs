using DeviceCredentialBroker.Domain;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace DeviceCredentialBroker.CyberArk.Tests;

public class CyberArkCredentialProviderTests
{
    private sealed class RecordingCyberArkClient : ICyberArkClient
    {
        public string? SafeReceived { get; private set; }
        public string? ObjectReceived { get; private set; }
        public string? AppIdReceived { get; private set; }

        public Task<CyberArkCredentialResult> GetAccountCredentialAsync(string safe, string @object, string appId, CancellationToken cancellationToken)
        {
            SafeReceived = safe;
            ObjectReceived = @object;
            AppIdReceived = appId;
            return Task.FromResult(new CyberArkCredentialResult
            {
                Success = true,
                Username = "DOMAIN\\svc-rename",
                Password = "P@ssw0rd!",
                NextRotationUtc = DateTimeOffset.UtcNow.AddDays(1)
            });
        }
    }

    private static CyberArkOptions CreateOptionsWithMapping() => new()
    {
        PurposeMappings = new Dictionary<string, CyberArkPurposeMapping>
        {
            [CredentialPurpose.ComputerRename.ToString()] = new CyberArkPurposeMapping
            {
                Safe = "RenameSafe",
                Object = "RenameServiceAccount",
                AppId = "DeviceCredentialBroker"
            }
        }
    };

    [Fact]
    public async Task GetCredentialAsync_ConfiguredPurpose_ReturnsCredentialFromServerSideMapping()
    {
        var client = new RecordingCyberArkClient();
        var provider = new CyberArkCredentialProvider(
            client, Options.Create(CreateOptionsWithMapping()), NullLogger<CyberArkCredentialProvider>.Instance);

        var credential = await provider.GetCredentialAsync(CredentialPurpose.ComputerRename, CancellationToken.None);

        Assert.NotNull(credential);
        Assert.Equal("DOMAIN\\svc-rename", credential!.Username);
        // The Safe/Object/AppID values came entirely from server-side configuration —
        // ICredentialProvider.GetCredentialAsync has no parameter through which a client
        // could ever supply/select them (prompt §9, §14 — structural anti-IDOR control).
        Assert.Equal("RenameSafe", client.SafeReceived);
        Assert.Equal("RenameServiceAccount", client.ObjectReceived);
        Assert.Equal("DeviceCredentialBroker", client.AppIdReceived);
    }

    [Fact]
    public async Task GetCredentialAsync_NoMappingConfiguredForPurpose_FailsClosed()
    {
        var client = new RecordingCyberArkClient();
        var provider = new CyberArkCredentialProvider(
            client, Options.Create(new CyberArkOptions()), NullLogger<CyberArkCredentialProvider>.Instance);

        var credential = await provider.GetCredentialAsync(CredentialPurpose.ComputerRename, CancellationToken.None);

        Assert.Null(credential);
    }

    [Fact]
    public async Task GetCredentialAsync_NotConfiguredClient_FailsClosed()
    {
        var provider = new CyberArkCredentialProvider(
            new NotConfiguredCyberArkClient(), Options.Create(CreateOptionsWithMapping()), NullLogger<CyberArkCredentialProvider>.Instance);

        var credential = await provider.GetCredentialAsync(CredentialPurpose.ComputerRename, CancellationToken.None);

        Assert.Null(credential);
    }

    [Fact]
    public async Task GetCredentialAsync_MockClient_ReturnsFixedFakeCredential()
    {
        var provider = new CyberArkCredentialProvider(
            new MockCyberArkClient(), Options.Create(CreateOptionsWithMapping()), NullLogger<CyberArkCredentialProvider>.Instance);

        var credential = await provider.GetCredentialAsync(CredentialPurpose.ComputerRename, CancellationToken.None);

        Assert.NotNull(credential);
        Assert.Equal("CONTOSO\\mock-rename-svc", credential!.Username);
    }
}
