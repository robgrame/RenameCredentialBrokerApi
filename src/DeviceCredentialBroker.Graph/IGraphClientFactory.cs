using Azure.Core;
using Azure.Identity;
using Microsoft.Graph;

namespace DeviceCredentialBroker.Graph;

/// <summary>
/// Creates a Graph client authenticated via Managed Identity only — no client secret
/// (prompt §8, §26 — VERIFIED REQUIREMENT).
/// </summary>
public interface IGraphClientFactory
{
    GraphServiceClient CreateClient();
}

public sealed class ManagedIdentityGraphClientFactory : IGraphClientFactory
{
    private readonly GraphServiceClient _client;

    public ManagedIdentityGraphClientFactory(string? managedIdentityClientId = null)
    {
        TokenCredential credential = managedIdentityClientId is null
            ? new DefaultAzureCredential()
            : new ManagedIdentityCredential(managedIdentityClientId);

        var scopes = new[] { "https://graph.microsoft.com/.default" };
        _client = new GraphServiceClient(credential, scopes);
    }

    public GraphServiceClient CreateClient() => _client;
}
