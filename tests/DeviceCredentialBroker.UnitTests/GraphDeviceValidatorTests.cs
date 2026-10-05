using System.Net;
using DeviceCredentialBroker.Graph;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Graph;
using Xunit;

namespace DeviceCredentialBroker.UnitTests;

/// <summary>
/// Closes the previously-flagged coverage gap: <see cref="EntraDeviceDirectoryValidator"/> and
/// <see cref="IntuneManagedDeviceValidator"/> are now standalone classes (extracted from
/// <see cref="CompositeDeviceDirectoryValidator"/>) and can be exercised independently against a
/// fake Graph HTTP transport, without needing a real Entra ID / Intune tenant.
/// </summary>
public class GraphDeviceValidatorTests
{
    private static GraphServiceClient CreateClient(HttpStatusCode statusCode, string jsonBody)
    {
        var httpClient = new HttpClient(new FakeGraphHttpMessageHandler(statusCode, jsonBody));
        return new GraphServiceClient(httpClient, baseUrl: "https://graph.microsoft.com/v1.0");
    }

    private static readonly Guid DeviceId = Guid.NewGuid();

    // ----- EntraDeviceDirectoryValidator -----

    [Fact]
    public async Task EntraValidator_DeviceFoundAndEnabled_ReturnsResolved()
    {
        var json = $$"""
        { "value": [ { "accountEnabled": true, "deviceId": "{{DeviceId:D}}" } ] }
        """;
        var client = CreateClient(HttpStatusCode.OK, json);
        var sut = new EntraDeviceDirectoryValidator(NullLogger<EntraDeviceDirectoryValidator>.Instance);

        var result = await sut.ValidateAsync(client, DeviceId, CancellationToken.None);

        Assert.True(result.Found);
        Assert.True(result.Enabled);
        Assert.False(result.LookupError);
    }

    [Fact]
    public async Task EntraValidator_DeviceFoundButDisabled_ReturnsResolvedNotEnabled()
    {
        var json = $$"""
        { "value": [ { "accountEnabled": false, "deviceId": "{{DeviceId:D}}" } ] }
        """;
        var client = CreateClient(HttpStatusCode.OK, json);
        var sut = new EntraDeviceDirectoryValidator(NullLogger<EntraDeviceDirectoryValidator>.Instance);

        var result = await sut.ValidateAsync(client, DeviceId, CancellationToken.None);

        Assert.True(result.Found);
        Assert.False(result.Enabled);
        Assert.False(result.LookupError);
    }

    [Fact]
    public async Task EntraValidator_NoMatchingDevice_ReturnsNotFound()
    {
        var client = CreateClient(HttpStatusCode.OK, """{ "value": [] }""");
        var sut = new EntraDeviceDirectoryValidator(NullLogger<EntraDeviceDirectoryValidator>.Instance);

        var result = await sut.ValidateAsync(client, DeviceId, CancellationToken.None);

        Assert.False(result.Found);
        Assert.False(result.LookupError);
    }

    [Fact]
    public async Task EntraValidator_GraphErrorResponse_ReturnsLookupError()
    {
        var json = """{ "error": { "code": "ServiceUnavailable", "message": "boom" } }""";
        var client = CreateClient(HttpStatusCode.ServiceUnavailable, json);
        var sut = new EntraDeviceDirectoryValidator(NullLogger<EntraDeviceDirectoryValidator>.Instance);

        var result = await sut.ValidateAsync(client, DeviceId, CancellationToken.None);

        Assert.False(result.Found);
        Assert.True(result.LookupError);
    }

    // ----- IntuneManagedDeviceValidator -----

    [Fact]
    public async Task IntuneValidator_ManagedAndCompliant_ReturnsResolved()
    {
        var json = """{ "value": [ { "complianceState": "compliant" } ] }""";
        var client = CreateClient(HttpStatusCode.OK, json);
        var sut = new IntuneManagedDeviceValidator(NullLogger<IntuneManagedDeviceValidator>.Instance);

        var result = await sut.ValidateAsync(client, DeviceId, CancellationToken.None);

        Assert.True(result.Managed);
        Assert.True(result.Compliant);
        Assert.False(result.LookupError);
    }

    [Fact]
    public async Task IntuneValidator_ManagedButNonCompliant_ReturnsResolvedNotCompliant()
    {
        var json = """{ "value": [ { "complianceState": "noncompliant" } ] }""";
        var client = CreateClient(HttpStatusCode.OK, json);
        var sut = new IntuneManagedDeviceValidator(NullLogger<IntuneManagedDeviceValidator>.Instance);

        var result = await sut.ValidateAsync(client, DeviceId, CancellationToken.None);

        Assert.True(result.Managed);
        Assert.False(result.Compliant);
        Assert.False(result.LookupError);
    }

    [Fact]
    public async Task IntuneValidator_NotManaged_ReturnsNotFound()
    {
        var client = CreateClient(HttpStatusCode.OK, """{ "value": [] }""");
        var sut = new IntuneManagedDeviceValidator(NullLogger<IntuneManagedDeviceValidator>.Instance);

        var result = await sut.ValidateAsync(client, DeviceId, CancellationToken.None);

        Assert.False(result.Managed);
        Assert.False(result.LookupError);
    }

    [Fact]
    public async Task IntuneValidator_GraphErrorResponse_ReturnsLookupError()
    {
        var json = """{ "error": { "code": "ServiceUnavailable", "message": "boom" } }""";
        var client = CreateClient(HttpStatusCode.ServiceUnavailable, json);
        var sut = new IntuneManagedDeviceValidator(NullLogger<IntuneManagedDeviceValidator>.Instance);

        var result = await sut.ValidateAsync(client, DeviceId, CancellationToken.None);

        Assert.False(result.Managed);
        Assert.True(result.LookupError);
    }
}
