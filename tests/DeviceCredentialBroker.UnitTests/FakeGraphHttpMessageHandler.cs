using System.Net;
using System.Text;

namespace DeviceCredentialBroker.UnitTests;

/// <summary>
/// Minimal fake transport for Graph SDK tests. Returns a canned JSON body (or a non-2xx status)
/// for every request, regardless of URL, which is sufficient because each test only ever issues
/// a single Graph call (Devices.GetAsync or ManagedDevices.GetAsync).
/// </summary>
internal sealed class FakeGraphHttpMessageHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _statusCode;
    private readonly string _jsonBody;

    public FakeGraphHttpMessageHandler(HttpStatusCode statusCode, string jsonBody)
    {
        _statusCode = statusCode;
        _jsonBody = jsonBody;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = new HttpResponseMessage(_statusCode)
        {
            Content = new StringContent(_jsonBody, Encoding.UTF8, "application/json")
        };
        return Task.FromResult(response);
    }
}
