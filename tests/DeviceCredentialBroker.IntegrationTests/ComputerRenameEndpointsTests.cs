using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DeviceCredentialBroker.Api.Contracts;
using DeviceCredentialBroker.Authentication;
using Xunit;

namespace DeviceCredentialBroker.IntegrationTests;

public class ComputerRenameEndpointsTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;

    public ComputerRenameEndpointsTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private static Guid DeviceIdFromCertificate(X509Certificate2 cert)
    {
        // Mirrors DeviceIdentityResolver's SAN-URI extraction for use in test request bodies.
        foreach (var extension in cert.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.17")
            {
                var formatted = extension.Format(false);
                foreach (var part in formatted.Split(new[] { ", ", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var idx = part.IndexOf('=');
                    var value = idx >= 0 ? part[(idx + 1)..].Trim() : part.Trim();
                    if (value.StartsWith("urn:uuid:", StringComparison.OrdinalIgnoreCase)
                        && Guid.TryParse(value["urn:uuid:".Length..], out var guid))
                    {
                        return guid;
                    }
                }
            }
        }
        throw new InvalidOperationException("Test certificate has no SAN URI device id.");
    }

    private static HttpRequestMessage BuildSignedRequest(
        HttpMethod method, string path, X509Certificate2 signingCertificate, object body)
    {
        var bodyBytes = JsonSerializer.SerializeToUtf8Bytes(body);
        var timestamp = DateTimeOffset.UtcNow;
        var nonce = Guid.NewGuid();

        var canonical = RequestSignature.BuildCanonicalRequest(method.Method, path, timestamp, nonce, bodyBytes);
        using var rsa = signingCertificate.GetRSAPrivateKey()!;
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var request = new HttpRequestMessage(method, path)
        {
            Content = new ByteArrayContent(bodyBytes)
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.Add("X-Request-Timestamp", timestamp.ToString("o"));
        request.Headers.Add("X-Request-Nonce", nonce.ToString("D"));
        request.Headers.Add("X-Request-Signature-Version", RequestSignature.ProtocolVersion);
        request.Headers.Add("X-Request-Signature-Algorithm", RequestSignature.RsaAlgorithm);
        request.Headers.Add("X-Request-Signature", Convert.ToBase64String(signature));
        request.Headers.Add("X-Test-Client-Certificate", Convert.ToBase64String(signingCertificate.Export(X509ContentType.Cert)));

        return request;
    }

    [Fact]
    public async Task Healthz_ReturnsHealthy()
    {
        using var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        var response = await client.GetAsync("/healthz");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CredentialRequest_ValidDeviceAndClaims_IssuesCredential_AndAcceptsResultReport()
    {
        using var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        var leaf = _factory.IssuedTestCertificate.Leaf;
        var deviceId = DeviceIdFromCertificate(leaf);

        var credentialBody = new ComputerRenameCredentialRequest
        {
            EntraDeviceId = deviceId,
            SerialNumber = "SN-001",
            CurrentComputerName = "OLD-HOST",
            DesiredComputerName = "NEW-HOST",
            TimestampUtc = DateTimeOffset.UtcNow,
            RequestId = Guid.NewGuid().ToString("D")
        };

        using var credentialRequest = BuildSignedRequest(
            HttpMethod.Post, "/api/v1/device/operations/computer-rename/credential", leaf, credentialBody);
        using var credentialResponse = await client.SendAsync(credentialRequest);

        Assert.Equal(HttpStatusCode.OK, credentialResponse.StatusCode);
        var payload = await credentialResponse.Content.ReadFromJsonAsync<ComputerRenameCredentialResponse>();
        Assert.NotNull(payload);
        Assert.False(string.IsNullOrWhiteSpace(payload!.Password));

        var resultBody = new ComputerRenameResultRequest
        {
            CredentialLeaseId = payload.CredentialLeaseId,
            RequestId = Guid.NewGuid().ToString("D"),
            Result = "Succeeded",
            RebootRequired = true,
            TimestampUtc = DateTimeOffset.UtcNow
        };

        using var resultRequest = BuildSignedRequest(
            HttpMethod.Post, "/api/v1/device/operations/computer-rename/result", leaf, resultBody);
        using var resultResponse = await client.SendAsync(resultRequest);

        Assert.Equal(HttpStatusCode.OK, resultResponse.StatusCode);
    }

    [Fact]
    public async Task CredentialRequest_ClaimedEntraDeviceIdMismatchesCertificate_IsRejected()
    {
        using var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        var leaf = _factory.IssuedTestCertificate.Leaf;

        var credentialBody = new ComputerRenameCredentialRequest
        {
            EntraDeviceId = Guid.NewGuid(), // deliberately NOT the certificate-bound device id
            CurrentComputerName = "OLD-HOST",
            DesiredComputerName = "NEW-HOST",
            TimestampUtc = DateTimeOffset.UtcNow,
            RequestId = Guid.NewGuid().ToString("D")
        };

        using var credentialRequest = BuildSignedRequest(
            HttpMethod.Post, "/api/v1/device/operations/computer-rename/credential", leaf, credentialBody);
        using var credentialResponse = await client.SendAsync(credentialRequest);

        Assert.Equal(HttpStatusCode.Forbidden, credentialResponse.StatusCode);
    }

    [Fact]
    public async Task CredentialRequest_DuplicateRequestId_IsRejectedOnSecondAttempt()
    {
        using var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        var leaf = _factory.IssuedTestCertificate.Leaf;
        var deviceId = DeviceIdFromCertificate(leaf);
        var requestId = Guid.NewGuid().ToString("D");

        ComputerRenameCredentialRequest MakeBody() => new()
        {
            EntraDeviceId = deviceId,
            CurrentComputerName = "OLD-HOST",
            DesiredComputerName = "NEW-HOST",
            TimestampUtc = DateTimeOffset.UtcNow,
            RequestId = requestId
        };

        using var first = BuildSignedRequest(HttpMethod.Post, "/api/v1/device/operations/computer-rename/credential", leaf, MakeBody());
        using var firstResponse = await client.SendAsync(first);
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);

        using var second = BuildSignedRequest(HttpMethod.Post, "/api/v1/device/operations/computer-rename/credential", leaf, MakeBody());
        using var secondResponse = await client.SendAsync(second);
        Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
    }

    [Fact]
    public async Task CredentialRequest_WithoutClientCertificate_IsRejected()
    {
        using var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });

        var body = new ComputerRenameCredentialRequest
        {
            CurrentComputerName = "OLD-HOST",
            DesiredComputerName = "NEW-HOST",
            TimestampUtc = DateTimeOffset.UtcNow,
            RequestId = Guid.NewGuid().ToString("D")
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/device/operations/computer-rename/credential")
        {
            Content = JsonContent.Create(body)
        };
        // Deliberately omit X-Test-Client-Certificate and all signature headers.
        using var response = await client.SendAsync(request);

        Assert.True(
            response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized,
            $"Expected 401/403 without a client certificate, got {response.StatusCode}.");
    }
}
