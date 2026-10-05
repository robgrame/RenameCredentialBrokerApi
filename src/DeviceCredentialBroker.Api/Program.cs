using DeviceCredentialBroker.Api.Endpoints;
using DeviceCredentialBroker.Api.Security;
using DeviceCredentialBroker.Application;
using DeviceCredentialBroker.Authentication;
using DeviceCredentialBroker.CyberArk;
using DeviceCredentialBroker.Graph;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Structured audit logging (Serilog) — every security decision is logged with a
// correlation id, device identity, and outcome. Passwords/secrets are NEVER logged
// (docs/security.md "Logging and telemetry").
builder.Host.UseSerilog((context, services, configuration) =>
    configuration.ReadFrom.Configuration(context.Configuration));

// --- mTLS: require the client certificate at the Kestrel level (prompt §5) ---
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
    });
});

builder.Services.AddOptions<DeviceCertificateOptions>()
    .Bind(builder.Configuration.GetSection(DeviceCertificateOptions.SectionName));
builder.Services.AddOptions<DeviceValidationOptions>()
    .Bind(builder.Configuration.GetSection(DeviceValidationOptions.SectionName));
builder.Services.AddOptions<CyberArkOptions>()
    .Bind(builder.Configuration.GetSection(CyberArkOptions.SectionName));

builder.Services.AddSingleton<IDeviceCertificateValidator, DeviceCertificateValidator>();
builder.Services.AddSingleton<IDeviceIdentityResolver, DeviceIdentityResolver>();
builder.Services.AddSingleton<IReplayNonceStore, InMemoryReplayNonceStore>();
builder.Services.AddSingleton(sp => new ReplayProtector(sp.GetRequiredService<IReplayNonceStore>()));
builder.Services.AddSingleton<SignedRequestAuthenticator>();

builder.Services.AddSingleton<IGraphClientFactory>(_ => new ManagedIdentityGraphClientFactory(
    builder.Configuration["Graph:ManagedIdentityClientId"]));
builder.Services.AddSingleton<EntraDeviceDirectoryValidator>();
builder.Services.AddSingleton<IntuneManagedDeviceValidator>();
builder.Services.AddSingleton<IDeviceDirectoryValidator, CompositeDeviceDirectoryValidator>();

builder.Services.AddSingleton<IAbuseDetector, InMemoryAbuseDetector>();
builder.Services.AddSingleton<IDeviceOperationAuthorizationService, DeviceOperationAuthorizationService>();
// NOTE: single-instance, dev/pilot scope only (same OPEN DECISION as IReplayNonceStore
// above) — a scaled-out/production deployment needs a durable, shared backing store so
// replay/duplicate/lease state is consistent across instances and restarts.
builder.Services.AddSingleton<ICredentialLeaseStore, InMemoryCredentialLeaseStore>();

// Fail-closed default: no production CyberArk connector exists until the interface and
// authentication mechanism are confirmed with the customer (docs/cyberark-integration.md,
// ADR 0004). Replace with a real ICyberArkClient implementation once confirmed.
builder.Services.AddSingleton<ICyberArkClient, NotConfiguredCyberArkClient>();
builder.Services.AddSingleton<ICredentialProvider, CyberArkCredentialProvider>();

var checkRevocation = builder.Configuration.GetValue("DeviceCertificate:CheckRevocation", true);
var revocationMode = checkRevocation
    ? System.Security.Cryptography.X509Certificates.X509RevocationMode.Online
    : System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;

// Azure App Service terminates TLS at its front end and forwards the client certificate
// via the X-ARR-ClientCert header rather than a real Kestrel TLS handshake — without this,
// HttpContext.Connection.ClientCertificate is always null when hosted there, silently
// failing every request (rubber-duck review finding). Only trust that header when actually
// running behind the App Service front end (WEBSITE_INSTANCE_ID is set exclusively in that
// environment); never trust a client-suppliable header when self-hosting Kestrel directly.
var behindAppServiceProxy = builder.Configuration.GetValue(
    "Hosting:BehindAppServiceProxy",
    !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID")));

if (behindAppServiceProxy)
{
    builder.Services.AddCertificateForwarding(options =>
    {
        options.CertificateHeader = "X-ARR-ClientCert";
        options.HeaderConverter = headerValue =>
            string.IsNullOrEmpty(headerValue)
                ? null!
                : System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(Convert.FromBase64String(headerValue));
    });
}

builder.Services
    .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.Chained;
        options.RevocationMode = revocationMode;
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                // Full profile/claims validation happens again, in detail, inside each
                // endpoint handler (IDeviceCertificateValidator) — this gate only
                // ensures *some* chained, non-expired client certificate was presented
                // before the request reaches authorization middleware at all.
                context.Success();
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                Log.Warning("mTLS authentication failed: {Reason}", context.Exception.Message);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireClientCertificate", policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(CertificateAuthenticationDefaults.AuthenticationScheme));
});

builder.Services.AddOpenApi();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

if (behindAppServiceProxy)
{
    app.UseCertificateForwarding();
}

// Test-only hook: WebApplicationFactory/TestServer never performs a real TLS handshake,
// so integration tests inject the client certificate via a header instead. Active only
// under the "Testing" environment — never reachable in Development/Staging/Production.
if (app.Environment.IsEnvironment("Testing"))
{
    app.Use(async (context, next) =>
    {
        var header = context.Request.Headers["X-Test-Client-Certificate"].ToString();
        if (!string.IsNullOrEmpty(header))
        {
            context.Connection.ClientCertificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(
                Convert.FromBase64String(header));
        }
        await next();
    });
}

app.UseAuthentication();
app.UseAuthorization();

app.MapComputerRenameEndpoints();

app.MapGet("/healthz", () => Results.Ok(new { status = "healthy" })).AllowAnonymous();

app.Run();

// Exposed for WebApplicationFactory-based integration tests.
public partial class Program;
