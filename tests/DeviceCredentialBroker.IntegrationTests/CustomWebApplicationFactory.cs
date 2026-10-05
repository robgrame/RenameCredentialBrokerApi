using DeviceCredentialBroker.Authentication;
using DeviceCredentialBroker.CyberArk;
using DeviceCredentialBroker.Domain;
using DeviceCredentialBroker.Graph;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DeviceCredentialBroker.IntegrationTests;

/// <summary>
/// Always-valid directory validator used in integration tests so the credential/result
/// pipeline can be exercised end to end without a live Microsoft Graph dependency. Never
/// used outside the "Testing" environment.
/// </summary>
internal sealed class AlwaysValidDeviceDirectoryValidator : IDeviceDirectoryValidator
{
    public Task<DeviceDirectoryValidationResult> ValidateAsync(DeviceIdentity identity, CancellationToken cancellationToken) =>
        Task.FromResult(new DeviceDirectoryValidationResult
        {
            IsValid = true,
            EntraDeviceFound = true,
            EntraDeviceEnabled = true,
            IntuneManaged = true,
            IntuneCompliant = true
        });
}

public sealed class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    public X509Certificate2Pair IssuedTestCertificate { get; }

    public CustomWebApplicationFactory()
    {
        IssuedTestCertificate = new X509Certificate2Pair(TestCertificateFactory.CreateChain(Guid.NewGuid()));

        // In production the corporate-PKI root/intermediate is deployed to the machine's
        // certificate stores (e.g. via GPO), so X509Chain.Build can always locate it as a
        // candidate issuer even though trust is decided explicitly by DeviceCertificateValidator's
        // thumbprint/subject allow-list. Tests reproduce that same precondition by installing the
        // generated test root into the current user's intermediate-CA store for the test's
        // lifetime, instead of weakening production chain-building logic.
        using var store = new System.Security.Cryptography.X509Certificates.X509Store(
            System.Security.Cryptography.X509Certificates.StoreName.CertificateAuthority,
            System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
        store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
        store.Add(IssuedTestCertificate.Root);
    }

    protected override void Dispose(bool disposing)
    {
        using (var store = new System.Security.Cryptography.X509Certificates.X509Store(
            System.Security.Cryptography.X509Certificates.StoreName.CertificateAuthority,
            System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser))
        {
            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
            store.Remove(IssuedTestCertificate.Root);
        }

        base.Dispose(disposing);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, configBuilder) =>
        {
            configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DeviceCertificate:ActiveProfile"] = "CorporatePKI",
                ["DeviceCertificate:CorporatePKI:TrustedRootThumbprints:0"] = IssuedTestCertificate.Root.Thumbprint,
                ["DeviceCertificate:CorporatePKI:CheckRevocation"] = "false",
                ["CyberArk:PurposeMappings:ComputerRename:Safe"] = "TestSafe",
                ["CyberArk:PurposeMappings:ComputerRename:Object"] = "TestObject",
                ["CyberArk:PurposeMappings:ComputerRename:AppId"] = "TestAppId"
            });
        });

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IDeviceDirectoryValidator>();
            services.AddSingleton<IDeviceDirectoryValidator, AlwaysValidDeviceDirectoryValidator>();

            services.RemoveAll<ICyberArkClient>();
            services.AddSingleton<ICyberArkClient, MockCyberArkClient>();

            // The built-in certificate authentication handler independently validates
            // chain trust before DeviceCertificateValidator ever runs. The test root is
            // not (and must never become) a Windows-trusted root, so tests explicitly
            // scope trust to the generated test root only, for this handler instance.
            services.Configure<Microsoft.AspNetCore.Authentication.Certificate.CertificateAuthenticationOptions>(
                Microsoft.AspNetCore.Authentication.Certificate.CertificateAuthenticationDefaults.AuthenticationScheme,
                options =>
                {
                    options.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                    options.ChainTrustValidationMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
                    options.CustomTrustStore = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection(
                        IssuedTestCertificate.Root);
                });
        });
    }
}

/// <summary>Small wrapper so the factory can expose both halves of the generated test chain.</summary>
public sealed class X509Certificate2Pair
{
    public System.Security.Cryptography.X509Certificates.X509Certificate2 Root { get; }
    public System.Security.Cryptography.X509Certificates.X509Certificate2 Leaf { get; }

    public X509Certificate2Pair((System.Security.Cryptography.X509Certificates.X509Certificate2 Root, System.Security.Cryptography.X509Certificates.X509Certificate2 Leaf) pair)
    {
        Root = pair.Root;
        Leaf = pair.Leaf;
    }
}
