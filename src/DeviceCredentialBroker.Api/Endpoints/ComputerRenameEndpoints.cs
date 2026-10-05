using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DeviceCredentialBroker.Api.Contracts;
using DeviceCredentialBroker.Api.Security;
using DeviceCredentialBroker.Application;
using DeviceCredentialBroker.Authentication;
using DeviceCredentialBroker.CyberArk;
using DeviceCredentialBroker.Domain;
using DeviceCredentialBroker.Graph;

namespace DeviceCredentialBroker.Api.Endpoints;

public static class ComputerRenameEndpoints
{
    public static void MapComputerRenameEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/device/operations/computer-rename")
            .RequireAuthorization("RequireClientCertificate");

        group.MapPost("/credential", HandleCredentialRequestAsync);
        group.MapPost("/result", HandleResultReportAsync);
    }

    private static async Task<IResult> HandleCredentialRequestAsync(
        HttpContext httpContext,
        IDeviceCertificateValidator certificateValidator,
        IDeviceIdentityResolver identityResolver,
        IDeviceDirectoryValidator directoryValidator,
        IDeviceOperationAuthorizationService authorizationService,
        ICredentialProvider credentialProvider,
        ICredentialLeaseStore leaseStore,
        SignedRequestAuthenticator signedRequestAuthenticator,
        ILogger<ComputerRenameLog> logger,
        CancellationToken cancellationToken)
    {
        var clientCertificate = httpContext.Connection.ClientCertificate;
        if (clientCertificate is null)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        httpContext.Request.EnableBuffering();
        using var bodyStream = new MemoryStream();
        await httpContext.Request.Body.CopyToAsync(bodyStream, cancellationToken);
        var bodyBytes = bodyStream.ToArray();
        httpContext.Request.Body.Position = 0;

        var signatureResult = await signedRequestAuthenticator.AuthenticateAsync(
            httpContext.Request, clientCertificate, clientCertificate.Thumbprint, bodyBytes, cancellationToken);
        if (!signatureResult.Success)
        {
            logger.LogWarning("Credential request rejected at signature stage: {Reason}", signatureResult.DenyReason);
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        ComputerRenameCredentialRequest? requestBody;
        try
        {
            requestBody = JsonSerializer.Deserialize<ComputerRenameCredentialRequest>(bodyBytes);
        }
        catch (JsonException)
        {
            return Results.BadRequest();
        }

        if (requestBody is null)
        {
            return Results.BadRequest();
        }

        using var chain = new X509Chain();
        var certificateValidation = certificateValidator.Validate(clientCertificate, chain);
        if (!certificateValidation.IsValid)
        {
            logger.LogWarning("DeviceCertificateRejected: {Reason}", certificateValidation.DenyReason);
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var identity = identityResolver.Resolve(
            clientCertificate, certificateValidation, requestBody.SerialNumber, requestBody.CurrentComputerName, out var identityDenyReason);
        if (identity is null)
        {
            logger.LogWarning("DeviceIdentityResolved failed: {Reason}", identityDenyReason);
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        // Anti-IDOR: the client-claimed EntraDeviceId must match the certificate-bound
        // device identity exactly — never a substring/partial match (prompt §11).
        if (requestBody.EntraDeviceId is Guid claimedId && claimedId != identity.CertificateBoundDeviceId)
        {
            logger.LogWarning("SuspiciousCredentialRequest: claimed EntraDeviceId does not match certificate-bound device id.");
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        if (!await leaseStore.TryClaimRequestIdAsync(requestBody.RequestId, cancellationToken))
        {
            // Atomic claim (not a separate check-then-issue): closes the race where two
            // concurrent requests sharing a RequestId could otherwise both pass this point
            // and both reach CyberArk (rubber-duck review finding — fail closed on either).
            logger.LogWarning("SuspiciousCredentialRequest: duplicate RequestId {RequestId}.", requestBody.RequestId);
            return Results.StatusCode(StatusCodes.Status409Conflict);
        }

        var identityWithEntraId = identity with { EntraDeviceId = identity.CertificateBoundDeviceId };

        var directoryValidation = await directoryValidator.ValidateAsync(identityWithEntraId, cancellationToken);
        if (!directoryValidation.IsValid)
        {
            logger.LogWarning("GraphDeviceValidationFailed: {Reason}", directoryValidation.DenyReason);
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var correlationId = Guid.NewGuid().ToString("D");
        var authorizationResult = await authorizationService.AuthorizeAsync(new DeviceOperationRequest
        {
            Identity = identityWithEntraId,
            DirectoryValidation = directoryValidation,
            Operation = DeviceOperation.ComputerRename,
            RequestTimestamp = requestBody.TimestampUtc,
            CorrelationId = correlationId,
            TargetComputerName = requestBody.DesiredComputerName
        }, cancellationToken);

        if (!authorizationResult.Authorized)
        {
            // Internal reason code is logged only — never returned to the client.
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var credential = await credentialProvider.GetCredentialAsync(CredentialPurpose.ComputerRename, cancellationToken);
        if (credential is null)
        {
            logger.LogWarning("CyberArkCredentialFailed for correlation {CorrelationId}.", correlationId);
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        var lease = await leaseStore.IssueAsync(
            identityWithEntraId.CertificateBoundDeviceId.ToString("D"),
            DeviceOperation.ComputerRename,
            requestBody.RequestId,
            correlationId,
            TimeSpan.FromMinutes(5),
            cancellationToken);

        logger.LogInformation("CredentialLeaseIssued: {LeaseId} for correlation {CorrelationId}.", lease.LeaseId, correlationId);

        return Results.Ok(new ComputerRenameCredentialResponse
        {
            Username = credential.Username,
            Password = credential.Password,
            ExpiresUtc = lease.ExpiresUtc,
            CredentialLeaseId = lease.LeaseId,
            CorrelationId = correlationId
        });
    }

    private static async Task<IResult> HandleResultReportAsync(
        HttpContext httpContext,
        IDeviceIdentityResolver identityResolver,
        IDeviceCertificateValidator certificateValidator,
        ICredentialLeaseStore leaseStore,
        SignedRequestAuthenticator signedRequestAuthenticator,
        ILogger<ComputerRenameLog> logger,
        CancellationToken cancellationToken)
    {
        var clientCertificate = httpContext.Connection.ClientCertificate;
        if (clientCertificate is null)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        httpContext.Request.EnableBuffering();
        using var bodyStream = new MemoryStream();
        await httpContext.Request.Body.CopyToAsync(bodyStream, cancellationToken);
        var bodyBytes = bodyStream.ToArray();
        httpContext.Request.Body.Position = 0;

        var signatureResult = await signedRequestAuthenticator.AuthenticateAsync(
            httpContext.Request, clientCertificate, clientCertificate.Thumbprint, bodyBytes, cancellationToken);
        if (!signatureResult.Success)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        ComputerRenameResultRequest? resultBody;
        try
        {
            resultBody = JsonSerializer.Deserialize<ComputerRenameResultRequest>(bodyBytes);
        }
        catch (JsonException)
        {
            return Results.BadRequest();
        }

        if (resultBody is null)
        {
            return Results.BadRequest();
        }

        using var chain = new X509Chain();
        var certificateValidation = certificateValidator.Validate(clientCertificate, chain);
        if (!certificateValidation.IsValid)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var identity = identityResolver.Resolve(clientCertificate, certificateValidation, null, null, out _);
        if (identity is null)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var succeeded = string.Equals(resultBody.Result, "Succeeded", StringComparison.OrdinalIgnoreCase);
        var marked = await leaseStore.TryMarkResultAsync(
            resultBody.CredentialLeaseId, identity.CertificateBoundDeviceId.ToString("D"), succeeded, cancellationToken);

        if (!marked)
        {
            logger.LogWarning(
                "SuspiciousCredentialRequest: result report for lease {LeaseId} did not match an issued lease for this certificate identity.",
                resultBody.CredentialLeaseId);
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        logger.LogInformation(
            succeeded ? "RenameSucceeded: lease {LeaseId}." : "RenameFailed: lease {LeaseId}.",
            resultBody.CredentialLeaseId);

        return Results.Ok();
    }
}

/// <summary>Category marker type used only to scope the logger for this endpoint group.</summary>
public sealed class ComputerRenameLog;
