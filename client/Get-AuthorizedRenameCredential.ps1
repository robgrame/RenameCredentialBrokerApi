#Requires -Version 5.1
<#
.SYNOPSIS
    Selects the device authentication certificate, signs a DCB-SIGNATURE-V1 request, and
    requests an authorized ComputerRename credential from the Device Credential Broker.

.DESCRIPTION
    Implements the client half of prompt §19 / §3 / §11 / §12:
      1. Select a device certificate from LocalMachine\My using explicit characteristics
         (private key present, valid, correct EKU/OID) — never FriendlyName (docs/certificate-options.md).
      2. Build the DCB-SIGNATURE-V1 canonical request and sign it with the certificate's
         private key (adapted from LogCollector's RequestSigning.psm1 pattern, docs/authentication.md §3).
      3. Call the Broker's credential endpoint over mutual TLS, presenting the same certificate
         as the TLS client certificate.
      4. Convert the returned password to a SecureString/PSCredential immediately and minimize
         plaintext lifetime (docs/security.md).

    This script does not modify, and is not invoked by, Monitor-HybridJoin-RenameReboot.ps1 in
    this phase (docs/rename-integration.md) — wiring it in is a separate, explicitly-approved step.

.NOTES
    Must run in a context (typically SYSTEM) that can access the device certificate's private
    key without a UI prompt.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:DcbSignatureProtocolVersion = 'DCB-SIGNATURE-V1'
$Script:DcbSignatureAlgorithm = 'RSA-PKCS1-SHA256'
$Script:IntuneDeviceIdOid = '1.2.840.113556.5.25'
$Script:ClientAuthenticationEkuOid = '1.3.6.1.5.5.7.3.2'

function Select-DeviceAuthenticationCertificate {
    <#
    .SYNOPSIS
        Selects a candidate device certificate using explicit characteristics only
        (docs/certificate-options.md "Selection logic") — never FriendlyName.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [ValidateSet('IntuneEnrollment', 'CorporatePKI')]
        [string]$CertificateProfile = 'IntuneEnrollment',

        [string]$StoreLocation = 'LocalMachine',
        [string]$StoreName = 'My'
    )

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $StoreLocation)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try {
        $now = Get-Date
        $candidates = $store.Certificates | Where-Object {
            $_.HasPrivateKey -and
            $_.NotBefore -le $now -and
            $_.NotAfter -ge $now -and
            # Only RSA private keys are supported by the current signing implementation
            # (DCB-SIGNATURE-V1's RSA-PKCS1-SHA256 path) — an ECDSA-only certificate would
            # otherwise be silently selected and every signed request would fail locally
            # with a null-reference error (rubber-duck review finding #6).
            ($null -ne [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($_)) -and
            ($_.Extensions | Where-Object {
                $_.Oid.Value -eq '2.5.29.37' -and
                ($_.Format($false) -match [regex]::Escape($Script:ClientAuthenticationEkuOid))
            })
        }

        if ($CertificateProfile -eq 'IntuneEnrollment') {
            $candidates = $candidates | Where-Object {
                $null -ne ($_.Extensions | Where-Object { $_.Oid.Value -eq $Script:IntuneDeviceIdOid })
            }
        }

        $selected = $candidates | Sort-Object NotBefore -Descending | Select-Object -First 1

        if (-not $selected) {
            throw "No candidate RSA device certificate found for profile '$CertificateProfile' in $StoreLocation\$StoreName."
        }

        return $selected
    }
    finally {
        $store.Close()
    }
}

function New-DcbCanonicalRequest {
    <#
    .SYNOPSIS
        Builds the DCB-SIGNATURE-V1 canonical string. Must stay byte-identical with
        DeviceCredentialBroker.Authentication.RequestSignature.BuildCanonicalRequest.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]$Method,
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [datetimeoffset]$TimestampUtc,
        [Parameter(Mandatory)] [guid]$Nonce,
        [Parameter(Mandatory)] [byte[]]$BodyBytes
    )

    $normalizedPath = $Path.Trim()
    if ($normalizedPath.Length -eq 0) { $normalizedPath = '/' }
    if (-not $normalizedPath.StartsWith('/')) { $normalizedPath = "/$normalizedPath" }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bodyHash = [Convert]::ToBase64String($sha256.ComputeHash($BodyBytes))
    }
    finally {
        $sha256.Dispose()
    }

    $lines = @(
        $Script:DcbSignatureProtocolVersion
        $Method.Trim().ToUpperInvariant()
        $normalizedPath
        $TimestampUtc.ToUniversalTime().ToString('o')
        $Nonce.ToString('D').ToLowerInvariant()
        $bodyHash
    )

    return [string]::Join("`n", $lines)
}

function Get-AuthorizedRenameCredential {
    <#
    .SYNOPSIS
        Requests an authorized ComputerRename credential from the Device Credential Broker.

    .OUTPUTS
        A PSCustomObject with Credential (PSCredential), CredentialLeaseId, CorrelationId,
        ExpiresUtc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$BrokerUri,
        [Parameter(Mandatory)] [string]$DesiredComputerName,

        [ValidateSet('IntuneEnrollment', 'CorporatePKI')]
        [string]$CertificateProfile = 'IntuneEnrollment',

        [string]$CurrentComputerName = $env:COMPUTERNAME,
        [string]$SerialNumber,
        [string]$EntraDeviceId,
        [string]$IntuneDeviceId,
        [int]$TimeoutSec = 30
    )

    $certificate = Select-DeviceAuthenticationCertificate -CertificateProfile $CertificateProfile

    if (-not $SerialNumber) {
        try {
            $SerialNumber = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SerialNumber
        }
        catch {
            Write-Verbose "Unable to read BIOS serial number: $($_.Exception.Message)"
        }
    }

    $requestId = [guid]::NewGuid().ToString('D')
    $timestampUtc = [datetimeoffset]::UtcNow

    $bodyObject = [ordered]@{
        entraDeviceId       = $EntraDeviceId
        intuneDeviceId      = $IntuneDeviceId
        serialNumber        = $SerialNumber
        currentComputerName = $CurrentComputerName
        desiredComputerName = $DesiredComputerName
        timestampUtc        = $timestampUtc.ToString('o')
        requestId           = $requestId
        clientVersion       = '1.0.0'
    }

    # No BOM: must match the server's UTF8 (no-BOM) body-hash computation exactly.
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $bodyJson = $bodyObject | ConvertTo-Json -Compress
    $bodyBytes = $utf8NoBom.GetBytes($bodyJson)

    $path = '/api/v1/device/operations/computer-rename/credential'
    $nonce = [guid]::NewGuid()

    $canonical = New-DcbCanonicalRequest -Method 'POST' -Path $path -TimestampUtc $timestampUtc -Nonce $nonce -BodyBytes $bodyBytes
    $canonicalBytes = $utf8NoBom.GetBytes($canonical)

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    if (-not $rsa) {
        throw 'Selected certificate does not expose an RSA private key.'
    }

    try {
        $signatureBytes = $rsa.SignData(
            $canonicalBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
    finally {
        $rsa.Dispose()
    }

    $headers = @{
        'X-Request-Timestamp'          = $timestampUtc.ToString('o')
        'X-Request-Nonce'              = $nonce.ToString('D')
        'X-Request-Signature-Version'  = $Script:DcbSignatureProtocolVersion
        'X-Request-Signature-Algorithm' = $Script:DcbSignatureAlgorithm
        'X-Request-Signature'          = [Convert]::ToBase64String($signatureBytes)
    }

    $uri = [uri]::new(([uri]$BrokerUri), $path)

    $response = Invoke-WebRequest -Uri $uri -Method Post -Headers $headers `
        -ContentType 'application/json' -Body $bodyBytes `
        -Certificate $certificate -TimeoutSec $TimeoutSec -UseBasicParsing

    $payload = $response.Content | ConvertFrom-Json

    # Convert to SecureString/PSCredential immediately; do not retain the plaintext
    # password reference any longer than necessary (docs/security.md "Sensitive memory handling").
    $securePassword = ConvertTo-SecureString -String $payload.password -AsPlainText -Force
    $pscred = [System.Management.Automation.PSCredential]::new($payload.username, $securePassword)

    $result = [PSCustomObject]@{
        Credential         = $pscred
        CredentialLeaseId  = $payload.credentialLeaseId
        CorrelationId      = $payload.correlationId
        ExpiresUtc         = $payload.expiresUtc
    }

    # Best-effort clearing of the plaintext reference obtained from JSON deserialization.
    # Honest caveat (docs/security.md): .NET/PowerShell do not guarantee this plaintext
    # string is unreachable or zeroed in memory; this reduces, but does not eliminate, exposure.
    $payload.password = $null
    [System.GC]::Collect()

    return $result
}

function Invoke-SecureComputerRenameResult {
    <#
    .SYNOPSIS
        Reports the ComputerRename operation result to the Broker (prompt §22), authenticated
        with the same device certificate used for the credential request.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$BrokerUri,
        [Parameter(Mandatory)] [guid]$CredentialLeaseId,
        [Parameter(Mandatory)] [ValidateSet('Succeeded', 'Failed')] [string]$Result,

        [ValidateSet('IntuneEnrollment', 'CorporatePKI')]
        [string]$CertificateProfile = 'IntuneEnrollment',

        [string]$PreviousComputerName,
        [string]$RequestedComputerName,
        [Nullable[int]]$WindowsErrorCode,
        [bool]$RebootRequired,
        [int]$TimeoutSec = 30
    )

    $certificate = Select-DeviceAuthenticationCertificate -CertificateProfile $CertificateProfile

    $requestId = [guid]::NewGuid().ToString('D')
    $timestampUtc = [datetimeoffset]::UtcNow

    $bodyObject = [ordered]@{
        credentialLeaseId      = $CredentialLeaseId.ToString('D')
        requestId               = $requestId
        previousComputerName    = $PreviousComputerName
        requestedComputerName   = $RequestedComputerName
        result                  = $Result
        windowsErrorCode        = $WindowsErrorCode
        rebootRequired          = $RebootRequired
        timestampUtc            = $timestampUtc.ToString('o')
    }

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $bodyJson = $bodyObject | ConvertTo-Json -Compress
    $bodyBytes = $utf8NoBom.GetBytes($bodyJson)

    $path = '/api/v1/device/operations/computer-rename/result'
    $nonce = [guid]::NewGuid()

    $canonical = New-DcbCanonicalRequest -Method 'POST' -Path $path -TimestampUtc $timestampUtc -Nonce $nonce -BodyBytes $bodyBytes
    $canonicalBytes = $utf8NoBom.GetBytes($canonical)

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    if (-not $rsa) {
        throw 'Selected certificate does not expose an RSA private key.'
    }

    try {
        $signatureBytes = $rsa.SignData(
            $canonicalBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
    finally {
        $rsa.Dispose()
    }

    $headers = @{
        'X-Request-Timestamp'          = $timestampUtc.ToString('o')
        'X-Request-Nonce'              = $nonce.ToString('D')
        'X-Request-Signature-Version'  = $Script:DcbSignatureProtocolVersion
        'X-Request-Signature-Algorithm' = $Script:DcbSignatureAlgorithm
        'X-Request-Signature'          = [Convert]::ToBase64String($signatureBytes)
    }

    $uri = [uri]::new(([uri]$BrokerUri), $path)

    Invoke-WebRequest -Uri $uri -Method Post -Headers $headers `
        -ContentType 'application/json' -Body $bodyBytes `
        -Certificate $certificate -TimeoutSec $TimeoutSec -UseBasicParsing | Out-Null
}
