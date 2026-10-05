#Requires -Version 5.1
<#
.SYNOPSIS
    Orchestrates an authorized, broker-mediated Windows computer rename (prompt §19).

.DESCRIPTION
    Conceptual flow:
      Get machine certificate → Authenticate Broker → Request ComputerRename credential
      → Receive credential → Immediately create SecureString → Create PSCredential
      → Call Rename-Computer → Dispose/remove all credential references → Report result.

    This script is the intended eventual call site for the existing
    Monitor-HybridJoin-RenameReboot.ps1 script's SYSTEM-context rename step, but wiring that in
    is explicitly out of scope for this phase (docs/rename-integration.md) — this script is
    self-contained and can be invoked/tested independently.

    Does not rewrite: Hybrid Join detection, Event ID detection, hostname retrieval,
    scheduled-task architecture, user notification, existing reboot workflow (prompt §19).

.PARAMETER BrokerUri
    Base URI of the Device Credential Broker, e.g. https://broker.contoso.com

.PARAMETER NewComputerName
    The desired new computer name.

.PARAMETER CertificateProfile
    Which IDeviceCertificateValidator profile the device certificate was issued under.

.EXAMPLE
    .\Invoke-SecureComputerRename.ps1 -BrokerUri 'https://broker.contoso.com' -NewComputerName 'NEW-HOST01'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$BrokerUri,
    [Parameter(Mandatory)] [string]$NewComputerName,

    [ValidateSet('IntuneEnrollment', 'CorporatePKI')]
    [string]$CertificateProfile = 'IntuneEnrollment',

    [string]$EntraDeviceId,
    [string]$IntuneDeviceId,
    [string]$SerialNumber,
    [switch]$Restart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Get-AuthorizedRenameCredential.ps1')

$previousComputerName = $env:COMPUTERNAME
$leaseResult = $null
$credential = $null

try {
    Write-Verbose "Requesting authorized ComputerRename credential for '$previousComputerName' -> '$NewComputerName'."

    $leaseResult = Get-AuthorizedRenameCredential `
        -BrokerUri $BrokerUri `
        -DesiredComputerName $NewComputerName `
        -CurrentComputerName $previousComputerName `
        -CertificateProfile $CertificateProfile `
        -EntraDeviceId $EntraDeviceId `
        -IntuneDeviceId $IntuneDeviceId `
        -SerialNumber $SerialNumber

    $credential = $leaseResult.Credential

    if ($PSCmdlet.ShouldProcess($previousComputerName, "Rename-Computer -NewName $NewComputerName")) {
        Rename-Computer -NewName $NewComputerName -DomainCredential $credential -Force -ErrorAction Stop

        Invoke-SecureComputerRenameResult `
            -BrokerUri $BrokerUri `
            -CredentialLeaseId $leaseResult.CredentialLeaseId `
            -CertificateProfile $CertificateProfile `
            -Result 'Succeeded' `
            -PreviousComputerName $previousComputerName `
            -RequestedComputerName $NewComputerName `
            -RebootRequired:$true

        Write-Output "Computer rename succeeded: '$previousComputerName' -> '$NewComputerName'. A restart is required to complete the rename."

        if ($Restart) {
            Restart-Computer -Force
        }
    }
}
catch {
    $windowsErrorCode = $null
    if ($_.Exception.PSObject.Properties.Match('NativeErrorCode').Count -gt 0) {
        $windowsErrorCode = $_.Exception.NativeErrorCode
    }

    if ($leaseResult) {
        try {
            Invoke-SecureComputerRenameResult `
                -BrokerUri $BrokerUri `
                -CredentialLeaseId $leaseResult.CredentialLeaseId `
                -CertificateProfile $CertificateProfile `
                -Result 'Failed' `
                -PreviousComputerName $previousComputerName `
                -RequestedComputerName $NewComputerName `
                -WindowsErrorCode $windowsErrorCode `
                -RebootRequired:$false
        }
        catch {
            Write-Warning "Failed to report rename failure to the Broker: $($_.Exception.Message)"
        }
    }

    throw
}
finally {
    # Minimize credential lifetime (docs/security.md "Sensitive memory handling"): drop all
    # references as soon as the rename attempt (success or failure) has been reported.
    if ($credential) {
        Remove-Variable -Name credential -ErrorAction SilentlyContinue
    }
    if ($leaseResult) {
        Remove-Variable -Name leaseResult -ErrorAction SilentlyContinue
    }
    [System.GC]::Collect()
}
