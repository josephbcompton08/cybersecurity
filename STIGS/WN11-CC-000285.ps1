<#
.SYNOPSIS
    This PowerShell script ensures that Remote Desktop Session Host requires secure RPC communication.

.DESCRIPTION
    Allowing unsecure RPC communication exposes systems to man-in-the-middle and data disclosure attacks.
    This script enforces the registry setting to require secure RPC traffic by setting 
    "fEncryptRPCTraffic" to 1.

.NOTES
    Author          : Joseph Compton
    LinkedIn        : https://www.linkedin.com/in/joseph-compton-26064766
    GitHub          : https://github.com/josephbcompton08/cybersecurity/tree/main
    Date Created    : 2025-09-22
    Last Modified   : 2025-09-22
    Version         : 1.0
    STIG-ID         : WN11-CC-000285
    SRG             : SRG-OS-000250-GPOS-00093
    Severity        : Medium
    CCI             : CCI-001453
    Vulnerability ID: V-253405
#>

# STIG: WN11-CC-000285
# Ensures "Require secure RPC communication" is enabled by setting fEncryptRPCTraffic = 1

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "fEncryptRPCTraffic"
$desiredValue = 1

if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Output "Created registry path: $regPath"
}

$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($null -eq $currentValue -or $currentValue -ne $desiredValue) {
    New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWord -Force | Out-Null
    Write-Output "Set $valueName to $desiredValue at $regPath"
} else {
    Write-Output "$valueName is already set to $desiredValue at $regPath"
}

$finalValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
Write-Output "Final value of $valueName at $regPath : $finalValue"

