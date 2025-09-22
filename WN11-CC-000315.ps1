<#
.SYNOPSIS
    This PowerShell script ensures that the Windows Installer feature 
    "Always install with elevated privileges" is disabled.

.DESCRIPTION
    Standard user accounts must not be granted elevated privileges. 
    Enabling Windows Installer to elevate privileges when installing applications 
    can allow malicious persons and applications to gain full control of a system.
    This script sets the registry value 'AlwaysInstallElevated' to 0 
    under both HKLM and HKCU.

.NOTES
    Author          : Joseph Compton
    LinkedIn        : https://www.linkedin.com/in/joseph-compton-26064766
    GitHub          : https://github.com/josephbcompton08/cybersecurity/tree/main
    Date Created    : 2025-09-22
    Last Modified   : 2025-09-22
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315
    SRG             : SRG-OS-000362-GPOS-00149
    Severity        : High
    CCI             : CCI-001812
    Vulnerability ID: V-253411

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example syntax:
    PS C:\> .\Remediate-WN11-CC-000315.ps1
# Ensures "Always install with elevated privileges" is disabled

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "AlwaysInstallElevated"
$desiredValue = 0

# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Output "Created registry path: $regPath"
}

# Set the value to 0 (Disabled)
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($null -eq $currentValue -or $currentValue -ne $desiredValue) {
    New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWord -Force | Out-Null
    Write-Output "Set $valueName to $desiredValue at $regPath"
} else {
    Write-Output "$valueName is already set to $desiredValue at $regPath"
}

# Verify
$finalValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
Write-Output "Final value of ${valueName}: $finalValue"
