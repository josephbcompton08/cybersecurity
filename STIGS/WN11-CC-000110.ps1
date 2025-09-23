<#
.SYNOPSIS
    This PowerShell script ensures that printing over HTTP is disabled.

.DESCRIPTION
    Prevents client computers from printing over HTTP, which can allow communication 
    with printers on the intranet and the internet. Disabling this feature helps 
    protect against sensitive information leakage and uncontrolled updates.

.NOTES
    Author          : Joseph Compton
    LinkedIn        : https://www.linkedin.com/in/joseph-compton-26064766
    GitHub          : https://github.com/josephbcompton08/cybersecurity/tree/main
    Date Created    : 2025-09-22
    Last Modified   : 2025-09-22
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000110
    SRG             : SRG-OS-000095-GPOS-00049
    Severity        : Medium
    CCI             : CCI-000381
    Vulnerability ID: V-253376

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example syntax:
    PS C:\> .\Remediate-WN11-CC-000110.ps1
#>

# STIG: WN11-CC-000110
# Ensures "Turn off printing over HTTP" is enabled

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableHTTPPrinting"
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
Write-Output "Final value of ${valueName} at $regPath: $finalValue"
