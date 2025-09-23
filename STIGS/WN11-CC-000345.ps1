<#
.SYNOPSIS
    This PowerShell script ensures that WinRM Basic authentication is disabled.
.DESCRIPTION
    Basic authentication uses plain text passwords that could be used to compromise a system.
    To prevent this security vulnerability, the registry setting 
    "AllowBasic" must be set to 0 to disable Basic authentication for WinRM.
.NOTES
    Author          : Joseph Compton
    LinkedIn        : https://www.linkedin.com/in/joseph-compton-26064766
    GitHub          : https://github.com/josephbcompton08/cybersecurity/tree/main
    Date Created    : 2025-09-23
    Last Modified   : 2025-09-23
    Version         : 1.0
    STIG-ID         : WN11-CC-000345
    SRG             : SRG-OS-000125-GPOS-00065
    Severity        : High
    CCI             : CCI-000877
    Vulnerability ID: V-253418
#>

# STIG: WN11-CC-000345
# Ensures WinRM Basic authentication is disabled by setting AllowBasic = 0
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$valueName = "AllowBasic"
$desiredValue = 0

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
