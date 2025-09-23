<#
.SYNOPSIS
    This PowerShell script ensures that Microsoft consumer experiences are turned off.

.DESCRIPTION
    Microsoft consumer experiences can install suggested apps and display notifications to users.
    To prevent unwanted applications and suggestions, the registry setting 
    "DisableWindowsConsumerFeatures" must be set to 1.

.NOTES
    Author          : Joseph Compton
    LinkedIn        : https://www.linkedin.com/in/joseph-compton-26064766
    GitHub          : https://github.com/josephbcompton08/cybersecurity/tree/main
    Date Created    : 2025-09-22
    Last Modified   : 2025-09-22
    Version         : 1.0
    STIG-ID         : WN11-CC-000197
    SRG             : SRG-OS-000095-GPOS-00049
    Severity        : Low
    CCI             : CCI-000381
    Vulnerability ID: V-253390
#>

# STIG: WN11-CC-000197
# Ensures "Turn off Microsoft consumer experiences" is enabled by setting DisableWindowsConsumerFeatures = 1

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$valueName = "DisableWindowsConsumerFeatures"
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
