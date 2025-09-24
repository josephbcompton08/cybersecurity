<#
.SYNOPSIS
    This PowerShell script ensures Remote Desktop Services client connection 
    encryption is set to the required level (High).
.DESCRIPTION
    Remote connections must be encrypted to prevent interception of data or 
    sensitive information. This script sets the "MinEncryptionLevel" registry 
    value to 3, which enforces "High Level" encryption for Remote Desktop 
    Services sessions.
.NOTES
    Author          : Joseph Compton
    LinkedIn        : https://www.linkedin.com/in/joseph-compton-26064766
    GitHub          : https://github.com/josephbcompton08/cybersecurity/tree/main
    Date Created    : 2025-09-24
    Last Modified   : 2025-09-24
    Version         : 1.0
    STIG-ID         : WN11-CC-000290
    SRG             : SRG-OS-000033-GPOS-00014
    Severity        : Medium
    CCI             : CCI-000068
    Vulnerability ID: V-253406
#>

# STIG: WN11-CC-000290
# Ensures Remote Desktop Services encryption is set to High (MinEncryptionLevel = 3)

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "MinEncryptionLevel"
$desiredValue = 3

# Ensure registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Output "Created registry path: $regPath"
}

# Get current value if it exists
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

# Apply fix if needed
if ($null -eq $currentValue -or $currentValue -ne $desiredValue) {
    New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWord -Force | Out-Null
    Write-Output "Set $valueName to $desiredValue at $regPath"
} else {
    Write-Output "$valueName is already set to $desiredValue at $regPath"
}

# Verify final value
$finalValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
Write-Output "Final value of $valueName at $regPath : $finalValue"
