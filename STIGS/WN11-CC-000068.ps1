<#
.SYNOPSIS
    This PowerShell script ensures that Windows is configured to enable 
    "Remote host allows delegation of non-exportable credentials".
.DESCRIPTION
    When credential delegation is used, exportable credentials may be exposed 
    to theft on a remote host. Restricted Admin mode or Remote Credential Guard 
    ensures only non-exportable credentials are delegated. 
    This script enforces the configuration by setting the registry value 
    "AllowProtectedCreds" to 1.
.NOTES
    Author          : Joseph Compton
    LinkedIn        : https://www.linkedin.com/in/joseph-compton-26064766
    GitHub          : https://github.com/josephbcompton08/cybersecurity/tree/main
    Date Created    : 2025-09-24
    Last Modified   : 2025-09-24
    Version         : 1.0
    STIG-ID         : WN11-CC-000068
    SRG             : SRG-OS-000480-GPOS-00227
    Severity        : Medium
    CCI             : CCI-000366
    Vulnerability ID: V-253368
#>

# STIG: WN11-CC-000068
# Ensures AllowProtectedCreds is set to 1 to enable delegation of non-exportable credentials.

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
$valueName = "AllowProtectedCreds"
$desiredValue = 1

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
