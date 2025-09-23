<#
.SYNOPSIS
    This PowerShell script ensures that Group Policy objects are reprocessed 
    even if they have not changed.

.DESCRIPTION
    Enabling this setting and selecting the "Process even if the Group Policy objects 
    have not changed" option ensures that policies are reapplied at every refresh, 
    preventing unauthorized changes from persisting.

.NOTES
    Author          : Joseph Compton
    LinkedIn        : https://www.linkedin.com/in/joseph-compton-26064766
    GitHub          : https://github.com/josephbcompton08/cybersecurity/tree/main
    Date Created    : 2025-09-22
    Last Modified   : 2025-09-22
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000090
    SRG             : SRG-OS-000480-GPOS-00227
    Severity        : Medium
    CCI             : CCI-000366
    Vulnerability ID: V-253373

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example syntax:
    PS C:\> .\Remediate-WN11-CC-000090.ps1
#>

# STIG: WN11-CC-000090
# Ensures "Process even if the Group Policy objects have not changed" is enabled

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$valueName = "NoGPOListChanges"
$desiredValue = 0

# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Output "Created registry path: $regPath"
}

# Get current value
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

# Set value if missing or incorrect
if ($null -eq $currentValue -or $currentValue -ne $desiredValue) {
    New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWord -Force | Out-Null
    Write-Output "Set $valueName to $desiredValue at $regPath"
} else {
    Write-Output "$valueName is already set to $desiredValue at $regPath"
}

# Verify
$finalValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
Write-Output "Final value of ${valueName} at $regPath: $finalValue"
