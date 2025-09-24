<#
.SYNOPSIS
    This PowerShell script ensures that local accounts are configured to require password expiration.
.DESCRIPTION
    Accounts configured with "Password never expires" increase the risk of compromised credentials.
    This script checks all local accounts and clears the "Password never expires" flag if set,
    ensuring compliance with Windows STIG requirements.
.NOTES
    Author          : Joseph Compton
    LinkedIn        : https://www.linkedin.com/in/joseph-compton-26064766
    GitHub          : https://github.com/josephbcompton08/cybersecurity/tree/main
    Date Created    : 2025-09-24
    Last Modified   : 2025-09-24
    Version         : 1.0
    STIG-ID         : WN11-00-000090
    SRG             : SRG-OS-000076-GPOS-00044
    Severity        : Medium
    CCI             : CCI-004066
    Vulnerability ID: V-253273
#>

# STIG: WN11-00-000090
# Ensures all local accounts are configured to require password expiration.

# Import module for local accounts (native to Windows 10/11)
Import-Module Microsoft.PowerShell.LocalAccounts

Write-Output "Checking local user accounts for 'Password never expires' setting..."

# Get all local users
$users = Get-LocalUser

foreach ($user in $users) {
    if ($user.Enabled -eq $true) {
        if ($user.PasswordNeverExpires -eq $true) {
            Write-Output "[$($user.Name)] has 'Password never expires' enabled. Fixing..."
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
        }
        else {
            Write-Output "[$($user.Name)] already compliant."
        }
    } else {
        Write-Output "[$($user.Name)] is disabled, skipping."
    }
}

Write-Output "Password expiration policy has been enforced for all active local accounts."
