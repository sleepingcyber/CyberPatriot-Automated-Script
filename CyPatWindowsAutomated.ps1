<#TODO: 
Disable weak services, 
enable auto updates, 
disable remote desktop, 
malwarebytes spot check, 
system integrity scan, 
enable firewall, 
check file and folder owner permissions
#>

#from:https://stackoverflow.com/questions/55774478/enforce-password-complexity-on-windows-using-powershell
#https://www.youtube.com/watch?v=iIIGhS3oAs0
Function Parse-SecPol($CfgFile){ 
    secedit /export /cfg "$CfgFile" | out-null
    $obj = New-Object psobject
    $index = 0
    $contents = Get-Content $CfgFile -raw
    [regex]::Matches($contents,"(?<=\[)(.*)(?=\])") | %{
        $title = $_
        [regex]::Matches($contents,"(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | %{
            $section = new-object psobject
            $_.value -split "\r\n" | ?{$_.length -gt 0} | %{
                $value = [regex]::Match($_,"(?<=\=).*").value
                $name = [regex]::Match($_,".*(?=\=)").value
                $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
            }
            $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
        }
        $index += 1
    }
    return $obj
}

Function Set-SecPol($Object, $CfgFile){
   $SecPool.psobject.Properties.GetEnumerator() | %{
        "[$($_.Name)]"
        $_.Value | %{
            $_.psobject.Properties.GetEnumerator() | %{
                "$($_.Name)=$($_.Value)"
            }
        }
    } | out-file $CfgFile -ErrorAction Stop
    secedit /configure /db c:\windows\security\local.sdb /cfg "$CfgFile" /areas SECURITYPOLICY
}

$CfgFileName = Read-Host "enter filename to save"
$SecPool = Parse-SecPol -CfgFile $CfgFileName
#Password Policy editing
$SecPool.'System Access'.PasswordComplexity = 1
$SecPool.'System Access'.MinimumPasswordLength = 8
$SecPool.'System Access'.MinimumPasswordAge = 5
$SecPool.'System Access'.MaximumPasswordAge = 90
$SecPool.'System Access'.PasswordHistorySize = 5
$SecPool.'System Access'.ClearTextPassword = 0
Write-Output "Password Policies edited"
#Account Lockout Policy editing
$SecPool.'System Access'.LockoutBadCount = 5
Write-Output "Account lockout policies edited"
#Audit Policy editing
$SecPool.'Event Audit'.AuditSystemEvents = 3
$SecPool.'Event Audit'.AuditLogonEvents = 3
$SecPool.'Event Audit'.AuditPrivilegeUse = 3
$SecPool.'Event Audit'.AuditPolicyChange = 3
$SecPool.'Event Audit'.AuditAccountManage = 2
$SecPool.'Event Audit'.AuditAccountLogon = 3
Write-Output "Audit Policies Set"

#users/privilege rights editing
<#
https://github.com/MicrosoftDocs/windowsserverdocs/blob/main/WindowsServerDocs/identity/ad-ds/manage/understand-security-identifiers.md
SIDs that may be used and their corresponding account names:
S-1-5-113: Local account
S-1-5-6: Service
S-1-5-9: Enterprise Domain Controllers
S-1-5-11:Authenticated Users
S-1-5-19: NT Authority (LocalService)
S-1-5-20: Network Service
S-1-5-90: Windows Manager\Windows Manager Group
S-1-5-32-544: Administrators
S-1-5-32-545: Users
S-1-5-32-546: Guests
S-1-5-32-551: Backup Operators
S-1-5-32-555: Builtin\Remote Desktop Users
#>

# 2.2.2: 'Access this computer from the network' to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'
$SecPool.'Privilege Rights'.SeNetworkLogonRight = "*S-1-5-32-544,*S-1-5-11,*S-1-5-9, S-1-5-32-551"
# 2.2.3: 'Act as part of the operating system' set to 'No One'
#$SecPool.'Privilege Rights'.SeTcbPrivilege = ""
# 2.2.4: 'Add workstations to domain' set to 'Administrators'
#$SecPool.'Privilege Rights'.SeMachineAccountPrivilege = "*S-1-5-32-544"
# 2.2.6: 'Adjust memory quotas for a process' set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
$SecPool.'Privilege Rights'.SeIncreaseQuotaPrivilege = "*S-1-5-32-544,*S-1-5-19,*S-1-5-20"
# 2.2.7: 'Allow log on locally' set to 'Administrators, ENTERPRISE DOMAIN CONTROLLERS, & USERS-(only for desktop windows, not server)'
$SecPool.'Privilege Rights'.SeInteractiveLogonRight = "*S-1-5-9, *S-1-5-32-544,*S-1-5-32-545, *S-1-5-32-551"
# 2.2.8: 'Allow log on through Remote Desktop Services' set to 'Administrators'
$SecPool.'Privilege Rights'.SeRemoteInteractiveLogonRight = "*S-1-5-32-544, *S-1-5-32-555"
#2.2.11: Ensure 'Back up files and directories' is set to 'Administrators'
$SecPool.'Privilege Rights'.SeBackupPrivilege = "*S-1-5-32-544,*S-1-5-32-551"
# 2.2.12: 'Change the system time' set to 'Administrators, LOCAL SERVICE'
$SecPool.'Privilege Rights'.SeSystemtimePrivilege = "*S-1-5-32-544,*S-1-5-19"
# 2.2.13: 'Change the time zone' set to 'Administrators, LOCAL SERVICE'
$SecPool.'Privilege Rights'.SeTimeZonePrivilege = "*S-1-5-32-544,*S-1-5-19"
#2.2.14 Ensure 'Create a pagefile' is set to 'Administrators'
$SecPool.'Privilege Rights'.SeCreatePagefilePrivilege = "*S-1-5-32-544"
#2.2.15 Ensure 'Create a token object' is set to 'No One'
$SecPool.'Privilege Rights'.SeAssignPrimaryTokenPrivilege = ""
#2.2.16 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
$SecPool.'Privilege Rights'.SeCreateGlobalPrivilege = "*S-1-5-32-544, *S-1-5-19, *S-1-5-20, *S-1-5-6"
#2.2.17 (L1) Ensure 'Create permanent shared objects' is set to 'No One' (Automated)
#should be default none
# 2.2.18: 'Create symbolic links' set to 'Administrators'
$SecPool.'Privilege Rights'.SeCreateSymbolicLinkPrivilege = "*S-1-5-32-544"
# 2.2.20 (L1) Ensure 'Debug programs' is set to 'Administrators'
#$SecPool.'Privilege Right'.SeDebugPrivilege = "S-1-5-32-544"

#MAKE SURE THE DENY LOGON RIGHTS SETTINGS DO NOT AFFECT ANYBODY THAT NEEDS THESE RIGHTS AS DEFINED IN THE README

#2.2.21 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests'
#$SecPool.'Privilege Right'.SeDenyNetworkLogonRight = "*S-1-5-32-546"
# 2.2.22: 'Deny access to this computer from the network' set to 'Guests, Local account and member of Administrators group'
$SecPool.'Privilege Rights'.SeDenyNetworkLogonRight = "*S-1-5-32-546"
# 2.2.23: 'Deny log on as a batch job' set to 'Guests'
#$SecPool.'Privilege Rights'.SeDenyBatchLogonRight = "*S-1-5-32-546"
# 2.2.24: 'Deny log on as a service' set to 'Guests'
#$SecPool.'Privilege Rights'.SeDenyServiceLogonRight = "*S-1-5-32-546"
# 2.2.25: 'Deny log on locally' set to 'Guests'
$SecPool.'Privilege Rights'.SeDenyInteractiveLogonRight = "*S-1-5-32-546"
# 2.2.26: 'Deny log on through Remote Desktop Services' set to 'Guests'
#$SecPool.'Privilege Rights'.SeDenyRemoteInteractiveLogonRight = "*S-1-5-32-546"

# 2.2.29: 'Enable computer and user accounts to be trusted for delegation' set to 'No One'
#$SecPool.'Privilege Rights'.SeEnableDelegationPrivilege = "*S-1-5-32-544"
# 2.2.30: 'Force shutdown from a remote system' set to 'Administrators'
$SecPool.'Privilege Rights'.SeRemoteShutdownPrivilege = "*S-1-5-32-544"
# 2.2.31: 'Generate security audits' set to 'LOCAL SERVICE, NETWORK SERVICE'
$SecPool.'Privilege Rights'.SeAuditPrivilege = "*S-1-5-19,*S-1-5-20"
# 2.2.33: 'Impersonate a client after authentication' (MS only) set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, IIS_IUSRS'
$SecPool.'Privilege Rights'.SeImpersonatePrivilege = "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6,*S-1-5-32-568"
# 2.2.34: 'Increase scheduling priority' set to 'Administrators, Window Manager\Window Manager Group'
$SecPool.'Privilege Rights'.SeIncreaseBasePriorityPrivilege = "*S-1-5-32-544,*S-1-5-90"
# 2.2.35: 'Load and unload device drivers' set to 'Administrators'
$SecPool.'Privilege Rights'.SeLoadDriverPrivilege = "*S-1-5-32-544"
# 2.2.36: 'Lock pages in memory' set to 'No One'
#$SecPool.'Privilege Rights'.SeLockMemoryPrivilege = ""
# 2.2.37: 'Log on as a batch job' set to 'Administrators'
$SecPool.'Privilege Rights'.SeBatchLogonRight = "*S-1-5-32-544"
# 2.2.38: 'Manage auditing and security log' set to 'Administrators' and (when applicable) 'Exchange Servers'
$SecPool.'Privilege Rights'.SeSecurityPrivilege = "*S-1-5-32-544,"
# 2.2.40: 'Modify an object label' set to 'No One'
#$SecPool.'Privilege Rights'.SeRelabelPrivilege = ""
# 2.2.41: 'Modify firmware environment values' set to 'Administrators'
$SecPool.'Privilege Rights'.SeSystemEnvironmentPrivilege = "*S-1-5-32-544"
# 2.2.42: 'Perform volume maintenance tasks' set to 'Administrators'
$SecPool.'Privilege Rights'.SeManageVolumePrivilege = "*S-1-5-32-544"
# 2.2.43: 'Profile single process' set to 'Administrators'
$SecPool.'Privilege Rights'.SeProfileSingleProcessPrivilege = "*S-1-5-32-544"
# 2.2.44: 'Profile system performance' set to 'Administrators, NT SERVICE\WdiServiceHost'
$SecPool.'Privilege Rights'.SeSystemProfilePrivilege = "*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
# 2.2.45: 'Replace a process level token' set to 'LOCAL SERVICE, NETWORK SERVICE'
$SecPool.'Privilege Rights'.SeAssignPrimaryTokenPrivilege = "*S-1-5-19,*S-1-5-20"
# 2.2.46: 'Restore files and directories' set to 'Administrators'
$SecPool.'Privilege Rights'.SeRestorePrivilege = "*S-1-5-32-544,*S-1-5-32-551"
# 2.2.47: 'Shut down the system' set to 'Administrators'
$SecPool.'Privilege Rights'.SeShutdownPrivilege = "*S-1-5-32-544, *S-1-5-32-545, *S-1-5-32-551"
# 2.2.48: 'Synchronize directory service data' set to 'No One' (DC only)
#$SecPool.'Privilege Rights'.SeSyncAgentPrivilege = ""
# 2.2.49: 'Take ownership of files or other objects' set to 'Administrators'
$SecPool.'Privilege Rights'.SeTakeOwnershipPrivilege = "*S-1-5-32-544"
Write-Output "Users Rights Assignment edited"

Set-SecPol -Object $SecPool -CfgFile $CfgFileName

#Security options editing
# Function to apply registry settings
function Set-RegistryValue {
    param (
        [string]$KeyPath,
        [string]$Name,
        [int]$Value
    )
    if (-not (Test-Path $KeyPath)) {
        New-Item -Path $KeyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $KeyPath -Name $Name -Value $Value -Force
    Write-Host "Set $Name at $KeyPath to $Value"
}

# Settings Definitions
$Settings = @(
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "NoConnectedUser"; # Accounts: Block Microsoft accounts
        Value = 3
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters";
        Name = "RestrictNullSessAccess"; # Accounts: Guest account status
        Value = 1
    },
    @{
        KeyPath = "HKLM:\System\CurrentControlSet\Control\Lsa";
        Name = "LimitBlankPasswordUse"; # Accounts: Limit local account use of blank passwords
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "AdministratorName"; # Accounts: Rename administrator account
        Value = 12 # Example name
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "GuestName"; # Accounts: Rename guest account
        Value = 13 # Example name
    },
    @{
        KeyPath = "HKLM:\System\CurrentControlSet\Control\Lsa";
        Name = "AuditBaseObjects"; # Audit: Force audit policy subcategory settings
        Value = 1
    },
    @{
        KeyPath = "HKLM:\System\CurrentControlSet\Services\EventLog\Security";
        Name = "CrashOnAuditFail"; # Audit: Shut down system immediately if unable to log security audits
        Value = 0
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers";
        Name = "PreventUserInstall"; # Devices: Prevent users from installing printer drivers
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters";
        Name = "RequireStrongKey"; # Domain Member: Require strong session key
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters";
        Name = "SealSecureChannel"; # Domain Member: Digitally encrypt or sign secure channel data (always)
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "DisableCAD"; # Interactive logon: Do not require CTRL+ALT+DEL
        Value = 0
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
        Name = "RequireSecuritySignature"; # Microsoft network client: Digitally sign communications (always)
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
        Name = "EnableSecuritySignature"; # Microsoft network client: Digitally sign communications (if server agrees)
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        Name = "RequireSecuritySignature"; # Microsoft network server: Digitally sign communications (always)
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        Name = "EnableSecuritySignature"; # Microsoft network server: Digitally sign communications (if client agrees)
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "DontDisplayLastUserName"; # Interactive logon: Don't display last signed-in
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "InactivityTimeoutSecs"; # Interactive logon: Machine inactivity limit
        Value = 900
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        Name = "CachedLogonsCount"; # Interactive logon: Number of previous logons to cache
        Value = 4
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "PromptPasswordExpiry"; # Interactive logon: Prompt user to change password before expiration
        Value = 5
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "ForceUnlockLogon"; # Interactive logon: Require Domain Controller Authentication to unlock workstation
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "ScRemoveOption"; # Interactive logon: Smart card removal behavior
        Value = 1 # Lock workstation
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
        Name = "RequireSecuritySignature"; # Microsoft network client: Digitally sign communications (always)
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
        Name = "EnableSecuritySignature"; # Microsoft network client: Digitally sign communications (if server agrees)
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
        Name = "EnablePlainTextPassword"; # Microsoft network client: Send unencrypted password to third-party SMB servers
        Value = 0
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        Name = "AutoDisconnect"; # Microsoft network server: Amount of idle time required before suspending session
        Value = 15
    },
    <#
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        Name = "EnableForcedLogOff"; # Microsoft network server: Disconnect clients when logon hours expire
        Value = 1
    },
#>
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        Name = "SmbServerNameValidation"; # Microsoft network server: Server SPN target name validation level
        Value = 1 # Accept if provided by client
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "AllowAnonymousSidNameTranslation"; # Network access: Allow anonymous SID/Name translation
        Value = 0 # Disabled
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "RestrictAnonymousSAM"; # Network access: Do not allow anonymous enumeration of SAM accounts
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "RestrictAnonymous"; # Network access: Do not allow anonymous enumeration of SAM accounts and shares
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "DisableDomainCreds"; # Network access: Do not allow storage of passwords and credentials for network authentication
        Value = 1
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "EveryoneIncludesAnonymous"; # Network access: Let Everyone permissions apply to anonymous users
        Value = 0 # Disabled
    },
    <#
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "ForceLogoffWhenHourExpire"; # Network security: Force logoff when logon hours expire
        Value = 1
    },
    #>
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "LmCompatibilityLevel"; # Network security: LAN Manager authentication level
        Value = 5 # Send NTLMv2 response only. Refuse LM & NTLM
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "AllowLocalSystemToUseComputerIdentityForNTLM"; # Network security: Allow Local System to use computer identity for NTLM
        Value = 1 # Enabled
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "LocalSystemNullSessionFallback"; # Network security: Allow LocalSystem NULL session fallback
        Value = 0 # Disabled
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "AllowPKU2UAuthentication"; # Network Security: Allow PKU2U authentication requests to use online identities
        Value = 0 # Disabled
    },
    <#
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "KerberosEncryptionTypes"; # Network security: Configure encryption types allowed for Kerberos
        Value = "AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types"
    },
    #>
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "DoNotStoreLANManagerHash"; # Network security: Do not store LAN Manager hash value on next password change
        Value = 1 # Enabled
    }, @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "LDAPClientSigningRequirements"; # Network security: LDAP client signing requirements
        Value = 1 # Negotiate signing
    },
    <#
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "MinimumSessionSecurityNTLMSSPClients"; # Network security: Minimum session security for NTLM SSP clients
        Value = "Require NTLMv2 session security, Require 128-bit encryption"
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "MinimumSessionSecurityNTLMSSPServers"; # Network security: Minimum session security for NTLM SSP servers
        Value = "Require NTLMv2 session security, Require 128-bit encryption"
    },
    #>
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "RestrictNTLMAuditIncomingNTLM"; # Network security: Restrict NTLM: Audit Incoming NTLM Traffic
        Value = 1 # Enable auditing for all accounts
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "RestrictNTLMAuditNTLMAuthentication"; # Network security: Restrict NTLM: Audit NTLM authentication in this domain
        Value = 2 # Enable all (DC only)
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
        Name = "RestrictNTLMAuditOutgoingNTLM"; # Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
        Value = 2 # Audit all or higher
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "ShutdownWithoutLogon"; # Shutdown: Allow system to be shut down without having to log on
        Value = 0 # Disabled
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager";
        Name = "ObCaseInsensitive"; # System objects: Require case insensitivity for non-Windows subsystems
        Value = 1 # Enabled
    },
    @{
        KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager";
        Name = "ProtectionMode"; # System objects: Strengthen default permissions of internal system objects
        Value = 1 # Enabled
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "FilterAdministratorToken"; # User Account Control: Admin Approval Mode for the Built-in Administrator account
        Value = 1 # Enabled
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "ConsentPromptBehaviorAdmin"; # User Account Control: Behavior of the elevation prompt for administrators
        Value = 2 # Prompt for consent on the secure desktop
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "ConsentPromptBehaviorUser"; # User Account Control: Behavior of the elevation prompt for standard users
        Value = 0 # Automatically deny elevation requests
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "EnableInstallerDetection"; # User Account Control: Detect application installations and prompt for elevation
        Value = 1 # Enabled
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "EnableSecureUIAPaths"; # User Account Control: Only elevate UIAccess applications installed in secure locations
        Value = 1 # Enabled
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "EnableLUA"; # User Account Control: Run all administrators in Admin Approval Mode
        Value = 1 # Enabled
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "PromptOnSecureDesktop"; # User Account Control: Switch to the secure desktop when prompting for elevation
        Value = 1 # Enabled
    },
    @{
        KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Name = "EnableVirtualization"; # User Account Control: Virtualize file and registry write failures
        Value = 1 # Enabled
    }

)


# Apply Settings
foreach ($Setting in $Settings) {
    Set-RegistryValue -KeyPath $Setting.KeyPath -Name $Setting.Name -Value $Setting.Value
}

# Confirm changes
Write-Output "All Security Options applied successfully!"

