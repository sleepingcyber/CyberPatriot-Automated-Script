#TODO: Disable weak services, enable auto updates, disable remote desktop, malwarebytes spot check, system integrity scan

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
#Account Lockout Policy editing
$SecPool.'System Access'.LockoutBadCount = 5
#Audit Policy editing
$SecPool.'System Access'.AuditSystemEvents = 3
$SecPool.'System Access'.AuditLogonEvents = 3
$SecPool.'System Access'.AuditPrivilegeUse = 3
$SecPool.'System Access'.AuditPolicyChange = 3
$SecPool.'System Access'.AuditAccountManage = 2
$SecPool.'System Access'.AuditAccountLogon = 3

#privilege rights editing
# 2.2.2: 'Access this computer from the network' to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'
$SecPool.'Privilege Rights'.SeNetworkLogonRight = "*S-1-5-32-544,*S-1-5-11,*S-1-5-9, S-1-5-32-551"
# 2.2.3: 'Act as part of the operating system' set to 'No One'
$SecPool.'Privilege Rights'.SeTcbPrivilege = ""
# 2.2.4: 'Add workstations to domain' set to 'Administrators'
$SecPool.'Privilege Rights'.SeMachineAccountPrivilege = "*S-1-5-32-544"
# 2.2.6: 'Adjust memory quotas for a process' set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
$SecPool.'Privilege Rights'.SeIncreaseQuotaPrivilege = "*S-1-5-32-544,*S-1-5-19,*S-1-5-20"
# 2.2.7: 'Allow log on locally' set to 'Administrators, ENTERPRISE DOMAIN CONTROLLERS'
$SecPool.'Privilege Rights'.SeInteractiveLogonRight = "*S-1-5-32-544,*S-1-5-9, *S-1-5-32-545, *S-1-5-32-551"
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
$SecPool.'Privilege Right'.SeDebugPrivilege = "S-1-5-32-544"
#2.2.21 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests'
$SecPool.'Privilege Right'.SeDenyNetworkLogonRight = "Guest"
# 2.2.22: 'Deny access to this computer from the network' set to 'Guests, Local account and member of Administrators group'
$SecPool.'Privilege Rights'.SeDenyNetworkLogonRight = "*S-1-5-32-546,*S-1-5-113"

# 2.2.23: 'Deny log on as a batch job' set to 'Guests'
$SecPool.'Privilege Rights'.SeDenyBatchLogonRight = "*S-1-5-32-546"

# 2.2.24: 'Deny log on as a service' set to 'Guests'
$SecPool.'Privilege Rights'.SeDenyServiceLogonRight = "*S-1-5-32-546"

# 2.2.25: 'Deny log on locally' set to 'Guests'
$SecPool.'Privilege Rights'.SeDenyInteractiveLogonRight = "*S-1-5-32-546"

# 2.2.26: 'Deny log on through Remote Desktop Services' set to 'Guests'
$SecPool.'Privilege Rights'.SeDenyRemoteInteractiveLogonRight = "*S-1-5-32-546"

Set-SecPol -Object $SecPool -CfgFile $CfgFileName
