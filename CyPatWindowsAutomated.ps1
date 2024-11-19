

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



Set-SecPol -Object $SecPool -CfgFile $CfgFileName
