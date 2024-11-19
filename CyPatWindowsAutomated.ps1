#password policies reg path
$PasswordPolicyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$AccountPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

#password policies
Set-ItemProperty -Path $PasswordPolicyPath -Name "PasswordHistorySize" -Value 5
Set-ItemProperty -Path $PasswordPolicyPath -Name "MaximumPasswordAge" -Value 90
Set-ItemProperty -Path $PasswordPolicyPath -Name "MinimumPasswordAge" -Value 10
Set-ItemProperty -Path $PasswordPolicyPath -Name "MinimumPasswordLength" -Value 5
Set-ItemProperty -Path $PasswordPolicyPath -Name "PasswordComplexity" -Value 1
Set-ItemProperty -Path $PasswordPolicyPath -Name "ClearTextPassword" -Value 0

#from:https://stackoverflow.com/questions/55774478/enforce-password-complexity-on-windows-using-powershell
#ToDO: Implement this into script to make local sec policy changes
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


$SecPool = Parse-SecPol -CfgFile C:\test\Test.cgf
$SecPool.'System Access'.PasswordComplexity = 1
$SecPool.'System Access'.MinimumPasswordLength = 8
$SecPool.'System Access'.MaximumPasswordAge = 60

Set-SecPol -Object $SecPool -CfgFile C:\Test\Test.cfg
