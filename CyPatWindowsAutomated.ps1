#password policies reg path
$PassowrdPolicyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$AccountPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

#password policies
Set-ItemProperty -Path $PasswordPolicyPath -Name "PasswordHistorySize" -Value 5
Set-ItemProperty -Path $PasswordPolicyPath -Name "MaximumPasswordAge" -Value 90
Set-ItemProperty -Path $PasswordPolicyPath -Name "MinimumPasswordAge" -Value 10
Set-ItemProperty -Path $PasswordPolicyPath -Name "MinimumPasswordLength" -Value 5
Set-ItemProperty -Path $PasswordPolicyPath -Name "PasswordComplexity" -Value 1
Set-ItemProperty -Path $PasswordPolicyPath -Name "ClearTextPassword" -Value 0


