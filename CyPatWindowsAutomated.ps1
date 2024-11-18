#variables
$TempFilePath = "$env:Temp\secedit.inf"
$LogFilePath = "$env:Temp\secedit.log"

#exporting the current sec policy
Write-Output "Exporting current sec policy"
secedit /export /cfg $TempFilePath /quiet

#read exported policy
Write-Output "Reading exported pol"
$SecurityPolicy = Get-Content $TempFilePath


#adding policies

#password Policies
$SecurityPolicy = $SecurityPolicy -replace '^PasswordHistorySize=.*', 'PasswordHistorySize = 5'
$SecurityPolicy = $SecurityPolicy -replace '^MaximumHistorySize=.*', 'PasswordHistorySize = 90'
$SecurityPolicy = $SecurityPolicy -replace '^MinimumPasswordAge=.*', 'MinimumPasswordAge = 10'
$SecurityPolicy = $SecurityPolicy -replace '^MinimumPasswordLength=.*', 'MinimumPasswordLength= 5'
$SecurityPolicy = $SecurityPolicy -replace '^PasswordComplexity=.*', 'PasswordComplexity = 1'
$SecurityPolicy = $SecurityPolicy -replace '^ClearTextPassword=.*', 'ClearTextPassword = 0'
Write-Output "Password policies updated successfully!"
#Account lockout policies
$SecurityPolicy = $SecurityPolicy -replace '^LockoutBadCount=.*', 'LockoutBadCount = 5'
$SecurityPolicy = $SecurityPolicy -replace '^LockoutDuration=.*', 'LockoutDuration = 30'
$SecurityPolicy = $SecurityPolicy -replace '^ResetLockoutCount=.*', 'ResetLockoutCount = 30'
Write-Output "Account lockout policies updated successfully!"

#saving updated
Write-Output "Saving updated policy"
$SecurityPolicy | Set-Content -Path $TempFilePath -Force

#aplying updated policy
Write-Output "applying updated policy"
secedit /configure /db/ secedit.sdb /cfg $TempFilePath /log $LogFilePath /quiet



# Clean up temporary files
Write-Output "Cleaning up temporary files..."
Remove-Item -Path $TempFilePath -Force
Remove-Item -Path $LogFilePath -Force