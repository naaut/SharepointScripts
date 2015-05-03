Param (
[string]$pass,
[string]$domain,
[string]$passphrase,
[string]$SQLName
)

$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName . | ? {$_.IPEnabled}
Start-Transcript -Path "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\Backend-es.log" -Append

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nStarting Install Backend..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

$nDomain = $env:USERDOMAIN
$SQLServer = "$SQLName"
$SQLUsername = "$nDomain\sp-farm"
$SQLPassword = $pass
$WebAppsName = "$nDomain\sp-webapp"
$ServiceAppName = "$nDomain\sp-serviceapp"
$FarmPassphrase = $passphrase
$ConfigDB = "SharePoint_Config"
$AdminDB = "SharePoint_Admin_Content"
$Port = "5555"
$FarmCredentials = New-Object System.Management.Automation.PSCredential $SQLUsername, (ConvertTo-SecureString $SQLPassword -AsPlainText -Force) -Verbose
$rcount=0

$done=$false
do{
Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
try
   {
   $rcount++
   New-SPConfigurationDatabase -DatabaseServer $SQLServer -DatabaseName $ConfigDB -AdministrationContentDatabaseName $AdminDB -Passphrase (ConvertTo-SecureString $FarmPassphrase -AsPlainText -Force) -FarmCredentials $FarmCredentials -Verbose
   } catch {
            Write-Output "`nWaiting SQL Server $rcount..."
            Start-Sleep 20
           }
New-SPCentralAdministration -Port $Port -WindowsAuthProvider NTLM -Verbose
Install-SPHelpCollection -All -Verbose
Initialize-SPResourceSecurity -Verbose
Install-SPService -Verbose
Install-SPFeature -AllExistingFeatures -Verbose
Install-SPApplicationContent -Verbose
$cred = New-Object System.Management.Automation.PSCredential $WebAppsName, (ConvertTo-SecureString $pass -AsPlainText -Force)
New-SPManagedAccount -Credential $cred -Verbose
$cred = New-Object System.Management.Automation.PSCredential $ServiceAppName, (ConvertTo-SecureString $pass -AsPlainText -Force)
New-SPManagedAccount -Credential $cred -Verbose
Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
if (Get-SPDatabase) {$done=$true}
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nWaiting SQL Server $rcount..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Start-Sleep 15
}
while ($done -ne $true)

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nInstall Backend Compled. IIS restart."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

#iisreset
Import-Module WebAdministration
Get-Website | Start-Website

#Cleanup
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nStarting Cleaning..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"


Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
rm -Path C:\Sharepoint\ -Confirm:$false -Recurse -Force -Verbose
rm -Path C:\Scripts\ -Confirm:$false -Recurse -Force -Verbose
#Enable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 1 -Force

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nAll is complited..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

Stop-Transcript
#$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName . | ? {$_.IPEnabled}
#$cred = New-Object System.Management.Automation.PSCredential "$nDomain\Administrator", (ConvertTo-SecureString $pass -AsPlainText -Force)
#Start-Process powershell -Credential $cred -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command Copy-Item -Path 'C:\Logs\*.*' -Destination '\\$($NIC.DNSServerSearchOrder | Select -First 1)\C$\Logs\'" 
#Start-Sleep 10
Shutdown -l