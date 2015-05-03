Param (
[string]$pass,
[string]$domain,
[string]$passphrase,
[string]$SQLName
)
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
$FarmCredentials = New-Object System.Management.Automation.PSCredential $SQLUsername, (ConvertTo-SecureString $SQLPassword -AsPlainText -Force)
$done=$false
do{
Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
try
   {
   New-SPConfigurationDatabase -DatabaseServer $SQLServer -DatabaseName $ConfigDB -AdministrationContentDatabaseName $AdminDB -Passphrase (ConvertTo-SecureString $FarmPassphrase -AsPlainText -Force) -FarmCredentials $FarmCredentials
   } catch {Start-Sleep 10}
New-SPCentralAdministration -Port $Port -WindowsAuthProvider NTLM
Install-SPHelpCollection -All
Initialize-SPResourceSecurity
Install-SPService  
Install-SPFeature -AllExistingFeatures 
Install-SPApplicationContent
$cred = New-Object System.Management.Automation.PSCredential $WebAppsName, (ConvertTo-SecureString $pass -AsPlainText -Force)
New-SPManagedAccount -Credential $cred
$cred = New-Object System.Management.Automation.PSCredential $ServiceAppName, (ConvertTo-SecureString $pass -AsPlainText -Force)
New-SPManagedAccount -Credential $cred
Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
if (Get-SPDatabase) {$done=$true}
}
while ($done -ne $true)
#iisreset
Import-Module WebAdministration
Get-Website | Start-Website
#Cleanup
Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
rm -Path C:\Sharepoint\ -Confirm:$false -Recurse -Force
rm -Path C:\Scripts\ -Confirm:$false -Recurse -Force
#Enable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 1 -Force
Shutdown -l