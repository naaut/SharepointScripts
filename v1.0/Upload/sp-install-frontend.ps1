Param (
[string]$pass,
[string]$domain,
[string]$passphrase
)
$nDomain = $env:USERDOMAIN
$domain = $env:USERDNSDOMAIN
$SQLServer = "MSSQL"
$SQLUsername = "$nDomain\sp-farm"
$SQLPassword = $pass
$FarmPassphrase = $passphrase
$ConfigDB = "SharePoint_Config"
$AdminDB = "SharePoint_Admin_Content"
$Port = "5555"
$FarmCredentials = New-Object System.Management.Automation.PSCredential $SQLUsername, (ConvertTo-SecureString $SQLPassword -AsPlainText -Force)
Add-PsSnapin Microsoft.SharePoint.PowerShell
$done=$false
do{
Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
Connect-SPConfigurationDatabase -DatabaseServer $SQLServer -DatabaseName $ConfigDB -Passphrase (ConvertTo-SecureString $FarmPassphrase -AsPlainText -Force)
Install-SPHelpCollection -All
Initialize-SPResourceSecurity
Install-SPService  
Install-SPFeature -AllExistingFeatures 
Install-SPApplicationContent

#create site
#Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
try
   {
    New-SPWebApplication -Name "frontend.$domain" -ApplicationPool "SharePoint - frontend.$domain" -AuthenticationMethod "NTLM" -ApplicationPoolAccount "$nDomain\sp-webapp" -Port 80 -URL "http://frontend.$domain" -DataBaseName "FrontEnd_Content_DB" -HostHeader "frontend.$domain"
    $template = Get-SPWebTemplate "STS#0"
    Start-Sleep 30
    try 
       {
       New-SPSite -Url "http://frontend.$domain/" -OwnerAlias "$nDomain\User" -SecondaryOwnerAlias "$nDomain\sp-installer" -Template $template
       $done=$true
       } Catch {Start-Sleep 10}
   } Catch {Start-Sleep 60}


}
while ($done -ne $true)

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
