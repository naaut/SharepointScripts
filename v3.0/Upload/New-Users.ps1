Param (
[string]$pass,
[string]$domain
)
$domainuser = "Administrator"
$domainpath = "DC="+($domain -replace '\.', ",DC=") 
Import-Module ActiveDirectory
$password = ConvertTo-SecureString $pass -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $domainuser, $password   
New-ADOrganizationalUnit -Name Accounts -Path $domainpath
New-ADUser -SamAccountName "sql-server" -UserPrincipalName "sql-server@$domain" -Name "SQL Server" -Surname "SQL Server" -GivenName  "Sharepoint"  -DisplayName "Sharepoint SQL Server" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred
New-ADUser -SamAccountName "sp-installer" -UserPrincipalName "sp-installer@$domain" -Name "Installer" -Surname "Installer" -GivenName  "Sharepoint" -DisplayName "Sharepoint Installer" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred
New-ADUser -SamAccountName "sp-farm" -UserPrincipalName "sp-farm@$domain" -Name "Farm"  -Surname "Farm" -GivenName "Sharepoint" -DisplayName "Sharepoint Farm" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred
New-ADUser -SamAccountName "sp-serviceapp" -UserPrincipalName "sp-serviceapp@$domain" -Name "Serviceapp"  -Surname "Serviceapp" -GivenName "Sharepoint" -DisplayName "Sharepoint Serviceapp" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred
New-ADUser -SamAccountName "sp-webapp" -UserPrincipalName "sp-webapp@$domain" -Name "WebApps"  -Surname "WebApps" -GivenName "Sharepoint" -DisplayName "Sharepoint WebApps" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred
New-ADUser -SamAccountName "User" -UserPrincipalName "User@$domain" -Name "User"  -Surname "User" -GivenName "Sharepoint" -DisplayName "Sharepoint User" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred
if ([adsi]::Exists("LDAP://OU=Accounts,$domainpath")) {
Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon 
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword 
rm -Path C:\Scripts\ -Confirm:$false -Recurse -Force
Shutdown -l
}
    