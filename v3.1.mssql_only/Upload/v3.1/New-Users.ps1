Param (
[string]$pass,
[string]$domain
)

Start-Transcript -Path "c:\Logs\new-users.log" -Append

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nCreating Users..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

$domainuser = "Administrator"
$domainpath = "DC="+($domain -replace '\.', ",DC=") 
Import-Module ActiveDirectory
$password = ConvertTo-SecureString $pass -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $domainuser, $password   
New-ADOrganizationalUnit -Name Accounts -Path $domainpath -Verbose
New-ADUser -SamAccountName "sql-server" -UserPrincipalName "sql-server@$domain" -Name "SQL Server" -Surname "SQL Server" -GivenName  "Sharepoint"  -DisplayName "Sharepoint SQL Server" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred -Verbose
New-ADUser -SamAccountName "sp-installer" -UserPrincipalName "sp-installer@$domain" -Name "Installer" -Surname "Installer" -GivenName  "Sharepoint" -DisplayName "Sharepoint Installer" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred -Verbose
New-ADUser -SamAccountName "sp-farm" -UserPrincipalName "sp-farm@$domain" -Name "Farm"  -Surname "Farm" -GivenName "Sharepoint" -DisplayName "Sharepoint Farm" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred -Verbose
New-ADUser -SamAccountName "sp-serviceapp" -UserPrincipalName "sp-serviceapp@$domain" -Name "Serviceapp"  -Surname "Serviceapp" -GivenName "Sharepoint" -DisplayName "Sharepoint Serviceapp" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred -Verbose
New-ADUser -SamAccountName "sp-webapp" -UserPrincipalName "sp-webapp@$domain" -Name "WebApps"  -Surname "WebApps" -GivenName "Sharepoint" -DisplayName "Sharepoint WebApps" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred -Verbose
New-ADUser -SamAccountName "User" -UserPrincipalName "User@$domain" -Name "User"  -Surname "User" -GivenName "Sharepoint" -DisplayName "Sharepoint User" -Path "OU=Accounts,$domainpath" -AccountPassword $password -ChangePasswordAtLogon:$false -PasswordNeverExpires:$true -Enabled:$true -Credential $cred -Verbose
if ([adsi]::Exists("LDAP://OU=Accounts,$domainpath")) {
    Write-Output "`nStarting cleanup..."
    Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon 
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword 
    rm -Path C:\Scripts\ -Confirm:$false -Recurse -Force
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
    Write-Output "`nCreating Shared foldel for logs..."
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
    if ((Test-Path "C:\Logs\")){New-SmbShare -Name "Logs" -Path "C:\Logs\" -FullAccess Everyone}
    Stop-Transcript
    Shutdown -l
}
    