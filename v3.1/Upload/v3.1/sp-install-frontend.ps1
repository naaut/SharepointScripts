Param (
[string]$pass,
[string]$domain,
[string]$passphrase,
[string]$SQLName01,
[string]$SQLName02
)

$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName . | ? {$_.IPEnabled}

Start-Transcript -Path "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\frontend-es.log" -Append

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nStarting Install frontend..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

$nDomain = $env:USERDOMAIN
$domain = $env:USERDNSDOMAIN
$SQLServer = "$SQLName01"
$SQLSlave = "$SQLName02"
$SQLUsername = "$nDomain\sp-farm"
$SQLPassword = $pass
$FarmPassphrase = $passphrase
$ConfigDB = "SharePoint_Config"
$AdminDB = "SharePoint_Admin_Content"
$Port = "5555"
$FarmCredentials = New-Object System.Management.Automation.PSCredential $SQLUsername, (ConvertTo-SecureString $SQLPassword -AsPlainText -Force) -Verbose
Add-PsSnapin Microsoft.SharePoint.PowerShell
$rcount=0
$done=$false
do{
$rcount++
Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
Connect-SPConfigurationDatabase -DatabaseServer $SQLServer -DatabaseName $ConfigDB -Passphrase (ConvertTo-SecureString $FarmPassphrase -AsPlainText -Force) -ErrorAction SilentlyContinue -Verbose
Install-SPHelpCollection -All -ErrorAction SilentlyContinue -Verbose
Initialize-SPResourceSecurity -ErrorAction SilentlyContinue -Verbose
Install-SPService -ErrorAction SilentlyContinue -Verbose
Install-SPFeature -AllExistingFeatures -ErrorAction SilentlyContinue -Verbose 
Install-SPApplicationContent -ErrorAction SilentlyContinue -Verbose

#create site
#Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
try
   {
    New-SPWebApplication -Name "frontend.$domain" -ApplicationPool "SharePoint - frontend.$domain" -AuthenticationMethod "NTLM" -ApplicationPoolAccount "$nDomain\sp-webapp" -Port 80 -URL "http://frontend.$domain" -DataBaseName "FrontEnd_Content_DB" -HostHeader "frontend.$domain"
    $template = Get-SPWebTemplate "STS#0"
    Start-Sleep 30
    try 
       {
       New-SPSite -Url "http://frontend.$domain/" -OwnerAlias "$nDomain\User" -SecondaryOwnerAlias "$nDomain\sp-installer" -Template $template -Verbose
       $done=$true
       } Catch {
               Start-Sleep 30
               Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
               Write-Output "`nTrying Site Create $rcount..."
               Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
               }
   } Catch {
            Start-Sleep 30
            Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
            Write-Output "`nWaiting SQL Server $rcount..."
            Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

           }


}
while ($done -ne $true)

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nAdd Failover DB..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

$dbs = Get-SPDatabase -Verbose
foreach ($db in $dbs) {
                      $db.AddFailoverServiceInstance("$SQLSlave")
                      $db.Update()
                      }

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nIIS restart..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
iisreset

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nCreate checkpoint file on SQL server..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
New-Item \\$SQLName01.$domain\c$\SQLBackups\done.txt -Type file -Verbose

#Cleanup

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nAll is completed, start cleaning..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
rm -Path C:\Sharepoint\ -Confirm:$false -Recurse -Force
rm -Path C:\Scripts\ -Confirm:$false -Recurse -Force
#Enable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 1 -Force
Stop-Transcript
#$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName . | ? {$_.IPEnabled}
#$cred = New-Object System.Management.Automation.PSCredential "$nDomain\Administrator", (ConvertTo-SecureString $pass -AsPlainText -Force)
#Start-Process powershell -Credential $cred -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command Copy-Item -Path 'C:\Logs\*.*' -Destination '\\$($NIC.DNSServerSearchOrder | Select -First 1)\C$\Logs\'" 
#Start-Sleep 10
Shutdown -l
