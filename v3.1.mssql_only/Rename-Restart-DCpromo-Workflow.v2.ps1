<powershell>

workflow Rename-Restart-DCpromo {{
#Start-Transcript -path "C:\Scripts\Logs\InstallLog.txt" -append
$user = "Administrator"
$pass = "{password}"
$domainname = "{domainname}"
$netbiosname = "{netbiosname}"
$newname = "{hostname}"
$ScriptPath = "c:\Scripts\"
$SqlAdmin = "{sqluser}"
$SqlPass = "{sqlpass}"

 
# set password
#Write-Output "`nSetting password ..."
net user $user $pass

#rename computer and restart
if ($env:COMPUTERNAME -ne $newname) {{
  #Write-Output "`nChanging hostname ..."
  Rename-Computer -Newname $newname -Force -Passthru -Restart:$False
  
  if ($newname -like "*DC*") {{
      #add Windows Features
      Add-WindowsFeature RSAT-AD-Tools
      }}
  
  # add startup script for resume worflow
  InlineScript {{
      Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\DC.log" -Append default
      Write-Output "`nRename Computer and Create Scheduled Task..." | Out-File "C:\Logs\DC.log" -Append default
      Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\DC.log" -Append default
      $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1''"'
      $pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
      $act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
      Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn)
      REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon /t REG_SZ /d 1
      REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName /t REG_SZ /d $Using:user
      REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword /t REG_SZ /d $Using:pass
  }}
     
  Restart-Computer -Force
}}

if ($env:COMPUTERNAME -like "DC*") {{ 
    #Install AD DS, DNS and GPMC    
    start-job -Name addFeature -ScriptBlock {{
        Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\DC.log" -Append default
        Write-Output "`nInstall AD DS, DNS and GPMC..." | Out-File "C:\Logs\DC.log" -Append default
        Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\DC.log" -Append default
        Add-WindowsFeature -Name "ad-domain-services" -IncludeAllSubFeature -IncludeManagementTools 
        Add-WindowsFeature -Name "dns" -IncludeAllSubFeature -IncludeManagementTools 
        Add-WindowsFeature -Name "gpmc" -IncludeAllSubFeature -IncludeManagementTools 
        }} 
    Wait-Job -Name addFeature

    if ($env:USERDNSDOMAIN -ne $domainname ) {{
     # Create New Forest, add Domain Controller  
      InlineScript {{          Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\DC.log" -Append default
          Write-Output "`nCreate and start script dc-promo..." | Out-File "C:\Logs\DC.log" -Append default
          Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\DC.log" -Append default                New-Item $Using:ScriptPath -ItemType file -Name "dc-promo.ps1" -Force -Value "# Create New Forest, add Domain ControllerStart-Transcript -Path 'c:\Logs\DC.log' -AppendWrite-Output '`nStart DC promotion...' `$safepass =  convertto-securestring '{password}' -asplaintext -forceImport-Module ADDSDeployment Install-ADDSForest -CreateDnsDelegation:`$false -DomainMode 'Win2012' -SafeModeAdministratorPassword `$safepass -DomainName '$Using:domainname' -DomainNetbiosName '$Using:netbiosName' -ForestMode 'Win2012' -InstallDns:`$true -LogPath 'C:\Windows\NTDS' -NoRebootOnCompletion:`$false -SysvolPath 'C:\Windows\SYSVOL' -Confirm:`$false -Force:`$true Stop-TraTranscript"           Invoke-Expression  -Command 'powershell -ExecutionPolicy Bypass -Command "&''c:\Scripts\dc-promo.ps1''"'      }}
    }}
 }}
 $curentdomain = Inlinescript {{$wmiDomain = (gwmi WIN32_ComputerSystem).Domain; $wmiDomain}} 
 if ($curentdomain -eq $domainname){{
 InlineScript {{
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\DC.log" -Append default
    Write-Output "`nStart script for creating new users..." | Out-File "C:\Logs\DC.log" -Append default
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\DC.log" -Append default
    Invoke-Expression  -Command "powershell -ExecutionPolicy Bypass -Command c:\Scripts\New-Users.ps1 -pass '$Using:pass' -domain '$Using:domainname' -sqluser '$Using:SqlAdmin' -sqlpass '$Using:SqlPass'" 
    }}
 }}
}}

if (!(Test-Path "c:\Logs\")){{mkdir "c:\Logs\"}}
Start-Transcript -Path "c:\Logs\DC.log" -Append

if (!(Test-Path "c:\Scripts\New-Users.ps1")){{    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
    Write-Output "`nDownloads Scripts Files..."
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"    if (!(Test-Path "c:\Scripts\")) {{mkdir "c:\Scripts\"}}    $source = "http://cubes-scripts.s3.amazonaws.com/v3.1.mssql_only/New-Users.ps1"    $destination = "c:\Scripts\New-Users.ps1"     Invoke-WebRequest $source -OutFile $destination
}}Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"$NICs = Get-WMIObject Win32_NetworkAdapterConfiguration -computername . | where{{$_.IPEnabled -eq $true -and $_.DHCPEnabled -eq $true}}Foreach($NIC in $NICs) {{     
    Write-Output "`nSetup Static IP for Adapter $NIC..."     $ip = ($NIC.IPAddress[0])     $gateway = $NIC.DefaultIPGateway     $subnet = $NIC.IPSubnet[0]     $dns = $NIC.DNSServerSearchOrder     $NIC.EnableStatic($ip, $subnet)     $NIC.SetGateways($gateway)    $dns = "127.0.0.1",($NIC.IPAddress[0])      $NIC.SetDNSServerSearchOrder($dns)     $NIC.SetDynamicDNSRegistration("FALSE") }} 
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nStarting Workflow..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

Stop-Transcript


Rename-Restart-DCpromo 

</powershell>

