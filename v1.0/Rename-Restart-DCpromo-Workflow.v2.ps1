<powershell>

workflow Rename-Restart-DCpromo {{
#Start-Transcript -path "C:\Scripts\Logs\InstallLog.txt" -append
$user = "Administrator"
$pass = "{password}"
$domainname = "test.com"
$netbiosname = "TEST"
$newname = "{hostname}"
$ScriptPath = "c:\Scripts\" 
# set password
#Write-Output "`nSetting password ..."
net user $user $pass

#rename computer and restart
if ($env:COMPUTERNAME -ne $newname) {{
  #Write-Output "`nChanging hostname ..."
  Rename-Computer -Newname $newname -Force -Passthru -Restart:$False
  
if ($newname -like "DC*") {{
  #add Windows Features
  Add-WindowsFeature RSAT-AD-Tools
  }}
  #create script for resume workflow
  #InlineScript {{
  #New-Item $Using:ScriptPath -ItemType file -Name "Resume-Workflow.ps1" -Force -Value "
#Start-Sleep 10
#Import-Module PSWorkflow
#Get-Job | Resume-Job
#Start-Sleep 10
#Get-Job | Receive-Job
#Start-Sleep 10
#Get-Job | Receive-Job
#Start-Sleep 10
#Get-Job"}}
  # add startup script for resume worflow
  InlineScript {{
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
    Add-WindowsFeature -Name "ad-domain-services" -IncludeAllSubFeature -IncludeManagementTools 
    Add-WindowsFeature -Name "dns" -IncludeAllSubFeature -IncludeManagementTools 
    Add-WindowsFeature -Name "gpmc" -IncludeAllSubFeature -IncludeManagementTools }} 
    Wait-Job -Name addFeature  
 #   }}
    
    if ($env:USERDNSDOMAIN -ne $domainname ) {{
     # Create New Forest, add Domain Controller  
      InlineScript {{            New-Item $Using:ScriptPath -ItemType file -Name "dc-promo.ps1" -Force -Value "# Create New Forest, add Domain Controller `$safepass =  convertto-securestring '{password}' -asplaintext -forceImport-Module ADDSDeployment Install-ADDSForest -CreateDnsDelegation:`$false -DomainMode 'Win2012' -SafeModeAdministratorPassword `$safepass -DomainName '$Using:domainname' -DomainNetbiosName '$Using:netbiosName' -ForestMode 'Win2012' -InstallDns:`$true -LogPath 'C:\Windows\NTDS' -NoRebootOnCompletion:`$false -SysvolPath 'C:\Windows\SYSVOL' -Confirm:`$false -Force:`$true "       Invoke-Expression  -Command 'powershell -ExecutionPolicy Bypass -Command "&''c:\Scripts\dc-promo.ps1''"'      #Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue      #$actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''c:\Scripts\Resume-Workflow.ps1''"'
      #$pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
      #$act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
      #Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn)      }}
    }}#Restart-Computer -Wait -Force
 }}
 $curentdomain = Inlinescript {{$wmiDomain = (gwmi WIN32_ComputerSystem).Domain; $wmiDomain}} 
 if ($curentdomain -eq $domainname){{
 InlineScript {{
 Invoke-Expression  -Command "powershell -ExecutionPolicy Bypass -Command c:\Scripts\New-Users.ps1 -pass '$Using:pass' -domain '$Using:domainname'" }}
 }}
}}
if (!(Test-Path "c:\Scripts\New-Users.ps1")){{if (!(Test-Path "c:\Scripts\")) {{mkdir "c:\Scripts\"}}$source = "http://cubes-scripts.s3.amazonaws.com/New-Users.ps1"$destination = "c:\Scripts\New-Users.ps1" Invoke-WebRequest $source -OutFile $destination
}}$NICs = Get-WMIObject Win32_NetworkAdapterConfiguration -computername . | where{{$_.IPEnabled -eq $true -and $_.DHCPEnabled -eq $true}}Foreach($NIC in $NICs) {{     $ip = ($NIC.IPAddress[0])     $gateway = $NIC.DefaultIPGateway     $subnet = $NIC.IPSubnet[0]     $dns = $NIC.DNSServerSearchOrder     $NIC.EnableStatic($ip, $subnet)     $NIC.SetGateways($gateway)    $dns = "127.0.0.1",($NIC.IPAddress[0])      $NIC.SetDNSServerSearchOrder($dns)     $NIC.SetDynamicDNSRegistration("FALSE") }} 
Rename-Restart-DCpromo 

</powershell>

