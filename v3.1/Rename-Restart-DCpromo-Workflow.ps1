<powershell>

workflow Rename-Restart-DCpromo {{
#Start-Transcript -path "C:\Scripts\Logs\InstallLog.txt" -append
$user = "Administrator"
$pass = "{password}"
$domainname = "test.com"
$netbiosName = "TEST"
$newname = "{hostname}"
$ScriptPath = "c:\Scripts\"
# set password
net user $user $pass

#rename computer and restart
if ( $env:COMPUTERNAME -ne $newname ) {{
  #Write-Output "`nChanging hostname ..."
  Rename-Computer -Newname $newname -Force -Passthru
  
if ($newname -like "DC*") {{
  #add Windows Features
  Add-WindowsFeature RSAT-AD-Tools
  }}
  #create script for resume workflow
  InlineScript {{
  New-Item $Using:ScriptPath -ItemType file -Name "Resume-Workflow.ps1" -Force -Value "
Start-Sleep 10
Import-Module PSWorkflow
Get-Job | Resume-Job
Start-Sleep 10
Get-Job | Receive-Job
Start-Sleep 10
Get-Job | Receive-Job
Start-Sleep 10
Get-Job"}}

  # add startup script for resume worflow
  #Write-Output "`nSetting ScheduledJob for ResumeWorkflow ..."
  InlineScript {{
  $password = ConvertTo-SecureString $Using:pass -AsPlainText -Force
  $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist "Administrator", $password
  $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1''"'
  $pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
  $act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
  Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn)
  REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon /t REG_SZ /d 1
  REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName /t REG_SZ /d "$Using:newname\$Using:user"
  REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword /t REG_SZ /d $Using:pass
  }}
     
  Restart-Computer -Wait -Force
}}

if ($newname -like "DC*") {{ 
    #Install AD DS, DNS and GPMC    
    start-job -Name addFeature -ScriptBlock {{ 
    Add-WindowsFeature -Name "ad-domain-services" -IncludeAllSubFeature -IncludeManagementTools 
    Add-WindowsFeature -Name "dns" -IncludeAllSubFeature -IncludeManagementTools 
    Add-WindowsFeature -Name "gpmc" -IncludeAllSubFeature -IncludeManagementTools }} 
    Wait-Job -Name addFeature  
    }}
    if ( $env:USERDNSDOMAIN -ne $domainname ) {{
      #Write-Output "`nUnregistering ScheduledJob ..."
      Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
      REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon 
      REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
      REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
      #Write-Output "`nInstalling new forest of AD ..."
      #Start Forest Promotion Script      
      # Create New Forest, add Domain Controller
      InlineScript {{
      New-Item $Using:ScriptPath -ItemType file -Name "dc-promo.ps1" -Force -Value "
# Create New Forest, add Domain Controller 
`$domainname = 'test.com' 
`$netbiosName = 'TEST'
`$safepass =  convertto-securestring '{password}' -asplaintext -force
Import-Module ADDSDeployment 
Install-ADDSForest -CreateDnsDelegation:`$false -DomainMode 'Win2012' -SafeModeAdministratorPassword `$safepass -DomainName `$domainname -DomainNetbiosName `$netbiosName -ForestMode 'Win2012' -InstallDns:`$true -LogPath 'C:\Windows\NTDS' -NoRebootOnCompletion:`$false -SysvolPath 'C:\Windows\SYSVOL' -Confirm:`$false -Force:`$true " 
      }}
      Invoke-Expression  -Command 'powershell -ExecutionPolicy Bypass -Command "&''c:\Scripts\dc-promo.ps1''"'
     }}
}}
$NICs = Get-WMIObject Win32_NetworkAdapterConfiguration -computername . | where{{$_.IPEnabled -eq $true -and $_.DHCPEnabled -eq $true}}
Foreach($NIC in $NICs) {{ 
    $ip = ($NIC.IPAddress[0]) 
    $gateway = $NIC.DefaultIPGateway 
    $subnet = $NIC.IPSubnet[0] 
    $dns = $NIC.DNSServerSearchOrder 
    $NIC.EnableStatic($ip, $subnet) 
    $NIC.SetGateways($gateway)
    $dns = "127.0.0.1",($NIC.IPAddress[0]) 
    $NIC.SetDNSServerSearchOrder($dns) 
    $NIC.SetDynamicDNSRegistration("FALSE") 
}} 
Rename-Restart-DCpromo 

</powershell>
