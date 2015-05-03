<powershell>

workflow Rename-Restart-AddToDomain-Backend {{
$user = "Administrator"
$pass = "{password}"
$domainuser = "Administrator"
$domainpass = "{password}"
$domainname = "{domainname}"
$newname = "{hostname}"
$ScriptPath = "c:\Scripts\" 
$SQLName = "{dbhost}"
$ipdns1 = "{dc}"
$ipdns2 = "{dc}"
$ipif = (Get-NetAdapter).ifIndex 
Set-DnsClientServerAddress -InterfaceIndex $ipif -ServerAddresses ($ipdns1,$ipdns2)
# set password
#Write-Output "`nSetting password ..."
net user $user $pass
#rename computer and restart
if ($env:COMPUTERNAME -ne $newname) {{
  Rename-Computer -Newname $newname -Force -Passthru
      InlineScript {{
      #Import-Module PSWorkflow 
      #Get-Job -State Suspended | Remove-Job -Force  
      #create script for resume workflow
      New-Item $Using:ScriptPath -ItemType file -Name "Resume-Workflow.ps1" -Force -Value "Import-Module PSWorkflow
      Get-Job | Resume-Job
      Get-Job | Receive-Job"
      # add startup script for resume worflow    
      $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1''"'
      #$actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Scripts\UserScript.ps1''"'
      $pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
      $act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
      Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn)
      REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon /t REG_SZ /d 1
      REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName /t REG_SZ /d $Using:user
      REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword /t REG_SZ /d $Using:pass
      }}
   Restart-Computer -Wait -Force
}}
 #add to domain and registering new ScheduledJob
 $curentdomain = Inlinescript {{$wmiDomain = (gwmi WIN32_ComputerSystem).Domain; $wmiDomain}} 
 if ($curentdomain -ne $domainname){{
    InlineScript {{  
    $password = ConvertTo-SecureString $Using:domainpass -AsPlainText -Force
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Using:domainuser, $Using:password    
    Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
    $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1''"'
    $pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
    Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn)
    $done=$false
    do{{
    try {{
        Add-Computer -DomainName $Using:domainname -Credential $cred -Restart:$true
        Start-Sleep 20
        ipconfig /flushdns
        }} catch {{Write-Output "`nWait DC...."}}
    }}
    while ($done -ne $true)
    }}    
 }}
 #setup server admins and scheduled job
 $curentdomain = Inlinescript {{$wmiDomain = (gwmi WIN32_ComputerSystem).Domain; $wmiDomain}} 
 if (($env:COMPUTERNAME -eq $newname) -and ($curentdomain -eq $domainname) -and ($env:USERDNSDOMAIN -ne ($curentdomain))) {{
 InlineScript {{  
    Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
    $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Scripts\Resume-Workflow.ps1''"'
    $pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
    Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn)
    }}
 $w = InlineScript {{$wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'";$wmiDomain}}
 $netbiosname = $w.DomainName

 InlineScript {{
    net Localgroup Administrators /add "$Using:netbiosname\sp-installer"
    net Localgroup Administrators /add "$Using:netbiosname\sp-farm"
    }}
  }}
 #Install Windows Features
 if (($env:COMPUTERNAME -eq $newname) -and ($curentdomain -eq $domainname) -and ($env:USERDNSDOMAIN -ne $curentdomain)) {{
    Set-DnsClientServerAddress -InterfaceIndex $ipif -ServerAddresses ($ipdns1,"8.8.8.8")    
    $RestartNeeded = InlineScript {{Import-Module ServerManager
    $WindowsFeatures = @(
			"Net-Framework-Features",
			"Web-Server",
			"Web-WebServer",
			"Web-Common-Http",
			"Web-Static-Content",
			"Web-Default-Doc",
			"Web-Dir-Browsing",
			"Web-Http-Errors",
			"Web-App-Dev",
			"Web-Asp-Net",
			"Web-Net-Ext",
			"Web-ISAPI-Ext",
			"Web-ISAPI-Filter",
			"Web-Health",
			"Web-Http-Logging",
			"Web-Log-Libraries",
			"Web-Request-Monitor",
			"Web-Http-Tracing",
			"Web-Security",
			"Web-Basic-Auth",
			"Web-Windows-Auth",
			"Web-Filtering",
			"Web-Digest-Auth",
			"Web-Performance",
			"Web-Stat-Compression",
			"Web-Dyn-Compression",
			"Web-Mgmt-Tools",
			"Web-Mgmt-Console",
			"Web-Mgmt-Compat",
			"Web-Metabase",
			"Application-Server",
			"AS-Web-Support",
			"AS-TCP-Port-Sharing",
			"AS-WAS-Support",
			"AS-HTTP-Activation",
			"AS-TCP-Activation",
			"AS-Named-Pipes",
			"AS-Net-Framework",
			"WAS",
			"WAS-Process-Model",
			"WAS-NET-Environment",
			"WAS-Config-APIs",
			"Web-Lgcy-Scripting",
			"Windows-Identity-Foundation",
			"Server-Media-Foundation",
			"Xps-Viewer"
        )
    $myCommand = 'Add-WindowsFeature ' + [string]::join(",",$WindowsFeatures) 
    $operation = Invoke-Expression $myCommand; $operation.RestartNeeded}}
    #Disable UAC
    New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
    Restart-Computer -Wait -Force

    InlineScript {{
    $password = ConvertTo-SecureString $Using:domainpass -AsPlainText -Force
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist "$Using:netbiosname\sp-installer", $password
    Start-Process powershell.exe -Credential $cred -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command C:\Scripts\sp-install-backend.ps1 -domain $Using:domainname -pass '$Using:domainpass'  -passphrase 'eeM8oo41' -SQLName '$Using:SQLName'"
    }}
             
 }}
    InlineScript {{
    Write-Output "`nWorkflow completed... please wait external script..."
    }}
    
}}
$user = "Administrator"
$newname = "{hostname}"
$pass = "{password}"
$ipdns1 = "{dc}"
$ipdns2 = "{dc}"
$ipif = (Get-NetAdapter).ifIndex
$ScriptPath = "c:\Scripts\" 
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
if (!(Test-Path "c:\Scripts\sp-install-backend.ps1")){{    if (!(Test-Path "c:\Scripts\")) {{mkdir "c:\Scripts\"}}    
    $source = "http://cubes-scripts.s3.amazonaws.com/sp-install-backend.ps1"    $destination = "c:\Scripts\sp-install-backend.ps1"     Invoke-WebRequest $source -OutFile $destination
    $source = "http://cubes-scripts.s3.amazonaws.com/create-shtask.ps1"    $destination = "c:\Scripts\create-shtask.ps1"     Invoke-WebRequest $source -OutFile $destination


}}

if ($env:COMPUTERNAME -ne $newname) {{
      Set-DnsClientServerAddress -InterfaceIndex $ipif -ServerAddresses ($ipdns1,$ipdns2)
      net user $user $pass
      Rename-Computer -Newname $newname -Force -Passthru  
      New-Item $ScriptPath -ItemType file -Name "Resume-Workflow.ps1" -Force -Value "Import-Module PSWorkflow
      Get-Job | Resume-Job
      Get-Job | Receive-Job"
      # add startup script for resume worflow    
      #$password = ConvertTo-SecureString $pass -AsPlainText -Force
      #$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $password
      Start-Process powershell.exe -verb runas -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command C:\Scripts\create-shtask.ps1 -user '$user' -pass '$pass'  -newname '$newname'"   
      Start-Sleep 20
      Restart-Computer -Force
}}

Rename-Restart-AddToDomain-Backend

</powershell>
