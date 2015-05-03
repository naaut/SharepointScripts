<powershell>

workflow Rename-Restart-AddToDomain-Backend {{
$user = "Administrator"
$pass = "{password}"
$domainuser = "Administrator"
$domainpass = "{password}"
$domainname = "test.com"
$newname = "{hostname}"
$ScriptPath = "c:\Scripts\" 
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
    $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Scripts\Resume-Workflow.ps1''"'
    $pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
    Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn)
    #REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
    #REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
    #REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName /t REG_SZ /d $Using:user
    #REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword /t REG_SZ /d $Using:pass
    $done=$false
    do{{
    try {{
    Add-Computer -DomainName $Using:domainname -Credential $cred -Restart:$true
    #$done=$true    
    ipconfig /flushdns
    Start-Sleep 20
    }} catch {{$done=$true}}
    }}
    while ($done -ne $true)
    }}    
 #Restart-Computer -Wait -Force
 }}
 #setup server admins
 $curentdomain = Inlinescript {{$wmiDomain = (gwmi WIN32_ComputerSystem).Domain; $wmiDomain}} 
 if (($env:COMPUTERNAME -eq $newname) -and ($curentdomain -eq $domainname) -and ($env:USERDNSDOMAIN -ne ($curentdomain))) {{
 $w = InlineScript {{$wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'";$wmiDomain}}
 $netbiosname = $w.DomainName
 #$ServerInstance = ".\MSSQLSERVER"
 #$Username1 = "$netbiosname\sp-installer"
 #$Username2 = "$netbiosname\sp-farm"
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
    InlineScript {{C:\SharePoint\PrerequisiteInstaller.exe /unattended | Out-Null}}
    Restart-Computer -Wait -Force
    InlineScript {{C:\SharePoint\PrerequisiteInstaller.exe /continue /unattended | Out-Null}}
    Restart-Computer -Wait -Force
    #InlineScript {{C:\SharePoint\PrerequisiteInstaller.exe /continue /unattended; Start-Sleep 120}}
    #Restart-Computer -Wait 

#config logon as sp-installer and restart
 <# 
     InlineScript {{
     $password = ConvertTo-SecureString $Using:domainpass -AsPlainText -Force
     $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Using:domainuser, $password    
     Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
     $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Scripts\UserScript.ps1''"'
     $pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
     $act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
     Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn) -User "$Using:netbiosname\sp-installer" -Password "$Using:domainpass"
     REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
     REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
     REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName /t REG_SZ /d "$Using:netbiosname\sp-installer"
     REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword /t REG_SZ /d $Using:domainpass
     }}
 Restart-Computer -Force #> 
    InlineScript {{C:\SharePoint\setup.exe /config C:\Scripts\Config.xml | Out-Null}}
    InlineScript {{
    $password = ConvertTo-SecureString $Using:domainpass -AsPlainText -Force
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist "$Using:netbiosname\sp-installer", $password
    Start-Process powershell.exe -Credential $cred -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command C:\Scripts\sp-install-backend.ps1 -domain $Using:domainname -pass '$Using:domainpass'  -passphrase 'eeM8oo41'"
    }}
             
 }}
 <#
 #after login sp-installer
 $curentdomain = Inlinescript {{$wmiDomain = (gwmi WIN32_ComputerSystem).Domain; $wmiDomain}}
 if ((Get-ScheduledTask -TaskName "Resume-Reboot") -and ($env:USERDNSDOMAIN -eq $curentdomain)) {{
     Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
     $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Scripts\UserScript.ps1''"'
     $pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
     $act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
     Register-ScheduledTask -TaskName "Resume-Reboot-02" -Action $act -Trigger (New-JobTrigger -AtLogOn)
     Restart-Computer -Force
     }} #>

#after all script zone
    InlineScript {{
    #Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
    #REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon
    #REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
    #REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
    #rm -Path C:\Sharepoint\ -Confirm:$false -Recurse -Force
    #rm -Path C:\Scripts\ -Confirm:$false -Recurse -Force
    #Enable UAC
    #New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 1 -Force
    #Shutdown -l
    Write-Output "`nWorkflow completed... please wait external script..."
    }}
    
}}


if (!(Test-Path "c:\Sharepoint\sharepoint.exe")){{    if (!(Test-Path "c:\Sharepoint\")) {{mkdir "c:\Sharepoint\"}}    $source = "http://cubes-scripts.s3.amazonaws.com/sharepoint.exe"    $destination = "c:\Sharepoint\sharepoint.exe"     Invoke-WebRequest $source -OutFile $destination
}}
if ((Test-Path "c:\Sharepoint\Sharepoint.exe") -and !(Test-Path "c:\Sharepoint\PrerequisiteInstaller.exe")){{
    c:\Sharepoint\Sharepoint.exe /quiet /extract:C:\Sharepoint\ 
    Start-Sleep 60
}}
if (!(Test-Path "c:\Scripts\config.xml")){{    if (!(Test-Path "c:\Scripts\")) {{mkdir "c:\Scripts\"}}    $source = "http://cubes-scripts.s3.amazonaws.com/Config.xml"    $destination = "c:\Scripts\Config.xml"     Invoke-WebRequest $source -OutFile $destination
    $source = "http://cubes-scripts.s3.amazonaws.com/sp-install-backend.ps1"    $destination = "c:\Scripts\sp-install-backend.ps1"     Invoke-WebRequest $source -OutFile $destination
}}
Rename-Restart-AddToDomain-Backend

</powershell>