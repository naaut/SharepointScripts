<powershell>

workflow Rename-Restart-AddToDomain-Frontend {{
$user = "Administrator"
$pass = "{password}"
$domainuser = "Administrator"
$domainpass = "{password}"
$domainname = "{domainname}"
$newname = "{hostname}"
$ScriptPath = "c:\Scripts\"
$SQLName01 = "{dbhost01}" 
$SQLName02 = "{dbhost02}"
$ipdns1 = "{dc}"
$ipdns2 = "{dc}"

$curentdomain = Inlinescript {{$wmiDomain = (gwmi WIN32_ComputerSystem).Domain; $wmiDomain}}
$NIC = Inlinescript {{$neta=Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName . | ? {{$_.IPEnabled}};$neta}} 

if ($curentdomain -ne $domainname)
    {{
    $logfolder = "c:\Logs\frontend.log"
    }}
else
    {{    
    $logfolder = "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\frontend.log"
    }}

$ipif = (Get-NetAdapter).ifIndex 
Set-DnsClientServerAddress -InterfaceIndex $ipif -ServerAddresses ($ipdns1,$ipdns2)
# set password
#Write-Output "`nSetting password ..."
net user $user $pass
#rename computer and restart
if ($env:COMPUTERNAME -ne $newname) {{
  Rename-Computer -Newname $newname -Force -Passthru
      InlineScript {{

      Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File $Using:logfolder -Append default
      Write-Output "`nRename Computer Start..." | Out-File $Using:logfolder -Append default
      Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File $Using:logfolder -Append default

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
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File $Using:logfolder -Append default
    Write-Output "`nAdd to Domain Computer Start..." | Out-File $Using:logfolder -Append default
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File $Using:logfolder -Append default    
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
        Write-Output "`nWait DC...." | Out-File $Using:logfolder -Append default 
        Start-Sleep 20
        ipconfig /flushdns
        }} catch {{Write-Output "`nWait DC...."}}
    }}
    while ($done -ne $true)
    }}
 }}
 #setup server admins
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
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File $Using:logfolder -Append default
    Write-Output "`nAdd sp-installer and sp-farm to local Administrators group..." | Out-File $Using:logfolder -Append default
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File $Using:logfolder -Append default  
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
    New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
    Restart-Computer -Wait -Force
    #setup Sharepoint
    InlineScript {{

    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File $Using:logfolder -Append default
    Write-Output "`nStart External Script for promotion BackEnd Server ..." | Out-File $Using:logfolder -Append default
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File $Using:logfolder -Append default 

    $password = ConvertTo-SecureString $Using:domainpass -AsPlainText -Force
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist "$Using:netbiosname\sp-installer", $password
    Start-Process powershell.exe -Credential $cred -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command C:\Scripts\sp-install-frontend.ps1 -domain '$Using:domainname' -pass '$Using:domainpass'  -passphrase 'eeM8oo41' -SQLName01 '$Using:SQLName01' -SQLName02 '$Using:SQLName02'"
    }}
             
 }}
#after all script zone
    InlineScript {{   
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File $Using:logfolder -Append default
    Write-Output "`nWorkflow completed... please wait external script..."  | Out-File $Using:logfolder -Append default
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File $Using:logfolder -Append default
    }}
    
}}


$domainname = "{domainname}"
$curentdomain = (gwmi WIN32_ComputerSystem).Domain

if ($curentdomain -ne $domainname)
    {{
    if (!(Test-Path "c:\Logs\")){{mkdir "c:\Logs\"}}
    Start-Transcript -Path "c:\Logs\frontend.log" -Append

    $user = "Administrator"
    $newname = "{hostname}"
    $pass = "{password}"
    $ipdns1 = "{dc}"
    $ipdns2 = "{dc}"
    $ipif = (Get-NetAdapter).ifIndex
    $ScriptPath = "c:\Scripts\" 
    New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
    if (!(Test-Path "c:\Scripts\sp-install-frontend.ps1"))        {{        Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
        Write-Output "`nDownloads Scripts Files..."
        Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"        if (!(Test-Path "c:\Scripts\")) {{mkdir "c:\Scripts\"}}    
        $source = "http://cubes-scripts.s3.amazonaws.com/v3.1/sp-install-frontend.ps1"        $destination = "c:\Scripts\sp-install-frontend.ps1"         Invoke-WebRequest $source -OutFile $destination -Verbose
        $source = "http://cubes-scripts.s3.amazonaws.com/v3.1/create-shtask.ps1"        $destination = "c:\Scripts\create-shtask.ps1"         Invoke-WebRequest $source -OutFile $destination -Verbose
        
        }}

   if ($env:COMPUTERNAME -ne $newname) 
        {{

        Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" 
        Write-Output "`nRename computer and create Scheduled Task..." 
        Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
        
        Set-DnsClientServerAddress -InterfaceIndex $ipif -ServerAddresses ($ipdns1,$ipdns2) -Verbose
        net user $user $pass
        Rename-Computer -Newname $newname -Force -Passthru -Verbose 
        New-Item $ScriptPath -ItemType file -Name "Resume-Workflow.ps1" -Force -Value "Import-Module PSWorkflow
        Get-Job | Resume-Job
        Get-Job | Receive-Job"
        # add startup script for resume worflow    
        $password = ConvertTo-SecureString $pass -AsPlainText -Force
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $password
        Start-Process powershell.exe -verb runas -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command C:\Scripts\create-shtask.ps1 -user '$user' -pass '$pass'  -newname '$newname'" -Verbose
        Start-Sleep 20
        Restart-Computer -Force -Verbose
        }}

   Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
   Write-Output "`nStarting Workflow..."
   Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

   Stop-Transcript
   }}
else 
   {{
   $NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName . | ? {{$_.IPEnabled}}

   if (!(Test-Path "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\frontend.log")) 
       {{
       
       Write-Output "`n::::"   |  Out-File "C:\Logs\frontend.log" -Append default
       Write-Output "`nCopy log file to DC..."   |  Out-File "C:\Logs\frontend.log" -Append default
       Write-Output "`n::::"  |  Out-File "C:\Logs\frontend.log" -Append default
       
       Copy-Item -Path "C:\Logs\frontend.log" -Destination "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\"

       Write-Output "`n::::"  |  Out-File "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\frontend.log" -Append default
       Write-Output "`nFile copied..."  |  Out-File "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\frontend.log" -Append default
       Write-Output "`n::::"  |  Out-File "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\frontend.log" -Append default
       }}
   }}

Rename-Restart-AddToDomain-Frontend

</powershell>
