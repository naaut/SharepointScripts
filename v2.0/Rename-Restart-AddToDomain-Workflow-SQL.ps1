<powershell>

workflow Rename-Restart-AddToDomain-SQL {{
$user = "Administrator"
$pass = "{password}"
$domainuser = "Administrator"
$domainpass = "{password}"
$domainname = "{domainname}"
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
      #create script for resume workflow
      New-Item $Using:ScriptPath -ItemType file -Name "Resume-Workflow.ps1" -Force -Value "Import-Module PSWorkflow
      Get-Job | Resume-Job
      Get-Job | Receive-Job"
      # add startup script for resume worflow    
      $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1''"'
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
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Using:domainuser, $password    
    #Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
    #$actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1''"'
    #$pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    #$act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
    #Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn)
    #REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
    #REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
    #REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName /t REG_SZ /d $Using:user
    #REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword /t REG_SZ /d $Using:pass
    $done=$false
    do{{
      try {{
        Add-Computer -DomainName $Using:domainname -Credential $cred -Restart:$true
        Start-Sleep 20
        ipconfig /flushdns
        Start-Sleep 20
        }} catch {{
        Write-Output "`nWorkflow completed... please wait external script..."
        Start-Sleep 30}}
      }}
    while ($done -ne $true)
    }}
   #Restart-Computer -Wait -Force
 }}
#setup sql server
 $curentdomain = Inlinescript {{$wmiDomain = (gwmi WIN32_ComputerSystem).Domain; $wmiDomain}} 
 if (($env:COMPUTERNAME -like "*SQL*") -and ($curentdomain -eq $domainname)) {{
 $w = InlineScript {{$wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'";$wmiDomain}}
 $netbiosname = $w.DomainName
 $ServerInstance = ".\MSSQLSERVER"
 $Username1 = "$netbiosname\sp-installer"
 $Username2 = "$netbiosname\sp-farm"

 start-job -Name SetupSQLService -ScriptBlock {{
    netsh firewall set portopening protocol = TCP port = 1433 name = SQLPort mode = ENABLE scope = SUBNET profile = CURRENT
    net Localgroup Administrators /add "$Using:netbiosname\sql-server"
    #net Localgroup Administrators /add "$Using:Username1"
    #net Localgroup Administrators /add "$Using:Username2"
    $sqlservice=(Get-Service *SQLServer).Name 
    $LocalSrv = Get-WmiObject Win32_service -filter "name='$sqlservice'"
    $LocalSrv.Change($null,$null,$null,$null,$null,$false,"$Using:netbiosname\sql-server","$Using:pass")
    Restart-Service $sqlservice
    }}
 Wait-Job -Name SetupSQLService
 InlineScript {{
    $sqlservice=(Get-Service *SQLServer).Name
    # add users 
    Import-Module -Name 'sqlps' -DisableNameChecking
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO')
    $SqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server ("(local)")
    $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, $Using:Username1
    $SqlUser.LoginType = 'WindowsUser'
    $SqlUser.Create()
    $SqlUser.AddToRole('sysadmin')
    $SqlUser.AddToRole('dbcreator')
    $SqlUser.AddToRole('securityadmin')
    $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, $Using:Username2
    $SqlUser.LoginType = 'WindowsUser'
    $SqlUser.Create()
    $SqlUser.AddToRole('sysadmin')
    $SqlUser.AddToRole('dbcreator')
    $SqlUser.AddToRole('securityadmin')
    #setup tcp
    $wmi = new-object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer
    $uri = "ManagedComputer[@Name='" + (get-item env:\computername).Value + "']/ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='Tcp']"
    $Tcp = $wmi.GetSmoObject($uri)
    $Tcp.IsEnabled = $true
    $Tcp.Alter()
    Restart-Service $sqlservice
    }}

  }}
#after config SQL Zone
    InlineScript {{
    Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
    rm -Path C:\Scripts\ -Confirm:$false -Recurse -Force
    Shutdown -l
    }}
}}

Rename-Restart-AddToDomain-SQL

</powershell>

