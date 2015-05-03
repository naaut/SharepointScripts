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
$SQLName01 = "{dbhost01}" 
$SQLName02 = "{dbhost02}"
$SQLName03 = "{dbhost03}"
$ipif = (Get-NetAdapter).ifIndex 
Set-DnsClientServerAddress -InterfaceIndex $ipif -ServerAddresses ($ipdns1,$ipdns2)

# set password
#Write-Output "`nSetting password ..."
net user $user $pass
#rename computer and restart
if ($env:COMPUTERNAME -ne $newname) {{
  Rename-Computer -Newname $newname -Force -Passthru
      InlineScript {{

      Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\sqlwitness.log" -Append
      Write-Output "`nRename Computer Start..." | Out-File "C:\Logs\sqlwitness.log" -Append
      Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\sqlwitness.log" -Append

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

    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`nAdd Computer to Domain..." | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\sqlwitness.log" -Append  

    $password = ConvertTo-SecureString $Using:domainpass -AsPlainText -Force
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Using:domainuser, $password    

    $done=$false
    do{{
      try {{
        Add-Computer -DomainName $Using:domainname -Credential $cred -Restart:$true
        Write-Output "`nWait DC...." | Out-File "C:\Logs\sqlwitness.log" -Append 
        Start-Sleep 20
        ipconfig /flushdns
        Start-Sleep 20
        }} catch {{Start-Sleep 20}}
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
 $Username3 = "$netbiosname\sql-server"
 $Username4 = "$netbiosname\sp-webapp"

 start-job -Name SetupSQLService -ScriptBlock {{

    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`nSetup firewall and SQL Service account..." | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\sqlwitness.log" -Append

    netsh firewall set portopening protocol = TCP port = 1433 name = SQLPort mode = ENABLE scope = ALL profile = ALL
    netsh firewall set portopening protocol = TCP port = 5022 name = SQLPort mode = ENABLE scope = ALL profile = ALL
    net Localgroup Administrators /add "$Using:netbiosname\sql-server"
    net Localgroup Administrators /add "$Using:netbiosname\sp-installer"
    #net Localgroup Administrators /add "$Using:Username1"
    #net Localgroup Administrators /add "$Using:Username2"
    $sqlservice=(Get-Service *SQLServer).Name 
    $LocalSrv = Get-WmiObject Win32_service -filter "name='$sqlservice'"
    $LocalSrv.Change($null,$null,$null,$null,$null,$false,"$Using:netbiosname\sql-server","$Using:pass")
    Restart-Service $sqlservice
    }}
 Wait-Job -Name SetupSQLService
 InlineScript {{

    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`nSetup SQL Server..." | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\sqlwitness.log" -Append

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
    $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, $Using:Username3
    $SqlUser.LoginType = 'WindowsUser'
    $SqlUser.Create()
    $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, $Using:Username4
    $SqlUser.LoginType = 'WindowsUser'
    $SqlUser.Create()
    $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, "$Using:netbiosname\$Using:SQLName01$"
    $SqlUser.LoginType = 'WindowsUser'
    $SqlUser.Create()
    $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, "$Using:netbiosname\$Using:SQLName02$"
    $SqlUser.LoginType = 'WindowsUser'
    $SqlUser.Create()
    #setup tcp
    $wmi = new-object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer
    $uri = "ManagedComputer[@Name='" + (get-item env:\computername).Value + "']/ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='Tcp']"
    $Tcp = $wmi.GetSmoObject($uri)
    $Tcp.IsEnabled = $true
    $Tcp.Alter()

    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`nCreate Endpoint..." | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\sqlwitness.log" -Append

    #createENDpoint
    $mirroringRole = [Microsoft.SqlServer.Management.Smo.ServerMirroringRole]::Witness
    $endPointName = "Database_Mirroring_5022"
    $endpoint  = new-object ('Microsoft.SqlServer.Management.Smo.EndPoint')('(local)', $endPointName)
    $endpoint.ProtocolType = [Microsoft.SqlServer.Management.Smo.ProtocolType]::Tcp
    $endpoint.EndpointType = [Microsoft.SqlServer.Management.Smo.EndpointType]::DatabaseMirroring
    $endpoint.Protocol.Tcp.ListenerPort = "5022"  
    $endpoint.Payload.DatabaseMirroring.ServerMirroringRole = $mirroringRole
    $endpoint.Create()
    $endpoint.Start()    
    
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`nSetup Endpoint Rules..." | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\sqlwitness.log" -Append
    
    Invoke-Sqlcmd -Query "GRANT CONNECT on ENDPOINT::Database_Mirroring_5022 TO [$Using:Username3];" -ServerInstance "(local)"
    Invoke-Sqlcmd -Query "GRANT CONNECT on ENDPOINT::Database_Mirroring_5022 TO [$Using:Username1];" -ServerInstance "(local)"
    Invoke-Sqlcmd -Query "GRANT CONNECT on ENDPOINT::Database_Mirroring_5022 TO [$Using:netbiosname\$Using:SQLName01$];" -ServerInstance "(local)"
    Invoke-Sqlcmd -Query "GRANT CONNECT on ENDPOINT::Database_Mirroring_5022 TO [$Using:netbiosname\$Using:SQLName02$];" -ServerInstance "(local)"
    
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"  | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`nCreate shared folder for backups..." | Out-File "C:\Logs\sqlwitness.log" -Append
    Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::" | Out-File "C:\Logs\sqlwitness.log" -Append
    
    #Create SharedFolder for Backup
    if (!(Test-Path "C:\SQLBackups\")){{        mkdir "C:\SQLBackups\"
        New-SmbShare -Name SQLBackups -Path "C:\SQLBackups\"
        }}
    Restart-Service $sqlservice -Force
   
    }}

  }}
#after config SQL Zone
    InlineScript {{
    Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
    rm -Path C:\Scripts\ -Confirm:$false -Recurse -Force
    Copy-Item -Path "C:\Logs\*.*" -Destination "\\$Using:ipdns1\C$\Logs\" 
    Shutdown -l
    }}
}}

if (!(Test-Path "c:\Logs\")){{mkdir "c:\Logs\"}}
Start-Transcript -Path "c:\Logs\sqlwitness.log" -Append

if (!(Test-Path "c:\Scripts\")) {{
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nDownloads Scripts Files..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
mkdir "c:\Scripts\" 
$source = "http://cubes-scripts.s3.amazonaws.com/v3.0/Invoke-Mirror.ps1"$destination = "c:\Scripts\Invoke-Mirror.ps1" Invoke-WebRequest $source -OutFile $destination
}}

Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Output "`nStarting Workflow..."
Write-Output "`n:::::::::::::::::::::::::::::::::::::::::::::::::::::"

Stop-Transcript

Rename-Restart-AddToDomain-SQL

</powershell>

