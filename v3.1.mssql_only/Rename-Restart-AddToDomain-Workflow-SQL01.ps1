<powershell>

workflow Rename-Restart-AddToDomain-SQL {{

$user = "Administrator"
$pass = "{password}"
$domainuser = "Administrator"
$domainpass = "{password}"
$domainname = "{domainname}"
$newname = "{hostname}"
$ScriptPath = "c:\Scripts\"
$SQLName01 = "{dbhost01}" 
$SQLName02 = "{dbhost02}"
$SQLName03 = "{dbhost03}"
$ipdns1 = "{dc}"
$ipdns2 = "{dc}"
$SqlAdmin = "{sqluser}"
$SqlBases = "{dbs}"

$curentdomain = Inlinescript {{$wmiDomain = (gwmi WIN32_ComputerSystem).Domain; $wmiDomain}}
$NIC = Inlinescript {{$neta=Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName . | ? {{$_.IPEnabled}};$neta}} 

if ($curentdomain -ne $domainname)
    {{
    $logfolder = "c:\Logs\sqlmaster.log"
    }}
else
    {{    
    $logfolder = "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\sqlmaster.log"
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

      Write-Output "`n::::"  |  Out-File $Using:logfolder -Append default
      Write-Output "`nRename Computer Start..." |  Out-File $Using:logfolder -Append default
      Write-Output "`n::::" |  Out-File $Using:logfolder -Append default

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

    Write-Output "`n::::"  |  Out-File $Using:logfolder -Append default
    Write-Output "`nAdd Computer to Domain..." |  Out-File $Using:logfolder -Append default
    Write-Output "`n::::" |  Out-File $Using:logfolder -Append  default

    $password = ConvertTo-SecureString $Using:domainpass -AsPlainText -Force
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Using:domainuser, $password    

    $done=$false
    do{{
      try {{
        Add-Computer -DomainName $Using:domainname -Credential $cred -Restart:$true
        Write-Output "`nWait DC...." |  Out-File $Using:logfolder -Append default
        Start-Sleep 20
        ipconfig /flushdns
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
 $Username1 = "$netbiosname\$SqlAdmin"
 $Username3 = "$netbiosname\sql-server"

 start-job -Name SetupSQLService -ScriptBlock {{

    Write-Output "`n::::"  |  Out-File $Using:logfolder -Append default
    Write-Output "`nSetup firewall and SQL Service account..." |  Out-File $Using:logfolder -Append default
    Write-Output "`n::::" |  Out-File $Using:logfolder -Append default

    netsh firewall set portopening protocol = TCP port = 1433 name = SQLPort mode = ENABLE scope = ALL profile = ALL
    netsh firewall set portopening protocol = TCP port = 5022 name = SQLPort mode = ENABLE scope = ALL profile = ALL
    net Localgroup Administrators /add "$Using:netbiosname\sql-server"
    net Localgroup Administrators /add "$Using:netbiosname\$Using:SqlAdmin"
    #net Localgroup Administrators /add "$Using:Username1"
    #net Localgroup Administrators /add "$Using:Username2"
    $sqlservice=(Get-Service *SQLServer).Name 
    $LocalSrv = Get-WmiObject Win32_service -filter "name='$sqlservice'"
    $LocalSrv.Change($null,$null,$null,$null,$null,$false,"$Using:netbiosname\sql-server","$Using:pass")
    Restart-Service $sqlservice
    }}
 Wait-Job -Name SetupSQLService
 InlineScript {{

    Write-Output "`n::::"  |  Out-File $Using:logfolder -Append default
    Write-Output "`nSetup SQL Server..." |  Out-File $Using:logfolder -Append default
    Write-Output "`n::::" |  Out-File $Using:logfolder -Append default

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
    $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, $Using:Username3
    $SqlUser.LoginType = 'WindowsUser'
    $SqlUser.Create()
    $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, "$Using:netbiosname\$Using:SQLName02$"
    $SqlUser.LoginType = 'WindowsUser'
    $SqlUser.Create()
    $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, "$Using:netbiosname\$Using:SQLName01$"
    $SqlUser.LoginType = 'WindowsUser'
    $SqlUser.Create()
    #setup tcp
    $wmi = new-object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer
    $uri = "ManagedComputer[@Name='" + (get-item env:\computername).Value + "']/ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='Tcp']"
    $Tcp = $wmi.GetSmoObject($uri)
    $Tcp.IsEnabled = $true
    $Tcp.Alter()

    Write-Output "`n::::"  |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`nCreate Endpoint..." |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`n::::" |  Out-File "FileSystem::\\$Using:logfolder" -Append default

    #createENDpoint
    $mirroringRole = [Microsoft.SqlServer.Management.Smo.ServerMirroringRole]::Partner
    $endPointName = "Database_Mirroring_5022"
    $endpoint  = new-object ('Microsoft.SqlServer.Management.Smo.EndPoint')('(local)', $endPointName)
    $endpoint.ProtocolType = [Microsoft.SqlServer.Management.Smo.ProtocolType]::Tcp
    $endpoint.EndpointType = [Microsoft.SqlServer.Management.Smo.EndpointType]::DatabaseMirroring
    $endpoint.Protocol.Tcp.ListenerPort = "5022"  
    $endpoint.Payload.DatabaseMirroring.ServerMirroringRole = $mirroringRole
    $endpoint.Create()
    $endpoint.Start()

    Write-Output "`n::::"  |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`nSetup Endpoint Rules..." |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`n::::" |  Out-File "FileSystem::\\$Using:logfolder" -Append default

    Invoke-Sqlcmd -Query "GRANT CONNECT on ENDPOINT::Database_Mirroring_5022 TO [$Using:Username3];" -ServerInstance "(local)"
    Invoke-Sqlcmd -Query "GRANT CONNECT on ENDPOINT::Database_Mirroring_5022 TO [$Using:Username1];" -ServerInstance "(local)"
    Invoke-Sqlcmd -Query "GRANT CONNECT on ENDPOINT::Database_Mirroring_5022 TO [$Using:netbiosname\$Using:SQLName02$];" -ServerInstance "(local)"
    Invoke-Sqlcmd -Query "GRANT CONNECT on ENDPOINT::Database_Mirroring_5022 TO [$Using:netbiosname\$Using:SQLName01$];" -ServerInstance "(local)"

    Write-Output "`n::::"  |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`nCreate shared folder for backups..." |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`n::::" |  Out-File "FileSystem::\\$Using:logfolder" -Append default

    #Create SharedFolder for Backup
    if (!(Test-Path "C:\SQLBackups\")){{        mkdir "C:\SQLBackups\"
        New-SmbShare -Name SQLBackups -Path "C:\SQLBackups\"
        }}
    
    #Create Empty DBs

    Write-Output "`n::::"  |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`nCreating Databases..." |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`n::::" |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    
    $tmp=$Using:SqlBases;    
    $eDbs = $tmp.Split(':');
    $SqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server ("(local)")

    foreach ($edbn in $eDbs)
        {{
        $edb = New-Object Microsoft.SqlServer.Management.Smo.Database($SqlServer, $edbn)
        $edb.Create()
        $edb.SetOwner($Using:Username1,$TRUE)
        $edb.RecoveryModel="Full"
        $edb.Alter()
        $t=$edb.CreateDate
        Write-Output "`nDatabase $edb created at $t..." |  Out-File "FileSystem::\\$Using:logfolder" -Append default
        }}

    #SetupMirroring
       
    $dtm = Date
    Write-Output "`n::::"  |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`nStart creating mirooring  $dtm..." |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`n::::" |  Out-File "FileSystem::\\$Using:logfolder" -Append default

    $password = ConvertTo-SecureString "$Using:pass" -AsPlainText -Force
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist "$Using:netbiosname\sp-installer", $password
    
    #SetupMirroring
    do{{
    $done=$true
    $SqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server ("(local)")
    $dbs = $SQLServer.Databases
        foreach ($db in $dbs)
            {{
            if (($db.Name -notlike'master') -and ($db.Name -notlike'model') -and ($db.Name -notlike'msdb') -and ($db.Name -notlike'tempdb'))
                {{
                    $dbname=$db.Name
                    if (!($db.IsMirroringEnabled) -or !($db.MirroringWitness)){{
                        #Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command C:\Scripts\Invoke-Mirror.ps1 -Database $dbname -SourceServer '$Using:SQLName01.$Using:domainname' -DestServer '$Using:SQLName02.$Using:domainname' -WitnessServer 'none'"
                        Start-Process powershell.exe  -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -Command C:\Scripts\Invoke-Mirror.ps1 -Database $dbname -SourceServer '$Using:SQLName01.$Using:domainname' -DestServer '$Using:SQLName02.$Using:domainname' -WitnessServer '$Using:SQLName03.$Using:domainname'"
                        Start-Sleep 40
                    }}
                    $done=($done -AND $db.IsMirroringEnabled -AND ($db.MirroringWitness))
                }}
            }}
      $done
      }}
      while ($done -ne $true)

      Date |  Out-File $Using:logfolder -Append
      Write-Output "`n::::"  |  Out-File "FileSystem::\\$Using:logfolder" -Append default
      Write-Output "`nMirroring Setup completed..." |  Out-File "FileSystem::\\$Using:logfolder" -Append default
      Write-Output "`n::::" |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    }}

  }}
#after config SQL Zone
    InlineScript {{
         
    Write-Output "`n::::"  |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`nStart Cleaning..." |  Out-File "FileSystem::\\$Using:logfolder" -Append default
    Write-Output "`n::::" |  Out-File "FileSystem::\\$Using:logfolder" -Append default


    Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName
    REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword
    rm -Path C:\Scripts\ -Confirm:$false -Recurse -Force
    rm -Path C:\SQLBackups\ -Confirm:$false -Recurse -Force
    rm -Path "\\$Using:SQLName02.$Using:domainname\c$\SQLBackups\*.*" -Confirm:$false -Recurse -Force
    #Copy-Item -Path "C:\Logs\*.*" -Destination "\\$Using:ipdns1\Logs\" 
    Shutdown -l
    }}
#Stop-Transcript
}}

$domainname = "{domainname}"
$curentdomain = (gwmi WIN32_ComputerSystem).Domain

if ($curentdomain -ne $domainname)
    {{

    if (!(Test-Path "c:\Logs\")){{mkdir "c:\Logs\"}}
    Start-Transcript -Path "c:\Logs\sqlmaster.log" -Append

    if (!(Test-Path "c:\Scripts\")) 
        {{
        Write-Output "`n::::"
        Write-Output "`nDownloads Scripts Files..."
        Write-Output "`n::::"
        mkdir "c:\Scripts\" 
        $source = "http://cubes-scripts.s3.amazonaws.com/v3.0/Invoke-Mirror.ps1"        $destination = "c:\Scripts\Invoke-Mirror.ps1"         Invoke-WebRequest $source -OutFile $destination
        }}

    Write-Output "`n::::"
    Write-Output "`nStarting Workflow..."
    Write-Output "`n::::"

    Stop-Transcript
    }}

else 
   {{
   $NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName . | ? {{$_.IPEnabled}}

   if (!(Test-Path "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\sqlmaster.log")) 
       {{
       
       Write-Output "`n::::"   |  Out-File "C:\Logs\sqlmaster.log" -Append default
       Write-Output "`nCopy log file to DC..."   |  Out-File "C:\Logs\sqlmaster.log" -Append default
       Write-Output "`n::::"  |  Out-File "C:\Logs\sqlmaster.log" -Append default
       
       Copy-Item -Path "C:\Logs\sqlmaster.log" -Destination "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\"

       Write-Output "`n::::"  |  Out-File "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\sqlmaster.log" -Append default
       Write-Output "`nFile copied..."  |  Out-File "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\sqlmaster.log" -Append default
       Write-Output "`n::::"  |  Out-File "\\$($NIC.DNSServerSearchOrder | Select -First 1)\Logs\sqlmaster.log" -Append default
       }}
   }}


Rename-Restart-AddToDomain-SQL

</powershell>