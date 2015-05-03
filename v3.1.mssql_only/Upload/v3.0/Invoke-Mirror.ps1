<#
     .SYNOPSIS
          Set up a mirrored database
     .DESCRIPTION
          Backs up a database and tlog, copies it to the destination,
          Restores the database on the mirror server, sets up the partner,
          and starts the mirror.
     .PARAMETER  database
          The name of the database to be mirrored
     .PARAMETER  SourceServer
          The name of the primary server
     .PARAMETER  SourcePath
          Local Path for the backup
     .PARAMETER  DestServer
          The name of mirror server
     .PARAMETER  DestPath
          Local path for restore file
     .PARAMETER  WitnessServer
          The name of the witness server. Use "none" value if witness not need.
     .EXAMPLE
          PS C:\> Invoke-Mirror -database 'string value' 1
                    -SourceServer 'string\string' -SourcePath 'string' `
                    -DestServer 'string\string' -DestPath 'string' -WitnessServer 'string\string'
#>
Param(
    [Parameter(Mandatory=$true)]
    [string]$database,
    [string]$SourceServer='mssql01',
    [string]$SourcePath='C:\SQLBackups\',
    [string]$DestServer='mssql02',
    [string]$DestPath='C:\SQLBackups\',
    [string]$WitnessServer='none'
    )
Set-StrictMode -Version 2
[Void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo")
[Void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
[Void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
Function Get-FileName {
    Param([string]$path)
    $names = $path.Split('\\')
    $names[$names.Count - 1]
}


Function New-SMOconnection {
    Param (
        [string]$server
    )
    $conn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection($server)
    $conn.applicationName = "PowerShell SMO"
    $conn.StatementTimeout = 0
    $conn.Connect()
    if ($conn.IsOpen -eq $false) {
        Throw "Could not connect to server $($server) for database backup of $($dbname)."
    }
    $smo = New-Object Microsoft.SqlServer.Management.Smo.Server($conn)
    $smo
}
Function Invoke-SqlBackup {
    $dbbk = new-object ('Microsoft.SqlServer.Management.Smo.Backup')
    $dbbk.Action = [Microsoft.SqlServer.Management.Smo.BackupActionType]::Database
    $dbbk.BackupSetDescription = "Full backup of " + $database
    $dbbk.BackupSetName = $database + " Backup"
    $dbbk.Database = $database
    $dbbk.MediaDescription = "Disk"
    $device = "$SourcePath\$bkpfile"
    $dbbk.Devices.AddDevice($device, 'File')
    $smo = New-SMOconnection -server $SourceServer
    Try {
        $dbbk.SqlBackup($smo)
        $dbbk.Action = [Microsoft.SqlServer.Management.Smo.BackupActionType]::Log
        $dbbk.SqlBackup($smo)
        $smo.ConnectionContext.Disconnect()
    }
    Catch {
        $ex = $_.Exception
        Write-Output $ex.message
        $ex = $ex.InnerException
        while ($ex.InnerException)
        {
            Write-Output $ex.InnerException.message
            $ex = $ex.InnerException
        };
        continue
    }
    Finally {
        if ($smo.ConnectionContext.IsOpen -eq $true) {
            $smo.ConnectionContext.Disconnect()
        }
    }
}
Function Invoke-SqlRestore {
    Param(
        [string]$filename
    )
    # Get a new connection to the server
    $smo = New-SMOconnection -server $DestServer
    $backupDevice = New-Object("Microsoft.SqlServer.Management.Smo.BackupDeviceItem") ($filename, "File")
    # Get local paths to the Database and Log file locations
    If ($smo.Settings.DefaultFile.Length -eq 0) {$DBPath = $smo.Information.MasterDBPath }
    Else { $DBPath = $smo.Settings.DefaultFile}
    If ($smo.Settings.DefaultLog.Length -eq 0 ) {$DBLogPath = $smo.Information.MasterDBLogPath }
    Else { $DBLogPath = $smo.Settings.DefaultLog}
    foreach ($base in $smo.Databases){
        if (($base.Name -like $database)) {
             Invoke-Sqlcmd -Query "ALTER DATABASE $database SET PARTNER OFF;" -ServerInstance $DestServer }
    }
 
    # Load up the Restore object settings
    $Restore = new-object Microsoft.SqlServer.Management.Smo.Restore
    $Restore.Action = 'Database'
    $Restore.Database = $database
    $Restore.ReplaceDatabase = $true
    $Restore.NoRecovery = $true
    $Restore.Devices.Add($backupDevice)
 
    # Get information from the backup file
    $RestoreDetails = $Restore.ReadBackupHeader($smo)
    $DataFiles = $Restore.ReadFileList($smo)
 
    # Restore all backup files
    ForEach ($DataRow in $DataFiles) {
        $LogicalName = $DataRow.LogicalName
        $PhysicalName = Get-FileName -path $DataRow.PhysicalName
        $RestoreData = New-Object("Microsoft.SqlServer.Management.Smo.RelocateFile")
        $RestoreData.LogicalFileName = $LogicalName
        if ($DataRow.Type -eq "D") {
            # Restore Data file
            $RestoreData.PhysicalFileName = $DBPath + "\" + $PhysicalName
        }
        Else {
            # Restore Log file
            $RestoreData.PhysicalFileName = $DBLogPath + "\" + $PhysicalName
        }
        [Void]$Restore.RelocateFiles.Add($RestoreData)
 
    }
    Try {
    $Restore.SqlRestore($smo)
    # If there are two files, assume the next is a Log
    if ($RestoreDetails.Rows.Count -gt 1) {
        $Restore.Action = [Microsoft.SqlServer.Management.Smo.RestoreActionType]::Log
        $Restore.FileNumber = 2
        $Restore.SqlRestore($smo)
    }
        $smo.ConnectionContext.Disconnect()
    }
    Catch {
        $ex = $_.Exception
        Write-Output $ex.message
        $ex = $ex.InnerException
        while ($ex.InnerException)
        {
            Write-Output $ex.InnerException.message
            $ex = $ex.InnerException
        };
        continue
    }
    Finally {
        if ($smo.ConnectionContext.IsOpen -eq $true) {
            $smo.ConnectionContext.Disconnect()
        }
    }
}
Function Set-Mirror {
    Param([string]$server,[string]$database,[string]$partner,[string]$witness)
    $conn = "Server=$server; Integrated Security=SSPI; Database=Master"
    $cn = New-Object "System.Data.SqlClient.SqlConnection" $conn
    $cn.Open()
    $cmd = New-Object "System.Data.SqlClient.SqlCommand"
    $cmd.CommandType = [System.Data.CommandType]::Text
 
    $cmd.CommandText = "ALTER DATABASE $database SET PARTNER = 'TCP://" + $partner + ":5022'"
    $cmd.Connection = $cn
    $cmd.ExecuteNonQuery()
    if ($witness -ne "none"){
    $cmd.CommandText = "ALTER DATABASE $database SET WITNESS = 'TCP://" + $witness + ":5022'"
    $cmd.ExecuteNonQuery()
    }
    $cn.Close()


    Trap {
        $ex = $_.Exception
        Write-Output $ex.message
        $ex = $ex.InnerException
        while ($ex.InnerException)
        {
            Write-Output $ex.InnerException.message
            $ex = $ex.InnerException
        };
        continue
    }
}
$srcUNC = Join-Path "\\$($SourceServer.Split('\\')[0])" $($SourcePath.Replace(':','$'))
if (-not(Test-Path $srcUNC)) { New-Item $srcUNC -ItemType directory | Out-Null}
$destUNC = Join-Path "\\$($DestServer.Split('\\')[0])" $($DestPath.Replace(':','$'))
if (-not(Test-Path $destUNC)) { New-Item $destUNC -ItemType directory | Out-Null}
$bkpfile = $($SourceServer.Replace("\", "$")) + "_" + $database + "_FULL_" + $(get-date -format yyyyMMdd-HHmmss) + ".bak"
Invoke-SqlBackup -filename $bkpfile
Copy-Item $(Join-Path $srcUNC $bkpfile) -Destination $destUNC -Verbose
Invoke-SqlRestore -filename $(Join-Path $DestPath $bkpfile)
# Establish Mirroring from the mirrored database
Set-Mirror -server $DestServer -database $database -partner $($SourceServer.Split('\\')[0]) -witness "none"
# Start the mirror
Set-Mirror -server $SourceServer -database $database -partner $($DestServer.Split('\\')[0]) -witness $WitnessServer
