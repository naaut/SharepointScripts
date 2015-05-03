
 Param (
[string]$pass,
[string]$user,
[string]$newname
)
 #Start-Transcript -path "C:\Scrits\InstallLog.txt" -append
 $actionscript = '-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -NoExit -Command "&''C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1''"'
 $pstart =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
 $act = New-ScheduledTaskAction -Execute $pstart -Argument $actionscript
 Get-ScheduledTask -TaskName "Resume-Reboot" | Unregister-ScheduledTask -Confirm:$false -ErrorAction:Continue
 Register-ScheduledTask -TaskName "Resume-Reboot" -Action $act -Trigger (New-JobTrigger -AtLogOn)  -User $user -Password $pass
 REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v AutoAdminLogon /t REG_SZ /d 1
 REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultUserName /t REG_SZ /d $user
 REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" /f /v DefaultPassword /t REG_SZ /d $pass 
 #$AtLonOn = New-JobTrigger -AtLogOn
 #Register-ScheduledJob -Name ScriptStart -Trigger $AtLonOn -ScriptBlock  {& 'C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1'}      