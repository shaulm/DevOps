#Requires -Version 7.4
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates (or updates) the Windows scheduled task that runs the health check every morning.

.DESCRIPTION
    The task runs Invoke-MorningHealthCheck.ps1 with PowerShell 7 as the given account, whether or not
    anyone is logged on. Use the SAME account you used with Set-HealthCheckCredential.ps1, otherwise the
    stored credentials cannot be decrypted. The account needs the "Log on as a batch job" right.

.EXAMPLE
    .\Register-HealthCheckTask.ps1 -RunAs CONTOSO\svc-healthcheck -At 06:30

.EXAMPLE
    .\Register-HealthCheckTask.ps1 -RunAs CONTOSO\svc-healthcheck -At 06:45 -WeekdaysOnly
#>
[CmdletBinding()]
param(
    [string]$TaskName = 'Morning Health Check',
    [ValidatePattern('^\d{1,2}:\d{2}$')][string]$At = '06:30',
    [string]$RunAs = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    [switch]$WeekdaysOnly,
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$pwsh = Join-Path $PSHOME 'pwsh.exe'
$scriptPath = Join-Path $PSScriptRoot 'Invoke-MorningHealthCheck.ps1'
$arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`""
if ($ConfigPath) { $arguments += " -ConfigPath `"$((Resolve-Path -LiteralPath $ConfigPath).Path)`"" }

$time = [datetime]::ParseExact($At.PadLeft(5, '0'), 'HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
$trigger = if ($WeekdaysOnly) {
    New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday, Tuesday, Wednesday, Thursday, Friday -At $time
} else {
    New-ScheduledTaskTrigger -Daily -At $time
}
$action = New-ScheduledTaskAction -Execute $pwsh -Argument $arguments -WorkingDirectory $PSScriptRoot
$taskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 10)

$credential = Get-Credential -UserName $RunAs -Message "Password of $RunAs - stored by Task Scheduler so the task runs while nobody is logged on"
$task = Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $taskSettings `
    -User $credential.UserName -Password $credential.GetNetworkCredential().Password -RunLevel Limited -Force `
    -Description 'Morning infrastructure health check - functionality, certificates and licenses; e-mails a report.'

Write-Host "Scheduled task '$($task.TaskName)' runs $(if ($WeekdaysOnly) { 'Monday-Friday' } else { 'daily' }) at $At as $($credential.UserName)." -ForegroundColor Green
Write-Host "Test it now with:  Start-ScheduledTask -TaskName '$TaskName'   (log: $(Join-Path $PSScriptRoot 'Logs'))"
