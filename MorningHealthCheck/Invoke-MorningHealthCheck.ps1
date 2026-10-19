#Requires -Version 7.4
<#
.SYNOPSIS
    Morning infrastructure health check with a colour-coded e-mail report.

.DESCRIPTION
    Checks functionality, certificates (validity, issuer, friendly name) and licenses (status, expiry) of
    domain controllers, NetApp clusters, vCenter servers, Forcepoint web proxies and management, Portnox,
    Juniper switches, Check Point firewall clusters and Trellix SIEM / ePO / EDR, then e-mails a report
    through Exchange that reads well in Gmail. The complete report is attached and kept in the Reports folder.

    Passwords are never stored in the config: they are kept encrypted (Windows DPAPI) by
    Set-HealthCheckCredential.ps1 and only the account that runs this script can decrypt them.

.PARAMETER ConfigPath
    Configuration file. Default: config\HealthCheck.config.psd1 next to this script.

.PARAMETER NoEmail
    Run the checks and save the report, but do not send e-mail.

.PARAMETER Demo
    Build the report from built-in sample data (no network access). Use it to preview the layout or,
    without -NoEmail, to test delivery and formatting in Gmail.

.PARAMETER Only
    Check only targets whose Type or Name matches (wildcards allowed), e.g. -Only NetApp, 'DC0*'.

.PARAMETER Sequential
    Check targets one after the other instead of in parallel (easier to troubleshoot).

.PARAMETER Open
    Open the saved HTML report when finished.

.PARAMETER To
    Send the e-mail to these addresses instead of Email.To (testing).

.EXAMPLE
    .\Invoke-MorningHealthCheck.ps1
    Normal run, as executed by the scheduled task.

.EXAMPLE
    .\Invoke-MorningHealthCheck.ps1 -Demo -To you@gmail.com
    Sends a sample report to check how it looks in Gmail.

.EXAMPLE
    .\Invoke-MorningHealthCheck.ps1 -Only CheckPoint -Sequential -NoEmail -Open -Verbose
    Troubleshoot one system type.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config/HealthCheck.config.psd1'),
    [switch]$NoEmail,
    [switch]$Demo,
    [string[]]$Only,
    [switch]$Sequential,
    [switch]$Open,
    [string[]]$To
)

$ErrorActionPreference = 'Stop'
$started = Get-Date
$modulePath = Join-Path $PSScriptRoot 'HealthCheck/HealthCheck.psm1'
Import-Module $modulePath -Force
$script:LogFile = $null

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding utf8 }
    $color = @{ INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red' }[$Level]
    Write-Host $line -ForegroundColor $color
}

function Get-PreviousRun {
    param([string]$Folder)
    $file = Get-ChildItem -LiteralPath $Folder -Filter 'HealthCheck_*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $file) { return $null }
    try { return (Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json) }
    catch { Write-Log "Ignoring unreadable previous run $($file.Name): $($_.Exception.Message)" WARN; return $null }
}

function Write-ConsoleSummary {
    param($Model)
    $colors = @{ OK = 'Green'; Info = 'Green'; Warning = 'Yellow'; Critical = 'Red'; Unknown = 'Magenta' }
    Write-Host ''
    foreach ($r in $Model.Results) {
        Write-Host ('  {0,-9}' -f $r.Status.ToUpperInvariant()) -ForegroundColor $colors[$r.Status] -NoNewline
        Write-Host (' {0,-24} {1,-24} {2}' -f $r.Category, $r.Name, $r.Summary)
    }
    Write-Host ''
    Write-Host ('  {0}' -f (Get-HCHeadline $Model)) -ForegroundColor $colors[$Model.Overall]
    Write-Host ''
}

function Send-FailureMail {
    param([hashtable]$Email, [hashtable]$Settings, [string]$ErrorText)
    $credential = $null
    if ($Email.Credential) { $credential = Import-HCCredential -Folder $Settings.CredentialFolder -Name $Email.Credential }
    $when = (Get-Date).ToString('ddd d MMM HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    $prefix = if ($Email.SubjectPrefix) { $Email.SubjectPrefix } else { 'Morning Health Check' }
    $subject = '{0}{1} FAILED to run - {2}' -f $(if ($Email.UseEmojiInSubject -ne $false) { [char]::ConvertFromUtf32(0x26A0) + ' ' }), $prefix, $when
    $encoded = [System.Net.WebUtility]::HtmlEncode($ErrorText)
    $html = "<div style=`"font-family:'Segoe UI',Arial,sans-serif;font-size:14px;color:#101828;`"><p style=`"color:#b42318;font-weight:700;`">The morning health check did not complete on $([Environment]::MachineName).</p><pre style=`"background:#f2f4f7;padding:12px;border-radius:8px;white-space:pre-wrap;`">$encoded</pre><p>See the log in $([System.Net.WebUtility]::HtmlEncode($Settings.LogFolder)).</p></div>"
    $text = "The morning health check did not complete on $([Environment]::MachineName).`r`n`r`n$ErrorText`r`n`r`nLog folder: $($Settings.LogFolder)"
    Send-HCReportMail -Email $Email -Subject $subject -Html $html -Text $text -Credential $credential -HighPriority -To $To
}

# --- configuration ------------------------------------------------------------------------------
if ($Demo -and -not (Test-Path -LiteralPath $ConfigPath)) { $config = Get-HCDemoConfig }
else { $config = Import-HCConfig -Path $ConfigPath }
$settings = New-HCSettings -Config $config -ScriptRoot $PSScriptRoot
$email = $config.Email
foreach ($folder in $settings.ReportFolder, $settings.LogFolder) {
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
}
$script:LogFile = Join-Path $settings.LogFolder ('HealthCheck_{0:yyyy-MM-dd}.log' -f $started)
$runAs = if ($IsWindows) { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } else { [Environment]::UserName }
Write-Log "Run started on $([Environment]::MachineName) as $runAs (PowerShell $($PSVersionTable.PSVersion))$(if ($Demo) { ' - DEMO data' })"

$exitCode = 0
try {
    # --- checks ---------------------------------------------------------------------------------
    if ($Demo) {
        $results = New-HCDemoResults -Settings $settings
        $previous = New-HCDemoPrevious -Results $results
    } else {
        $targets = @(Resolve-HCTargets -Config $config)
        $targets = @(Expand-HCDomainControllerTargets -Targets $targets)
        $targets = @(Select-HCTargets -Targets $targets -Only $Only)
        if ($targets.Count -eq 0) { throw 'No targets to check - add Targets to the config (or check the -Only filter).' }
        Write-Log ('{0} targets: {1}' -f $targets.Count, (($targets | Group-Object Type | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '))

        foreach ($name in Get-HCReferencedCredentialNames -Targets $targets -Email $email) {
            try {
                $settings.Credentials[$name] = Import-HCCredential -Folder $settings.CredentialFolder -Name $name
            } catch {
                $settings.Credentials[$name] = Get-HCErrorText $_
                Write-Log "Credential '$name' not available: $($settings.Credentials[$name])" WARN
            }
        }

        # Values remembered by the previous run (e.g. when the ePO repository content last changed).
        $lastRun = Get-PreviousRun -Folder $settings.ReportFolder
        if ($lastRun -and $lastRun.PSObject.Properties['State']) { $settings.PreviousState = ConvertTo-HCStateTable $lastRun.State }

        $results = Invoke-HCAllTargets -Targets $targets -Settings $settings -ModulePath $modulePath -Sequential:$Sequential
        # A partial (-Only) run is not compared with, and does not become, the "last run".
        $previous = if ($Only) { $null } else { $lastRun }
    }
    foreach ($r in $results) {
        foreach ($line in $r.Log) { Write-Log $line }
        Write-Log ('{0,-9} {1} / {2}: {3} ({4} s)' -f $r.Status.ToUpperInvariant(), $r.Category, $r.Name, $r.Summary, $r.DurationSec)
    }

    # --- report ---------------------------------------------------------------------------------
    $model = New-HCReportModel -Results $results -Settings $settings -Previous $previous -Started $started -Demo:$Demo
    $showAddresses = $email.ShowAddresses -ne $false
    $baseName = if ($Demo) { 'HealthCheck_SAMPLE' } else { 'HealthCheck_{0:yyyy-MM-dd_HHmm}' -f $started }
    if ($Only) { $baseName += '_partial' }
    $reportPath = Join-Path $settings.ReportFolder "$baseName.html"
    $fullHtml = ConvertTo-HCReportHtml -Model $model -Mode Full -ShowAddresses:$showAddresses
    [System.IO.File]::WriteAllText($reportPath, $fullHtml, [System.Text.UTF8Encoding]::new($false))
    if (-not $Demo -and -not $Only) {
        ConvertTo-HCPreviousRun -Model $model -PreviousState $settings.PreviousState | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath (Join-Path $settings.ReportFolder "$baseName.json") -Encoding utf8
    }
    Write-Log "Report saved to $reportPath"

    # --- e-mail ---------------------------------------------------------------------------------
    if (-not $NoEmail -and $email.Enabled -ne $false) {
        $body = @{
            Model           = $model
            ShowAddresses   = $showAddresses
            CertificateDays = [int](Get-HCOption $email 'CertificateDays' 90)
            LicenseDays     = [int](Get-HCOption $email 'LicenseDays' 120)
        }
        $html = ConvertTo-HCReportHtml @body -Mode Email
        if ((Get-HCHtmlSize $html) -gt 95KB) {
            Write-Log 'E-mail body would exceed Gmail''s clipping size - using the compact layout'
            $html = ConvertTo-HCReportHtml @body -Mode Compact
        }
        $smtpCredential = $null
        if ($email.Credential) {
            $smtpCredential = $settings.Credentials[$email.Credential]
            if ($smtpCredential -isnot [pscredential]) { $smtpCredential = Import-HCCredential -Folder $settings.CredentialFolder -Name $email.Credential }
        }
        $mail = @{
            Email        = $email
            Subject      = Get-HCMailSubject -Model $model -Email $email
            Html         = $html
            Text         = ConvertTo-HCReportText -Model $model
            Attachments  = $(if ($email.AttachFullReport -ne $false) { @($reportPath) } else { @() })
            Credential   = $smtpCredential
            HighPriority = ($email.HighPriorityOnCritical -ne $false -and $model.Overall -eq 'Critical')
            To           = $To
        }
        Send-HCReportMail @mail
        Write-Log ('E-mail "{0}" sent to {1}' -f $mail.Subject, ((@($(if ($To) { $To } else { $email.To })) -join ', ')))
    }

    # --- housekeeping ---------------------------------------------------------------------------
    $cutoff = (Get-Date).AddDays(-$settings.KeepDays)
    Get-ChildItem -LiteralPath $settings.ReportFolder -File -Filter 'HealthCheck_*' -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt $cutoff | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $settings.LogFolder -File -Filter 'HealthCheck_*.log' -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt $cutoff | Remove-Item -Force -ErrorAction SilentlyContinue

    Write-ConsoleSummary -Model $model
    Write-Log ('Run finished in {0}: {1}' -f (Format-HCDuration ((Get-Date) - $started)), (Get-HCHeadline $model))
    if ($Open) { Invoke-Item -LiteralPath $reportPath }
} catch {
    $exitCode = 1
    $errorText = "$($_.Exception.Message)`n$($_.ScriptStackTrace)"
    Write-Log "Run FAILED: $errorText" ERROR
    if (-not $NoEmail -and $email.Enabled -ne $false -and $email.SmtpServer -and -not $Demo) {
        try { Send-FailureMail -Email $email -Settings $settings -ErrorText $errorText; Write-Log 'Failure notification sent' }
        catch { Write-Log "Could not send the failure notification: $($_.Exception.Message)" ERROR }
    }
}
exit $exitCode
