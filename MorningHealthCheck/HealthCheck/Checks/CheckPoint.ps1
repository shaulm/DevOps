# Check Point firewall cluster (ClusterXL) through the Management API (R80.10 or later).
#
# Functionality : Management API login, cluster member states (cphaprob state) and active PNOTEs,
#                 installed policy and install time (fw stat), disk usage, member reachability,
#                 optional management-server process list (cpwd_admin list)
# Certificates  : Management API / SmartConsole web certificate + each member's Gaia portal
# License       : "cplic print" on every member: license expiry and service contracts (blade subscriptions)
#
# The commands run on the gateways through the "run-script" API (needs the "Run One Time Script"
# permission in the administrator's permission profile). Credential may be a normal admin or an API key
# (store it with user name "api-key").

$script:HCCheckPointMarker = '###HC:{0}###'

function Split-HCMarkedOutput {
    # Splits combined script output into sections delimited by ###HC:NAME### lines.
    param([string]$Text)
    $sections = @{}
    $current = $null
    foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^###HC:(?<name>[A-Z]+)###\s*$') { $current = $Matches.name; $sections[$current] = [System.Text.StringBuilder]::new(); continue }
        if ($current) { [void]$sections[$current].AppendLine($line) }
    }
    $out = @{}
    foreach ($k in $sections.Keys) { $out[$k] = $sections[$k].ToString() }
    return $out
}

function ConvertFrom-HCCphaprobState {
    param([string]$Text)
    $members = foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^\s*(?<id>\d+)\s*(?<local>\(local\))?\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<load>\d+%)\s+(?<rest>.+?)\s*$') {
            $g = $Matches   # keep the groups: the next -match replaces $Matches
            $state = $g.rest; $name = ''
            if ($g.rest -match '^(?<state>.+?)\s{2,}(?<name>\S+)$') { $state = $Matches.state; $name = $Matches.name }
            [pscustomobject]@{ Id = [int]$g.id; Local = [bool]$g.local; IP = $g.ip; Load = $g.load; State = $state.Trim(); Name = $name }
        }
    }
    [pscustomobject]@{
        Mode         = [regex]::Match($Text, '(?m)^\s*Cluster Mode:\s*(.+?)\s*$').Groups[1].Value
        Members      = @($members)
        ActivePnotes = [regex]::Match($Text, '(?m)^\s*Active PNOTEs:\s*(.+?)\s*$').Groups[1].Value
        NotCluster   = ($Text -match 'not a member of a cluster|Cluster is not active|HA module not started|is not a cluster member')
    }
}

function ConvertFrom-HCCplicPrint {
    # Licenses ("Host  Expiration  Features") and the "Contract Coverage" table.
    param([string]$Text)
    $licenses = @(); $contracts = @()
    foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^\s*(?<host>\S+)\s+(?<exp>\d{1,2}[A-Za-z]{3}\d{4}|[Nn]ever)\s+(?<features>.+?)\s*$') {
            $g = $Matches
            $features = $g.features
            $licenses += [pscustomobject]@{
                Host       = $g.host
                Expiration = ConvertTo-HCDateTime $g.exp
                Never      = ($g.exp -like 'never')
                CK         = [regex]::Match($features, '\bCK-[0-9A-Fa-f]+\b').Value
                Features   = ($features -replace '\s*\bCK-[0-9A-Fa-f]+\b', '').Trim()
            }
        } elseif ($line -match '^\s*\d+\s*\|\s*(?<id>[^|]+?)\s*\|\s*(?<exp>[^|]+?)\s*\|\s*(?<sku>[^|]+?)\s*$') {
            $contracts += [pscustomobject]@{ Id = $Matches.id; Expiration = ConvertTo-HCDateTime $Matches.exp; Sku = $Matches.sku }
        }
    }
    [pscustomobject]@{ Licenses = $licenses; Contracts = $contracts }
}

function ConvertFrom-HCFwStat {
    # "localhost Standard   14Oct2026 22:10:33 :  [>eth1] ..." -> policy name + install time
    param([string]$Text)
    $m = [regex]::Match($Text, '(?m)^\s*localhost\s+(?<policy>\S+)\s*(?<date>\d{1,2}[A-Za-z]{3}\d{4})?\s*(?<time>\d{1,2}:\d{2}:\d{2})?')
    if (-not $m.Success) { return $null }
    $installed = $null
    if ($m.Groups['date'].Success) {
        $installed = ConvertTo-HCDateTime $m.Groups['date'].Value
        if ($installed -and $m.Groups['time'].Success) { $installed = $installed.Add([TimeSpan]::Parse($m.Groups['time'].Value)) }
    }
    [pscustomobject]@{ Policy = $m.Groups['policy'].Value; Installed = $installed }
}

function ConvertFrom-HCDfOutput {
    # POSIX "df -P" output.
    param([string]$Text)
    foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^(?<fs>\S+)\s+(?<blocks>\d+)\s+(?<used>\d+)\s+(?<avail>\d+)\s+(?<cap>\d+)%\s+(?<mount>\S+)\s*$') {
            [pscustomobject]@{ FileSystem = $Matches.fs; Capacity = [int]$Matches.cap; AvailableKB = [long]$Matches.avail; Mount = $Matches.mount }
        }
    }
}

function ConvertFrom-HCCpwdList {
    # "cpwd_admin list": APP PID STAT #START ...  (STAT E = executing, T = terminated)
    param([string]$Text)
    foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^(?<app>[A-Za-z0-9_\-]+)\s+(?<pid>\d+|-)\s+(?<stat>[ET])\s+(?<starts>\d+)') {
            [pscustomobject]@{ App = $Matches.app; State = $Matches.stat; Starts = [int]$Matches.starts }
        }
    }
}

function ConvertFrom-HCCheckPointResponse {
    # run-script output is base64 encoded in task-details.responseMessage.
    param([string]$Value)
    if (-not $Value) { return '' }
    $compact = $Value -replace '\s', ''
    if ($compact -match '^[A-Za-z0-9+/]+={0,2}$' -and ($compact.Length % 4) -eq 0) {
        try { return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($compact)) } catch { Write-Verbose 'responseMessage is not base64' }
    }
    return $Value
}

function Invoke-HCCheckPointScript {
    # Runs a one-time script on the given targets and waits for the results: name -> @{ Ok; Text; Error }
    param(
        [Parameter(Mandatory)][hashtable]$Api,
        [Parameter(Mandatory)][string[]]$Targets,
        [Parameter(Mandatory)][string]$Script,
        [string]$ScriptName = 'MorningHealthCheck',
        [int]$WaitSec = 180
    )
    $rest = @{ Headers = $Api.Headers; SkipCertificateCheck = $Api.Skip; TimeoutSec = $Api.TimeoutSec; Method = 'POST' }
    $started = Invoke-HCRest @rest -Uri "$($Api.Base)/run-script" -Body @{ 'script-name' = $ScriptName; script = $Script; targets = @($Targets) }
    $results = @{}
    $deadline = (Get-Date).AddSeconds($WaitSec)
    foreach ($task in @($started.tasks)) {
        $target = [string]$task.target
        $taskInfo = $null
        do {
            $show = Invoke-HCRest @rest -Uri "$($Api.Base)/show-task" -Body @{ 'task-id' = $task.'task-id'; 'details-level' = 'full' }
            $taskInfo = @($show.tasks)[0]
            if ($taskInfo.status -ne 'in progress') { break }
            Start-Sleep -Seconds 2
        } while ((Get-Date) -lt $deadline)
        if (-not $taskInfo -or $taskInfo.status -eq 'in progress') {
            $results[$target] = @{ Ok = $false; Text = ''; Error = 'timed out waiting for the run-script task' }
            continue
        }
        $detail = @($taskInfo.'task-details')[0]
        $text = if ($detail) { ConvertFrom-HCCheckPointResponse ([string]$detail.responseMessage) } else { '' }
        $errorText = @($detail.statusDescription, $detail.responseError, $taskInfo.comments) | Where-Object { $_ } | Select-Object -First 2
        $results[$target] = @{ Ok = ($taskInfo.status -eq 'succeeded'); Text = $text; Error = ($errorText -join ' ') ; Status = $taskInfo.status }
    }
    return $results
}

function Add-HCCheckPointLicenses {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Label, [string]$Text, [hashtable]$Thresholds)
    $parsed = ConvertFrom-HCCplicPrint $Text
    if (-not $parsed.Licenses -and -not $parsed.Contracts) {
        Add-HCCheck $Context "$Label licenses" 'Unknown' 'Could not read cplic print output'
        return
    }
    foreach ($l in $parsed.Licenses) {
        $tokens = @($l.Features -split '\s+' | Where-Object { $_ })
        $name = '{0} license {1}' -f $Label, (Format-HCList -Items $tokens -Max 2)
        $null = Add-HCLicense -Context $Context -Name $name -StatusText $(if ($l.Never) { 'permanent' } else { 'installed' }) `
            -Expires $l.Expiration -Note $l.CK -Source 'Device' -Thresholds $Thresholds
    }
    # Contracts (blade subscriptions / support): one row per expiry date to keep the report short.
    foreach ($group in ($parsed.Contracts | Group-Object { if ($_.Expiration) { $_.Expiration.ToString('yyyy-MM-dd') } else { 'never' } })) {
        $first = $group.Group[0]
        $skus = @($group.Group | ForEach-Object Sku | Select-Object -Unique)
        $null = Add-HCLicense -Context $Context -Name ('{0} contracts ({1})' -f $Label, $skus.Count) -StatusText 'service contract' `
            -Expires $first.Expiration -Note (Format-HCList -Items $skus -Max 4) -Source 'Device' -Thresholds $Thresholds
    }
}

function Test-HCDfSections {
    param([Parameter(Mandatory)]$Context, [string]$Label, [string]$Text, [hashtable]$Thresholds)
    $warnUsed = 100 - $Thresholds.DiskFreeWarningPct
    $critUsed = 100 - $Thresholds.DiskFreeCriticalPct
    $fs = @(ConvertFrom-HCDfOutput $Text)
    foreach ($f in $fs) {
        if ($f.Capacity -ge $warnUsed) {
            Add-HCCheck $Context "$Label disk $($f.Mount)" (Get-HCThresholdStatus -Value $f.Capacity -Warning $warnUsed -Critical $critUsed) ('{0}% used' -f $f.Capacity)
        }
    }
    return $fs
}

function Invoke-HCCheckCheckPoint {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $t = $Settings.Thresholds
    $port = [int](Get-HCOption $Target 'Port' 443)
    $members = @($Target.Members | Where-Object { $_ } | ForEach-Object { if ($_ -is [hashtable]) { $_ } else { @{ Name = [string]$_ } } })
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports @($port))) { return }
    $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $port -Source "Management :$port"

    # Member reachability + Gaia portal certificate
    foreach ($m in $members) {
        if (-not $m.Address) { continue }
        $portalPort = [int](Get-HCOption $m 'PortalPort' (Get-HCOption $Target 'MemberPortalPort' 443))
        $tcp = Test-HCTcpPort -HostName $m.Address -Port $portalPort -TimeoutMs $Settings.TcpTimeoutMs
        if (-not $tcp.Open) { Add-HCCheck $Context "Member $($m.Name)" 'Critical' "Port $portalPort on $($m.Address): $($tcp.Error)"; continue }
        $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target @{ Address = $m.Address; IgnoreCertificates = $Target.IgnoreCertificates } `
            -Port $portalPort -Source "$($m.Name) Gaia portal :$portalPort"
    }

    if (-not $Credential) {
        Add-HCMissingCredentialCheck -Context $Context -Target $Target -Name 'Management API'
        return
    }
    $api = @{ Base = "https://$($Target.Address):$port/web_api"; Skip = [bool]$Target.SkipCertificateCheck; TimeoutSec = [math]::Max($Settings.TimeoutSec, 30); Headers = @{} }
    $password = $Credential.GetNetworkCredential().Password
    $loginBody = if ($Credential.UserName -in 'api-key', 'apikey') { @{ 'api-key' = $password } } else { @{ user = $Credential.UserName; password = $password } }
    if ($Target.Domain) { $loginBody.domain = $Target.Domain }
    try {
        $login = Invoke-HCRest -Method POST -Uri "$($api.Base)/login" -Body $loginBody -SkipCertificateCheck:$api.Skip -TimeoutSec $api.TimeoutSec
        $api.Headers = @{ 'X-chkp-sid' = [string]$login.sid }
        Add-HCCheck $Context 'Management API' 'OK' ('Logged in (API {0})' -f $login.'api-server-version')
    } catch {
        Add-HCCheck $Context 'Management API' 'Critical' "Login failed: $(Get-HCErrorText $_)"
        return
    }

    try {
        if ($members.Count) {
            $mk = $script:HCCheckPointMarker
            $memberScript = @(
                "echo '$($mk -f 'HA')'; cphaprob state 2>&1"
                "echo '$($mk -f 'LIC')'; cplic print 2>&1"
                "echo '$($mk -f 'POLICY')'; fw stat 2>&1"
                "echo '$($mk -f 'VER')'; fw ver 2>&1"
                "echo '$($mk -f 'UPTIME')'; uptime 2>&1"
                "echo '$($mk -f 'DF')'; df -P / /var/log 2>&1"
            ) -join '; '
            $outputs = Invoke-HCCheckPointScript -Api $api -Targets @($members.Name) -Script $memberScript
            $clusterViews = @()
            foreach ($m in $members) {
                $r = $outputs[$m.Name]
                if (-not $r) { Add-HCCheck $Context "Member $($m.Name)" 'Critical' 'No run-script result (object name correct? SIC OK?)'; continue }
                if (-not $r.Ok -and -not $r.Text) { Add-HCCheck $Context "Member $($m.Name)" 'Critical' "run-script failed: $($r.Error)"; continue }
                $sections = Split-HCMarkedOutput $r.Text

                $ha = ConvertFrom-HCCphaprobState $sections['HA']
                if ($ha.Members.Count) { $clusterViews += [pscustomobject]@{ Member = $m.Name; View = $ha } }

                $policy = ConvertFrom-HCFwStat $sections['POLICY']
                if (-not $policy -or $policy.Policy -eq '-') {
                    Add-HCCheck $Context "$($m.Name) policy" 'Critical' 'No security policy installed'
                } else {
                    $when = if ($policy.Installed) { ' installed ' + $policy.Installed.ToString('dd MMM HH:mm') } else { '' }
                    Add-HCCheck $Context "$($m.Name) policy" 'OK' ("'$($policy.Policy)'$when")
                    if ($policy.Installed -and ((Get-Date) - $policy.Installed).TotalHours -le 24) {
                        Set-HCFact $Context 'Policy installed' ('{0} ({1})' -f (Format-HCAgo $policy.Installed), $policy.Policy)
                    }
                }
                $ver = [regex]::Match($sections['VER'], 'version\s+(?<v>R[\d\.]+)(\s*-\s*Build\s+(?<b>\d+))?')
                if ($ver.Success) { Set-HCFact $Context 'Version' $ver.Groups['v'].Value }
                $up = [regex]::Match($sections['UPTIME'], 'up\s+(?<d>\d+)\s+day')
                if ($up.Success) { Set-HCFact $Context "$($m.Name) up" ('{0}d' -f $up.Groups['d'].Value) }
                $null = Test-HCDfSections -Context $Context -Label $m.Name -Text $sections['DF'] -Thresholds $t
                Add-HCCheckPointLicenses -Context $Context -Label $m.Name -Text $sections['LIC'] -Thresholds $t
            }

            # Cluster state as seen by the first member that answered
            if ($clusterViews.Count) {
                $view = $clusterViews[0].View
                $good = 'ACTIVE', 'STANDBY', 'BACKUP'
                $states = foreach ($cm in $view.Members) {
                    $label = if ($cm.Name) { $cm.Name } else { "member $($cm.Id)" }
                    $s = $cm.State.ToUpperInvariant()
                    $status = if ($s -in $good) { 'OK' } elseif ($s -match '^ACTIVE\(!|ATTENTION') { 'Warning' } else { 'Critical' }
                    [pscustomobject]@{ Label = $label; State = $cm.State; Status = $status }
                }
                $summary = ($states | ForEach-Object { "$($_.Label) $($_.State)" }) -join ' / '
                $overall = Get-HCWorstStatus @($states.Status)
                if (-not ($view.Members | Where-Object { $_.State -match '^ACTIVE' })) { $overall = 'Critical'; $summary = "No ACTIVE member! $summary" }
                Add-HCCheck $Context 'Cluster state' $overall ("$summary" + $(if ($view.Mode) { " - $($view.Mode)" }))
                Set-HCFact $Context 'Cluster' $summary
                if ($view.ActivePnotes -and $view.ActivePnotes -notmatch '^None') {
                    Add-HCCheck $Context 'Active PNOTEs' 'Warning' $view.ActivePnotes
                }
            } elseif ($members.Count -gt 1) {
                Add-HCCheck $Context 'Cluster state' 'Unknown' 'Could not read cphaprob state from any member'
            }
        }

        # Optional: the management server itself (processes, license, disk)
        if ($Target.ManagementObjectName) {
            $mk = $script:HCCheckPointMarker
            $mgmtScript = @(
                "echo '$($mk -f 'CPWD')'; cpwd_admin list 2>&1"
                "echo '$($mk -f 'LIC')'; cplic print 2>&1"
                "echo '$($mk -f 'DF')'; df -P / /var/log 2>&1"
            ) -join '; '
            $name = [string]$Target.ManagementObjectName
            $r = (Invoke-HCCheckPointScript -Api $api -Targets @($name) -Script $mgmtScript)[$name]
            if (-not $r -or (-not $r.Ok -and -not $r.Text)) {
                Add-HCCheck $Context 'Management server' 'Unknown' ('run-script failed: {0}' -f $(if ($r) { $r.Error } else { 'no result' }))
            } else {
                $sections = Split-HCMarkedOutput $r.Text
                $processes = @(ConvertFrom-HCCpwdList $sections['CPWD'])
                $terminated = @($processes | Where-Object State -eq 'T' | ForEach-Object App)
                if ($terminated) { Add-HCCheck $Context 'Management processes' 'Warning' ('Terminated: ' + ($terminated -join ', ')) }
                elseif ($processes) { Add-HCCheck $Context 'Management processes' 'OK' ('{0} processes running' -f $processes.Count) }
                $null = Test-HCDfSections -Context $Context -Label 'Management' -Text $sections['DF'] -Thresholds $t
                Add-HCCheckPointLicenses -Context $Context -Label 'Management' -Text $sections['LIC'] -Thresholds $t
            }
        }
    } catch {
        Add-HCCheck $Context 'Management API' 'Unknown' (Get-HCErrorText $_)
    } finally {
        try { $null = Invoke-HCRest -Method POST -Uri "$($api.Base)/logout" -Headers $api.Headers -Body @{} -SkipCertificateCheck:$api.Skip -TimeoutSec 15 } catch { Write-Verbose 'logout failed' }
    }
}
