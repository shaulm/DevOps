# Trellix (formerly McAfee) SIEM / ePO / EDR.
#
# TrellixESM (Enterprise Security Manager / SIEM)
#   Functionality : web console, REST API login (rs/esm/v2), ESM clock vs. this server,
#                   unacknowledged alarms of the last 24 h (informational)
#   Certificates  : console certificate
# TrellixEPO (ePolicy Orchestrator)
#   Functionality : console, Web API (remote commands), managed systems not seen for N days,
#                   your own saved queries with thresholds, ePO Windows services and disks
#   Certificates  : console (8443) + agent handler ports, optional LocalMachine\My
# TrellixEDR
#   Functionality : console / URL check (generic web check, works for SaaS or on-prem consoles)
#   Certificates  : console certificate
# License         : not exposed by these APIs -> list the subscription dates under Licenses in the config.

function Get-HCEsmValue {
    # ESM wraps most answers as {"return": ...} and sometimes {"value": ...}.
    param($Response)
    $v = $Response
    if ($null -ne $v -and $v.PSObject.Properties['return']) { $v = $v.return }
    if ($null -ne $v -and $v -isnot [string] -and $v.PSObject.Properties['value']) { $v = $v.value }
    return $v
}

function Invoke-HCCheckTrellixESM {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $t = $Settings.Thresholds
    $port = [int](Get-HCOption $Target 'Port' 443)
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports (@($port) + @(Get-HCOption $Target 'Ports' @())))) { return }
    $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $port -Source "ESM console :$port"
    if (-not $Credential) {
        Invoke-HCWebCheck -Context $Context -Settings $Settings -Url "https://$($Target.Address):$port/" -Name 'ESM console' -SkipCertificateCheck
        Add-HCMissingCredentialCheck -Context $Context -Target $Target -Name 'ESM API'
        return
    }
    $base = "https://$($Target.Address):$port/rs/esm/v2"
    $skip = [bool]$Target.SkipCertificateCheck
    $timeout = [math]::Max($Settings.TimeoutSec, 30)
    $web = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $encode = { param($s) [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($s)) }
    $body = @{ username = (& $encode $Credential.UserName); password = (& $encode $Credential.GetNetworkCredential().Password); locale = 'en_US'; os = 'Win32' }
    try {
        $login = Invoke-HCRest -Method POST -Uri "$base/login" -Body $body -WebSession $web -SkipCertificateCheck:$skip -TimeoutSec $timeout -Raw
        $xsrf = @($login.Headers['Xsrf-Token'])[0]
        $headers = @{}
        if ($xsrf) { $headers['X-Xsrf-Token'] = [string]$xsrf }
        Add-HCCheck $Context 'ESM API' 'OK' 'Logged in'
    } catch {
        Add-HCCheck $Context 'ESM API' 'Critical' "Login failed: $(Get-HCErrorText $_)"
        return
    }
    $call = @{ Method = 'POST'; Headers = $headers; WebSession = $web; SkipCertificateCheck = $skip; TimeoutSec = $timeout }
    try {
        try {
            $raw = Get-HCEsmValue (Invoke-HCRest @call -Uri "$base/essmgtGetESSTime")
            $esmTime = ConvertTo-HCDateTime $raw
            if ($esmTime) {
                $offset = ($esmTime - (Get-Date)).TotalSeconds
                $status = Get-HCThresholdStatus -Value ([math]::Abs($offset)) -Warning $t.TimeSkewWarningSec -Critical $t.TimeSkewCriticalSec
                Add-HCCheck $Context 'ESM clock' $status ('{0:+0;-0;0} s compared with the monitoring server' -f $offset)
            } else {
                Add-HCCheck $Context 'ESM services' 'OK' "ESM answered (time: $raw)"
            }
        } catch {
            Add-HCCheck $Context 'ESM services' 'Critical' "essmgtGetESSTime failed: $(Get-HCErrorText $_)"
        }
        if ($Target.CheckAlarms -ne $false) {
            try {
                $query = 'alarmGetTriggeredAlarms?triggeredTimeRange=LAST_24_HOURS&customStart=&customEnd=&status=unacknowledged&pageSize=500&pageNumber=1'
                $alarms = @(Get-HCEsmValue (Invoke-HCRest @call -Uri "$base/$query") | Where-Object { $_ })
                $limit = Get-HCOption $Target 'AlarmWarningCount' $null
                $status = if ($null -ne $limit -and $alarms.Count -gt [int]$limit) { 'Warning' } else { 'Info' }
                Add-HCCheck $Context 'Unacknowledged alarms (24h)' $status ('{0}' -f $alarms.Count)
                Set-HCFact $Context 'Alarms 24h' $alarms.Count
            } catch {
                Add-HCLog $Context "alarmGetTriggeredAlarms: $(Get-HCErrorText $_)"
            }
        }
    } finally {
        try { $null = Invoke-HCRest -Method DELETE -Uri "$base/logout" -Headers $headers -WebSession $web -SkipCertificateCheck:$skip -TimeoutSec 15 } catch { Write-Verbose 'ESM logout failed' }
    }
}

function Invoke-HCEpoCommand {
    # Calls an ePO Web API command and returns the parsed JSON ("OK:" prefix removed).
    param(
        [Parameter(Mandatory)][string]$Api,
        [Parameter(Mandatory)][string]$Command,
        [hashtable]$Parameters,
        [Parameter(Mandatory)][pscredential]$Credential,
        [bool]$Skip,
        [int]$TimeoutSec = 60
    )
    $query = @()
    if ($Parameters) {
        foreach ($k in $Parameters.Keys) { $query += '{0}={1}' -f [uri]::EscapeDataString($k), [uri]::EscapeDataString([string]$Parameters[$k]) }
    }
    $query += ':output=json'
    $uri = '{0}/{1}?{2}' -f $Api, $Command, ($query -join '&')
    $response = Invoke-HCRest -Uri $uri -Credential $Credential -SkipCertificateCheck:$Skip -TimeoutSec $TimeoutSec -Raw
    $text = [string]$response.Content
    if ($text -match '^\s*OK:') {
        $json = $text -replace '^\s*OK:\s*', ''
        if ([string]::IsNullOrWhiteSpace($json)) { return $null }
        return ($json | ConvertFrom-Json)
    }
    if ($text -match '^\s*Error\s+(?<code>-?\d+)\s*:\s*(?<msg>[\s\S]*)$') {
        throw ('ePO error {0}: {1}' -f $Matches.code, (($Matches.msg.Trim() -split "`r?`n")[0]))
    }
    throw ('Unexpected ePO response: ' + $text.Substring(0, [math]::Min(120, $text.Length)))
}

function Invoke-HCCheckTrellixEPO {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $t = $Settings.Thresholds
    $port = [int](Get-HCOption $Target 'Port' 8443)
    $ports = @($port) + @(Get-HCOption $Target 'Ports' @(443))
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports $ports)) { return }
    foreach ($p in @(Get-HCOption $Target 'TlsPorts' @($port, 443)) | Select-Object -Unique) {
        $label = if ($p -eq $port) { "ePO console :$p" } else { "Agent handler :$p" }
        $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $p -Source $label
    }

    if ($Credential) {
        $api = "https://$($Target.Address):$port/remote"
        $epo = @{ Api = $api; Credential = $Credential; Skip = [bool]$Target.SkipCertificateCheck; TimeoutSec = [math]::Max($Settings.TimeoutSec * 3, 60) }
        $apiOk = $false
        try {
            $version = Invoke-HCEpoCommand @epo -Command 'epo.getVersion'
            Set-HCFact $Context 'ePO' $version
            Add-HCCheck $Context 'ePO Web API' 'OK' "Responding (version $version)"
            $apiOk = $true
        } catch {
            try {
                $null = Invoke-HCEpoCommand @epo -Command 'core.help'
                Add-HCCheck $Context 'ePO Web API' 'OK' 'Responding'
                $apiOk = $true
            } catch {
                Add-HCCheck $Context 'ePO Web API' 'Critical' (Get-HCErrorText $_)
            }
        }
        if ($apiOk -and $Target.CheckAgents -ne $false) {
            try {
                $rows = $null
                try {
                    $rows = @(Invoke-HCEpoCommand @epo -Command 'core.executeQuery' -Parameters @{
                            target = 'EPOLeafNode'; select = '(select EPOLeafNode.NodeName EPOLeafNode.LastUpdate EPOLeafNode.ManagedState)'
                        })
                    $rows = @($rows | Where-Object { $null -eq $_.'EPOLeafNode.ManagedState' -or [string]$_.'EPOLeafNode.ManagedState' -in '1', 'True' })
                } catch {
                    $rows = @(Invoke-HCEpoCommand @epo -Command 'core.executeQuery' -Parameters @{
                            target = 'EPOLeafNode'; select = '(select EPOLeafNode.NodeName EPOLeafNode.LastUpdate)'
                        })
                }
                $cutoff = (Get-Date).AddDays(-$t.StaleAgentDays)
                $stale = @($rows | Where-Object { $d = ConvertTo-HCDateTime $_.'EPOLeafNode.LastUpdate'; -not $d -or $d -lt $cutoff })
                $pct = if ($rows.Count) { [math]::Round(100 * $stale.Count / $rows.Count, 1) } else { 0 }
                $status = Get-HCThresholdStatus -Value $pct -Warning $t.StaleAgentWarningPct -Critical $t.StaleAgentCriticalPct
                Add-HCCheck $Context 'Agent communication' $status ('{0:N0} managed systems, {1:N0} not seen for more than {2} days ({3}%)' -f $rows.Count, $stale.Count, $t.StaleAgentDays, $pct)
                Set-HCFact $Context 'Systems' ('{0:N0}' -f $rows.Count)
            } catch {
                Add-HCCheck $Context 'Agent communication' 'Unknown' (Get-HCErrorText $_)
            }
        }
        if ($apiOk) {
            foreach ($q in @($Target.SavedQueries)) {
                if (-not $q -or -not $q.Id) { continue }
                $name = if ($q.Name) { [string]$q.Name } else { "Query $($q.Id)" }
                try {
                    $result = @(Invoke-HCEpoCommand @epo -Command 'core.executeQuery' -Parameters @{ queryId = [string]$q.Id } | Where-Object { $null -ne $_ })
                    $n = $result.Count
                    $status = if ($null -ne $q.CriticalAbove -and $n -gt [int]$q.CriticalAbove) { 'Critical' }
                    elseif ($null -ne $q.WarningAbove -and $n -gt [int]$q.WarningAbove) { 'Warning' } else { 'OK' }
                    Add-HCCheck $Context $name $status ('{0} result row(s)' -f $n)
                } catch {
                    Add-HCCheck $Context $name 'Unknown' (Get-HCErrorText $_)
                }
            }
        }
    } else {
        Invoke-HCWebCheck -Context $Context -Settings $Settings -Url "https://$($Target.Address):$port/" -Name 'ePO console' -SkipCertificateCheck
    }

    if ($Target.Windows -ne $false) {
        $windowsCredential = Get-HCNamedCredential -Settings $Settings -Name $Target.WindowsCredential -Context $Context -Purpose 'Windows'
        Invoke-HCWindowsChecks -Context $Context -Target $Target -Credential $windowsCredential -Settings $Settings `
            -ServicePatterns (Get-HCOption $Target 'ServicePatterns' @('MCAFEE*SRV*', '*ePolicy Orchestrator*')) -Services $Target.Services `
            -Disks -CertificateStore:([bool]$Target.CheckCertificateStore)
    }
}

function Invoke-HCCheckTrellixEDR {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    Invoke-HCCheckWebService -Context $Context -Target $Target -Credential $Credential -Settings $Settings
}
