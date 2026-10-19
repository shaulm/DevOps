# Small helpers: error text, dates, formatting.

function Get-HCHttpStatus {
    # HTTP status code of a failed Invoke-RestMethod / Invoke-WebRequest call, or $null.
    param($ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    if ($ex -is [Microsoft.PowerShell.Commands.HttpResponseException] -and $ex.Response) { return [int]$ex.Response.StatusCode }
    if ($ex -and $ex.PSObject.Properties['StatusCode'] -and $ex.StatusCode) { return [int]$ex.StatusCode }
    return $null
}

function Get-HCErrorText {
    # Short, single-line error message suitable for the report.
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 'unknown error' }
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    if ($ex -is [string]) { return $ex }

    if ($ex -is [Microsoft.PowerShell.Commands.HttpResponseException] -and $ex.Response) {
        $code = [int]$ex.Response.StatusCode
        $text = "HTTP $code $($ex.Response.ReasonPhrase)".Trim()
        $body = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.ErrorDetails) { $ErrorRecord.ErrorDetails.Message } else { $null }
        if ($body) {
            $body = ($body -replace '<[^>]+>', ' ' -replace '\s+', ' ').Trim()
            if ($body.Length -gt 160) { $body = $body.Substring(0, 160) + '...' }
            if ($body) { $text += " - $body" }
        }
        return $text
    }

    $inner = $ex
    while ($inner.InnerException) { $inner = $inner.InnerException }
    $message = $inner.Message
    if ($inner -is [System.Net.Sockets.SocketException]) {
        $message = switch ($inner.SocketErrorCode.ToString()) {
            'ConnectionRefused' { 'connection refused' }
            'TimedOut' { 'connection timed out' }
            'HostNotFound' { 'host name could not be resolved (DNS)' }
            'NoData' { 'host name could not be resolved (DNS)' }
            'HostUnreachable' { 'host unreachable' }
            'NetworkUnreachable' { 'network unreachable' }
            'ConnectionReset' { 'connection reset by peer' }
            default { $inner.Message }
        }
    } elseif ($inner -is [System.TimeoutException] -or $inner -is [System.Threading.Tasks.TaskCanceledException]) {
        $message = 'timed out'
    }
    if (-not $message) { $message = $ex.Message }
    return (($message -replace '\s+', ' ').Trim())
}

function ConvertTo-HCDateTime {
    # Accepts DateTime, DateTimeOffset, epoch seconds/milliseconds and the date formats used by the
    # vendors in this project. Returns local time, or $null when the value cannot be parsed.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    if ($Value -is [datetimeoffset]) { return $Value.LocalDateTime }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        $n = [long]$Value
        if ($n -gt 100000000000) { return [DateTimeOffset]::FromUnixTimeMilliseconds($n).LocalDateTime }
        return [DateTimeOffset]::FromUnixTimeSeconds($n).LocalDateTime
    }
    $s = ([string]$Value).Trim()
    if (-not $s -or $s -match '^(never|permanent|perpetual|unlimited|none|n/?a|-)$') { return $null }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($s -match '^\d{10}$') { return [DateTimeOffset]::FromUnixTimeSeconds([long]$s).LocalDateTime }
    if ($s -match '^\d{13}$') { return [DateTimeOffset]::FromUnixTimeMilliseconds([long]$s).LocalDateTime }
    if ($s -match '^\d{4}-\d{2}-\d{2}$') {
        return [datetime]::ParseExact($s, 'yyyy-MM-dd', $inv, [System.Globalization.DateTimeStyles]::AssumeLocal)
    }
    # AD generalized time: 20261015063001.0Z
    if ($s -match '^(?<v>\d{14})(\.\d+)?Z$') {
        $utc = [datetime]::ParseExact($Matches.v, 'yyyyMMddHHmmss', $inv, [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
        return $utc.ToLocalTime()
    }
    # Check Point style: 24Apr2027
    if ($s -match '^\d{1,2}[A-Za-z]{3}\d{4}$') {
        $d = [datetime]::MinValue
        if ([datetime]::TryParseExact($s, [string[]]@('dMMMyyyy', 'ddMMMyyyy'), $inv, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$d)) { return $d }
    }
    # "2026-10-14 22:01:33 IDT": a time-zone abbreviation other than UTC/GMT - treat as local time.
    if ($s -match '^(?<t>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?)\s+(?<tz>[A-Z]{2,5})$' -and $Matches.tz -notin 'UTC', 'GMT', 'Z') {
        return [datetime]::Parse($Matches.t, $inv, [System.Globalization.DateTimeStyles]::AssumeLocal)
    }
    $normalised = $s -replace '\s+UTC$', 'Z' -replace '\s+GMT$', 'Z' -replace '([+-]\d{2})(\d{2})$', '$1:$2'
    $dto = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($normalised, $inv, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) {
        return $dto.LocalDateTime
    }
    $d = [datetime]::MinValue
    $formats = [string[]]@('MM/dd/yyyy HH:mm:ss', 'M/d/yyyy H:mm:ss', 'ddd MMM d HH:mm:ss yyyy', 'ddd MMM dd HH:mm:ss yyyy')
    if ([datetime]::TryParseExact(($s -replace '\s+', ' '), $formats, $inv, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$d)) { return $d }
    return $null
}

function Format-HCDuration {
    param([TimeSpan]$TimeSpan)
    if ($TimeSpan.TotalDays -ge 1) { return ('{0}d {1}h' -f [int][math]::Floor($TimeSpan.TotalDays), $TimeSpan.Hours) }
    if ($TimeSpan.TotalHours -ge 1) { return ('{0}h {1}m' -f [int][math]::Floor($TimeSpan.TotalHours), $TimeSpan.Minutes) }
    if ($TimeSpan.TotalMinutes -ge 1) { return ('{0}m {1}s' -f [int][math]::Floor($TimeSpan.TotalMinutes), $TimeSpan.Seconds) }
    return ('{0}s' -f [int][math]::Round($TimeSpan.TotalSeconds))
}

function Format-HCAgo {
    param($Date)
    $d = ConvertTo-HCDateTime $Date
    if (-not $d) { return 'never' }
    $span = (Get-Date) - $d
    if ($span.TotalMinutes -lt 2) { return 'just now' }
    if ($span.TotalHours -lt 1) { return ('{0} min ago' -f [int]$span.TotalMinutes) }
    if ($span.TotalHours -lt 48) { return ('{0} h ago' -f [int][math]::Floor($span.TotalHours)) }
    return ('{0} days ago' -f [int][math]::Floor($span.TotalDays))
}

function Format-HCBytes {
    param([double]$Bytes)
    $units = 'B', 'KB', 'MB', 'GB', 'TB', 'PB'
    $i = 0
    while ([math]::Abs($Bytes) -ge 1024 -and $i -lt $units.Count - 1) { $Bytes /= 1024; $i++ }
    $fmt = if ($i -eq 0 -or $Bytes -ge 100) { '{0:N0} {1}' } else { '{0:N1} {1}' }
    return ($fmt -f $Bytes, $units[$i])
}

function Format-HCList {
    # "a, b, c (+4 more)"
    param([object[]]$Items, [int]$Max = 3)
    $list = @($Items | Where-Object { $null -ne $_ -and "$_" -ne '' })
    if ($list.Count -le $Max) { return ($list -join ', ') }
    return ('{0} (+{1} more)' -f (($list | Select-Object -First $Max) -join ', '), ($list.Count - $Max))
}

function Get-HCOption {
    # $Target.Key when present, else the default. Arrays from the .psd1 stay arrays.
    param([hashtable]$Table, [string]$Key, $Default)
    if ($Table -and $Table.ContainsKey($Key) -and $null -ne $Table[$Key]) { return $Table[$Key] }
    return $Default
}

function Get-HCShortOsName {
    param([string]$Caption)
    if (-not $Caption) { return '' }
    return (($Caption -replace 'Microsoft\s+', '' -replace '\(R\)|\(TM\)', '' -replace '^Windows\s+Server', 'Server' -replace '\s+Evaluation', ' Eval' -replace '\s+', ' ').Trim())
}

function Get-HCNamedCredential {
    # Looks up an additional stored credential (e.g. WindowsCredential, Radius.SecretCredential).
    param([hashtable]$Settings, [string]$Name, $Context, [string]$Purpose)
    if (-not $Name) { return $null }
    $entry = if ($Settings.Credentials) { $Settings.Credentials[$Name] } else { $null }
    if ($entry -is [pscredential]) { return $entry }
    if ($Context) {
        $why = if ($entry) { [string]$entry } else { "credential '$Name' is not loaded" }
        Add-HCCheck $Context "$Purpose credential" 'Unknown' $why
    }
    return $null
}

function Add-HCMissingCredentialCheck {
    # API checks without a usable credential: one clear message instead of a misleading second error.
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [Parameter(Mandatory)][string]$Name)
    if ($Target.Credential) {
        Add-HCCheck $Context $Name 'Info' "Skipped - stored credential '$($Target.Credential)' is not available (see the Credential row)"
    } else {
        Add-HCCheck $Context $Name 'Unknown' 'No credential configured for this target (set Credential in the config)'
    }
}

function Get-HCValueSince {
    <#
      Returns when a value was first seen for this target and remembers it for the next run.
      Used to notice things that should change regularly but did not (e.g. the content version in
      the ePO master repository). The first time a value is seen the answer is "now".
    #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Settings, [Parameter(Mandatory)][string]$Key, [string]$Value)
    $since = Get-Date
    $previous = $null
    if ($Settings.PreviousState) {
        $targetState = $Settings.PreviousState["$($Context.Type)|$($Context.Name)"]
        if ($targetState) { $previous = $targetState[$Key] }
    }
    if ($previous -and [string]$previous.Value -eq $Value) {
        $seen = ConvertTo-HCDateTime $previous.Since
        if ($seen -and $seen -lt $since) { $since = $seen }
    }
    $Context.State[$Key] = @{ Value = $Value; Since = $since.ToString('o') }
    return $since
}

function ConvertTo-HCStateTable {
    # Previous-run state (as read back from JSON) -> nested hashtables.
    param($State)
    $result = @{}
    if (-not $State) { return $result }
    if ($State -is [hashtable]) { return $State }
    foreach ($target in $State.PSObject.Properties) {
        $entries = @{}
        foreach ($entry in $target.Value.PSObject.Properties) {
            $entries[$entry.Name] = @{ Value = $entry.Value.Value; Since = $entry.Value.Since }
        }
        $result[$target.Name] = $entries
    }
    return $result
}
