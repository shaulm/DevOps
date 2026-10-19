# Configuration loading, defaults and target expansion.

function Get-HCDefaultThresholds {
    @{
        CertWarningDays           = 30      # certificate expires within N days -> Warning
        CertCriticalDays          = 7       # ... within N days (or expired) -> Critical
        CertUntrustedStatus       = 'Info'  # untrusted / self-signed chain: Info (just noted) or Warning
        LicenseWarningDays        = 60
        LicenseCriticalDays       = 14
        KmsRenewalWarningDays     = 150     # KMS/AVMA activation normally stays > 173 days; less means renewal fails
        DiskFreeWarningPct        = 15      # Windows / appliance file systems
        DiskFreeCriticalPct       = 5
        AggregateUsedWarningPct   = 85      # NetApp aggregates
        AggregateUsedCriticalPct  = 95
        VolumeUsedWarningPct      = 90      # NetApp volumes
        VolumeUsedCriticalPct     = 97
        DatastoreUsedWarningPct   = 85      # vSphere datastores
        DatastoreUsedCriticalPct  = 95
        TimeSkewWarningSec        = 5       # DC / SIEM clock vs. the monitoring server
        TimeSkewCriticalSec       = 60
        ReplicationWarningHours   = 24      # AD: last successful inbound replication
        SnapMirrorLagWarningHours = 26
        BackupMaxAgeHours         = 36      # vCenter file-based backup
        HttpSlowMs                = 5000    # web console / proxy response time
        StaleAgentDays            = 7       # ePO: agent not seen for N days
        StaleAgentWarningPct      = 10
        StaleAgentCriticalPct     = 25
    }
}

function Import-HCConfig {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        $example = Join-Path (Split-Path $Path -Parent) 'HealthCheck.config.example.psd1'
        throw "Configuration file not found: $Path`nCopy '$example' to '$Path' and edit it for your environment."
    }
    $config = Import-PowerShellDataFile -LiteralPath $Path
    foreach ($section in 'General', 'Email', 'Thresholds', 'Defaults') {
        if (-not $config.ContainsKey($section) -or $null -eq $config[$section]) { $config[$section] = @{} }
    }
    if (-not $config.ContainsKey('Targets')) { $config.Targets = @() }
    return $config
}

function Merge-HCHashtable {
    # Shallow merge; later tables win.
    param([hashtable[]]$Table)
    $result = @{}
    foreach ($t in $Table) {
        if (-not $t) { continue }
        foreach ($k in $t.Keys) { $result[$k] = $t[$k] }
    }
    return $result
}

function New-HCSettings {
    param([Parameter(Mandatory)][hashtable]$Config, [Parameter(Mandatory)][string]$ScriptRoot)
    $g = $Config.General
    $resolve = {
        param($value, $default)
        $p = if ($value) { [string]$value } else { $default }
        if ([System.IO.Path]::IsPathRooted($p)) { $p } else { Join-Path $ScriptRoot $p }
    }
    @{
        Title            = Get-HCOption $g 'Title' 'Morning Infrastructure Health Check'
        Organization     = Get-HCOption $g 'Organization' ''
        Thresholds       = Merge-HCHashtable @((Get-HCDefaultThresholds), $Config.Thresholds)
        TimeoutSec       = [int](Get-HCOption $g 'TimeoutSec' 20)
        TcpTimeoutMs     = [int](Get-HCOption $g 'TcpTimeoutMs' 3000)
        ThrottleLimit    = [int](Get-HCOption $g 'ThrottleLimit' 8)
        MaxRunMinutes    = [int](Get-HCOption $g 'MaxRunMinutes' 20)
        KeepDays         = [int](Get-HCOption $g 'KeepDays' 30)
        ReportFolder     = & $resolve $g.ReportFolder 'Reports'
        LogFolder        = & $resolve $g.LogFolder 'Logs'
        CredentialFolder = & $resolve $g.CredentialFolder 'Credentials'
        Credentials      = @{}
        PreviousState    = @{}      # "Type|Name" -> @{ Key = @{ Value; Since } } from the previous run
    }
}

function Resolve-HCTargets {
    # Applies Defaults.All and Defaults.<Type> to every target and validates the basics.
    param([Parameter(Mandatory)][hashtable]$Config)
    $defaults = $Config.Defaults
    $validTypes = Get-HCTargetTypes
    $seen = @{}
    foreach ($raw in @($Config.Targets)) {
        if (-not $raw) { continue }
        if ($raw -isnot [hashtable]) { throw "Every entry under Targets must be a hashtable: @{ Type = '...'; Name = '...'; Address = '...' }" }
        $type = [string]$raw.Type
        if ($type -notin $validTypes) {
            throw "Unknown target Type '$type' (target '$($raw.Name)'). Valid types: $($validTypes -join ', ')"
        }
        $t = Merge-HCHashtable @($defaults['All'], $defaults[$type], $raw)
        $t.Type = $type
        if ($t.Enabled -eq $false) { continue }
        if (-not $t.Address -and $t.Url) { $t.Address = ([uri]$t.Url).Host }
        if (-not $t.Name) { $t.Name = if ($t.Address) { $t.Address } else { $t.Discover } }
        if (-not $t.Address -and -not $t.Discover) { throw "Target '$($t.Name)' ($type) needs an Address (or Url / Discover)." }
        $key = "$type|$($t.Name)"
        if ($seen.ContainsKey($key)) { throw "Duplicate target name '$($t.Name)' for type $type." }
        $seen[$key] = $true
        $t
    }
}

function Get-HCReferencedCredentialNames {
    # Every value whose key ends in "Credential", at any depth of the targets and the e-mail section.
    param([object[]]$Targets, [hashtable]$Email)
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $walk = {
        param($node)
        if ($node -is [hashtable]) {
            foreach ($k in $node.Keys) {
                $v = $node[$k]
                if ($k -like '*Credential' -and $v -is [string] -and $v) { [void]$names.Add($v) }
                elseif ($v -is [hashtable] -or $v -is [array]) { & $walk $v }
            }
        } elseif ($node -is [array]) {
            foreach ($item in $node) { & $walk $item }
        }
    }
    foreach ($t in $Targets) { & $walk $t }
    if ($Email) { & $walk $Email }
    return @($names)
}

function Select-HCTargets {
    # -Only filter: matches Type or Name (wildcards allowed).
    param([object[]]$Targets, [string[]]$Only)
    if (-not $Only) { return $Targets }
    foreach ($t in $Targets) {
        foreach ($o in $Only) {
            if ($t.Type -like $o -or $t.Name -like $o -or ($t.Discover -and $t.Discover -like $o)) { $t; break }
        }
    }
}
