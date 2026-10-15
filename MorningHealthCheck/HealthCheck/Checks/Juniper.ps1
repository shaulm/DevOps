# Juniper EX/QFX switches (Junos) over SSH - needs the Posh-SSH module on the monitoring server.
#
# Functionality : SSH login, chassis + system alarms, power/fans/temperature, Virtual Chassis members,
#                 file-system usage, last configuration commit (flagged when it happened overnight)
# Certificates  : local PKI certificates ("show security pki local-certificate") + optional J-Web HTTPS
# License       : "show system license" - features in use without a license, expiring licenses
#
# Use a read-only Junos login class, e.g.:  set system login user svc-healthcheck class read-only

function ConvertFrom-HCJunosVersion {
    param([string]$Text)
    $version = [regex]::Match($Text, '(?m)^\s*Junos:\s*(\S+)').Groups[1].Value
    if (-not $version) { $version = [regex]::Match($Text, 'JUNOS[^\[\r\n]*\[([^\]]+)\]').Groups[1].Value }
    [pscustomobject]@{
        Hostname = [regex]::Match($Text, '(?m)^\s*Hostname:\s*(\S+)').Groups[1].Value
        Model    = [regex]::Match($Text, '(?m)^\s*Model:\s*(\S+)').Groups[1].Value
        Version  = $version
    }
}

function ConvertFrom-HCJunosUptime {
    # "System booted: 2026-03-01 04:22:11 UTC (32w1d 02:08 ago)" -> "32w1d 02:08"
    param([string]$Text)
    $m = [regex]::Match($Text, 'System booted:[^\(\r\n]*\((?<ago>[^)]+?)\s+ago\)')
    if ($m.Success) { return $m.Groups['ago'].Value }
    return $null
}

function ConvertFrom-HCJunosAlarms {
    # Parses "show chassis alarms" / "show system alarms" (also the per-member blocks of a Virtual Chassis).
    param([string]$Text)
    $member = ''
    foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^(?<m>(fpc|member)\d+):\s*$') { $member = $Matches.m; continue }
        if ($line -match '^\s*(?<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+)\s+(?<class>Major|Minor)\s+(?<desc>.+?)\s*$') {
            [pscustomobject]@{ Member = $member; Time = $Matches.time; Class = $Matches.class; Description = $Matches.desc }
        }
    }
}

function ConvertFrom-HCJunosEnvironment {
    # Parses "show chassis environment"; returns one object per item with its status.
    param([string]$Text)
    $member = ''
    $class = ''
    foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^(?<m>fpc\d+):\s*$') { $member = $Matches.m; continue }
        if ($line -match '^(?<class>[A-Z][A-Za-z ]*?)?\s+(?<item>\S.*?)\s{2,}(?<status>OK|Check|Failed|Absent|Present|Testing|Online|Offline|Empty)\b(?<rest>.*)$') {
            if ($Matches.class) { $class = $Matches.class.Trim() }
            if ($Matches.item -eq 'Item') { continue }
            [pscustomobject]@{ Member = $member; Class = $class; Item = $Matches.item.Trim(); Status = $Matches.status; Detail = $Matches.rest.Trim() }
        }
    }
}

function ConvertFrom-HCJunosVirtualChassis {
    # Parses "show virtual-chassis". Returns $null when the switch is not a Virtual Chassis.
    param([string]$Text)
    if ($Text -notmatch 'Virtual Chassis ID|Member ID') { return $null }
    $members = foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^\s*(?<id>\d+)\s+\(FPC\s+[\d-]+\)\s+(?<status>\S+)(?<rest>.*)$') {
            $g = $Matches
            $rest = @($g.rest.Trim() -split '\s+' | Where-Object { $_ })
            $role = ($rest | Where-Object { $_ -like 'Master*' -or $_ -like 'Backup*' -or $_ -like 'Linecard*' -or $_ -like 'Primary*' } | Select-Object -First 1)
            [pscustomobject]@{
                Id     = [int]$g.id
                Status = $g.status
                Serial = $(if ($rest.Count -gt 0) { $rest[0] } else { '' })
                Model  = $(if ($rest.Count -gt 1) { $rest[1] } else { '' })
                Role   = [string]$role
            }
        }
    }
    return [pscustomobject]@{ Members = @($members) }
}

function ConvertFrom-HCJunosStorage {
    # Parses "show system storage" (df style). Returns file systems with capacity in percent.
    param([string]$Text)
    $member = ''
    foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^(?<m>fpc\d+):\s*$') { $member = $Matches.m; continue }
        if ($line -match '^\s*(?<fs>\S+)\s+(?<size>\S+)\s+(?<used>\S+)\s+(?<avail>\S+)\s+(?<cap>\d+)%\s+(?<mount>\S+)\s*$') {
            [pscustomobject]@{ Member = $member; FileSystem = $Matches.fs; Size = $Matches.size; Available = $Matches.avail; Capacity = [int]$Matches.cap; Mount = $Matches.mount }
        }
    }
}

function ConvertFrom-HCJunosCommit {
    # First entry of "show system commit": "0   2026-10-14 22:01:33 UTC by jdoe via cli"
    param([string]$Text)
    $m = [regex]::Match($Text, '(?m)^\s*0\s+(?<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+)\s+by\s+(?<user>\S+)(\s+via\s+(?<via>\S+))?')
    if (-not $m.Success) { return $null }
    [pscustomobject]@{ Time = ConvertTo-HCDateTime $m.Groups['time'].Value; User = $m.Groups['user'].Value; Via = $m.Groups['via'].Value }
}

function ConvertFrom-HCJunosLicense {
    # Parses the "License usage" table of "show system license".
    param([string]$Text)
    $inUsage = $false
    $member = ''
    foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^(?<m>fpc\d+):\s*$') { $member = $Matches.m; continue }
        if ($line -match '^\s*License usage') { $inUsage = $true; continue }
        if ($line -match '^\s*Licenses installed') { $inUsage = $false; continue }
        if (-not $inUsage) { continue }
        if ($line -match '^\s+(?<feature>[A-Za-z0-9][\w\-\./+]*)\s+(?<used>\d+)\s+(?<installed>\d+)\s+(?<needed>\d+)\s*(?<expiry>.*?)\s*$') {
            $g = $Matches   # keep the groups: the next -match replaces $Matches
            $expiryText = $g.expiry
            $expires = $null
            if ($expiryText -match '\d{4}-\d{2}-\d{2}') { $expires = ConvertTo-HCDateTime ($expiryText -replace '\s*\(.*\)$', '') }
            [pscustomobject]@{
                Member    = $member
                Feature   = $g.feature
                Used      = [int]$g.used
                Installed = [int]$g.installed
                Needed    = [int]$g.needed
                Permanent = ($expiryText -match 'permanent')
                Expires   = $expires
                Expiry    = $expiryText
            }
        }
    }
}

function ConvertFrom-HCJunosPkiCertificates {
    # Parses "show security pki local-certificate" (one block per "Certificate identifier").
    param([string]$Text)
    $blocks = [regex]::Split($Text, '(?m)^(?=\s*Certificate identifier:)')
    foreach ($block in $blocks) {
        $id = [regex]::Match($block, 'Certificate identifier:\s*(\S+)').Groups[1].Value
        if (-not $id) { continue }
        $issuedTo = [regex]::Match($block, 'Issued to:\s*(?<to>.+?),\s*Issued by:\s*(?<by>.+?)\s*$', 'Multiline')
        $notAfter = [regex]::Match($block, 'Not after:\s*(?<m>\d{1,2})-\s*(?<d>\d{1,2})-(?<y>\d{4})\s+(?<h>\d{1,2}):(?<min>\d{2})')
        $notBefore = [regex]::Match($block, 'Not before:\s*(?<m>\d{1,2})-\s*(?<d>\d{1,2})-(?<y>\d{4})\s+(?<h>\d{1,2}):(?<min>\d{2})')
        $toDate = {
            param($m)
            if (-not $m.Success) { return $null }
            ([datetime]::new([int]$m.Groups['y'].Value, [int]$m.Groups['m'].Value, [int]$m.Groups['d'].Value,
                [int]$m.Groups['h'].Value, [int]$m.Groups['min'].Value, 0, [System.DateTimeKind]::Utc)).ToLocalTime()
        }
        [pscustomobject]@{
            Identifier = $id
            IssuedTo   = $issuedTo.Groups['to'].Value.Trim()
            IssuedBy   = $issuedTo.Groups['by'].Value.Trim()
            NotBefore  = & $toDate $notBefore
            NotAfter   = & $toDate $notAfter
        }
    }
}

function Invoke-HCJunosCommand {
    # Runs one CLI command; retries through "cli -c" when the account lands in the FreeBSD shell (root).
    param([Parameter(Mandatory)]$SessionId, [Parameter(Mandatory)][string]$Command, [int]$TimeoutSec = 60)
    $run = {
        param($text)
        $r = Invoke-SSHCommand -SessionId $SessionId -Command $text -TimeOut $TimeoutSec -ErrorAction Stop
        $out = @($r.Output) -join "`n"
        if ($r.PSObject.Properties['Error'] -and $r.Error) { $out += "`n" + $r.Error }
        $out
    }
    $output = & $run "$Command | no-more"
    if ($output -match 'Command not found|command not found') {
        $output = & $run ("cli -c '{0} | no-more'" -f $Command)
    }
    return $output
}

function Invoke-HCCheckJuniper {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $t = $Settings.Thresholds
    $sshPort = [int](Get-HCOption $Target 'SshPort' 22)
    $ports = @($sshPort) + @($(if ($Target.HttpsPort) { [int]$Target.HttpsPort }))
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports $ports)) { return }
    if ($Target.HttpsPort) {
        $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port ([int]$Target.HttpsPort) -Source "J-Web :$($Target.HttpsPort)"
    }
    if (-not $Credential) {
        Add-HCMissingCredentialCheck -Context $Context -Target $Target -Name 'SSH'
        return
    }
    try {
        Import-Module Posh-SSH -ErrorAction Stop -Verbose:$false
    } catch {
        Add-HCCheck $Context 'SSH' 'Unknown' 'Posh-SSH module is not installed on the monitoring server (Install-Module Posh-SSH -Scope AllUsers)'
        return
    }
    $session = $null
    try {
        $p = @{
            ComputerName = $Target.Address; Port = $sshPort; Credential = $Credential; AcceptKey = $true
            ConnectionTimeout = [math]::Max($Settings.TimeoutSec, 15); ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue'
        }
        if ($Target.KeyFile) { $p.KeyFile = $Target.KeyFile }
        $session = New-SSHSession @p
    } catch {
        Add-HCCheck $Context 'SSH login' 'Critical' (Get-HCErrorText $_)
        return
    }
    try {
        $timeout = [math]::Max($Settings.TimeoutSec * 3, 60)
        $junos = { param($cmd) Invoke-HCJunosCommand -SessionId $session.SessionId -Command $cmd -TimeoutSec $timeout }

        $version = ConvertFrom-HCJunosVersion (& $junos 'show version')
        Set-HCFact $Context 'Model' $version.Model
        Set-HCFact $Context 'Junos' $version.Version
        Set-HCFact $Context 'Uptime' (ConvertFrom-HCJunosUptime (& $junos 'show system uptime'))
        Add-HCCheck $Context 'SSH login' 'OK' $(if ($version.Hostname) { "Logged in to $($version.Hostname)" } else { 'Logged in' })

        # Alarms
        $alarms = @(ConvertFrom-HCJunosAlarms (& $junos 'show chassis alarms')) + @(ConvertFrom-HCJunosAlarms (& $junos 'show system alarms'))
        # The same alarm is often reported by several VC members and by both commands - show it once.
        $alarms = @($alarms | Where-Object { -not (Test-HCIgnored -Value @($_.Description) -Pattern $Target.IgnoreAlarms) } |
                Group-Object Class, Description | ForEach-Object { $_.Group[0] })
        foreach ($a in ($alarms | Select-Object -First 6)) {
            $where = if ($a.Member) { "$($a.Member): " } else { '' }
            Add-HCCheck $Context "$($a.Class) alarm" $(if ($a.Class -eq 'Major') { 'Critical' } else { 'Warning' }) ("$where$($a.Description) (since $($a.Time))")
        }
        if ($alarms.Count -gt 6) { Add-HCCheck $Context 'Alarms' 'Warning' ('{0} more active alarms' -f ($alarms.Count - 6)) }
        if ($alarms.Count -eq 0) { Add-HCCheck $Context 'Alarms' 'OK' 'No active chassis or system alarms' }

        # Power, fans, temperature
        if ($Target.CheckEnvironment -ne $false) {
            $environment = @(ConvertFrom-HCJunosEnvironment (& $junos 'show chassis environment'))
            $bad = @($environment | Where-Object Status -in 'Check', 'Failed')
            foreach ($e in $bad) {
                $where = if ($e.Member) { "$($e.Member) " } else { '' }
                Add-HCCheck $Context "$($e.Class) $where$($e.Item)".Trim() $(if ($e.Status -eq 'Failed') { 'Critical' } else { 'Warning' }) ("$($e.Status) $($e.Detail)".Trim())
            }
            if ($environment.Count -and -not $bad) {
                Add-HCCheck $Context 'Environment' 'OK' ('{0} power/fan/temperature sensors OK' -f @($environment | Where-Object Status -eq 'OK').Count)
            }
        }

        # Virtual Chassis
        if ($Target.CheckVirtualChassis -ne $false) {
            $vc = ConvertFrom-HCJunosVirtualChassis (& $junos 'show virtual-chassis')
            if ($vc -and $vc.Members.Count) {
                $present = @($vc.Members | Where-Object Status -eq 'Prsnt')
                foreach ($m in @($vc.Members | Where-Object Status -ne 'Prsnt')) {
                    Add-HCCheck $Context "VC member $($m.Id)" 'Critical' ('{0} {1} {2}' -f $m.Status, $m.Model, $m.Serial).Trim()
                }
                if ($vc.Members.Count -gt 1) {
                    Set-HCFact $Context 'VC' ('{0}/{1}' -f $present.Count, $vc.Members.Count)
                    if (-not ($vc.Members | Where-Object Role -like 'Backup*')) { Add-HCCheck $Context 'VC redundancy' 'Warning' 'No backup routing engine in the Virtual Chassis' }
                }
                if ($present.Count -eq $vc.Members.Count -and $vc.Members.Count -gt 1) {
                    Add-HCCheck $Context 'Virtual Chassis' 'OK' ('{0}/{1} members present' -f $present.Count, $vc.Members.Count)
                }
            }
        }

        # File systems
        if ($Target.CheckStorage -ne $false) {
            $pattern = Get-HCOption $Target 'StorageMountPattern' '^(/|/\.mount|/\.mount/var|/\.mount/tmp|/\.mount/config|/var|/var/tmp|/var/log|/config|/tmp)$'
            $filesystems = @(ConvertFrom-HCJunosStorage (& $junos 'show system storage') | Where-Object { $_.Mount -match $pattern })
            $warnUsed = 100 - $t.DiskFreeWarningPct
            $critUsed = 100 - $t.DiskFreeCriticalPct
            $full = @($filesystems | Where-Object { $_.Capacity -ge $warnUsed })
            foreach ($f in $full) {
                $where = if ($f.Member) { "$($f.Member) " } else { '' }
                Add-HCCheck $Context "Storage $where$($f.Mount)" (Get-HCThresholdStatus -Value $f.Capacity -Warning $warnUsed -Critical $critUsed) ('{0}% used ({1} free)' -f $f.Capacity, $f.Available)
            }
            if ($filesystems.Count -and -not $full) {
                Add-HCCheck $Context 'Storage' 'OK' ('Max {0}% used' -f ($filesystems | Measure-Object Capacity -Maximum).Maximum)
            }
        }

        # Last configuration change - shown when it happened in the last 24 hours
        $commit = ConvertFrom-HCJunosCommit (& $junos 'show system commit')
        if ($commit -and $commit.Time -and ((Get-Date) - $commit.Time).TotalHours -le 24) {
            Set-HCFact $Context 'Changed' ('{0} by {1}' -f (Format-HCAgo $commit.Time), $commit.User)
        }

        # Licenses
        $licenseText = & $junos 'show system license'
        $features = @(ConvertFrom-HCJunosLicense $licenseText)
        $permanent = @()
        foreach ($f in $features) {
            $name = if ($f.Member) { "$($f.Member) $($f.Feature)" } else { $f.Feature }
            if ($f.Needed -gt 0) {
                $null = Add-HCLicense -Context $Context -Name $name -Status 'Warning' -StatusText "used without license ($($f.Needed) needed)" `
                    -Expires $f.Expires -Usage ('{0} used / {1} installed' -f $f.Used, $f.Installed) -Source 'Device' -Thresholds $t
            } elseif ($f.Expires) {
                $null = Add-HCLicense -Context $Context -Name $name -StatusText 'installed' -Expires $f.Expires `
                    -Usage ('{0} used / {1} installed' -f $f.Used, $f.Installed) -Source 'Device' -Thresholds $t
            } elseif ($f.Installed -gt 0) {
                $permanent += $f.Feature
            }
        }
        if ($permanent) {
            $null = Add-HCLicense -Context $Context -Name ('Junos licenses ({0})' -f @($permanent | Select-Object -Unique).Count) -StatusText 'permanent' `
                -Note (Format-HCList -Items @($permanent | Select-Object -Unique) -Max 6) -Source 'Device' -Thresholds $t
        } elseif (-not $features -and $licenseText -notmatch 'error') {
            $null = Add-HCLicense -Context $Context -Name 'Junos feature licenses' -StatusText 'none installed / not required' -Source 'Device' -Thresholds $t
        }

        # Local PKI certificates (certificate identifier = friendly name)
        if ($Target.CheckPkiCertificates -ne $false) {
            $pkiText = & $junos 'show security pki local-certificate'
            foreach ($c in @(ConvertFrom-HCJunosPkiCertificates $pkiText)) {
                $null = Add-HCCertificate -Context $Context -Source 'Junos PKI' -FriendlyName $c.Identifier -Subject "CN=$($c.IssuedTo)" `
                    -Issuer $c.IssuedBy -NotBefore $c.NotBefore -NotAfter $c.NotAfter -Thresholds $t -Ignore $Target.IgnoreCertificates
            }
        }
    } catch {
        Add-HCCheck $Context 'SSH commands' 'Unknown' (Get-HCErrorText $_)
    } finally {
        if ($session) { $null = Remove-SSHSession -SessionId $session.SessionId -ErrorAction SilentlyContinue }
    }
}
