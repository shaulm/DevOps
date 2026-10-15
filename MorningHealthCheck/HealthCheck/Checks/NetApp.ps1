# NetApp ONTAP clusters (ONTAP REST API, 9.6 or later).
#
# Functionality : API reachable, nodes up, storage failover, controller hardware, health alerts,
#                 aggregates / volumes space and state, failed disks, LIFs down or not home,
#                 SnapMirror health and lag, cluster peers
# Certificates  : every server/client certificate installed on the cluster (with its ONTAP name) +
#                 the certificate served on the cluster management LIF
# License       : license packages, compliance state and expiry dates
#
# Use a read-only account, e.g.:
#   security login create -user-or-group-name svc_healthcheck -application http -authentication-method password -role readonly

function Get-HCOntapRecords {
    # GET helper that follows ONTAP's _links.next pagination and returns all records.
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Rest)
    $uri = "$Base$Path"
    $pages = 0
    while ($uri -and $pages -lt 100) {
        $pages++
        $response = Invoke-HCRest -Uri $uri @Rest
        foreach ($record in @($response.records)) { if ($null -ne $record) { $record } }
        $next = $null
        if ($response.PSObject.Properties['_links'] -and $response._links.PSObject.Properties['next']) { $next = $response._links.next.href }
        $uri = if ($next) { "$Base$next" } else { $null }
    }
}

function Invoke-HCCheckNetApp {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $t = $Settings.Thresholds
    $address = $Target.Address
    $port = [int](Get-HCOption $Target 'Port' 443)
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports @($port))) { return }
    $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $port -Source "Cluster mgmt :$port"
    if (-not $Credential) {
        Add-HCMissingCredentialCheck -Context $Context -Target $Target -Name 'ONTAP REST API'
        return
    }
    $base = "https://${address}:$port"
    $rest = @{ Credential = $Credential; SkipCertificateCheck = [bool]$Target.SkipCertificateCheck; TimeoutSec = [math]::Max($Settings.TimeoutSec, 30) }

    try {
        $cluster = Invoke-HCRest -Uri "$base/api/cluster?fields=name,version" @rest
        $version = if ($cluster.version.full -match 'Release\s+(?<v>[^\s:]+)') { $Matches.v } else { '{0}.{1}.{2}' -f $cluster.version.generation, $cluster.version.major, $cluster.version.minor }
        Set-HCFact $Context 'ONTAP' $version
        Add-HCCheck $Context 'ONTAP REST API' 'OK' "Cluster '$($cluster.name)' responding"
    } catch {
        Add-HCCheck $Context 'ONTAP REST API' 'Critical' (Get-HCErrorText $_)
        return
    }

    # --- Nodes and storage failover -------------------------------------------------------------
    try {
        $nodes = @(Get-HCOntapRecords -Base $base -Path '/api/cluster/nodes?fields=name,state,membership,uptime,model,ha' -Rest $rest)
        $problems = 0
        foreach ($n in $nodes) {
            if ($n.state -ne 'up') { Add-HCCheck $Context "Node $($n.name)" 'Critical' "State: $($n.state)"; $problems++; continue }
            if ($n.ha -and $n.ha.enabled) {
                $takeover = [string]$n.ha.takeover.state
                $giveback = [string]$n.ha.giveback.state
                if ($takeover -in 'in_takeover', 'in_progress', 'failed') { Add-HCCheck $Context "Node $($n.name) failover" 'Critical' "Takeover state: $takeover"; $problems++ }
                elseif ($takeover -eq 'not_possible') { Add-HCCheck $Context "Node $($n.name) failover" 'Warning' 'Takeover is not possible (HA pair impaired)'; $problems++ }
                if ($giveback -in 'failed', 'partial_failed', 'in_progress') { Add-HCCheck $Context "Node $($n.name) giveback" 'Warning' "Giveback state: $giveback"; $problems++ }
            }
        }
        $up = @($nodes | Where-Object state -eq 'up').Count
        Set-HCFact $Context 'Nodes' "$up/$($nodes.Count) up"
        $models = @($nodes | ForEach-Object model | Where-Object { $_ } | Select-Object -Unique)
        if ($models) { Set-HCFact $Context 'Model' ($models -join ', ') }
        if ($problems -eq 0) { Add-HCCheck $Context 'Nodes' 'OK' ('{0}/{1} nodes up, storage failover healthy' -f $up, $nodes.Count) }
    } catch {
        Add-HCCheck $Context 'Nodes' 'Unknown' (Get-HCErrorText $_)
    }

    # Controller hardware (fans, PSUs, temperature) - not on every ONTAP version, so best effort.
    try {
        $hw = @(Get-HCOntapRecords -Base $base -Path '/api/cluster/nodes?fields=name,controller.failed_fan,controller.failed_power_supply,controller.over_temperature' -Rest $rest)
        foreach ($n in $hw) {
            $c = $n.controller
            if (-not $c) { continue }
            if ($c.over_temperature -eq 'over') { Add-HCCheck $Context "Node $($n.name) temperature" 'Critical' 'Controller over temperature' }
            if ($c.failed_fan -and [int]$c.failed_fan.count -gt 0) { Add-HCCheck $Context "Node $($n.name) fans" 'Warning' ('{0} failed fan(s)' -f $c.failed_fan.count) }
            if ($c.failed_power_supply -and [int]$c.failed_power_supply.count -gt 0) { Add-HCCheck $Context "Node $($n.name) power" 'Warning' ('{0} failed power supply(ies)' -f $c.failed_power_supply.count) }
        }
    } catch {
        Add-HCLog $Context "controller hardware fields not available: $(Get-HCErrorText $_)"
    }

    # System health alerts ("system health alert show") via the CLI passthrough - best effort.
    try {
        $alerts = @(Get-HCOntapRecords -Base $base -Path '/api/private/cli/system/health/alert' -Rest $rest)
        if ($alerts.Count) {
            $text = $alerts | ForEach-Object { '{0} on {1}' -f $_.alert_id, $(if ($_.alerting_resource) { $_.alerting_resource } else { $_.node }) }
            Add-HCCheck $Context 'Health alerts' 'Warning' (Format-HCList -Items $text -Max 3)
        } else {
            Add-HCCheck $Context 'Health alerts' 'OK' 'No active system health alerts'
        }
    } catch {
        Add-HCLog $Context "system health alerts not available: $(Get-HCErrorText $_)"
    }

    # --- Aggregates ------------------------------------------------------------------------------
    try {
        $aggregates = @(Get-HCOntapRecords -Base $base -Path '/api/storage/aggregates?fields=name,state,space.block_storage' -Rest $rest)
        $fullest = $null; $issues = 0
        foreach ($a in $aggregates) {
            if ($a.state -ne 'online') { Add-HCCheck $Context "Aggregate $($a.name)" 'Critical' "State: $($a.state)"; $issues++; continue }
            $size = [double]$a.space.block_storage.size
            $used = [double]$a.space.block_storage.used
            if ($size -le 0) { continue }
            $pct = [math]::Round(100 * $used / $size, 1)
            if ($null -eq $fullest -or $pct -gt $fullest.Pct) { $fullest = @{ Name = $a.name; Pct = $pct } }
            $status = Get-HCThresholdStatus -Value $pct -Warning $t.AggregateUsedWarningPct -Critical $t.AggregateUsedCriticalPct
            if ($status -ne 'OK') { Add-HCCheck $Context "Aggregate $($a.name)" $status ('{0}% used, {1} free' -f $pct, (Format-HCBytes ($size - $used))); $issues++ }
        }
        Set-HCFact $Context 'Aggregates' $aggregates.Count
        if ($issues -eq 0 -and $aggregates.Count) {
            Add-HCCheck $Context 'Aggregates' 'OK' ('{0} online, fullest {1} at {2}%' -f $aggregates.Count, $fullest.Name, $fullest.Pct)
        }
    } catch {
        Add-HCCheck $Context 'Aggregates' 'Unknown' (Get-HCErrorText $_)
    }

    # --- Volumes ---------------------------------------------------------------------------------
    try {
        $volumes = @(Get-HCOntapRecords -Base $base -Path '/api/storage/volumes?fields=name,state,svm.name,space.used,space.available&max_records=2000' -Rest $rest)
        $offline = @(); $broken = @(); $full = @()
        foreach ($v in $volumes) {
            $label = "$($v.svm.name):$($v.name)"
            if (Test-HCIgnored -Value @($v.name, $label) -Pattern $Target.IgnoreVolumes) { continue }
            if ($v.state -eq 'offline') { $offline += $label; continue }
            if ($v.state -and $v.state -ne 'online') { $broken += "$label ($($v.state))"; continue }
            $used = [double]$v.space.used; $avail = [double]$v.space.available
            if (($used + $avail) -le 0) { continue }
            $pct = [math]::Round(100 * $used / ($used + $avail), 1)
            $status = Get-HCThresholdStatus -Value $pct -Warning $t.VolumeUsedWarningPct -Critical $t.VolumeUsedCriticalPct
            if ($status -ne 'OK') { $full += [pscustomobject]@{ Label = $label; Pct = $pct; Status = $status; Free = $avail } }
        }
        foreach ($f in @($full | Sort-Object Pct -Descending | Select-Object -First 5)) {
            Add-HCCheck $Context "Volume $($f.Label)" $f.Status ('{0}% used, {1} free' -f $f.Pct, (Format-HCBytes $f.Free))
        }
        if ($full.Count -gt 5) {
            Add-HCCheck $Context 'Volumes' (Get-HCWorstStatus @($full | Select-Object -Skip 5 | ForEach-Object Status)) ('{0} more volumes above {1}% used' -f ($full.Count - 5), $t.VolumeUsedWarningPct)
        }
        if ($broken) { Add-HCCheck $Context 'Volumes in error' 'Critical' (Format-HCList -Items $broken -Max 5) }
        if ($offline) { Add-HCCheck $Context 'Offline volumes' 'Warning' (Format-HCList -Items $offline -Max 5) }
        Set-HCFact $Context 'Volumes' $volumes.Count
        if (-not $full -and -not $broken -and -not $offline) {
            Add-HCCheck $Context 'Volumes' 'OK' ('{0} volumes online, none above {1}% used' -f $volumes.Count, $t.VolumeUsedWarningPct)
        }
    } catch {
        Add-HCCheck $Context 'Volumes' 'Unknown' (Get-HCErrorText $_)
    }

    # --- Disks -----------------------------------------------------------------------------------
    try {
        $disks = @(Get-HCOntapRecords -Base $base -Path '/api/storage/disks?fields=name,state,container_type' -Rest $rest)
        $failed = @($disks | Where-Object { $_.state -eq 'broken' -or $_.container_type -eq 'broken' } | ForEach-Object name)
        $rebuilding = @($disks | Where-Object { $_.state -in 'reconstructing', 'copy' } | ForEach-Object name)
        if ($failed) { Add-HCCheck $Context 'Failed disks' 'Critical' (Format-HCList -Items $failed -Max 6) }
        if ($rebuilding) { Add-HCCheck $Context 'Disk rebuild' 'Warning' ('In progress: ' + (Format-HCList -Items $rebuilding -Max 6)) }
        if (-not $failed -and -not $rebuilding) { Add-HCCheck $Context 'Disks' 'OK' ('{0} disks, no failures' -f $disks.Count) }
    } catch {
        Add-HCCheck $Context 'Disks' 'Unknown' (Get-HCErrorText $_)
    }

    # --- Network interfaces ----------------------------------------------------------------------
    try {
        $lifs = @(Get-HCOntapRecords -Base $base -Path '/api/network/ip/interfaces?fields=name,state,enabled,location.is_home,svm.name' -Rest $rest)
        $down = @($lifs | Where-Object { $_.enabled -ne $false -and $_.state -and $_.state -ne 'up' } | ForEach-Object name)
        $away = @($lifs | Where-Object { $_.location -and $_.location.is_home -eq $false } | ForEach-Object name)
        if ($down) { Add-HCCheck $Context 'LIFs down' 'Critical' (Format-HCList -Items $down -Max 5) }
        if ($away) { Add-HCCheck $Context 'LIFs not on home port' 'Warning' (Format-HCList -Items $away -Max 5) }
        if (-not $down -and -not $away) { Add-HCCheck $Context 'Network interfaces' 'OK' ('{0} LIFs up and home' -f $lifs.Count) }
    } catch {
        Add-HCCheck $Context 'Network interfaces' 'Unknown' (Get-HCErrorText $_)
    }

    # --- SnapMirror + cluster peers --------------------------------------------------------------
    try {
        $relationships = @(Get-HCOntapRecords -Base $base -Path '/api/snapmirror/relationships?fields=source.path,destination.path,healthy,state,lag_time,unhealthy_reason' -Rest $rest)
        $unhealthy = @(); $lagging = @(); $maxLag = [TimeSpan]::Zero
        foreach ($r in $relationships) {
            if ($r.healthy -eq $false) {
                $why = @($r.unhealthy_reason | ForEach-Object { $_.message } | Where-Object { $_ }) -join '; '
                $unhealthy += ('{0}{1}' -f $r.destination.path, $(if ($why) { " ($why)" }))
            }
            if ($r.lag_time) {
                try {
                    $lag = [System.Xml.XmlConvert]::ToTimeSpan([string]$r.lag_time)
                    if ($lag -gt $maxLag) { $maxLag = $lag }
                    if ($lag.TotalHours -gt $t.SnapMirrorLagWarningHours) { $lagging += ('{0} ({1})' -f $r.destination.path, (Format-HCDuration $lag)) }
                } catch {
                    Add-HCLog $Context "cannot parse lag_time '$($r.lag_time)'"
                }
            }
        }
        if ($unhealthy) { Add-HCCheck $Context 'SnapMirror' 'Critical' ('Unhealthy: ' + (Format-HCList -Items $unhealthy -Max 3)) }
        if ($lagging) { Add-HCCheck $Context 'SnapMirror lag' 'Warning' (Format-HCList -Items $lagging -Max 3) }
        if ($relationships.Count -and -not $unhealthy -and -not $lagging) {
            Add-HCCheck $Context 'SnapMirror' 'OK' ('{0} relationships healthy, max lag {1}' -f $relationships.Count, (Format-HCDuration $maxLag))
        }
    } catch {
        Add-HCCheck $Context 'SnapMirror' 'Unknown' (Get-HCErrorText $_)
    }
    try {
        $peers = @(Get-HCOntapRecords -Base $base -Path '/api/cluster/peers?fields=name,status' -Rest $rest)
        foreach ($p in $peers) {
            if ($p.status -and $p.status.state -and $p.status.state -ne 'available') {
                Add-HCCheck $Context "Cluster peer $($p.name)" 'Warning' "Peer state: $($p.status.state)"
            }
        }
    } catch {
        Add-HCLog $Context "cluster peers: $(Get-HCErrorText $_)"
    }

    # --- Licenses --------------------------------------------------------------------------------
    try {
        $packages = @(Get-HCOntapRecords -Base $base -Path '/api/cluster/licensing/licenses?fields=*' -Rest $rest)
        $permanent = @()
        foreach ($p in $packages) {
            if ($p.state -eq 'unlicensed') { continue }
            $entries = @($p.licenses | Where-Object { $_ })
            $expiries = @($entries | ForEach-Object { ConvertTo-HCDateTime $_.expiry_time } | Where-Object { $_ } | Sort-Object)
            $evaluation = @($entries | Where-Object { $_.evaluation }).Count -gt 0
            $vendorStatus = switch ([string]$p.state) { 'compliant' { 'OK' } 'noncompliant' { 'Critical' } default { 'Warning' } }
            if ($expiries.Count -eq 0 -and $vendorStatus -eq 'OK' -and -not $evaluation) { $permanent += $p.name; continue }
            $installed = @($entries | ForEach-Object { $_.installed_license } | Where-Object { $_ } | Select-Object -Unique) -join ', '
            $note = @($(if ($evaluation) { 'evaluation' }), $installed) | Where-Object { $_ }
            $null = Add-HCLicense -Context $Context -Name "ONTAP $($p.name)" -Status $vendorStatus -StatusText ([string]$p.state) `
                -Expires $(if ($expiries) { $expiries[0] } else { $null }) -Note ($note -join '; ') -Thresholds $t
        }
        if ($permanent) {
            $null = Add-HCLicense -Context $Context -Name ('ONTAP license packages ({0})' -f $permanent.Count) -StatusText 'compliant' `
                -Note (Format-HCList -Items $permanent -Max 8) -Thresholds $t
        }
    } catch {
        Add-HCCheck $Context 'Licenses' 'Unknown' (Get-HCErrorText $_)
    }

    # --- Certificates installed on the cluster ---------------------------------------------------
    try {
        $types = @(Get-HCOption $Target 'CertificateTypes' @('server', 'client'))
        $certs = @(Get-HCOntapRecords -Base $base -Path ('/api/security/certificates?type={0}&fields=*' -f ($types -join '|')) -Rest $rest)
        foreach ($c in $certs) {
            $x509 = ConvertFrom-HCPem -Pem ([string]$c.public_certificate) | Select-Object -First 1
            $scope = if ($c.svm -and $c.svm.name) { "SVM $($c.svm.name)" } else { 'cluster' }
            $p = @{
                Context = $Context; Source = "ONTAP $scope ($($c.type))"; FriendlyName = [string]$c.name
                Thresholds = $t; Ignore = $Target.IgnoreCertificates
            }
            if ($x509) { $p.Certificate = $x509 }
            else { $p.Subject = "CN=$($c.common_name)"; $p.Issuer = "CN=$($c.ca)"; $p.NotAfter = ConvertTo-HCDateTime $c.expiry_time }
            $null = Add-HCCertificate @p
        }
    } catch {
        Add-HCCheck $Context 'Certificates' 'Unknown' (Get-HCErrorText $_)
    }
}
