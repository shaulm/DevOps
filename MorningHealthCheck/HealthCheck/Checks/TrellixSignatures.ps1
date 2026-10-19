# Trellix ePO: are the signatures up to date?
# (AMCore content for Endpoint Security, DAT files for the legacy VirusScan Enterprise.)
#
# 1. Endpoints : content date (or version) of every managed system, read through the ePO Web API.
#                Systems with content older than Signatures.MaxAgeDays are out of date; the share of
#                out-of-date systems sets the status (WarningPct / CriticalPct). The oldest are named.
# 2. ePO itself: content is released daily, so the newest content on ANY system, and the AMCore/DAT
#                package in the master repository, must keep changing. When they stop changing for
#                RepositoryMaxAgeDays, ePO is no longer pulling updates from Trellix.
#
# The per-system data comes from a saved ePO query (Signatures.QueryId) when one is configured;
# otherwise the check tries the property names ePO uses for Endpoint Security and VirusScan.

$script:HCEpoContentSources = @(
    @{ Product = 'AMCore content'; Property = 'AM_CustomProps.AMCoreContentDate' }                # Endpoint Security: content date
    @{ Product = 'AMCore content'; Property = 'EPOProdPropsView_THREATPREVENTION.verDAT32Major' }  # Endpoint Security: content version
    @{ Product = 'DAT'; Property = 'EPOProdPropsView_VIRUSCAN.datver' }                          # VirusScan Enterprise: DAT version
)

function ConvertTo-HCContentVersion {
    # "5321.0" / 5321 / "9876.0000" -> 5321 / 9876 (the major number is what increases daily)
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return [double][math]::Floor($Value) }
    $m = [regex]::Match([string]$Value, '^\s*(\d+)(\.\d+)?\s*$')
    if ($m.Success) { return [double]$m.Groups[1].Value }
    return $null
}

function Get-HCContentColumns {
    # Finds the system-name column and the content date / content version column in ePO query rows.
    param([object[]]$Rows)
    $sample = @($Rows | Where-Object { $null -ne $_ } | Select-Object -First 200)
    if ($sample.Count -eq 0) { return $null }
    $names = @($sample[0].PSObject.Properties.Name)
    $find = {
        param([string[]]$Patterns, [string]$Exclude)
        foreach ($pattern in $Patterns) {
            foreach ($n in $names) { if ($n -match $pattern -and -not ($Exclude -and $n -match $Exclude)) { return $n } }
        }
        return $null
    }
    $nameColumn = & $find @('NodeName$', 'ComputerName$', 'System\s*Name$', 'HostName$', 'Name$') ''
    if (-not $nameColumn) { $nameColumn = $names[0] }
    $dateColumn = & $find @('AMCoreContentDate', 'Content\s*Date', 'DAT\s*Date', 'Date') 'Update|Install|Boot|Comm|Policy|Seen|Last|Scan'
    $versionColumn = & $find @('AMCoreContentVersion', 'verDAT32Major', 'DATVer', 'Content\s*Version', 'DAT\s*Version', 'AMCore') 'Engine|Product|Agent|Hotfix|Patch|Date'
    # Keep a column only when its values really are dates / versions.
    if ($dateColumn -and -not ($sample | Where-Object { ConvertTo-HCDateTime $_.$dateColumn } | Select-Object -First 1)) { $dateColumn = $null }
    if ($versionColumn -and -not ($sample | Where-Object { $null -ne (ConvertTo-HCContentVersion $_.$versionColumn) } | Select-Object -First 1)) { $versionColumn = $null }
    [pscustomobject]@{ Name = $nameColumn; Date = $dateColumn; Version = $versionColumn }
}

function Measure-HCContentFreshness {
    <#
      Rows: ePO query result, one row per system. Mode 'Date' when content dates are available
      (out of date = older than MaxAgeDays), otherwise 'Version' (out of date = more than
      MaxVersionsBehind behind the newest version any system has). Mode 'None' if neither.
    #>
    param([object[]]$Rows, [int]$MaxAgeDays = 3, [int]$MaxVersionsBehind = 3)
    $result = [pscustomobject]@{
        Mode = 'None'; Column = $null; Total = 0; NoData = 0; Outdated = @()
        NewestDate = $null; NewestAgeDays = $null; NewestVersion = $null
    }
    $columns = Get-HCContentColumns -Rows $Rows
    if (-not $columns) { return $result }
    $today = (Get-Date).Date
    $items = @(foreach ($row in $Rows) {
            if ($null -eq $row) { continue }
            [pscustomobject]@{
                Name    = [string]$row.($columns.Name)
                Date    = $(if ($columns.Date) { ConvertTo-HCDateTime $row.($columns.Date) } else { $null })
                Version = $(if ($columns.Version) { ConvertTo-HCContentVersion $row.($columns.Version) } else { $null })
                AgeDays = $null
                Behind  = $null
            }
        })
    $dated = @($items | Where-Object { $_.Date })
    $versioned = @($items | Where-Object { $null -ne $_.Version })
    if ($versioned.Count) { $result.NewestVersion = ($versioned | Sort-Object Version -Descending | Select-Object -First 1).Version }
    if ($dated.Count) {
        foreach ($i in $dated) { $i.AgeDays = [int][math]::Max(0, ($today - $i.Date.Date).TotalDays) }
        $newest = ($dated | Sort-Object Date -Descending | Select-Object -First 1).Date
        $result.Mode = 'Date'
        $result.Column = $columns.Date
        $result.Total = $dated.Count
        $result.NewestDate = $newest
        $result.NewestAgeDays = [int][math]::Max(0, ($today - $newest.Date).TotalDays)
        $result.Outdated = @($dated | Where-Object { $_.AgeDays -gt $MaxAgeDays } | Sort-Object AgeDays -Descending)
    } elseif ($versioned.Count) {
        foreach ($i in $versioned) { $i.Behind = [int]($result.NewestVersion - $i.Version) }
        $result.Mode = 'Version'
        $result.Column = $columns.Version
        $result.Total = $versioned.Count
        $result.Outdated = @($versioned | Where-Object { $_.Behind -gt $MaxVersionsBehind } | Sort-Object Behind -Descending)
    }
    $result.NoData = $items.Count - $result.Total
    return $result
}

function Select-HCContentPackage {
    # Picks the AMCore (or DAT) package from repository.findPackages output, preferring the Current branch.
    param([object[]]$Packages)
    $candidates = foreach ($p in $Packages) {
        if ($null -eq $p -or $p -is [string]) { continue }
        $props = @($p.PSObject.Properties)
        $text = ($props | ForEach-Object { [string]$_.Value }) -join ' '
        if ($text -notmatch 'AMCORDAT|AMCore\s*Content|VSCANDAT|DAT\s*(File|Package)') { continue }
        $value = {
            param([string]$Pattern, [string]$Exclude)
            ($props | Where-Object { $_.Name -match $Pattern -and -not ($Exclude -and $_.Name -match $Exclude) } | Select-Object -First 1).Value
        }
        $version = & $value 'version' 'engine|extension|agent'
        if (-not $version) { continue }
        [pscustomobject]@{
            Name    = $(if ($text -match 'AMCORDAT|AMCore') { 'AMCore content' } else { 'DAT' })
            Version = [string]$version
            Branch  = [string](& $value 'branch' '')
        }
    }
    $candidates | Sort-Object @{ Expression = { if ($_.Branch -match '^current$') { 0 } elseif (-not $_.Branch) { 1 } else { 2 } } },
    @{ Expression = { if ($_.Name -eq 'AMCore content') { 0 } else { 1 } } } | Select-Object -First 1
}

function Test-HCEpoSignatures {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][hashtable]$Target,
        [Parameter(Mandatory)][hashtable]$Epo,
        [Parameter(Mandatory)][hashtable]$Settings
    )
    $cfg = if ($Target.Signatures -is [hashtable]) { $Target.Signatures } else { @{} }
    if ($cfg.Enabled -eq $false) { return }
    $maxAge = [int](Get-HCOption $cfg 'MaxAgeDays' 3)
    $maxBehind = [int](Get-HCOption $cfg 'MaxVersionsBehind' $maxAge)
    $warnPct = [double](Get-HCOption $cfg 'WarningPct' 5)
    $critPct = [double](Get-HCOption $cfg 'CriticalPct' 15)
    $repoDays = [int](Get-HCOption $cfg 'RepositoryMaxAgeDays' 2)
    $show = [int](Get-HCOption $cfg 'ShowOldest' 5)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture

    # --- 1. content on the managed systems ------------------------------------------------------
    $measure = $null
    $product = 'AMCore/DAT content'
    if ($cfg.QueryId) {
        try {
            $rows = @(Invoke-HCEpoCommand @Epo -Command 'core.executeQuery' -Parameters @{ queryId = [string]$cfg.QueryId } | Where-Object { $null -ne $_ })
            $measure = Measure-HCContentFreshness -Rows $rows -MaxAgeDays $maxAge -MaxVersionsBehind $maxBehind
            if ($measure.Column -match 'AMCore|THREATPREVENTION|AM_') { $product = 'AMCore content' }
            elseif ($measure.Column -match 'DAT|VIRUSCAN') { $product = 'DAT' }
            if ($measure.Total -eq 0) {
                Add-HCCheck $Context 'Signatures' 'Unknown' "Saved query $($cfg.QueryId) returned $($rows.Count) row(s) but no content date or version column - add 'AMCore Content Date' (or 'DAT Version') to the query"
            }
        } catch {
            Add-HCCheck $Context 'Signatures' 'Unknown' "Saved query $($cfg.QueryId) failed: $(Get-HCErrorText $_)"
        }
    } else {
        foreach ($source in $script:HCEpoContentSources) {
            try {
                $rows = @(Invoke-HCEpoCommand @Epo -Command 'core.executeQuery' -Parameters @{
                        target = 'EPOLeafNode'; select = "(select EPOLeafNode.NodeName $($source.Property))"
                    } | Where-Object { $null -ne $_ })
                $candidate = Measure-HCContentFreshness -Rows $rows -MaxAgeDays $maxAge -MaxVersionsBehind $maxBehind
                if ($candidate.Total -gt 0) { $measure = $candidate; $product = $source.Product; break }
                Add-HCLog $Context "signatures: $($source.Property) returned no values"
            } catch {
                Add-HCLog $Context "signatures: $($source.Property): $(Get-HCErrorText $_)"
            }
        }
        if (-not $measure) {
            Add-HCCheck $Context 'Signatures' 'Unknown' ('Could not read the AMCore/DAT content of the managed systems automatically - ' +
                'create a saved ePO query with System Name and AMCore Content Date and set Signatures.QueryId (see README)')
        }
    }

    if ($measure -and $measure.Total -gt 0) {
        $outdated = @($measure.Outdated)
        $pct = [math]::Round(100 * $outdated.Count / $measure.Total, 1)
        $status = Get-HCThresholdStatus -Value $pct -Warning $warnPct -Critical $critPct
        $rule = if ($measure.Mode -eq 'Date') { "content older than $maxAge days" } else { "content more than $maxBehind versions behind $($measure.NewestVersion)" }
        $message = '{0:N0} of {1:N0} systems ({2}%) have {3}' -f $outdated.Count, $measure.Total, $pct, $rule
        if ($outdated.Count) {
            $names = @($outdated | Select-Object -First $show | ForEach-Object {
                    if ($measure.Mode -eq 'Date') { '{0} ({1} d)' -f $_.Name, $_.AgeDays } else { '{0} ({1} behind)' -f $_.Name, $_.Behind }
                })
            $message += '; oldest: ' + ($names -join ', ')
            if ($outdated.Count -gt $show) { $message += " (+$($outdated.Count - $show) more)" }
        }
        if ($measure.NoData) { $message += ('; {0:N0} system(s) report no {1}' -f $measure.NoData, $product) }
        Add-HCCheck $Context "Signatures ($product)" $status $message
        Set-HCFact $Context 'Signatures' ('{0}% current' -f [math]::Round(100 - $pct, 1))

        # The newest content on ANY system shows whether new content still reaches ePO.
        if ($measure.Mode -eq 'Date') {
            $age = $measure.NewestAgeDays
            $when = if ($age -le 0) { 'today' } elseif ($age -eq 1) { '1 day old' } else { "$age days old" }
            $text = '{0} dated {1:dd MMM yyyy} ({2})' -f $product, $measure.NewestDate, $when
            if ($null -ne $measure.NewestVersion) { $text += ", version $($measure.NewestVersion)" }
            if ($age -gt $repoDays) {
                Add-HCCheck $Context 'Newest content in use' 'Warning' "$text - no system has anything newer: is ePO still pulling content from Trellix?"
            } else {
                Add-HCCheck $Context 'Newest content in use' 'OK' $text
            }
        } elseif ($null -ne $measure.NewestVersion) {
            $since = Get-HCValueSince -Context $Context -Settings $Settings -Key 'NewestContentVersion' -Value ([string]$measure.NewestVersion)
            $days = [int][math]::Floor(((Get-Date) - $since).TotalDays)
            if ($days -gt $repoDays) {
                Add-HCCheck $Context 'Newest content in use' 'Warning' ("{0} {1} on the newest systems has not changed since {2} - is ePO still pulling content from Trellix?" -f $product, $measure.NewestVersion, $since.ToString('dd MMM', $inv))
            } else {
                Add-HCCheck $Context 'Newest content in use' 'OK' ('{0} {1} on the newest systems' -f $product, $measure.NewestVersion)
            }
        }
    }

    # --- 2. the package in the master repository (best effort) -------------------------------------
    if ($cfg.CheckRepository -ne $false) {
        $package = $null
        foreach ($parameters in @(@{}, @{ searchText = 'AMCore' }, @{ searchText = 'DAT' })) {
            try {
                $found = @(Invoke-HCEpoCommand @Epo -Command 'repository.findPackages' -Parameters $parameters | Where-Object { $null -ne $_ })
                $package = Select-HCContentPackage -Packages $found
                if ($package) { break }
            } catch {
                $why = Get-HCErrorText $_
                Add-HCLog $Context "repository.findPackages: $why"
                if ($why -match 'Unknown command|not found|permission|HTTP 40') { break }   # retrying with other parameters will not help
            }
        }
        if ($package) {
            $label = '{0} {1}' -f $package.Name, $package.Version
            Set-HCFact $Context 'Repository' $label
            $since = Get-HCValueSince -Context $Context -Settings $Settings -Key 'RepositoryContent' -Value $label
            $days = [int][math]::Floor(((Get-Date) - $since).TotalDays)
            $branch = if ($package.Branch) { " ($($package.Branch) branch)" } else { '' }
            if ($days -gt $repoDays) {
                Add-HCCheck $Context 'Master repository content' 'Warning' ("{0}{1} has not changed since {2} ({3} days) - check the repository pull server task" -f $label, $branch, $since.ToString('dd MMM', $inv), $days)
            } else {
                Add-HCCheck $Context 'Master repository content' 'OK' "$label$branch"
            }
        } else {
            Add-HCLog $Context 'signatures: no AMCore/DAT package found through repository.findPackages'
        }
    }
}
