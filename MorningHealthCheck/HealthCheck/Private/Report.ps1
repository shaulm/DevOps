# HTML / plain-text report.
#
# Written for e-mail clients, Gmail in particular: table layout, no scripts, images or web fonts.
# Layout CSS lives in one small <style> block (supported by Gmail for Gmail accounts); everything that
# carries meaning - status colours, badges - is also inline, so the report stays readable if a client
# strips the <style> block. Tables use cellpadding as a spacing fallback.
# Gmail clips messages over ~102 KB, so the e-mail body is kept short (only what needs a look) and
# switches to a compact layout for very large environments; the attached report always has everything.

$script:HCPalette = @{
    Critical = @{ Fg = '#b42318'; Bg = '#fee4e2'; Solid = '#d92d20'; Label = 'CRITICAL' }
    Warning  = @{ Fg = '#93370d'; Bg = '#fef0c7'; Solid = '#f79009'; Label = 'WARNING' }
    Unknown  = @{ Fg = '#5925dc'; Bg = '#ebe9fe'; Solid = '#7a5af8'; Label = 'UNKNOWN' }
    OK       = @{ Fg = '#067647'; Bg = '#dcfae6'; Solid = '#17b26a'; Label = 'OK' }
    Info     = @{ Fg = '#475467'; Bg = '#f2f4f7'; Solid = '#98a2b3'; Label = 'INFO' }
}
$script:HCFont = "'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif"
$script:HCHighlightFacts = @('Changed', 'Policy installed')
$script:HCCss = @"
body{margin:0;padding:0;background-color:#eef1f5;}
.w{font-family:$($script:HCFont);color:#101828;}
.card{background-color:#ffffff;border:1px solid #e4e7ec;border-radius:12px;border-collapse:separate;}
.h2{padding:14px 16px 6px 16px;font-size:15px;line-height:20px;font-weight:700;color:#101828;}
.hint{font-size:12px;font-weight:400;color:#667085;}
.g td{padding:8px;border-bottom:1px solid #f2f4f7;font-size:12px;line-height:17px;vertical-align:top;color:#344054;word-break:break-word;overflow-wrap:anywhere;}
.g tr.c td{padding:14px 8px 6px 8px;border-bottom:1px solid #eaecf0;}
.g tr.h td{padding:6px 8px;font-size:10px;line-height:12px;font-weight:700;color:#98a2b3;text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid #eaecf0;}
.cn{font-size:11px;font-weight:700;color:#344054;text-transform:uppercase;letter-spacing:.6px;}
.n{font-size:13px;line-height:18px;font-weight:600;color:#101828;}
.s{font-size:11px;line-height:15px;color:#98a2b3;}
.m{color:#667085;}
.b{display:inline-block;min-width:58px;text-align:center;padding:3px 6px;border-radius:10px;font-size:10px;line-height:12px;font-weight:700;letter-spacing:.4px;white-space:nowrap;}
.p{display:inline-block;min-width:54px;text-align:center;padding:4px 6px;border-radius:8px;font-size:12px;line-height:14px;font-weight:700;white-space:nowrap;}
.new{display:inline-block;padding:1px 6px;border-radius:8px;background-color:#d1e9ff;color:#175cd3;font-size:10px;font-weight:700;}
.foot{padding:18px 12px 6px 12px;font-size:11px;line-height:17px;color:#98a2b3;text-align:center;}
"@

function ConvertTo-HCHtmlText {
    param([AllowNull()][object]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-HCStyle {
    param([string]$Status)
    if ($Status -and $script:HCPalette.ContainsKey($Status)) { return $script:HCPalette[$Status] }
    return $script:HCPalette['Unknown']
}

function New-HCBadgeHtml {
    param([string]$Status, [string]$Text)
    $p = Get-HCStyle $Status
    $label = if ($Text) { $Text } else { $p.Label }
    "<span class=`"b`" style=`"background-color:$($p.Bg);color:$($p.Fg);font-weight:700;`">$label</span>"
}

function New-HCDaysPillHtml {
    param([AllowNull()][Nullable[int]]$Days, [string]$Status)
    if ($null -eq $Days) {
        $p = Get-HCStyle 'Info'; $text = 'no expiry'
    } else {
        $p = Get-HCStyle $(if ($Status) { $Status } else { 'OK' })
        $text = if ($Days -lt 0) { 'EXPIRED' } elseif ($Days -ge 1000) { '{0:N0} d' -f $Days } else { "$Days d" }
    }
    "<span class=`"p`" style=`"background-color:$($p.Bg);color:$($p.Fg);font-weight:700;`">$text</span>"
}

function New-HCSectionHtml {
    param([string]$Title, [string]$Hint, [string]$Inner)
    $hintHtml = if ($Hint) { "&nbsp;&nbsp;<span class=`"hint`">$Hint</span>" } else { '' }
    @"
<tr><td style="padding:14px 0 0 0;">
<table role="presentation" class="card" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff">
<tr><td class="h2"><b>$Title</b>$hintHtml</td></tr>
<tr><td style="padding:0 8px 8px 8px;">$Inner</td></tr>
</table>
</td></tr>
"@
}

function New-HCGridHtml {
    # Data table; cellpadding is the fallback spacing when a client ignores the <style> block.
    param([string[]]$Rows)
    "<table role=`"presentation`" class=`"g w`" width=`"100%`" cellpadding=`"6`" cellspacing=`"0`" border=`"0`">$($Rows -join "`n")</table>"
}

function New-HCColumnHeaderHtml {
    param([string[]]$Labels, [string[]]$Widths)
    $cells = for ($i = 0; $i -lt $Labels.Count; $i++) {
        $w = if ($Widths -and $Widths[$i]) { " width=`"$($Widths[$i])`"" } else { '' }
        "<td$w>$($Labels[$i])</td>"
    }
    '<tr class="h">' + ($cells -join '') + '</tr>'
}

function Format-HCFactsHtml {
    param($Facts)
    if (-not $Facts -or $Facts.Count -eq 0) { return '' }
    $plain = @(); $highlight = @()
    foreach ($k in $Facts.Keys) {
        $text = '{0} {1}' -f $k, $Facts[$k]
        if ($k -in $script:HCHighlightFacts) { $highlight += $text } else { $plain += $text }
    }
    $html = (@($plain | ForEach-Object { ConvertTo-HCHtmlText $_ }) -join ' &#183; ')
    if ($highlight) {
        $hl = (@($highlight | ForEach-Object { ConvertTo-HCHtmlText $_ }) -join ' &#183; ')
        $html = (@($html, "<span style=`"color:#b54708;font-weight:600;`">$hl</span>") | Where-Object { $_ }) -join ' &#183; '
    }
    return $html
}

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

function New-HCReportModel {
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][hashtable]$Settings,
        $Previous,
        [datetime]$Started = (Get-Date),
        [switch]$Demo
    )
    $sorted = @($Results | Sort-Object CategoryOrder, Name)
    $issues = foreach ($r in $sorted) {
        foreach ($i in @(Get-HCIssues -Context $r)) {
            [pscustomobject]@{
                Status = $i.Status; Category = $r.Category; CategoryOrder = $r.CategoryOrder; System = $r.Name
                Kind = $i.Kind; Title = $i.Title; Detail = $i.Detail; Key = "$($r.Type)|$($r.Name)|$($i.Key)"; IsNew = $false
            }
        }
    }
    $issues = @($issues | Sort-Object @{ Expression = { Get-HCStatusRank $_.Status }; Descending = $true }, CategoryOrder, System)
    $resolved = @()
    if ($Previous) {
        $previousKeys = @($Previous.Issues | ForEach-Object { $_.Key })
        foreach ($i in $issues) { $i.IsNew = $previousKeys -notcontains $i.Key }
        $currentKeys = @($issues | ForEach-Object Key)
        $resolved = @($Previous.Issues | Where-Object { $_ -and $currentKeys -notcontains $_.Key })
    }
    $t = $Settings.Thresholds
    $certificates = @($sorted | ForEach-Object { $_.Certificates } | Where-Object { $_ })
    $licenses = @($sorted | ForEach-Object { $_.Licenses } | Where-Object { $_ })
    $expiring = @($certificates | Where-Object { $_.Status -in 'Warning', 'Critical' -and $null -ne $_.DaysLeft -and $_.DaysLeft -le $t.CertWarningDays }).Count +
    @($licenses | Where-Object { $_.Status -in 'Warning', 'Critical' -and $null -ne $_.DaysLeft -and $_.DaysLeft -le $t.LicenseWarningDays }).Count
    $user = if ($IsWindows) { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } else { [Environment]::UserName }
    [pscustomobject]@{
        Title         = $Settings.Title
        Organization  = $Settings.Organization
        Generated     = $Started
        DurationSec   = [math]::Round(((Get-Date) - $Started).TotalSeconds)
        Computer      = [Environment]::MachineName
        RunAs         = $user
        Results       = $sorted
        Issues        = $issues
        Resolved      = $resolved
        HasPrevious   = [bool]$Previous
        Counts        = [ordered]@{
            Systems  = $sorted.Count
            OK       = @($sorted | Where-Object Status -in 'OK', 'Info').Count
            Warning  = @($sorted | Where-Object Status -eq 'Warning').Count
            Critical = @($sorted | Where-Object Status -eq 'Critical').Count
            Unknown  = @($sorted | Where-Object Status -eq 'Unknown').Count
        }
        Overall       = Get-HCWorstStatus -Status @($sorted | ForEach-Object Status) -Default 'OK'
        Certificates  = $certificates
        Licenses      = $licenses
        ExpiringCount = $expiring
        Thresholds    = $t
        Demo          = [bool]$Demo
    }
}

function ConvertTo-HCPreviousRun {
    # What is kept from a run so the next one can mark issues as new / resolved.
    param([Parameter(Mandatory)]$Model)
    [pscustomobject]@{
        Generated = $Model.Generated.ToString('o')
        Counts    = $Model.Counts
        Issues    = @($Model.Issues | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Status = $_.Status; System = $_.System; Title = $_.Title; Detail = $_.Detail } })
    }
}

function Get-HCHeadline {
    param([Parameter(Mandatory)]$Model)
    $c = $Model.Counts
    $parts = @()
    if ($c.Critical) { $parts += "$($c.Critical) critical" }
    if ($c.Warning) { $parts += ('{0} warning{1}' -f $c.Warning, $(if ($c.Warning -gt 1) { 's' })) }
    if ($c.Unknown) { $parts += "$($c.Unknown) unknown" }
    if ($parts) { return ($parts -join ', ') }
    return "All $($c.Systems) systems healthy"
}

function Get-HCMailSubject {
    param([Parameter(Mandatory)]$Model, [hashtable]$Email)
    $prefix = if ($Email -and $Email.SubjectPrefix) { $Email.SubjectPrefix } else { 'Morning Health Check' }
    $emoji = ''
    if (-not $Email -or $Email.UseEmojiInSubject -ne $false) {
        $code = switch ($Model.Overall) { 'Critical' { 0x1F534 } { $_ -in 'Warning', 'Unknown' } { 0x1F7E1 } default { 0x1F7E2 } }
        $emoji = [char]::ConvertFromUtf32($code) + ' '
    }
    $demo = if ($Model.Demo) { '[SAMPLE] ' } else { '' }
    $date = $Model.Generated.ToString('ddd d MMM', [System.Globalization.CultureInfo]::InvariantCulture)
    return ('{0}{1}{2} - {3} - {4}' -f $emoji, $demo, (Get-HCHeadline $Model), $prefix, $date)
}

function Get-HCPreheader {
    # The grey preview text Gmail shows next to the subject in the inbox list.
    param([Parameter(Mandatory)]$Model)
    $issues = @($Model.Issues)
    if ($issues.Count -eq 0) { return "All $($Model.Counts.Systems) systems healthy. No certificates or licenses need attention." }
    $parts = $issues | Select-Object -First 3 | ForEach-Object {
        $detail = if ($_.Kind -eq 'Check') { "$($_.Title): $($_.Detail)" } else { "$($_.Title) $($_.Detail)" }
        if ($detail.Length -gt 70) { $detail = $detail.Substring(0, 67) + '...' }
        "$($_.System) - $detail"
    }
    $text = $parts -join ' | '
    if ($issues.Count -gt 3) { $text += " | +$($issues.Count - 3) more" }
    return $text
}

# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

function New-HCHeaderHtml {
    param([Parameter(Mandatory)]$Model)
    $p = Get-HCStyle $Model.Overall
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $org = if ($Model.Organization) { ConvertTo-HCHtmlText $Model.Organization } else { 'Infrastructure' }
    $when = $Model.Generated.ToString('dddd d MMMM yyyy', $inv) + ' &#183; ' + $Model.Generated.ToString('HH:mm', $inv)
    $duration = Format-HCDuration ([TimeSpan]::FromSeconds($Model.DurationSec))
    $headline = ConvertTo-HCHtmlText (Get-HCHeadline $Model)
    $icon = if ($Model.Overall -eq 'OK') { '&#10003;' } else { '&#9679;' }
    $trend = ''
    if ($Model.HasPrevious) {
        $new = @($Model.Issues | Where-Object IsNew).Count
        $trend = '<span style="display:inline-block;padding:9px 0 0 2px;font-size:12px;line-height:18px;color:#d0d5dd;">Since last run: <b style="color:#ffffff;">{0} new</b> &#183; <b style="color:#ffffff;">{1} resolved</b></span>' -f $new, $Model.Resolved.Count
    }
    $sample = if ($Model.Demo) { '&nbsp;<span style="display:inline-block;padding:2px 8px;border-radius:8px;background-color:#344054;color:#fef0c7;font-size:10px;letter-spacing:.5px;">SAMPLE DATA</span>' } else { '' }
    @"
<tr><td class="w" bgcolor="#101828" style="background-color:#101828;border-radius:12px 12px 0 0;padding:20px 22px 18px 22px;">
<div style="font-size:11px;line-height:14px;letter-spacing:1.2px;text-transform:uppercase;color:#98a2b3;font-weight:700;">$org$sample</div>
<div style="font-size:22px;line-height:28px;font-weight:700;color:#ffffff;padding-top:4px;">$(ConvertTo-HCHtmlText $Model.Title)</div>
<div style="font-size:12px;line-height:18px;color:#d0d5dd;padding-top:4px;">$when &#183; $($Model.Counts.Systems) systems checked in $duration</div>
<div style="padding-top:12px;"><span style="display:inline-block;margin-right:12px;padding:8px 14px;border-radius:18px;background-color:$($p.Solid);color:#ffffff;font-size:14px;line-height:16px;font-weight:700;">$icon&nbsp; $headline</span>$trend</div>
</td></tr>
<tr><td bgcolor="$($p.Solid)" style="background-color:$($p.Solid);height:4px;line-height:4px;font-size:4px;">&nbsp;</td></tr>
"@
}

function New-HCTilesHtml {
    param([Parameter(Mandatory)]$Model)
    $c = $Model.Counts
    $tiles = @(
        @{ Label = 'Systems'; Value = $c.Systems; Status = '' }
        @{ Label = 'Healthy'; Value = $c.OK; Status = 'OK' }
        @{ Label = 'Warning'; Value = $c.Warning; Status = 'Warning' }
        @{ Label = 'Critical'; Value = $c.Critical; Status = 'Critical' }
        @{ Label = 'Unknown'; Value = $c.Unknown; Status = 'Unknown' }
        @{ Label = 'Expiring'; Value = $Model.ExpiringCount; Status = 'Warning' }
    )
    # Fluid tiles: inline-blocks sit six in a row on a desktop and wrap to three per row on a phone.
    $cells = foreach ($tile in $tiles) {
        if (-not $tile.Status) { $bg = '#f2f4f7'; $fg = '#101828' }
        elseif ($tile.Value -eq 0 -and $tile.Status -ne 'OK') { $bg = '#f9fafb'; $fg = '#d0d5dd' }
        else { $s = Get-HCStyle $tile.Status; $bg = $s.Bg; $fg = $s.Fg }
        "<div style=`"display:inline-block;width:15.6%;min-width:94px;vertical-align:top;margin:3px 0;`"><div style=`"margin:0 3px;padding:12px 2px 10px 2px;border-radius:10px;background-color:$bg;text-align:center;`"><div style=`"font-size:24px;line-height:28px;font-weight:700;color:$fg;`">$($tile.Value)</div><div style=`"font-size:10px;line-height:13px;color:#475467;text-transform:uppercase;letter-spacing:.5px;font-weight:700;`">$($tile.Label)</div></div></div>"
    }
    "<tr><td class=`"w`" align=`"center`" bgcolor=`"#ffffff`" style=`"background-color:#ffffff;border:1px solid #e4e7ec;border-top:0;border-radius:0 0 12px 12px;padding:9px 8px;text-align:center;font-size:0;line-height:0;`">$($cells -join '')</td></tr>"
}

function New-HCAttentionHtml {
    param([Parameter(Mandatory)]$Model, [int]$MaxRows = 0)
    $issues = @($Model.Issues)
    if ($issues.Count -eq 0) {
        $ok = Get-HCStyle 'OK'
        $inner = "<table role=`"presentation`" class=`"w`" width=`"100%`" cellpadding=`"0`" cellspacing=`"0`" border=`"0`"><tr><td bgcolor=`"$($ok.Bg)`" style=`"padding:12px 10px;border-radius:10px;background-color:$($ok.Bg);color:$($ok.Fg);font-size:14px;font-weight:600;`">&#10003;&nbsp; Nothing needs your attention this morning.</td></tr></table>"
    } else {
        $shown = if ($MaxRows -gt 0) { @($issues | Select-Object -First $MaxRows) } else { $issues }
        $rows = foreach ($i in $shown) {
            $new = if ($i.IsNew) { ' <span class="new">NEW</span>' } else { '' }
            $what = if ($i.Kind -eq 'Check') { "<b>$(ConvertTo-HCHtmlText $i.Title):</b> " } else { "<b>$(ConvertTo-HCHtmlText $i.Title)</b> " }
            "<tr><td width=`"74`">$(New-HCBadgeHtml $i.Status)</td><td><span class=`"n`">$(ConvertTo-HCHtmlText $i.System)</span><span class=`"s`"> &#183; $(ConvertTo-HCHtmlText $i.Category)</span>$new<div>$what$(ConvertTo-HCHtmlText $i.Detail)</div></td></tr>"
        }
        if ($shown.Count -lt $issues.Count) {
            $rows = @($rows) + "<tr><td colspan=`"2`" class=`"m`">... and $($issues.Count - $shown.Count) more in the attached report</td></tr>"
        }
        $inner = New-HCGridHtml -Rows $rows
    }
    if ($Model.Resolved.Count) {
        $ok = Get-HCStyle 'OK'
        $list = Format-HCList -Items @($Model.Resolved | ForEach-Object { "$($_.System): $($_.Title)" }) -Max 6
        $inner += "<div class=`"w`" style=`"padding:10px 8px 2px 8px;font-size:12px;line-height:17px;color:$($ok.Fg);`">&#10003; <b>Resolved since last run:</b> $(ConvertTo-HCHtmlText $list)</div>"
    }
    $hint = if ($issues.Count) { '{0} item{1}, most severe first' -f $issues.Count, $(if ($issues.Count -ne 1) { 's' }) } else { '' }
    New-HCSectionHtml -Title 'Needs attention' -Hint $hint -Inner $inner
}

function New-HCOverviewHtml {
    param([Parameter(Mandatory)]$Model, [switch]$Compact, [switch]$ShowAddresses)
    $rows = [System.Collections.Generic.List[string]]::new()
    foreach ($group in ($Model.Results | Group-Object Category | Sort-Object { $_.Group[0].CategoryOrder })) {
        $systems = @($group.Group)
        $mini = foreach ($status in 'Critical', 'Warning', 'Unknown', 'OK') {
            $n = @($systems | Where-Object { $_.Status -eq $status -or ($status -eq 'OK' -and $_.Status -eq 'Info') }).Count
            if ($n) { "<span style=`"color:$((Get-HCStyle $status).Solid);`">&#9679;</span>&nbsp;$n" }
        }
        $rows.Add("<tr class=`"c`"><td colspan=`"3`"><span class=`"cn`">$(ConvertTo-HCHtmlText $group.Name)</span>&nbsp;&nbsp;<span class=`"s`">$($mini -join '&nbsp;&nbsp;')</span></td></tr>")
        $healthy = @()
        foreach ($r in $systems) {
            if ($Compact -and $r.Status -in 'OK', 'Info') { $healthy += $r.Name; continue }
            $color = if ($r.Status -in 'OK', 'Info') { '#475467' } else { (Get-HCStyle $r.Status).Fg }
            $address = if ($ShowAddresses -and $r.Address -and $r.Address -ne $r.Name) { "<div class=`"s`">$(ConvertTo-HCHtmlText $r.Address)</div>" } else { '' }
            $facts = Format-HCFactsHtml $r.Facts
            $factsHtml = if ($facts) { "<div class=`"m`">$facts</div>" } else { '' }
            $rows.Add("<tr><td width=`"74`">$(New-HCBadgeHtml $r.Status)</td><td width=`"28%`"><div class=`"n`">$(ConvertTo-HCHtmlText $r.Name)</div>$address</td><td><div style=`"color:$color;`">$(ConvertTo-HCHtmlText $r.Summary)</div>$factsHtml</td></tr>")
        }
        if ($healthy) {
            $rows.Add("<tr><td colspan=`"3`"><b style=`"color:$((Get-HCStyle 'OK').Fg);`">&#10003; $($healthy.Count) healthy:</b> $(ConvertTo-HCHtmlText (Format-HCList -Items $healthy -Max 12))</td></tr>")
        }
    }
    $hint = '{0} systems in {1} groups' -f $Model.Results.Count, @($Model.Results | Group-Object Category).Count
    New-HCSectionHtml -Title 'Systems at a glance' -Hint $hint -Inner (New-HCGridHtml -Rows $rows)
}

function Test-HCNeedsLook {
    # Certificate / license rows that belong in the short e-mail list.
    param($Item, [int]$WithinDays)
    if ($Item.Status -in 'Warning', 'Critical', 'Unknown') { return $true }
    if ($Item.Status -eq 'Info') { return $false }
    return ($WithinDays -gt 0 -and $null -ne $Item.DaysLeft -and $Item.DaysLeft -le $WithinDays)
}

function New-HCCertificatesHtml {
    <#
      -WithinDays N : list only certificates expiring within N days (plus every problem); 0 lists all.
      -OnlyProblems : list only Warning / Critical / Unknown (compact e-mail).
    #>
    param([Parameter(Mandatory)]$Model, [int]$WithinDays = 0, [switch]$OnlyProblems)
    $t = $Model.Thresholds
    $all = @($Model.Certificates | Sort-Object @{ Expression = { if ($null -eq $_.DaysLeft) { [int]::MaxValue } else { $_.DaysLeft } } }, System)
    if ($all.Count -eq 0) { return '' }
    $listed = if ($OnlyProblems) { @($all | Where-Object { Test-HCNeedsLook $_ 0 }) }
    elseif ($WithinDays -gt 0) { @($all | Where-Object { Test-HCNeedsLook $_ $WithinDays }) }
    else { $all }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $rows = [System.Collections.Generic.List[string]]::new()
    $rows.Add((New-HCColumnHeaderHtml -Labels @('Valid for', 'Certificate (friendly name)', 'Issuer') -Widths @('70', '', '36%')))
    foreach ($c in $listed) {
        $name = if ($c.FriendlyName) { $c.FriendlyName } else { $c.SubjectCN }
        $cnLine = if ($c.FriendlyName -and $c.SubjectCN -and $c.FriendlyName -ne $c.SubjectCN) { "<div class=`"m`">CN $(ConvertTo-HCHtmlText $c.SubjectCN)</div>" } else { '' }
        $noFriendly = if (-not $c.FriendlyName) { ' &#183; no friendly name' } else { '' }
        $expires = if ($c.NotAfter) { 'expires ' + ([datetime]$c.NotAfter).ToString('dd MMM yyyy', $inv) } else { 'expiry unknown' }
        $notes = (@($expires, $c.Note) | Where-Object { $_ } | ForEach-Object { ConvertTo-HCHtmlText $_ }) -join ' &#183; '
        $rows.Add("<tr><td width=`"70`">$(New-HCDaysPillHtml $c.DaysLeft $c.Status)</td><td><div class=`"n`">$(ConvertTo-HCHtmlText $name)</div>$cnLine<div class=`"s`">$(ConvertTo-HCHtmlText $c.System) &#183; $(ConvertTo-HCHtmlText $c.Source)$noFriendly</div></td><td width=`"36%`"><div>$(ConvertTo-HCHtmlText $c.IssuerCN)</div><div class=`"s`">$notes</div></td></tr>")
    }
    $hidden = $all.Count - @($listed).Count
    if (@($listed).Count -eq 0) {
        $ok = Get-HCStyle 'OK'
        $rows.Add("<tr><td colspan=`"3`" style=`"color:$($ok.Fg);`"><b>&#10003; No certificate expires within $([math]::Max($WithinDays, $t.CertWarningDays)) days</b> ($($all.Count) checked).</td></tr>")
        $hidden = 0
    }
    if ($hidden -gt 0) {
        $rows.Add("<tr><td colspan=`"3`" class=`"m`">+ $hidden more certificate$(if ($hidden -ne 1) { 's' }), all valid for more than $([math]::Max($WithinDays, $t.CertWarningDays)) days - full list with issuers and friendly names in the attached report.</td></tr>")
    }
    $hint = 'warning &le; {0} d &#183; critical &le; {1} d' -f $t.CertWarningDays, $t.CertCriticalDays
    New-HCSectionHtml -Title 'Certificates' -Hint $hint -Inner (New-HCGridHtml -Rows $rows)
}

function New-HCLicensesHtml {
    param([Parameter(Mandatory)]$Model, [int]$WithinDays = 0, [switch]$OnlyProblems)
    $t = $Model.Thresholds
    $all = @($Model.Licenses | Sort-Object @{ Expression = { if ($null -eq $_.DaysLeft) { [int]::MaxValue } else { $_.DaysLeft } } }, CategoryOrder, Category, System)
    if ($all.Count -eq 0) { return '' }
    $filtered = $OnlyProblems -or $WithinDays -gt 0
    $listed = [System.Collections.Generic.List[object]]::new()
    $collapsed = @()
    foreach ($group in ($all | Group-Object Category)) {
        $perpetual = @($group.Group | Where-Object { $null -eq $_.Expires -and $_.Status -in 'OK', 'Info' })
        $collapse = (-not $filtered) -and $perpetual.Count -gt 3
        foreach ($l in $group.Group) {
            if ($OnlyProblems -and -not (Test-HCNeedsLook $l 0)) { continue }
            if (-not $OnlyProblems -and $WithinDays -gt 0 -and -not (Test-HCNeedsLook $l $WithinDays)) { continue }
            if ($collapse -and $perpetual -contains $l) { continue }
            $listed.Add($l)
        }
        if ($collapse) {
            $collapsed += [pscustomobject]@{ Category = $group.Name; Count = $perpetual.Count; Systems = @($perpetual | ForEach-Object System | Select-Object -Unique).Count }
        }
    }
    $listed = @($listed | Sort-Object @{ Expression = { if ($null -eq $_.DaysLeft) { [int]::MaxValue } else { $_.DaysLeft } } }, Category, System)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $rows = [System.Collections.Generic.List[string]]::new()
    $rows.Add((New-HCColumnHeaderHtml -Labels @('Expires in', 'License / subscription', 'Status') -Widths @('70', '', '36%')))
    foreach ($l in $listed) {
        $source = if ($l.Source -eq 'Manual') { ' &#183; <span style="color:#b54708;">date from config</span>' } else { '' }
        $expires = if ($l.Expires) { 'expires ' + ([datetime]$l.Expires).ToString('dd MMM yyyy', $inv) } else { 'no expiry date' }
        $details = (@($l.Usage, $expires, $l.Note) | Where-Object { $_ } | ForEach-Object { ConvertTo-HCHtmlText $_ }) -join ' &#183; '
        $color = if ($l.Status -in 'OK', 'Info') { '#344054' } else { (Get-HCStyle $l.Status).Fg }
        $rows.Add("<tr><td width=`"70`">$(New-HCDaysPillHtml $l.DaysLeft $l.Status)</td><td><div class=`"n`">$(ConvertTo-HCHtmlText $l.Name)</div><div class=`"s`">$(ConvertTo-HCHtmlText $l.System) &#183; $(ConvertTo-HCHtmlText $l.Category)$source</div></td><td width=`"36%`"><div style=`"color:$color;`">$(ConvertTo-HCHtmlText $l.StatusText)</div><div class=`"s`">$details</div></td></tr>")
    }
    foreach ($c in $collapsed) {
        $rows.Add("<tr><td width=`"70`">$(New-HCDaysPillHtml $null 'Info')</td><td colspan=`"2`" class=`"m`"><b>$(ConvertTo-HCHtmlText $c.Category)</b>: $($c.Count) permanent / non-expiring license entries on $($c.Systems) systems - all OK</td></tr>")
    }
    $hidden = $all.Count - $listed.Count - [int](($collapsed | Measure-Object Count -Sum).Sum)
    if ($listed.Count -eq 0 -and $collapsed.Count -eq 0) {
        $ok = Get-HCStyle 'OK'
        $rows.Add("<tr><td colspan=`"3`" style=`"color:$($ok.Fg);`"><b>&#10003; No license or subscription expires within $([math]::Max($WithinDays, $t.LicenseWarningDays)) days</b> ($($all.Count) checked).</td></tr>")
        $hidden = 0
    }
    if ($hidden -gt 0) {
        $rows.Add("<tr><td colspan=`"3`" class=`"m`">+ $hidden more license entr$(if ($hidden -ne 1) { 'ies' } else { 'y' }) that are permanent or valid for more than $([math]::Max($WithinDays, $t.LicenseWarningDays)) days - see the attached report.</td></tr>")
    }
    $hint = 'warning &le; {0} d &#183; critical &le; {1} d' -f $t.LicenseWarningDays, $t.LicenseCriticalDays
    New-HCSectionHtml -Title 'Licenses &amp; subscriptions' -Hint $hint -Inner (New-HCGridHtml -Rows $rows)
}

function New-HCDetailsHtml {
    # Every check of every system - part of the complete (attached / saved) report.
    param([Parameter(Mandatory)]$Model, [switch]$ShowAddresses)
    $rows = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $Model.Results) {
        $address = if ($ShowAddresses -and $r.Address -and $r.Address -ne $r.Name) { " <span class=`"s`">$(ConvertTo-HCHtmlText $r.Address)</span>" } else { '' }
        $facts = Format-HCFactsHtml $r.Facts
        $rows.Add("<tr class=`"c`"><td colspan=`"3`"><span class=`"n`">$(ConvertTo-HCHtmlText $r.Name)</span>$address <span class=`"s`">&#183; $(ConvertTo-HCHtmlText $r.Category) &#183; $($r.DurationSec) s</span><div class=`"m`">$facts</div></td></tr>")
        foreach ($c in $r.Checks) {
            $rows.Add("<tr><td width=`"74`">$(New-HCBadgeHtml $c.Status)</td><td width=`"30%`"><b>$(ConvertTo-HCHtmlText $c.Name)</b></td><td class=`"m`">$(ConvertTo-HCHtmlText $c.Message)</td></tr>")
        }
    }
    New-HCSectionHtml -Title 'All checks' -Hint 'every check of every system' -Inner (New-HCGridHtml -Rows $rows)
}

function ConvertTo-HCReportHtml {
    <#
      -Mode Email   : e-mail body - every system, plus certificates / licenses expiring within the e-mail windows
      -Mode Compact : e-mail body when the normal one would exceed Gmail's clipping size - problems only
      -Mode Full    : complete report, saved to disk and attached to the e-mail
    #>
    param(
        [Parameter(Mandatory)]$Model,
        [ValidateSet('Email', 'Compact', 'Full')][string]$Mode = 'Email',
        [switch]$ShowAddresses,
        [int]$CertificateDays = 90,
        [int]$LicenseDays = 120
    )
    $compact = $Mode -eq 'Compact'
    $full = $Mode -eq 'Full'
    $sections = [System.Collections.Generic.List[string]]::new()
    $sections.Add((New-HCAttentionHtml -Model $Model -MaxRows $(if ($compact) { 25 } else { 0 })))
    $sections.Add((New-HCOverviewHtml -Model $Model -Compact:$compact -ShowAddresses:$ShowAddresses))
    if ($full) {
        $sections.Add((New-HCCertificatesHtml -Model $Model))
        $sections.Add((New-HCLicensesHtml -Model $Model))
        $sections.Add((New-HCDetailsHtml -Model $Model -ShowAddresses:$ShowAddresses))
    } else {
        $sections.Add((New-HCCertificatesHtml -Model $Model -WithinDays $CertificateDays -OnlyProblems:$compact))
        $sections.Add((New-HCLicensesHtml -Model $Model -WithinDays $LicenseDays -OnlyProblems:$compact))
    }
    $t = $Model.Thresholds
    $note = if ($full) { 'Complete report: every system, check, certificate and license.' } else { 'The complete report (every check, certificate and license) is attached.' }
    $preheader = ConvertTo-HCHtmlText (Get-HCPreheader $Model)
    $title = ConvertTo-HCHtmlText ('{0} - {1}' -f $Model.Title, $Model.Generated.ToString('yyyy-MM-dd'))
    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>$title</title>
<style>
$($script:HCCss)
</style>
</head>
<body style="margin:0;padding:0;background-color:#eef1f5;">
<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;line-height:1px;color:#eef1f5;opacity:0;">$preheader$('&#847;&zwnj;&nbsp;' * 30)</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#eef1f5" style="background-color:#eef1f5;">
<tr><td align="center" style="padding:16px 8px 24px 8px;">
<table role="presentation" class="w" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:920px;font-family:$($script:HCFont);color:#101828;">
$(New-HCHeaderHtml -Model $Model)
$(New-HCTilesHtml -Model $Model)
$($sections -join "`n")
<tr><td class="foot w" style="padding:18px 12px 6px 12px;font-size:11px;line-height:17px;color:#98a2b3;text-align:center;">
$note<br>
Certificates: warning &le; $($t.CertWarningDays) d, critical &le; $($t.CertCriticalDays) d &#183; Licenses: warning &le; $($t.LicenseWarningDays) d, critical &le; $($t.LicenseCriticalDays) d<br>
Generated on $(ConvertTo-HCHtmlText $Model.Computer) as $(ConvertTo-HCHtmlText $Model.RunAs) by Invoke-MorningHealthCheck
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"@
}

function ConvertTo-HCReportText {
    # Plain-text alternative part of the e-mail.
    param([Parameter(Mandatory)]$Model)
    $t = $Model.Thresholds
    $sb = [System.Text.StringBuilder]::new()
    $line = '-' * 72
    [void]$sb.AppendLine($Model.Title.ToUpperInvariant())
    [void]$sb.AppendLine(('{0}  |  {1} systems  |  {2}' -f $Model.Generated.ToString('ddd dd MMM yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture), $Model.Counts.Systems, (Get-HCHeadline $Model)))
    if ($Model.HasPrevious) { [void]$sb.AppendLine(('Since last run: {0} new, {1} resolved' -f @($Model.Issues | Where-Object IsNew).Count, $Model.Resolved.Count)) }
    [void]$sb.AppendLine($line)
    [void]$sb.AppendLine('NEEDS ATTENTION')
    if (-not $Model.Issues) { [void]$sb.AppendLine('  Nothing - all systems healthy.') }
    foreach ($i in $Model.Issues) {
        $new = if ($i.IsNew) { ' (NEW)' } else { '' }
        $detail = if ($i.Kind -eq 'Check') { "$($i.Title): $($i.Detail)" } else { "$($i.Title) $($i.Detail)" }
        [void]$sb.AppendLine(('  [{0,-8}] {1} ({2}){3}' -f $i.Status.ToUpperInvariant(), $i.System, $i.Category, $new))
        [void]$sb.AppendLine("             $detail")
    }
    [void]$sb.AppendLine($line)
    [void]$sb.AppendLine('SYSTEMS')
    foreach ($r in $Model.Results) {
        [void]$sb.AppendLine(('  [{0,-8}] {1,-24} {2}' -f $r.Status.ToUpperInvariant(), $r.Name, $r.Summary))
    }
    $certs = @($Model.Certificates | Where-Object { $null -ne $_.DaysLeft -and $_.DaysLeft -le $t.CertWarningDays -and $_.Status -ne 'Info' } | Sort-Object DaysLeft)
    if ($certs) {
        [void]$sb.AppendLine($line)
        [void]$sb.AppendLine("CERTIFICATES EXPIRING WITHIN $($t.CertWarningDays) DAYS")
        foreach ($c in $certs) {
            $name = if ($c.FriendlyName) { $c.FriendlyName } else { $c.SubjectCN }
            [void]$sb.AppendLine(('  {0,5} d  {1} - {2} ({3}) issued by {4}' -f $c.DaysLeft, $c.System, $name, $c.Source, $c.IssuerCN))
        }
    }
    $lics = @($Model.Licenses | Where-Object { $null -ne $_.DaysLeft -and $_.DaysLeft -le $t.LicenseWarningDays } | Sort-Object DaysLeft)
    if ($lics) {
        [void]$sb.AppendLine($line)
        [void]$sb.AppendLine("LICENSES EXPIRING WITHIN $($t.LicenseWarningDays) DAYS")
        foreach ($l in $lics) { [void]$sb.AppendLine(('  {0,5} d  {1} - {2}' -f $l.DaysLeft, $l.System, $l.Name)) }
    }
    [void]$sb.AppendLine($line)
    [void]$sb.AppendLine('The complete HTML report is attached.')
    return $sb.ToString()
}

function Get-HCHtmlSize {
    param([string]$Html)
    [System.Text.Encoding]::UTF8.GetByteCount($Html)
}
