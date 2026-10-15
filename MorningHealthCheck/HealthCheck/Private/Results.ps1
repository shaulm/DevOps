# Result model shared by all checks.
#
# Every target (one DC, one NetApp cluster, ...) gets a "context" object. Checks add rows to it:
#   Add-HCCheck        functional checks       (Ping, Services, Replication, ...)
#   Add-HCCertificate  certificates            (validity, issuer, friendly name)
#   Add-HCLicense      licenses / subscriptions (status, expiry)
#   Set-HCFact         short facts shown in the overview (version, uptime, site, ...)
# Complete-HCContext then computes the overall status and a one-line summary.

$script:HCStatusRank = @{ Info = 0; OK = 1; Unknown = 2; Warning = 3; Critical = 4 }

$script:HCCategories = [ordered]@{
    DomainController  = 'Domain Controllers'
    NetApp            = 'NetApp Clusters'
    VCenter           = 'vCenter Servers'
    ForcepointProxy   = 'Forcepoint Web Proxies'
    ForcepointManager = 'Forcepoint Management'
    Portnox           = 'Portnox NAC'
    Juniper           = 'Juniper Switches'
    CheckPoint        = 'Check Point Firewalls'
    TrellixESM        = 'Trellix SIEM'
    TrellixEPO        = 'Trellix ePO'
    TrellixEDR        = 'Trellix EDR'
    WindowsServer     = 'Windows Servers'
    WebService        = 'Web Services'
}

function Get-HCTargetTypes {
    @($script:HCCategories.Keys)
}

function Get-HCCategoryName {
    param([string]$Type)
    if ($script:HCCategories.Contains($Type)) { return $script:HCCategories[$Type] }
    return $Type
}

function Get-HCCategoryOrder {
    param([string]$Type)
    $index = [array]::IndexOf(@($script:HCCategories.Keys), $Type)
    if ($index -lt 0) { return 99 }
    return $index
}

function Get-HCStatusRank {
    param([string]$Status)
    if ($Status -and $script:HCStatusRank.ContainsKey($Status)) { return $script:HCStatusRank[$Status] }
    return $script:HCStatusRank['Unknown']
}

function Get-HCWorstStatus {
    # Returns the most severe status. "Info" never makes a system look unhealthy.
    param([string[]]$Status, [string]$Default = 'OK')
    $worst = $null
    foreach ($s in $Status) {
        if (-not $s) { continue }
        if ($null -eq $worst -or (Get-HCStatusRank $s) -gt (Get-HCStatusRank $worst)) { $worst = $s }
    }
    if ($null -eq $worst -or $worst -eq 'Info') { return $Default }
    return $worst
}

function Get-HCThresholdStatus {
    # Status for a "higher is worse" value such as percent used.
    param([double]$Value, [double]$Warning, [double]$Critical)
    if ($Value -ge $Critical) { return 'Critical' }
    if ($Value -ge $Warning) { return 'Warning' }
    return 'OK'
}

function New-HCContext {
    param([Parameter(Mandatory)][hashtable]$Target)
    [pscustomobject]@{
        Type          = $Target.Type
        Category      = Get-HCCategoryName -Type $Target.Type
        CategoryOrder = Get-HCCategoryOrder -Type $Target.Type
        Name          = [string]$Target.Name
        Address       = [string]$Target.Address
        Status        = 'Unknown'
        Summary       = ''
        Facts         = [ordered]@{}
        Checks        = [System.Collections.Generic.List[object]]::new()
        Certificates  = [System.Collections.Generic.List[object]]::new()
        Licenses      = [System.Collections.Generic.List[object]]::new()
        Log           = [System.Collections.Generic.List[string]]::new()
        Started       = Get-Date
        DurationSec   = 0
    }
}

function Add-HCCheck {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('OK', 'Warning', 'Critical', 'Unknown', 'Info')][string]$Status,
        [string]$Message = ''
    )
    $Context.Checks.Add([pscustomobject]@{ Name = $Name; Status = $Status; Message = $Message })
}

function Add-HCLog {
    param([Parameter(Mandatory)]$Context, [string]$Message)
    $Context.Log.Add(('{0:HH:mm:ss} [{1}] {2}' -f (Get-Date), $Context.Name, $Message))
}

function Set-HCFact {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name, $Value)
    if ($null -ne $Value -and "$Value" -ne '') { $Context.Facts[$Name] = [string]$Value }
}

function Get-HCDaysLeft {
    param([Nullable[datetime]]$Date)
    if ($null -eq $Date) { return $null }
    # Calendar days until the expiry date (what people expect next to "expires 20 Oct 2026").
    # PowerShell unwraps Nullable[datetime] automatically, so $Date is a plain DateTime here.
    return [int](([datetime]$Date).Date - (Get-Date).Date).TotalDays
}

function Format-HCDaysText {
    param([Nullable[int]]$Days)
    if ($null -eq $Days) { return 'no expiry' }
    if ($Days -lt 0) { return ('expired {0} day{1} ago' -f (-$Days), $(if ($Days -eq -1) { '' } else { 's' })) }
    if ($Days -eq 0) { return 'expires today' }
    return ('expires in {0} day{1}' -f $Days, $(if ($Days -eq 1) { '' } else { 's' }))
}

function Test-HCIgnored {
    # True when any of the wildcard patterns matches any of the given values.
    param([string[]]$Value, [object[]]$Pattern)
    foreach ($p in @($Pattern)) {
        if (-not $p) { continue }
        foreach ($v in @($Value)) { if ($v -and $v -like [string]$p) { return $true } }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

function ConvertTo-HCCertInfo {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $simple = [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName
    $names = @()
    foreach ($ext in $Certificate.Extensions) {
        if ($ext.Oid.Value -ne '2.5.29.17') { continue }
        try {
            $san = [System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]::new($ext.RawData, $ext.Critical)
            $names += @($san.EnumerateDnsNames())
            $names += @($san.EnumerateIPAddresses() | ForEach-Object { $_.ToString() })
        } catch {
            Write-Verbose "Could not decode SAN extension: $($_.Exception.Message)"
        }
    }
    [pscustomobject]@{
        SubjectCN    = $Certificate.GetNameInfo($simple, $false)
        Subject      = $Certificate.Subject
        IssuerCN     = $Certificate.GetNameInfo($simple, $true)
        Issuer       = $Certificate.Issuer
        NotBefore    = $Certificate.NotBefore
        NotAfter     = $Certificate.NotAfter
        Thumbprint   = $Certificate.Thumbprint
        DnsNames     = $names
        SelfSigned   = ($Certificate.Subject -eq $Certificate.Issuer)
        FriendlyName = $Certificate.FriendlyName
    }
}

function Get-HCDistinguishedNameCN {
    # "CN=foo, OU=bar" -> "foo". Returns the input when there is no CN.
    param([string]$Name)
    if (-not $Name) { return '' }
    if ($Name -match '(?:^|[,/]\s*)CN\s*=\s*(?<cn>[^,/]+)') { return $Matches.cn.Trim() }
    return $Name.Trim()
}

function Update-HCCertificateStatus {
    param([Parameter(Mandatory)]$Record, [hashtable]$Thresholds)
    $t = $Thresholds
    $label = if ($Record.FriendlyName) { $Record.FriendlyName } else { $Record.SubjectCN }
    $days = $Record.DaysLeft
    $status = 'OK'
    $issue = ''
    if ($Record.ForcedStatus) {
        $status = $Record.ForcedStatus
    } elseif ($Record.Ignored) {
        $status = 'Info'
    } elseif ($null -eq $Record.NotAfter) {
        $status = 'Unknown'; $issue = 'expiry date unknown'
    } elseif ($days -lt 0 -or $days -le $t.CertCriticalDays) {
        $status = 'Critical'; $issue = '{0} ({1:dd MMM yyyy})' -f (Format-HCDaysText $days), $Record.NotAfter
    } elseif ($days -le $t.CertWarningDays) {
        $status = 'Warning'; $issue = '{0} ({1:dd MMM yyyy})' -f (Format-HCDaysText $days), $Record.NotAfter
    } elseif ($Record.NotBefore -and $Record.NotBefore -gt (Get-Date)) {
        $status = 'Warning'; $issue = 'not valid yet (valid from {0:dd MMM yyyy})' -f $Record.NotBefore
    } elseif ($Record.Trusted -eq $false -and $t.CertUntrustedStatus -in 'Warning', 'Critical') {
        $status = $t.CertUntrustedStatus; $issue = 'certificate chain is not trusted by the monitoring server'
    }
    $Record.Status = $status
    $Record.Issue = if ($issue) { "'$label' on $($Record.Source): $issue" } else { '' }
}

function Add-HCCertificate {
    <#
      Adds a certificate row. Pass either -Certificate (an X509Certificate2) or the individual fields
      (-Subject, -Issuer, -NotAfter ...) when an API only returns metadata. Rows with the same thumbprint
      on one system are merged, so the same certificate seen in the Windows store and on LDAPS shows once.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Source,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$FriendlyName,
        [string]$Subject,
        [string]$Issuer,
        [Nullable[datetime]]$NotBefore,
        [Nullable[datetime]]$NotAfter,
        [string]$Thumbprint,
        [string[]]$DnsNames,
        [Nullable[bool]]$Trusted,
        [string]$Note,
        [string]$Template,
        [ValidateSet('', 'OK', 'Warning', 'Critical', 'Unknown', 'Info')][string]$ForceStatus = '',
        [hashtable]$Thresholds,
        [object[]]$Ignore
    )
    $subjectCN = Get-HCDistinguishedNameCN $Subject
    $issuerCN = Get-HCDistinguishedNameCN $Issuer
    $selfSigned = $false
    if ($Certificate) {
        $info = ConvertTo-HCCertInfo -Certificate $Certificate
        $subjectCN = $info.SubjectCN; $Subject = $info.Subject
        $issuerCN = $info.IssuerCN; $Issuer = $info.Issuer
        if ($null -eq $NotBefore) { $NotBefore = $info.NotBefore }
        if ($null -eq $NotAfter) { $NotAfter = $info.NotAfter }
        if (-not $Thumbprint) { $Thumbprint = $info.Thumbprint }
        if (-not $DnsNames) { $DnsNames = $info.DnsNames }
        if (-not $FriendlyName -and $info.FriendlyName) { $FriendlyName = $info.FriendlyName }
        $selfSigned = $info.SelfSigned
    } elseif ($Subject -and $Issuer) {
        $selfSigned = ($Subject -eq $Issuer)
    }
    if (-not $subjectCN -and $DnsNames) { $subjectCN = $DnsNames[0] }
    if (-not $Thresholds) { $Thresholds = Get-HCDefaultThresholds }

    # Merge with an existing row for the same certificate.
    if ($Thumbprint) {
        $existing = $Context.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
        if ($existing) {
            if ($existing.Source -notlike "*$Source*") { $existing.Source = "$($existing.Source) + $Source" }
            if (-not $existing.FriendlyName -and $FriendlyName) { $existing.FriendlyName = $FriendlyName }
            if ($null -eq $existing.Trusted -and $null -ne $Trusted) { $existing.Trusted = $Trusted }
            foreach ($extra in @($Note, $(if ($Template) { "template: $Template" }))) {
                if ($extra -and $existing.Note -notlike "*$extra*") { $existing.Note = (@($existing.Note, $extra) | Where-Object { $_ }) -join '; ' }
            }
            Update-HCCertificateStatus -Record $existing -Thresholds $Thresholds
            return $existing
        }
    }

    $notes = [System.Collections.Generic.List[string]]::new()
    if ($Note) { $notes.Add($Note) }
    if ($selfSigned) { $notes.Add('self-signed') }
    elseif ($Trusted -eq $false) { $notes.Add('chain not trusted here') }
    if ($Template) { $notes.Add("template: $Template") }

    $record = [pscustomobject]@{
        System       = $Context.Name
        Category     = $Context.Category
        Type         = $Context.Type
        Source       = $Source
        FriendlyName = $FriendlyName
        SubjectCN    = $subjectCN
        Subject      = $Subject
        DnsNames     = (@($DnsNames) | Where-Object { $_ } | Select-Object -First 6) -join ', '
        IssuerCN     = $issuerCN
        Issuer       = $Issuer
        NotBefore    = $NotBefore
        NotAfter     = $NotAfter
        DaysLeft     = Get-HCDaysLeft $NotAfter
        Thumbprint   = $Thumbprint
        Trusted      = $Trusted
        SelfSigned   = $selfSigned
        Note         = ($notes -join '; ')
        Ignored      = (Test-HCIgnored -Value @($FriendlyName, $subjectCN, $Thumbprint) -Pattern $Ignore)
        ForcedStatus = $ForceStatus
        Status       = 'OK'
        Issue        = ''
    }
    if ($record.Ignored) { $record.Note = (@($record.Note, 'ignored by config') | Where-Object { $_ }) -join '; ' }
    Update-HCCertificateStatus -Record $record -Thresholds $Thresholds
    $Context.Certificates.Add($record)
    return $record
}

# ---------------------------------------------------------------------------
# Licenses
# ---------------------------------------------------------------------------

function Add-HCLicense {
    <#
      Adds a license / subscription row.
      -Status       vendor-reported health (e.g. ONTAP "noncompliant" -> Critical); expiry is evaluated on top.
      -Expires      $null means perpetual / no expiry date.
      -StatusText   short vendor wording shown in the report ("compliant", "Licensed (KMS)", ...).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('OK', 'Warning', 'Critical', 'Unknown', 'Info')][string]$Status = 'OK',
        [string]$StatusText,
        [Nullable[datetime]]$Expires,
        [string]$Usage,
        [ValidateSet('API', 'Device', 'Manual')][string]$Source = 'API',
        [string]$Note,
        [string]$Issue,
        [hashtable]$Thresholds,
        [Nullable[int]]$WarningDays,
        [Nullable[int]]$CriticalDays
    )
    if (-not $Thresholds) { $Thresholds = Get-HCDefaultThresholds }
    $warn = if ($null -ne $WarningDays) { $WarningDays } else { $Thresholds.LicenseWarningDays }
    $crit = if ($null -ne $CriticalDays) { $CriticalDays } else { $Thresholds.LicenseCriticalDays }
    $days = Get-HCDaysLeft $Expires
    $expiryStatus = 'OK'
    if ($null -ne $days) {
        if ($days -lt 0 -or $days -le $crit) { $expiryStatus = 'Critical' }
        elseif ($days -le $warn) { $expiryStatus = 'Warning' }
    }
    $final = Get-HCWorstStatus -Status @($Status, $expiryStatus) -Default 'OK'
    if ($Status -eq 'Info' -and $expiryStatus -eq 'OK') { $final = 'Info' }
    if (-not $Issue -and $final -notin 'OK', 'Info') {
        $parts = @()
        if ($StatusText -and $Status -notin 'OK', 'Info') { $parts += $StatusText }
        if ($expiryStatus -ne 'OK') { $parts += ('{0} ({1:dd MMM yyyy})' -f (Format-HCDaysText $days), $Expires) }
        if ($Note -and $Status -notin 'OK', 'Info') { $parts += $Note }
        $Issue = "'$Name': " + ($parts -join ', ')
    }
    $record = [pscustomobject]@{
        System     = $Context.Name
        Category   = $Context.Category
        Type       = $Context.Type
        Name       = $Name
        StatusText = if ($StatusText) { $StatusText } elseif ($null -eq $Expires) { 'Active' } else { 'Valid' }
        Expires    = $Expires
        DaysLeft   = $days
        Usage      = $Usage
        Source     = $Source
        Note       = $Note
        Status     = $final
        Issue      = if ($final -in 'OK', 'Info') { '' } else { $Issue }
    }
    $Context.Licenses.Add($record)
    return $record
}

function Add-HCManualLicense {
    # Licenses that cannot be read from an API are listed in the config:
    #   Licenses = @( @{ Name = 'Web Security subscription'; Expires = '2027-06-30'; Usage = '2500 users' } )
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$License, [hashtable]$Settings)
    $name = [string]$License.Name
    if (-not $name) { $name = 'License' }
    $expires = $null
    if ($License.Expires) {
        $expires = ConvertTo-HCDateTime $License.Expires
        if (-not $expires) {
            Add-HCCheck $Context "License '$name'" 'Unknown' "Invalid Expires value '$($License.Expires)' in the config (use yyyy-MM-dd)"
            return
        }
    }
    $p = @{
        Context    = $Context
        Name       = $name
        Expires    = $expires
        Usage      = [string]$License.Usage
        Note       = [string]$License.Note
        Source     = 'Manual'
        StatusText = $(if ($License.StatusText) { [string]$License.StatusText } else { 'Subscription' })
        Thresholds = $Settings.Thresholds
    }
    if ($null -ne $License.WarningDays) { $p.WarningDays = [int]$License.WarningDays }
    if ($null -ne $License.CriticalDays) { $p.CriticalDays = [int]$License.CriticalDays }
    $null = Add-HCLicense @p
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

function Get-HCIssues {
    # All non-OK rows of one target, normalised for the "Needs attention" list.
    param([Parameter(Mandatory)]$Context)
    foreach ($c in $Context.Checks) {
        if ($c.Status -in 'Warning', 'Critical', 'Unknown') {
            [pscustomobject]@{ Status = $c.Status; Kind = 'Check'; Title = $c.Name; Detail = $c.Message; Key = "chk|$($c.Name)" }
        }
    }
    foreach ($c in $Context.Certificates) {
        if ($c.Status -in 'Warning', 'Critical', 'Unknown') {
            $id = if ($c.Thumbprint) { $c.Thumbprint } else { "$($c.SubjectCN)|$($c.Source)" }
            [pscustomobject]@{ Status = $c.Status; Kind = 'Certificate'; Title = 'Certificate'; Detail = $c.Issue; Key = "crt|$id" }
        }
    }
    foreach ($l in $Context.Licenses) {
        if ($l.Status -in 'Warning', 'Critical', 'Unknown') {
            [pscustomobject]@{ Status = $l.Status; Kind = 'License'; Title = 'License'; Detail = $l.Issue; Key = "lic|$($l.Name)" }
        }
    }
}

function Complete-HCContext {
    param([Parameter(Mandatory)]$Context)
    $Context.DurationSec = [math]::Round(((Get-Date) - $Context.Started).TotalSeconds, 1)
    $all = @($Context.Checks) + @($Context.Certificates) + @($Context.Licenses)
    if ($all.Count -eq 0) {
        Add-HCCheck $Context 'Checks' 'Unknown' 'No checks were executed'
        $all = @($Context.Checks)
    }
    $Context.Status = Get-HCWorstStatus -Status @($all | ForEach-Object { $_.Status }) -Default 'OK'
    $issues = @(Get-HCIssues -Context $Context | Sort-Object { - (Get-HCStatusRank $_.Status) })
    if ($issues.Count -eq 0) {
        $okChecks = @($Context.Checks | Where-Object Status -eq 'OK').Count
        $Context.Summary = 'All {0} checks passed' -f ($okChecks + @($Context.Certificates).Count + @($Context.Licenses).Count)
    } else {
        # Short labels only - the details are listed under "Needs attention".
        $labels = [System.Collections.Generic.List[string]]::new()
        foreach ($i in @($issues | Where-Object Kind -eq 'Check')) { if (-not $labels.Contains($i.Title)) { $labels.Add($i.Title) } }
        foreach ($kind in 'Certificate', 'License') {
            $rows = @(if ($kind -eq 'Certificate') { $Context.Certificates } else { $Context.Licenses }) | Where-Object { $_.Status -in 'Warning', 'Critical', 'Unknown' }
            if (-not $rows) { continue }
            $n = @($rows).Count
            $days = @($rows | Where-Object { $null -ne $_.DaysLeft } | ForEach-Object DaysLeft | Sort-Object)
            $label = if ($days.Count -and $days[0] -lt 0) {
                if ($n -eq 1) { "$kind expired" } else { "$n ${kind}s expired" }
            } elseif ($days.Count) {
                if ($n -eq 1) { "$kind expires in $($days[0]) d" } else { "$n ${kind}s expiring, first in $($days[0]) d" }
            } else {
                if ($n -eq 1) { "$kind needs a look" } else { "$n ${kind}s need a look" }
            }
            $labels.Add($label)
        }
        $Context.Summary = (@($labels | Select-Object -First 3) -join ' | ')
        if ($labels.Count -gt 3) { $Context.Summary += (' (+{0} more)' -f ($labels.Count - 3)) }
    }
    return $Context
}
