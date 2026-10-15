#Requires -Version 7.4
<#
.SYNOPSIS
    Offline self-test: parsers, date handling, status logic, report rendering and config validation.
    Needs no network and no Pester:  pwsh -File .\tests\Test-HealthCheck.ps1
#>
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../HealthCheck/HealthCheck.psm1') -Force
$script:failures = 0
$script:passed = 0

function Assert {
    param([string]$Name, [scriptblock]$Condition)
    try {
        $ok = & $Condition
    } catch {
        $ok = $false
        $Name += " (threw: $($_.Exception.Message))"
    }
    if ($ok) { $script:passed++ } else { $script:failures++; Write-Host "FAIL  $Name" -ForegroundColor Red }
}

$thresholds = Get-HCDefaultThresholds
$settings = @{ Thresholds = $thresholds; TimeoutSec = 5; TcpTimeoutMs = 1000; Credentials = @{} }
function New-TestContext { New-HCContext -Target @{ Type = 'WebService'; Name = 'T'; Address = 't.local' } }

# --------------------------------------------------------------------------------------------- dates
$inv = [System.Globalization.CultureInfo]::InvariantCulture
Assert 'date: Check Point 24Apr2027' { (ConvertTo-HCDateTime '24Apr2027').ToString('yyyy-MM-dd') -eq '2027-04-24' }
Assert 'date: Check Point 4Apr2027' { (ConvertTo-HCDateTime '4Apr2027').ToString('yyyy-MM-dd') -eq '2027-04-04' }
Assert 'date: never -> null' { $null -eq (ConvertTo-HCDateTime 'never') }
Assert 'date: manual yyyy-MM-dd is local midnight' { (ConvertTo-HCDateTime '2027-06-30') -eq [datetime]::new(2027, 6, 30) }
Assert 'date: ISO with Z' { (ConvertTo-HCDateTime '2027-01-01T00:00:00Z').ToUniversalTime().ToString('yyyy-MM-dd HH') -eq '2027-01-01 00' }
Assert 'date: +0000 offset' { (ConvertTo-HCDateTime '2026-10-15T06:30:01.000+0000').ToUniversalTime().ToString('HH:mm:ss') -eq '06:30:01' }
Assert 'date: Junos UTC suffix' { (ConvertTo-HCDateTime '2027-01-15 00:00:00 UTC').ToUniversalTime().ToString('yyyy-MM-dd HH') -eq '2027-01-15 00' }
Assert 'date: AD generalized time' { (ConvertTo-HCDateTime '20261015063001.0Z').ToUniversalTime().ToString('yyyyMMddHHmmss') -eq '20261015063001' }
Assert 'date: epoch seconds' { (ConvertTo-HCDateTime 1792050601).ToUniversalTime().Year -eq 2026 }
Assert 'date: garbage -> null' { $null -eq (ConvertTo-HCDateTime 'not a date') }

# --------------------------------------------------------------------------------------------- Juniper
$version = @'
fpc0:
--------------------------------------------------------------------------
Hostname: core-sw1
Model: ex4650-48y-8c
Junos: 22.4R3-S2.11
JUNOS OS Kernel 64-bit  [20231107.0b3d9a2_builder_stable_12_224]
'@
$v = ConvertFrom-HCJunosVersion $version
Assert 'junos version: hostname' { $v.Hostname -eq 'core-sw1' }
Assert 'junos version: model' { $v.Model -eq 'ex4650-48y-8c' }
Assert 'junos version: version' { $v.Version -eq '22.4R3-S2.11' }
Assert 'junos version: legacy format' { (ConvertFrom-HCJunosVersion 'JUNOS EX  Software Suite [12.3R12.4]').Version -eq '12.3R12.4' }
Assert 'junos uptime' { (ConvertFrom-HCJunosUptime "Current time: 2026-10-15 06:30:01 IDT`nSystem booted: 2026-01-01 04:22:11 IST (41w2d 02:08 ago)") -eq '41w2d 02:08' }

$alarms = @'
fpc0:
--------------------------------------------------------------------------
2 alarms currently active
Alarm time               Class  Description
2026-10-13 02:14:51 IDT  Major  FPC 0 PEM 1 Not Powered
2026-10-01 09:00:00 IDT  Minor  Rescue configuration is not set

fpc1:
--------------------------------------------------------------------------
No alarms currently active
'@
$a = @(ConvertFrom-HCJunosAlarms $alarms)
Assert 'junos alarms: count' { $a.Count -eq 2 }
Assert 'junos alarms: major' { $a[0].Class -eq 'Major' -and $a[0].Description -eq 'FPC 0 PEM 1 Not Powered' -and $a[0].Member -eq 'fpc0' }
Assert 'junos alarms: none' { @(ConvertFrom-HCJunosAlarms 'No alarms currently active').Count -eq 0 }

$environment = @'
Class Item                           Status     Measurement
Power FPC 0 Power Supply 0           OK
      FPC 0 Power Supply 1           Failed
Temp  FPC 0 GEPHY Front Left         OK         33 degrees C / 91 degrees F
Fans  FPC 0 Fan Tray 0 Fan 0         OK         Spinning at normal speed
      FPC 0 Fan Tray 1 Fan 0         Check
      FPC 0 Fan Tray 2               Absent
'@
$e = @(ConvertFrom-HCJunosEnvironment $environment)
Assert 'junos environment: items' { $e.Count -eq 6 }
Assert 'junos environment: failed psu' { ($e | Where-Object Status -eq 'Failed').Item -eq 'FPC 0 Power Supply 1' -and ($e | Where-Object Status -eq 'Failed').Class -eq 'Power' }
Assert 'junos environment: fan check' { ($e | Where-Object Status -eq 'Check').Class -eq 'Fans' }

$vc = @'
Preprovisioned Virtual Chassis
Virtual Chassis ID: 1a2b.3c4d.5e6f
Virtual Chassis Mode: Enabled
                                                Mstr           Mixed Route Neighbor List
Member ID  Status   Serial No    Model          prio  Role      Mode  Mode ID  Interface
0 (FPC 0)  Prsnt    JX0123456789 ex4300-48p     129   Master*      N  VC   1  vcp-255/1/0
1 (FPC 1)  Prsnt    JX0123456790 ex4300-48p     129   Backup       N  VC   0  vcp-255/1/0
2 (FPC 2)  NotPrsnt JX0123456791 ex4300-48p
'@
$vcParsed = ConvertFrom-HCJunosVirtualChassis $vc
Assert 'junos vc: members' { $vcParsed.Members.Count -eq 3 }
Assert 'junos vc: roles' { $vcParsed.Members[0].Role -eq 'Master*' -and $vcParsed.Members[1].Role -eq 'Backup' }
Assert 'junos vc: not present' { $vcParsed.Members[2].Status -eq 'NotPrsnt' -and $vcParsed.Members[2].Serial -eq 'JX0123456791' }
Assert 'junos vc: not a vc' { $null -eq (ConvertFrom-HCJunosVirtualChassis 'error: command is not valid on the qfx5120') }

$storage = @'
Filesystem              Size       Used      Avail  Capacity  Mounted on
/dev/gpt/junos          1.3G       626M       617M       50%  /.mount
/dev/gpt/var            3.2G       3.0G       200M       94%  /.mount/var
/dev/md5                 45M        45M         0B      100%  /packages/mnt/jbase
'@
$fs = @(ConvertFrom-HCJunosStorage $storage)
Assert 'junos storage: parsed' { $fs.Count -eq 3 -and ($fs | Where-Object Mount -eq '/.mount/var').Capacity -eq 94 }

$commit = ConvertFrom-HCJunosCommit "0   2026-10-14 22:01:33 IDT by jdoe via cli`n1   2026-10-10 09:12:07 IDT by admin via netconf"
Assert 'junos commit' { $commit.User -eq 'jdoe' -and $commit.Via -eq 'cli' -and $commit.Time.Year -eq 2026 }

$license = @'
License usage:
                                 Licenses     Licenses    Licenses    Expiry
  Feature name                       used    installed      needed
  ex-advanced                           1            1           0    permanent
  vcf                                   0            1           0    2027-01-15 00:00:00 UTC
  mpls                                  1            0           1    invalid

Licenses installed:
  License identifier: JUNOS123456
'@
$l = @(ConvertFrom-HCJunosLicense $license)
Assert 'junos license: rows' { $l.Count -eq 3 }
Assert 'junos license: permanent' { ($l | Where-Object Feature -eq 'ex-advanced').Permanent }
Assert 'junos license: dated' { ($l | Where-Object Feature -eq 'vcf').Expires.Year -eq 2027 }
Assert 'junos license: needed' { ($l | Where-Object Feature -eq 'mpls').Needed -eq 1 }

$pki = @'
Certificate identifier: jweb-cert
  Issued to: core-sw1.contoso.local, Issued by: CN = Contoso Issuing CA 01, DC = contoso, DC = local
  Validity:
    Not before: 10- 1-2025 12:00 UTC
    Not after: 10- 1-2027 12:00 UTC
  Public key algorithm: rsaEncryption(2048 bits)
Certificate identifier: old-cert
  Issued to: core-sw1, Issued by: CN = core-sw1
  Validity:
    Not before: 01- 5-2020 08:30 UTC
    Not after: 01- 5-2025 08:30 UTC
'@
$p = @(ConvertFrom-HCJunosPkiCertificates $pki)
Assert 'junos pki: two certs' { $p.Count -eq 2 }
Assert 'junos pki: fields' { $p[0].Identifier -eq 'jweb-cert' -and $p[0].IssuedTo -eq 'core-sw1.contoso.local' -and $p[0].NotAfter.ToUniversalTime().ToString('yyyy-MM-dd') -eq '2027-10-01' }
Assert 'junos pki: issuer CN' { (Get-HCDistinguishedNameCN $p[0].IssuedBy) -eq 'Contoso Issuing CA 01' }

# --------------------------------------------------------------------------------------------- Check Point
$cphaprob = @'

Cluster Mode:   High Availability (Active Up) with IGMP Membership

ID         Unique Address  Assigned Load   State          Name

1 (local)  10.0.0.2        100%            ACTIVE         fw-a
2          10.0.0.3        0%              STANDBY        fw-b


Active PNOTEs: None

Last member state change event:
   Event Code:                 CLUS-114904
'@
$ha = ConvertFrom-HCCphaprobState $cphaprob
Assert 'cphaprob: members' { $ha.Members.Count -eq 2 }
Assert 'cphaprob: local active' { ($ha.Members | Where-Object Local).State -eq 'ACTIVE' -and ($ha.Members | Where-Object Local).Name -eq 'fw-a' }
Assert 'cphaprob: standby' { $ha.Members[1].State -eq 'STANDBY' -and $ha.Members[1].Name -eq 'fw-b' }
Assert 'cphaprob: mode' { $ha.Mode -like 'High Availability*' }
Assert 'cphaprob: pnotes' { $ha.ActivePnotes -eq 'None' }
$haDown = ConvertFrom-HCCphaprobState "1 (local)  10.0.0.2        100%            ACTIVE(!)      fw-a`n2          10.0.0.3        0%              DOWN           fw-b`nActive PNOTEs: LPRB, IAC"
Assert 'cphaprob: degraded states' { $haDown.Members[0].State -eq 'ACTIVE(!)' -and $haDown.Members[1].State -eq 'DOWN' -and $haDown.ActivePnotes -eq 'LPRB, IAC' }

$cplic = @'
Host             Expiration  Features
10.0.0.2         never       CPSG-C-4-U CPSB-FW CPSB-VPN CPSB-IPS CPSB-ADNC CK-0A1B2C3D4E5F
10.0.0.2         14Nov2026   CPSB-EVAL CK-ABCDEF012345

Contract Coverage:

  #   ID          Expiration   SKU
===+===========+============+====================
  1 | 6ALBC2J   | 24Apr2027  | CPSB-ADNC-M-1Y
    +-----------+------------+--------------------
    |Covers:  CK-0A1B2C3D4E5F
===+===========+============+====================
  2 | 6ALBCA9   | 24Apr2027  | CPSB-ABOT-M-1Y
===+===========+============+====================
  3 | 7XYZ123   | 1Dec2026   | CPSB-URLF-M-1Y
'@
$lic = ConvertFrom-HCCplicPrint $cplic
Assert 'cplic: licenses' { $lic.Licenses.Count -eq 2 }
Assert 'cplic: permanent' { $lic.Licenses[0].Never -and $null -eq $lic.Licenses[0].Expiration -and $lic.Licenses[0].CK -eq 'CK-0A1B2C3D4E5F' }
Assert 'cplic: features without CK' { $lic.Licenses[0].Features -eq 'CPSG-C-4-U CPSB-FW CPSB-VPN CPSB-IPS CPSB-ADNC' }
Assert 'cplic: dated license' { $lic.Licenses[1].Expiration.ToString('yyyy-MM-dd') -eq '2026-11-14' }
Assert 'cplic: contracts' { $lic.Contracts.Count -eq 3 -and $lic.Contracts[2].Sku -eq 'CPSB-URLF-M-1Y' -and $lic.Contracts[2].Expiration.ToString('yyyy-MM-dd') -eq '2026-12-01' }

$policy = ConvertFrom-HCFwStat "HOST      POLICY     DATE`nlocalhost Standard   14Oct2026 22:10:33 :  [>eth1] [<eth1]"
Assert 'fw stat: policy' { $policy.Policy -eq 'Standard' -and $policy.Installed.ToString('yyyy-MM-dd HH:mm') -eq '2026-10-14 22:10' }
Assert 'fw stat: no policy' { (ConvertFrom-HCFwStat "HOST      POLICY     DATE`nlocalhost -          -").Policy -eq '-' }

$df = @(ConvertFrom-HCDfOutput "Filesystem 1024-blocks Used Available Capacity Mounted on`n/dev/mapper/vg_splat-lv_current 20642428 19201234 1441194 94% /`n/dev/mapper/vg_splat-lv_log 41284928 9876543 29309832 26% /var/log")
Assert 'df: parsed' { $df.Count -eq 2 -and $df[0].Capacity -eq 94 -and $df[1].Mount -eq '/var/log' }

$cpwd = @(ConvertFrom-HCCpwdList "APP        PID    STAT  #START  START_TIME             MON  COMMAND`nCPD        12345  E     1       [12:00:01] 1/10/2026   Y    cpd`nFWM        -      T     3       [12:00:05] 1/10/2026   N    fwm")
Assert 'cpwd: states' { $cpwd.Count -eq 2 -and ($cpwd | Where-Object State -eq 'T').App -eq 'FWM' }

$encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("###HC:HA###`nline1`n###HC:LIC###`nline2"))
$decoded = ConvertFrom-HCCheckPointResponse $encoded
$sections = Split-HCMarkedOutput $decoded
Assert 'run-script: base64 decode + sections' { $sections['HA'].Trim() -eq 'line1' -and $sections['LIC'].Trim() -eq 'line2' }
Assert 'run-script: plain text passthrough' { (ConvertFrom-HCCheckPointResponse '###HC:X### plain') -eq '###HC:X### plain' }

# --------------------------------------------------------------------------------------------- certificates
$ctx = New-TestContext
$r = Add-HCCertificate -Context $ctx -Source 'TLS :443' -Subject 'CN=a.contoso.local' -Issuer 'CN=Contoso CA' -NotAfter (Get-Date).AddDays(5) -Thumbprint 'AA' -Thresholds $thresholds
Assert 'cert: 5 days -> Critical' { $r.Status -eq 'Critical' -and $r.DaysLeft -eq 5 -and $r.Issue -like '*expires in 5 days*' }
$r = Add-HCCertificate -Context $ctx -Source 'TLS :443' -Subject 'CN=b' -Issuer 'CN=CA' -NotAfter (Get-Date).AddDays(20) -Thumbprint 'BB' -Thresholds $thresholds
Assert 'cert: 20 days -> Warning' { $r.Status -eq 'Warning' }
$r = Add-HCCertificate -Context $ctx -Source 'TLS :443' -Subject 'CN=c' -Issuer 'CN=CA' -NotAfter (Get-Date).AddDays(-3) -Thumbprint 'CC' -Thresholds $thresholds
Assert 'cert: expired -> Critical' { $r.Status -eq 'Critical' -and $r.Issue -like '*expired 3 days ago*' }
$r = Add-HCCertificate -Context $ctx -Source 'TLS :443' -Subject 'CN=d' -Issuer 'CN=d' -NotAfter (Get-Date).AddDays(400) -Thumbprint 'DD' -Trusted $false -Thresholds $thresholds
Assert 'cert: self-signed, long validity -> OK with note' { $r.Status -eq 'OK' -and $r.SelfSigned -and $r.Note -like '*self-signed*' }
$r = Add-HCCertificate -Context $ctx -Source 'LocalMachine\My' -Subject 'CN=a.contoso.local' -Issuer 'CN=Contoso CA' -NotAfter (Get-Date).AddDays(5) -Thumbprint 'AA' -FriendlyName 'LDAPS 2026' -Thresholds $thresholds
Assert 'cert: same thumbprint merged' { @($ctx.Certificates | Where-Object Thumbprint -eq 'AA').Count -eq 1 -and $r.Source -eq 'TLS :443 + LocalMachine\My' -and $r.FriendlyName -eq 'LDAPS 2026' }
$r = Add-HCCertificate -Context $ctx -Source 'x' -Subject 'CN=old-test-1' -Issuer 'CN=CA' -NotAfter (Get-Date).AddDays(-30) -Thumbprint 'EE' -Ignore @('old-test-*') -Thresholds $thresholds
Assert 'cert: ignored pattern -> Info' { $r.Status -eq 'Info' -and $r.Note -like '*ignored*' }
$r = Add-HCCertificate -Context $ctx -Source 'x' -Subject 'CN=f' -Issuer 'CN=CA' -NotAfter (Get-Date).AddDays(-30) -Thumbprint 'FF' -ForceStatus 'Info' -Thresholds $thresholds
Assert 'cert: forced Info (superseded)' { $r.Status -eq 'Info' }
$strict = $thresholds.Clone(); $strict.CertUntrustedStatus = 'Warning'
$r = Add-HCCertificate -Context $ctx -Source 'x' -Subject 'CN=g' -Issuer 'CN=Other CA' -NotAfter (Get-Date).AddDays(400) -Thumbprint '11' -Trusted $false -Thresholds $strict
Assert 'cert: untrusted -> Warning when configured' { $r.Status -eq 'Warning' -and $r.Issue -like '*not trusted*' }

# --------------------------------------------------------------------------------------------- licenses
$ctx = New-TestContext
$r = Add-HCLicense -Context $ctx -Name 'Perpetual' -Thresholds $thresholds
Assert 'license: perpetual OK' { $r.Status -eq 'OK' -and $null -eq $r.DaysLeft -and $r.StatusText -eq 'Active' }
$r = Add-HCLicense -Context $ctx -Name 'Soon' -Expires (Get-Date).AddDays(30) -Thresholds $thresholds
Assert 'license: 30 days -> Warning' { $r.Status -eq 'Warning' -and $r.Issue -like "'Soon': expires in 30 days*" }
$r = Add-HCLicense -Context $ctx -Name 'Very soon' -Expires (Get-Date).AddDays(10) -Thresholds $thresholds
Assert 'license: 10 days -> Critical' { $r.Status -eq 'Critical' }
$r = Add-HCLicense -Context $ctx -Name 'Noncompliant' -Status 'Critical' -StatusText 'noncompliant' -Thresholds $thresholds
Assert 'license: vendor status kept' { $r.Status -eq 'Critical' -and $r.Issue -like '*noncompliant*' }
$r = Add-HCLicense -Context $ctx -Name 'Custom window' -Expires (Get-Date).AddDays(80) -WarningDays 90 -Thresholds $thresholds
Assert 'license: per-license warning window' { $r.Status -eq 'Warning' }
$ctx2 = New-TestContext
Add-HCManualLicense -Context $ctx2 -License @{ Name = 'Bad date'; Expires = '31/12/2027' } -Settings $settings
Assert 'license: invalid manual date reported' { $ctx2.Checks[0].Status -eq 'Unknown' -and $ctx2.Licenses.Count -eq 0 }
Add-HCManualLicense -Context $ctx2 -License @{ Name = 'Good'; Expires = '2099-12-31'; Usage = '10 users' } -Settings $settings
Assert 'license: manual license source' { $ctx2.Licenses[0].Source -eq 'Manual' -and $ctx2.Licenses[0].Status -eq 'OK' }

# --------------------------------------------------------------------------------------------- summary
$ctx = New-TestContext
Add-HCCheck $ctx 'Ping' 'OK' 'ok'
Add-HCCheck $ctx 'Fact' 'Info' 'info only'
$null = Complete-HCContext $ctx
Assert 'summary: Info does not degrade' { $ctx.Status -eq 'OK' -and $ctx.Summary -like 'All * checks passed' }
Add-HCCheck $ctx 'Replication' 'Critical' 'broken'
$null = Add-HCCertificate -Context $ctx -Source 'x' -Subject 'CN=z' -Issuer 'CN=CA' -NotAfter (Get-Date).AddDays(12) -Thumbprint 'ZZ' -Thresholds $thresholds
$null = Complete-HCContext $ctx
Assert 'summary: worst status wins' { $ctx.Status -eq 'Critical' }
Assert 'summary: short labels' { $ctx.Summary -eq 'Replication | Certificate expires in 12 d' }
Assert 'worst status ignores Info' { (Get-HCWorstStatus @('Info', 'Info')) -eq 'OK' -and (Get-HCWorstStatus @('OK', 'Unknown', 'Warning')) -eq 'Warning' }

# --------------------------------------------------------------------------------------------- report
$evil = New-HCContext -Target @{ Type = 'WebService'; Name = 'X<script>alert(1)</script>'; Address = 'x' }
Add-HCCheck $evil 'Check <b>' 'Critical' 'msg & <img src=x onerror=alert(1)>'
$null = Add-HCCertificate -Context $evil -Source 'TLS' -Subject 'CN=<evil>' -Issuer 'CN=I&I' -NotAfter (Get-Date).AddDays(3) -Thumbprint 'EV' -Thresholds $thresholds
$null = Complete-HCContext $evil
$model = New-HCReportModel -Results @($evil) -Settings @{ Thresholds = $thresholds; Title = 'T'; Organization = 'O' }
$html = ConvertTo-HCReportHtml -Model $model -Mode Full
Assert 'report: HTML-encodes system names' { $html -notmatch '<script>' -and $html -match '&lt;script&gt;' }
Assert 'report: HTML-encodes messages' { $html -notmatch '<img src=x' }
Assert 'report: HTML-encodes certificate fields' { $html -notmatch 'CN <evil>' -and $html -match '&lt;evil&gt;' }
Assert 'report: plain text' { (ConvertTo-HCReportText -Model $model) -match 'NEEDS ATTENTION' }

$demoSettings = New-HCSettings -Config (Get-HCDemoConfig) -ScriptRoot $PSScriptRoot
$demo = New-HCDemoResults -Settings $demoSettings
$demoModel = New-HCReportModel -Results $demo -Settings $demoSettings -Previous (New-HCDemoPrevious -Results $demo) -Demo
$email = ConvertTo-HCReportHtml -Model $demoModel -Mode Email -ShowAddresses
$compact = ConvertTo-HCReportHtml -Model $demoModel -Mode Compact
Assert 'report: e-mail body below Gmail clipping size' { (Get-HCHtmlSize $email) -lt 95KB }
Assert 'report: compact is smaller' { (Get-HCHtmlSize $compact) -lt (Get-HCHtmlSize $email) }
Assert 'report: new/resolved markers' { @($demoModel.Issues | Where-Object IsNew).Count -gt 0 -and $demoModel.Resolved.Count -eq 1 }
Assert 'report: subject' { (Get-HCMailSubject -Model $demoModel -Email @{ UseEmojiInSubject = $false }) -match '^\[SAMPLE\] \d+ critical' }
Assert 'report: every category present' { @($demoModel.Results | Select-Object -ExpandProperty Category -Unique).Count -eq 11 }

# --------------------------------------------------------------------------------------------- config
$base = @{ General = @{}; Email = @{}; Thresholds = @{}; Defaults = @{ All = @{ Ping = $false }; NetApp = @{ Credential = 'netapp' } } }
$cfg = $base.Clone(); $cfg.Targets = @(@{ Type = 'NetApp'; Name = 'A'; Address = 'a' }, @{ Type = 'NetApp'; Name = 'B'; Address = 'b'; Credential = 'other'; Enabled = $true }, @{ Type = 'NetApp'; Name = 'C'; Address = 'c'; Enabled = $false })
$targets = @(Resolve-HCTargets -Config $cfg)
Assert 'config: disabled targets skipped' { $targets.Count -eq 2 }
Assert 'config: defaults merged and overridden' { $targets[0].Credential -eq 'netapp' -and $targets[1].Credential -eq 'other' -and $targets[0].Ping -eq $false }
Assert 'config: credential names' { ((Get-HCReferencedCredentialNames -Targets $targets -Email @{ Credential = 'smtp' }) | Sort-Object) -join ',' -eq 'netapp,other,smtp' }
$cfg.Targets = @(@{ Type = 'NetAp'; Name = 'Typo'; Address = 'x' })
Assert 'config: unknown type rejected' { try { $null = @(Resolve-HCTargets -Config $cfg); $false } catch { $_.Exception.Message -like '*Unknown target Type*' } }
$cfg.Targets = @(@{ Type = 'NetApp'; Name = 'A'; Address = 'a' }, @{ Type = 'NetApp'; Name = 'A'; Address = 'b' })
Assert 'config: duplicate names rejected' { try { $null = @(Resolve-HCTargets -Config $cfg); $false } catch { $_.Exception.Message -like '*Duplicate*' } }
$cfg.Targets = @(@{ Type = 'TrellixEDR'; Name = 'EDR'; Url = 'https://edr.example.com:8443/ui' })
Assert 'config: Address derived from Url' { (@(Resolve-HCTargets -Config $cfg))[0].Address -eq 'edr.example.com' }
$example = Import-HCConfig -Path (Join-Path $PSScriptRoot '../config/HealthCheck.config.example.psd1')
Assert 'config: example file is valid' { @(Resolve-HCTargets -Config $example).Count -gt 10 }

# --------------------------------------------------------------------------------------------- misc
Assert 'format: list' { (Format-HCList -Items @('a', 'b', 'c', 'd') -Max 2) -eq 'a, b (+2 more)' }
Assert 'format: bytes' { (Format-HCBytes 1536) -eq '1.5 KB' -and (Format-HCBytes (4.2 * 1TB)) -eq '4.2 TB' }
Assert 'format: duration' { (Format-HCDuration ([TimeSpan]::FromHours(50))) -eq '2d 2h' }
Assert 'os name' { (Get-HCShortOsName 'Microsoft Windows Server 2022 Standard') -eq 'Server 2022 Standard' }
Assert 'threshold status' { (Get-HCThresholdStatus 96 85 95) -eq 'Critical' -and (Get-HCThresholdStatus 90 85 95) -eq 'Warning' -and (Get-HCThresholdStatus 10 85 95) -eq 'OK' }

Write-Host ''
if ($script:failures) {
    Write-Host "$($script:failures) test(s) FAILED, $($script:passed) passed" -ForegroundColor Red
    exit 1
}
Write-Host "All $($script:passed) tests passed" -ForegroundColor Green
