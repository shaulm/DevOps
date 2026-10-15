# Sample results for every system type, used by "Invoke-MorningHealthCheck.ps1 -Demo" to preview the
# report and test e-mail delivery/formatting without touching any infrastructure.

function Add-HCDemoChecks {
    param($Context, [object[]]$Rows)
    foreach ($r in $Rows) { Add-HCCheck $Context $r[0] $r[1] $r[2] }
}

function Add-HCDemoCert {
    param($Context, [string]$Source, [string]$FriendlyName, [string]$CN, [string]$Issuer, [int]$Days, [hashtable]$Thresholds, [string]$Note, [Nullable[bool]]$Trusted = $true, [string]$Template)
    $thumb = -join ((1..40) | ForEach-Object { '0123456789ABCDEF'[(Get-Random -Maximum 16)] })
    $null = Add-HCCertificate -Context $Context -Source $Source -FriendlyName $FriendlyName -Subject "CN=$CN" -Issuer "CN=$Issuer" `
        -NotBefore (Get-Date).AddDays(-(Get-Random -Minimum 30 -Maximum 330)) -NotAfter (Get-Date).AddDays($Days).AddHours(2) -Thumbprint $thumb -Trusted $Trusted `
        -Note $Note -Template $Template -Thresholds $Thresholds
}

function New-HCDemoResults {
    param([Parameter(Mandatory)][hashtable]$Settings)
    $t = $Settings.Thresholds
    $results = [System.Collections.Generic.List[object]]::new()
    $new = {
        param($type, $name, $address)
        $ctx = New-HCContext -Target @{ Type = $type; Name = $name; Address = $address }
        $ctx.Started = (Get-Date).AddSeconds(-(Get-Random -Minimum 2 -Maximum 14))
        $ctx
    }
    $issuing = 'Contoso Issuing CA 01'

    # --- Domain controllers ---------------------------------------------------------------
    $dcs = @(
        @{ Name = 'DC01'; Site = 'HQ'; Roles = 'PDC,RID,Infra'; Up = '23d 4h'; Ldaps = 214; Friendly = 'DC01 Kerberos Authentication 2026' }
        @{ Name = 'DC02'; Site = 'HQ'; Roles = 'Schema,Naming'; Up = '23d 4h'; Ldaps = 12; Friendly = '' }
        @{ Name = 'DC03'; Site = 'DR-Site'; Roles = ''; Up = '61d 2h'; Ldaps = 301; Friendly = 'DC03 LDAPS' }
        @{ Name = 'DC04-BR'; Site = 'Branch-Haifa'; Roles = ''; Up = '9d 11h'; Ldaps = 188; Friendly = 'DC04 Kerberos Authentication' }
    )
    foreach ($d in $dcs) {
        $ctx = & $new 'DomainController' $d.Name ("{0}.contoso.local" -f $d.Name.ToLowerInvariant())
        Set-HCFact $ctx 'Site' $d.Site
        Set-HCFact $ctx 'OS' 'Server 2022 Standard'
        if ($d.Roles) { Set-HCFact $ctx 'FSMO' $d.Roles }
        Set-HCFact $ctx 'Uptime' $d.Up
        Add-HCDemoChecks $ctx @(
            , @('Ping', 'OK', 'Reply in 1 ms')
            , @('TCP ports', 'OK', 'Open: 53, 88, 135, 389, 445, 636')
            , @('LDAP (389)', 'OK', 'Bind and RootDSE read in 14 ms')
            , @('LDAPS (636)', 'OK', 'Bind and RootDSE read in 31 ms')
            , @('Global Catalog (3268)', 'OK', 'Bind and RootDSE read in 12 ms')
            , @('SYSVOL share', 'OK', 'Accessible')
            , @('NETLOGON share', 'OK', 'Accessible')
            , @('DNS', 'OK', 'contoso.local: 4 A record(s), 4 DC SRV record(s)')
            , @('Services', 'OK', 'All 8 monitored services running')
            , @('Disk space', 'OK', 'C: 61% free, D: 74% free')
        )
        if ($d.Name -eq 'DC02') {
            Add-HCCheck $ctx 'AD replication' 'Critical' 'DC03/contoso.local: error 1722 (The RPC server is unavailable.), 14 failure(s), last success 7 h ago | DC03/Configuration: error 1722 (The RPC server is unavailable.), 14 failure(s), last success 7 h ago'
        } else {
            Add-HCCheck $ctx 'AD replication' 'OK' '10 inbound links healthy, last success 4 min ago'
        }
        if ($d.Name -eq 'DC03') { Add-HCCheck $ctx 'Clock offset' 'Warning' '+7 s compared with the monitoring server' }
        else { Add-HCCheck $ctx 'Clock offset' 'OK' '+0 s compared with the monitoring server' }
        Add-HCDemoCert $ctx 'LocalMachine\My + LDAPS :636' $d.Friendly ("{0}.contoso.local" -f $d.Name.ToLowerInvariant()) $issuing $d.Ldaps $t -Template 'Kerberos Authentication'
        $null = Add-HCLicense -Context $ctx -Name 'Windows activation' -StatusText 'Licensed (KMS client)' -Expires (Get-Date).AddDays(176) -Source 'Device' -Note 'renews automatically (180-day validity)' -Thresholds $t
        $results.Add($ctx)
    }

    # --- NetApp ---------------------------------------------------------------------------
    $ctx = & $new 'NetApp' 'NA-PROD' 'na-prod.contoso.local'
    Set-HCFact $ctx 'ONTAP' '9.14.1P4'; Set-HCFact $ctx 'Nodes' '4/4 up'; Set-HCFact $ctx 'Model' 'AFF-A400'; Set-HCFact $ctx 'Volumes' 318
    Add-HCDemoChecks $ctx @(
        , @('ONTAP REST API', 'OK', "Cluster 'na-prod' responding")
        , @('Nodes', 'OK', '4/4 nodes up, storage failover healthy')
        , @('Health alerts', 'OK', 'No active system health alerts')
        , @('Aggregate aggr_data_01', 'Warning', '88.4% used, 4.2 TB free')
        , @('Volumes', 'OK', '318 volumes online, none above 90% used')
        , @('Disks', 'OK', '96 disks, no failures')
        , @('Network interfaces', 'OK', '42 LIFs up and home')
        , @('SnapMirror', 'OK', '27 relationships healthy, max lag 1h 12m')
    )
    Add-HCDemoCert $ctx 'Cluster mgmt :443 + ONTAP cluster (server)' 'na-prod_17A4E2C9F1B35D2A' 'na-prod.contoso.local' $issuing 45 $t
    Add-HCDemoCert $ctx 'ONTAP SVM svm_cifs (server)' 'svm_cifs_17A4E2C9F1B35E01' 'svm_cifs' 'svm_cifs' 1102 $t -Trusted $false
    $null = Add-HCLicense -Context $ctx -Name 'ONTAP license packages (14)' -StatusText 'compliant' -Note 'base, nfs, cifs, iscsi, snapmirror, snaprestore, flexclone, snapvault (+6 more)' -Thresholds $t
    $results.Add($ctx)

    $ctx = & $new 'NetApp' 'NA-DR' 'na-dr.contoso.local'
    Set-HCFact $ctx 'ONTAP' '9.14.1P4'; Set-HCFact $ctx 'Nodes' '2/2 up'; Set-HCFact $ctx 'Model' 'FAS2750'; Set-HCFact $ctx 'Volumes' 141
    Add-HCDemoChecks $ctx @(
        , @('ONTAP REST API', 'OK', "Cluster 'na-dr' responding")
        , @('Nodes', 'OK', '2/2 nodes up, storage failover healthy')
        , @('Aggregates', 'OK', '2 online, fullest aggr_dr_01 at 71.3%')
        , @('Volumes', 'OK', '141 volumes online, none above 90% used')
        , @('Disks', 'OK', '48 disks, no failures')
        , @('SnapMirror', 'OK', '27 relationships healthy, max lag 1h 12m')
    )
    Add-HCDemoCert $ctx 'Cluster mgmt :443 + ONTAP cluster (server)' 'na-dr_17A4E2D01C77AB11' 'na-dr.contoso.local' $issuing 233 $t
    $null = Add-HCLicense -Context $ctx -Name 'ONTAP license packages (11)' -StatusText 'compliant' -Note 'base, nfs, cifs, snapmirror, snaprestore (+6 more)' -Thresholds $t
    $results.Add($ctx)

    # --- vCenter -------------------------------------------------------------------------
    $ctx = & $new 'VCenter' 'VC01' 'vc01.contoso.local'
    Set-HCFact $ctx 'vCenter' '8.0.3 (24322831)'; Set-HCFact $ctx 'Hosts' '14/14 connected'; Set-HCFact $ctx 'VMs on' 412
    Add-HCDemoChecks $ctx @(
        , @('vSphere API', 'OK', 'Logged in (api)')
        , @('Appliance health', 'OK', 'All 7 components green')
        , @('vCenter services', 'OK', '41 automatic services started')
        , @('ESXi hosts', 'OK', '14 hosts connected')
        , @('Datastores', 'OK', '9 datastores, fullest DS-PROD-03 at 79.5%')
        , @('File-based backup', 'OK', 'Last backup succeeded 4 h ago')
    )
    Add-HCDemoCert $ctx 'HTTPS :443' 'Machine SSL (__MACHINE_CERT)' 'vc01.contoso.local' $issuing 298 $t
    Add-HCDemoCert $ctx 'SSO token signing' 'STS signing certificate' 'ssoserverSign' 'CA' 611 $t -Trusted $false
    $null = Add-HCLicense -Context $ctx -Name 'VMware vSphere 8 Enterprise Plus' -StatusText 'Valid' -Expires (Get-Date).AddDays(41) -Usage '448/512 cpuCore' -Note 'key ...4K2NP' -Thresholds $t
    $null = Add-HCLicense -Context $ctx -Name 'VMware vCenter Server 8 Standard' -StatusText 'Valid' -Expires (Get-Date).AddDays(41) -Usage '2/2 server' -Note 'key ...8JH3Q' -Thresholds $t
    $results.Add($ctx)

    $ctx = & $new 'VCenter' 'VC-DR' 'vc-dr.contoso.local'
    Set-HCFact $ctx 'vCenter' '8.0.3 (24322831)'; Set-HCFact $ctx 'Hosts' '6/6 connected'; Set-HCFact $ctx 'VMs on' 37
    Add-HCDemoChecks $ctx @(
        , @('vSphere API', 'OK', 'Logged in (api)')
        , @('Appliance health', 'OK', 'All 7 components green')
        , @('ESXi hosts', 'OK', '6 hosts connected')
        , @('Datastores', 'OK', '4 datastores, fullest DS-DR-01 at 62.0%')
        , @('File-based backup', 'Warning', 'Last backup (FAILED) is 3 days ago: Unable to reach SFTP target 10.20.0.15')
    )
    Add-HCDemoCert $ctx 'HTTPS :443' 'Machine SSL (__MACHINE_CERT)' 'vc-dr.contoso.local' $issuing 298 $t
    $results.Add($ctx)

    # --- Forcepoint -----------------------------------------------------------------------
    foreach ($p in @(@{ Name = 'FP-PROXY1'; Ms = 142; Cert = 5 }, @{ Name = 'FP-PROXY2'; Ms = 167; Cert = 340 })) {
        $ctx = & $new 'ForcepointProxy' $p.Name ("{0}.contoso.local" -f $p.Name.ToLowerInvariant())
        Set-HCFact $ctx 'Proxy' ':8080'
        Add-HCDemoChecks $ctx @(
            , @('Ping', 'OK', 'Reply in 1 ms')
            , @('TCP ports', 'OK', 'Open: 8080, 8081')
            , @('Browse via proxy: www.google.com', 'OK', ('HTTP 204 in {0} ms' -f $p.Ms))
            , @('Browse via proxy: www.msftconnecttest.com', 'OK', ('HTTP 200 in {0} ms' -f ($p.Ms - 40)))
            , @('Filtering enforcement', 'OK', 'Test URL blocked as expected (HTTP 403)')
            , @('SSL inspection', 'OK', "www.google.com re-signed by 'Contoso Web Inspection CA'")
        )
        Add-HCDemoCert $ctx 'Content Gateway Manager :8081' '' ("{0}.contoso.local" -f $p.Name.ToLowerInvariant()) ("{0}.contoso.local" -f $p.Name.ToLowerInvariant()) $p.Cert $t -Trusted $false
        Add-HCDemoCert $ctx 'SSL inspection CA (via proxy)' 'SSL inspection CA' 'Contoso Web Inspection CA' 'Contoso Root CA' 1460 $t
        $results.Add($ctx)
    }
    $ctx = & $new 'ForcepointManager' 'FP-MGMT' 'fp-mgmt.contoso.local'
    Set-HCFact $ctx 'OS' 'Server 2019 Standard'; Set-HCFact $ctx 'Uptime' '44d 7h'
    Add-HCDemoChecks $ctx @(
        , @('TCP ports', 'OK', 'Open: 9443')
        , @('Security Manager console', 'OK', 'HTTP 200 in 388 ms')
        , @('Services', 'OK', 'All 14 monitored services running')
        , @('Disk space', 'OK', 'C: 38% free, D: 52% free')
    )
    Add-HCDemoCert $ctx 'Security Manager :9443' '' 'fp-mgmt.contoso.local' $issuing 402 $t
    $null = Add-HCLicense -Context $ctx -Name 'Forcepoint Web Security (2,500 users)' -StatusText 'Subscription' -Expires (Get-Date).AddDays(230) -Source 'Manual' -Thresholds $t
    $results.Add($ctx)

    # --- Portnox --------------------------------------------------------------------------
    $ctx = & $new 'Portnox' 'PORTNOX01' 'portnox01.contoso.local'
    Set-HCFact $ctx 'OS' 'Server 2022 Standard'; Set-HCFact $ctx 'Uptime' '17d 1h'
    Add-HCDemoChecks $ctx @(
        , @('TCP ports', 'OK', 'Open: 443')
        , @('Portnox console', 'OK', 'HTTP 200 in 512 ms')
        , @('RADIUS portnox01.contoso.local:1812', 'OK', 'Access-Reject in 23 ms')
        , @('Services', 'OK', 'All 6 monitored services running')
        , @('Disk space', 'OK', 'C: 47% free')
    )
    Add-HCDemoCert $ctx 'Web console :443 + LocalMachine\My' 'Portnox Console 2026' 'portnox01.contoso.local' $issuing 160 $t
    Add-HCDemoCert $ctx 'LocalMachine\My' 'Portnox RADIUS EAP 2026' 'radius.contoso.local' $issuing 160 $t -Template 'Contoso RADIUS Server'
    $null = Add-HCLicense -Context $ctx -Name 'Portnox CORE (1,800 devices)' -StatusText 'Subscription' -Expires (Get-Date).AddDays(95) -Source 'Manual' -Thresholds $t
    $results.Add($ctx)

    # --- Juniper --------------------------------------------------------------------------
    $switches = @(
        @{ Name = 'CORE-SW1'; Model = 'ex4650-48y-8c'; Junos = '22.4R3-S2.11'; Up = '41w2d'; VC = '2/2' }
        @{ Name = 'CORE-SW2'; Model = 'ex4650-48y-8c'; Junos = '22.4R3-S2.11'; Up = '41w2d'; VC = '2/2' }
        @{ Name = 'ACC-SW-1F'; Model = 'ex4300-48p'; Junos = '21.4R3-S5.4'; Up = '18w6d'; VC = '3/3' }
        @{ Name = 'ACC-SW-3F'; Model = 'ex4300-48p'; Junos = '21.4R3-S5.4'; Up = '2d 05:11'; VC = '2/2' }
    )
    foreach ($s in $switches) {
        $ctx = & $new 'Juniper' $s.Name ("{0}.mgmt.contoso.local" -f $s.Name.ToLowerInvariant())
        Set-HCFact $ctx 'Model' $s.Model; Set-HCFact $ctx 'Junos' $s.Junos; Set-HCFact $ctx 'Uptime' $s.Up; Set-HCFact $ctx 'VC' $s.VC
        Add-HCDemoChecks $ctx @(
            , @('Ping', 'OK', 'Reply in 2 ms')
            , @('TCP ports', 'OK', 'Open: 22')
            , @('SSH login', 'OK', "Logged in to $($s.Name.ToLowerInvariant())")
            , @('Virtual Chassis', 'OK', "$($s.VC) members present")
            , @('Storage', 'OK', 'Max 47% used')
        )
        if ($s.Name -eq 'ACC-SW-3F') {
            Add-HCCheck $ctx 'Major alarm' 'Critical' 'fpc1: FPC 1 PEM 1 Not Powered (since 2026-10-13 02:14:51 IDT)'
            Add-HCCheck $ctx 'Power FPC 1 Power Supply 1' 'Critical' 'Failed'
            Set-HCFact $ctx 'Changed' '9 h ago by netadmin'
        } else {
            Add-HCCheck $ctx 'Alarms' 'OK' 'No active chassis or system alarms'
            Add-HCCheck $ctx 'Environment' 'OK' '14 power/fan/temperature sensors OK'
        }
        if ($s.Name -like 'CORE*') {
            $null = Add-HCLicense -Context $ctx -Name 'Junos licenses (2)' -StatusText 'permanent' -Note 'ex-advanced, ex-ospf' -Source 'Device' -Thresholds $t
        } else {
            $null = Add-HCLicense -Context $ctx -Name 'Junos feature licenses' -StatusText 'none installed / not required' -Source 'Device' -Thresholds $t
        }
        Add-HCDemoCert $ctx 'Junos PKI' 'jweb-cert' ("{0}.mgmt.contoso.local" -f $s.Name.ToLowerInvariant()) ("{0}.mgmt.contoso.local" -f $s.Name.ToLowerInvariant()) 1630 $t -Trusted $false
        $results.Add($ctx)
    }

    # --- Check Point ----------------------------------------------------------------------
    $ctx = & $new 'CheckPoint' 'FW-CLUSTER' 'cp-mgmt.contoso.local'
    Set-HCFact $ctx 'Version' 'R81.20'; Set-HCFact $ctx 'Cluster' 'fw-a ACTIVE / fw-b STANDBY'; Set-HCFact $ctx 'Policy installed' '5 h ago (Standard)'
    Add-HCDemoChecks $ctx @(
        , @('TCP ports', 'OK', 'Open: 443')
        , @('Management API', 'OK', 'Logged in (API 1.9.1)')
        , @('Cluster state', 'OK', 'fw-a ACTIVE / fw-b STANDBY - High Availability (Active Up) with IGMP Membership')
        , @('fw-a policy', 'OK', "'Standard' installed 15 Oct 01:12")
        , @('fw-b policy', 'OK', "'Standard' installed 15 Oct 01:12")
        , @('Management processes', 'OK', '17 processes running')
    )
    Add-HCDemoCert $ctx 'Management :443' '' 'cp-mgmt.contoso.local' $issuing 199 $t
    Add-HCDemoCert $ctx 'fw-a Gaia portal :443' '' 'fw-a' 'fw-a' 2210 $t -Trusted $false
    Add-HCDemoCert $ctx 'fw-b Gaia portal :443' '' 'fw-b' 'fw-b' 2210 $t -Trusted $false
    foreach ($m in 'fw-a', 'fw-b') {
        $null = Add-HCLicense -Context $ctx -Name "$m license CPSG-C-4-U, CPSB-FW (+11 more)" -StatusText 'permanent' -Note 'CK-0A1B2C3D4E5F' -Source 'Device' -Thresholds $t
        $null = Add-HCLicense -Context $ctx -Name "$m contracts (7)" -StatusText 'service contract' -Expires (Get-Date).AddDays(27) -Note 'CPSB-IPS-M-1Y, CPSB-ABOT-M-1Y, CPSB-URLF-M-1Y, CPSB-AV-M-1Y (+3 more)' -Source 'Device' -Thresholds $t
    }
    $results.Add($ctx)

    # --- Trellix --------------------------------------------------------------------------
    $ctx = & $new 'TrellixESM' 'ESM01' 'esm01.contoso.local'
    Set-HCFact $ctx 'Alarms 24h' 3
    Add-HCDemoChecks $ctx @(
        , @('TCP ports', 'OK', 'Open: 443')
        , @('ESM API', 'OK', 'Logged in')
        , @('ESM clock', 'OK', '+1 s compared with the monitoring server')
        , @('Unacknowledged alarms (24h)', 'Info', '3')
    )
    Add-HCDemoCert $ctx 'ESM console :443' '' 'esm01.contoso.local' $issuing 512 $t
    $null = Add-HCLicense -Context $ctx -Name 'Trellix SIEM support & content' -StatusText 'Subscription' -Expires (Get-Date).AddDays(301) -Source 'Manual' -Thresholds $t
    $results.Add($ctx)

    $ctx = & $new 'TrellixEPO' 'EPO01' 'epo01.contoso.local'
    Set-HCFact $ctx 'ePO' '5.10.0'; Set-HCFact $ctx 'Systems' '1,532'; Set-HCFact $ctx 'OS' 'Server 2019 Standard'
    Add-HCDemoChecks $ctx @(
        , @('TCP ports', 'OK', 'Open: 8443, 443')
        , @('ePO Web API', 'OK', 'Responding (version 5.10.0)')
        , @('Agent communication', 'OK', '1,532 managed systems, 41 not seen for more than 7 days (2.7%)')
        , @('Systems with AMCore content older than 3 days', 'Warning', '64 result row(s)')
        , @('Services', 'OK', 'All 5 monitored services running')
        , @('Disk space', 'OK', 'C: 41% free, D: 66% free')
    )
    Add-HCDemoCert $ctx 'ePO console :8443' '' 'epo01' 'Orion_CA_EPO01' 2731 $t -Trusted $false
    Add-HCDemoCert $ctx 'Agent handler :443' '' 'epo01' 'Orion_CA_EPO01' 2731 $t -Trusted $false
    $null = Add-HCLicense -Context $ctx -Name 'Trellix Endpoint Security (1,600 nodes)' -StatusText 'Subscription' -Expires (Get-Date).AddDays(64) -Source 'Manual' -Thresholds $t
    $results.Add($ctx)

    $ctx = & $new 'TrellixEDR' 'EDR' 'ui.soc.trellix.com'
    Add-HCDemoChecks $ctx @(
        , @('TCP ports', 'OK', 'Open: 443')
        , @('Console', 'OK', 'HTTP 200 in 611 ms')
    )
    Add-HCDemoCert $ctx 'HTTPS :443' '' 'ui.soc.trellix.com' 'Amazon RSA 2048 M02' 148 $t
    $null = Add-HCLicense -Context $ctx -Name 'Trellix EDR (1,600 nodes)' -StatusText 'Subscription' -Expires (Get-Date).AddDays(64) -Source 'Manual' -Thresholds $t
    $results.Add($ctx)

    foreach ($r in $results) { $null = Complete-HCContext -Context $r }
    return $results.ToArray()
}

function New-HCDemoPrevious {
    # A fake "yesterday": everything open today was already open, except a few new issues, and one
    # issue from yesterday is gone - so the demo shows both NEW markers and a "Resolved" line.
    param([Parameter(Mandatory)][object[]]$Results)
    $newToday = @('FP-PROXY1', 'ACC-SW-3F', 'VC-DR')
    $issues = foreach ($r in $Results) {
        if ($r.Name -in $newToday) { continue }
        foreach ($i in @(Get-HCIssues -Context $r)) {
            [pscustomobject]@{ Key = "$($r.Type)|$($r.Name)|$($i.Key)"; Status = $i.Status; System = $r.Name; Title = $i.Title }
        }
    }
    [pscustomobject]@{
        Generated = (Get-Date).AddDays(-1).ToString('o')
        Issues    = @($issues) + [pscustomobject]@{ Key = 'VCenter|VC01|chk|Datastore DS-PROD-03'; Status = 'Warning'; System = 'VC01'; Title = 'Datastore DS-PROD-03' }
    }
}

function Get-HCDemoConfig {
    @{
        General    = @{ Title = 'Morning Infrastructure Health Check'; Organization = 'Contoso IT (sample)' }
        Email      = @{ Enabled = $false }
        Thresholds = @{}
        Defaults   = @{}
        Targets    = @()
    }
}
