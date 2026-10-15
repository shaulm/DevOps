# Active Directory domain controllers.
#
# Functionality : ports, LDAP + LDAPS + Global Catalog binds, RootDSE isSynchronized, clock offset,
#                 SYSVOL/NETLOGON, DNS (domain A + DC SRV records), inbound replication, AD services, disks
# Certificates  : the certificate served on LDAPS (636) + LocalMachine\My (friendly name, template, issuer)
# License       : Windows activation state / channel / expiry
#
# Runs as the scheduled-task account (Kerberos) unless Credential is set. Needs the ActiveDirectory
# PowerShell module (RSAT) for replication and DC details.

function Import-HCActiveDirectoryModule {
    param($Context)
    if (Get-Module -Name ActiveDirectory) { return $true }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue -Verbose:$false
        return $true
    } catch {
        if ($Context) {
            Add-HCCheck $Context 'AD PowerShell module' 'Unknown' ('ActiveDirectory module missing on the monitoring server (install RSAT: ' +
                'Install-WindowsFeature RSAT-AD-PowerShell, or Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0)')
        }
        return $false
    }
}

function Expand-HCDomainControllerTargets {
    # Turns @{ Type = 'DomainController'; Discover = 'contoso.local' } into one target per DC.
    param([object[]]$Targets)
    foreach ($t in $Targets) {
        if ($t.Type -ne 'DomainController' -or -not $t.Discover) { $t; continue }
        try {
            if (-not (Import-HCActiveDirectoryModule)) { throw 'ActiveDirectory PowerShell module (RSAT) is not installed' }
            $dcs = @(Get-ADDomainController -Filter * -Server $t.Discover -ErrorAction Stop | Sort-Object HostName)
            foreach ($dc in $dcs) {
                if (Test-HCIgnored -Value @($dc.Name, $dc.HostName) -Pattern $t.Exclude) { continue }
                $n = $t.Clone()
                $n.Remove('Discover')
                $n.Name = $dc.Name
                $n.Address = $dc.HostName
                $n.Domain = $t.Discover
                $n
            }
        } catch {
            $n = $t.Clone()
            $n.Name = "Discovery $($t.Discover)"
            $n.Address = $t.Discover
            $n.DiscoveryError = Get-HCErrorText $_
            $n
        }
    }
}

function Test-HCLdapBind {
    # Binds with Negotiate (Kerberos) and reads RootDSE. Returns the RootDSE attributes or $null.
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Server,
        [int]$Port = 389,
        [switch]$Ssl,
        [pscredential]$Credential,
        [string]$Name,
        [int]$TimeoutSec = 15
    )
    Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
    $connection = $null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Server, $Port, $false, $false)
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        if ($Credential) { $connection.Credential = $Credential.GetNetworkCredential() }
        $connection.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $connection.SessionOptions.ProtocolVersion = 3
        if ($Ssl) { $connection.SessionOptions.SecureSocketLayer = $true }
        $connection.Bind()
        $attributes = [string[]]@('currentTime', 'isSynchronized', 'isGlobalCatalogReady', 'defaultNamingContext', 'dnsHostName', 'serverName')
        $request = [System.DirectoryServices.Protocols.SearchRequest]::new('', '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, $attributes)
        $response = [System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($request)
        $values = @{}
        $entry = $response.Entries[0]
        foreach ($attributeName in $entry.Attributes.AttributeNames) {
            $values[[string]$attributeName] = @($entry.Attributes[[string]$attributeName].GetValues([string]))[0]
        }
        Add-HCCheck $Context $Name 'OK' ('Bind and RootDSE read in {0} ms' -f $sw.ElapsedMilliseconds)
        return $values
    } catch {
        $message = Get-HCErrorText $_
        if ($Ssl -and $message -match 'unavailable|not available' -and (Test-HCTcpPort -HostName $Server -Port $Port -TimeoutMs 3000).Open) {
            $message += " - port $Port is open, so the LDAPS certificate is probably missing, expired, untrusted or does not match the DC name"
        }
        Add-HCCheck $Context $Name 'Critical' $message
        return $null
    } finally {
        if ($connection) { $connection.Dispose() }
    }
}

function Test-HCDcShares {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Server, [string]$Domain, [pscredential]$Credential)
    foreach ($share in 'SYSVOL', 'NETLOGON') {
        $root = "\\$Server\$share"
        $drive = $null
        try {
            if ($Credential) {
                $drive = New-PSDrive -Name ('HC' + [guid]::NewGuid().ToString('N').Substring(0, 8)) -PSProvider FileSystem -Root $root -Credential $Credential -ErrorAction Stop
            }
            $probe = if ($share -eq 'SYSVOL' -and $Domain) { "$root\$Domain\Policies" } else { $root }
            if (Test-Path -LiteralPath $probe) { Add-HCCheck $Context "$share share" 'OK' 'Accessible' }
            else { Add-HCCheck $Context "$share share" 'Critical' "Not accessible: $probe" }
        } catch {
            Add-HCCheck $Context "$share share" 'Critical' (Get-HCErrorText $_)
        } finally {
            if ($drive) { Remove-PSDrive -Name $drive.Name -Force -ErrorAction SilentlyContinue }
        }
    }
}

function Test-HCDcDns {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Domain)
    if (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
        Add-HCLog $Context 'Resolve-DnsName not available - DNS check skipped'
        return
    }
    try {
        $a = @(Resolve-DnsName -Name $Domain -Server $Server -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Section -eq 'Answer' -and $_.Type -eq 'A' })
        $srv = @(Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Domain" -Server $Server -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Section -eq 'Answer' -and $_.Type -eq 'SRV' })
        if ($srv.Count -eq 0) { Add-HCCheck $Context 'DNS' 'Critical' "No DC locator SRV records for $Domain" }
        else { Add-HCCheck $Context 'DNS' 'OK' ('{0}: {1} A record(s), {2} DC SRV record(s)' -f $Domain, $a.Count, $srv.Count) }
    } catch {
        Add-HCCheck $Context 'DNS' 'Critical' "Query to $Server failed: $(Get-HCErrorText $_)"
    }
}

function Get-HCPartitionShortName {
    param([string]$DistinguishedName)
    switch -Regex ($DistinguishedName) {
        '^CN=Schema,' { return 'Schema' }
        '^CN=Configuration,' { return 'Configuration' }
        '^DC=DomainDnsZones,' { return 'DomainDnsZones' }
        '^DC=ForestDnsZones,' { return 'ForestDnsZones' }
        default { return (($DistinguishedName -split ',' | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) }) -join '.') }
    }
}

function Test-HCDcReplication {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Server, [pscredential]$Credential, [hashtable]$Thresholds)
    $p = @{ Target = $Server; Partition = '*'; ErrorAction = 'Stop' }
    if ($Credential) { $p.Credential = $Credential }
    try {
        $links = @(Get-ADReplicationPartnerMetadata @p)
    } catch {
        Add-HCCheck $Context 'AD replication' 'Unknown' "Cannot read replication metadata: $(Get-HCErrorText $_)"
        return
    }
    if ($links.Count -eq 0) {
        Add-HCCheck $Context 'AD replication' 'Info' 'No inbound replication partners (single DC?)'
        return
    }
    $failing = @(); $stale = @()
    foreach ($l in $links) {
        $partner = if ($l.Partner -match '^CN=NTDS Settings,CN=(?<dc>[^,]+)') { $Matches.dc } else { [string]$l.Partner }
        $partition = Get-HCPartitionShortName ([string]$l.Partition)
        if ([int]$l.LastReplicationResult -ne 0) {
            $text = try { [System.ComponentModel.Win32Exception]::new([int]$l.LastReplicationResult).Message } catch { '' }
            $failing += ('{0}/{1}: error {2}{3}, {4} failure(s), last success {5}' -f $partner, $partition, $l.LastReplicationResult,
                $(if ($text -and $text -notmatch '^Unknown error') { " ($text)" }), $l.ConsecutiveReplicationFailures, (Format-HCAgo $l.LastReplicationSuccess))
        } elseif ($l.LastReplicationSuccess -and ((Get-Date) - $l.LastReplicationSuccess).TotalHours -gt $Thresholds.ReplicationWarningHours) {
            $stale += ('{0}/{1}: last success {2}' -f $partner, $partition, (Format-HCAgo $l.LastReplicationSuccess))
        }
    }
    if ($failing) {
        Add-HCCheck $Context 'AD replication' 'Critical' (Format-HCList -Items $failing -Max 3)
    } elseif ($stale) {
        Add-HCCheck $Context 'AD replication' 'Warning' (Format-HCList -Items $stale -Max 3)
    } else {
        $latest = ($links | Measure-Object -Property LastReplicationSuccess -Maximum).Maximum
        Add-HCCheck $Context 'AD replication' 'OK' ('{0} inbound links healthy, last success {1}' -f $links.Count, (Format-HCAgo $latest))
    }
}

function Invoke-HCCheckDomainController {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    if ($Target.DiscoveryError) {
        Add-HCCheck $Context 'DC discovery' 'Critical' "Could not enumerate domain controllers of $($Target.Address): $($Target.DiscoveryError)"
        return
    }
    $t = $Settings.Thresholds
    $server = $Target.Address
    $ports = @(Get-HCOption $Target 'Ports' @(53, 88, 135, 389, 445, 636))
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports $ports)) { return }

    # AD's own view of this DC: site, GC, FSMO roles, RODC
    $isGC = $null
    $adModule = Import-HCActiveDirectoryModule -Context $Context
    if ($adModule) {
        try {
            $p = @{ Identity = $server; Server = $server; ErrorAction = 'Stop' }
            if ($Credential) { $p.Credential = $Credential }
            $dc = Get-ADDomainController @p
            Set-HCFact $Context 'Site' $dc.Site
            $isGC = [bool]$dc.IsGlobalCatalog
            $roleNames = @{ PDCEmulator = 'PDC'; RIDMaster = 'RID'; InfrastructureMaster = 'Infra'; SchemaMaster = 'Schema'; DomainNamingMaster = 'Naming' }
            $roles = @($dc.OperationMasterRoles | ForEach-Object { $roleNames[[string]$_] } | Where-Object { $_ })
            if ($roles) { Set-HCFact $Context 'FSMO' ($roles -join ',') }
            if ($dc.IsReadOnly) { Set-HCFact $Context 'Role' 'RODC' }
        } catch {
            Add-HCLog $Context "Get-ADDomainController: $(Get-HCErrorText $_)"
        }
    }

    # LDAP + RootDSE (sync state, clock)
    $domain = $Target.Domain
    $rootDse = Test-HCLdapBind -Context $Context -Server $server -Port 389 -Credential $Credential -Name 'LDAP (389)'
    if ($rootDse) {
        if ($rootDse['isSynchronized'] -and $rootDse['isSynchronized'] -ne 'TRUE') {
            Add-HCCheck $Context 'Directory sync state' 'Critical' 'RootDSE isSynchronized = FALSE (DC has not completed initial replication / is not advertising)'
        }
        if ($null -eq $isGC -and $rootDse['isGlobalCatalogReady']) { $isGC = ($rootDse['isGlobalCatalogReady'] -eq 'TRUE') }
        if (-not $domain -and $rootDse['defaultNamingContext']) { $domain = Get-HCPartitionShortName $rootDse['defaultNamingContext'] }
        $dcTime = ConvertTo-HCDateTime $rootDse['currentTime']
        if ($dcTime) {
            $offset = ($dcTime - (Get-Date)).TotalSeconds
            $status = Get-HCThresholdStatus -Value ([math]::Abs($offset)) -Warning $t.TimeSkewWarningSec -Critical $t.TimeSkewCriticalSec
            Add-HCCheck $Context 'Clock offset' $status ('{0:+0;-0;0} s compared with the monitoring server' -f $offset)
        }
    }
    if ($isGC) { Set-HCFact $Context 'GC' 'yes' }

    if ($Target.CheckLdaps -ne $false) {
        $null = Test-HCLdapBind -Context $Context -Server $server -Port 636 -Ssl -Credential $Credential -Name 'LDAPS (636)'
        $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port 636 -Source 'LDAPS :636'
    }
    if ($isGC -and $Target.CheckGlobalCatalog -ne $false) {
        $null = Test-HCLdapBind -Context $Context -Server $server -Port 3268 -Credential $Credential -Name 'Global Catalog (3268)'
    }
    if ($Target.CheckShares -ne $false) { Test-HCDcShares -Context $Context -Server $server -Domain $domain -Credential $Credential }
    if ($Target.CheckDns -ne $false -and $domain) { Test-HCDcDns -Context $Context -Server $server -Domain $domain }
    if ($adModule -and $Target.CheckReplication -ne $false) {
        Test-HCDcReplication -Context $Context -Server $server -Credential $Credential -Thresholds $t
    }

    Invoke-HCWindowsChecks -Context $Context -Target $Target -Credential $Credential -Settings $Settings `
        -Services (Get-HCOption $Target 'Services' @('NTDS', 'Netlogon', 'Kdc', 'W32Time', 'DFSR', 'ADWS')) `
        -OptionalServices (Get-HCOption $Target 'OptionalServices' @('DNS', 'IsmServ')) `
        -Disks:($Target.CheckDisks -ne $false) -Activation:($Target.CheckActivation -ne $false) `
        -CertificateStore:($Target.CheckCertificateStore -ne $false)
}
