# VMware vCenter Server (vSphere Automation REST API, vCenter 7.0 U2 or later; falls back to /rest on older).
#
# Functionality : appliance health (system, database, storage, memory, load, swap), vCenter services,
#                 ESXi host connection state, datastore usage, last file-based backup, VM count
# Certificates  : Machine SSL certificate (served on 443) and the STS/SSO signing certificate
# License       : vSphere license keys (vCenter, ESXi, ...) with usage and expiry, via the vSphere SOAP API
#
# A read-only vSphere role is enough for hosts, datastores and licenses. The appliance health and backup
# endpoints may need an SSO account with appliance rights; without them those rows show "Unknown".

function Connect-HCVCenterRest {
    param([string]$Base, [pscredential]$Credential, [bool]$Skip, [int]$TimeoutSec)
    try {
        $token = Invoke-HCRest -Method POST -Uri "$Base/api/session" -Credential $Credential -SkipCertificateCheck:$Skip -TimeoutSec $TimeoutSec
        return @{ Mode = 'api'; Base = $Base; Headers = @{ 'vmware-api-session-id' = [string]$token }; Skip = $Skip; TimeoutSec = $TimeoutSec }
    } catch {
        if ((Get-HCHttpStatus $_) -ne 404) { throw }
    }
    $legacy = Invoke-HCRest -Method POST -Uri "$Base/rest/com/vmware/cis/session" -Credential $Credential -SkipCertificateCheck:$Skip -TimeoutSec $TimeoutSec
    return @{ Mode = 'rest'; Base = $Base; Headers = @{ 'vmware-api-session-id' = [string]$legacy.value }; Skip = $Skip; TimeoutSec = $TimeoutSec }
}

function Invoke-HCVCenterGet {
    # GET <base>/api/<path> (or /rest/<path> on old versions, unwrapping "value").
    param([Parameter(Mandatory)][hashtable]$Session, [Parameter(Mandatory)][string]$Path)
    $prefix = if ($Session.Mode -eq 'api') { '/api/' } else { '/rest/' }
    $response = Invoke-HCRest -Uri ($Session.Base + $prefix + $Path) -Headers $Session.Headers -SkipCertificateCheck:$Session.Skip -TimeoutSec $Session.TimeoutSec
    if ($Session.Mode -eq 'rest' -and $null -ne $response -and $response.PSObject.Properties['value']) { return $response.value }
    return $response
}

function Invoke-HCVimSoap {
    # Minimal vSphere Web Services (SOAP) call - used for licensing, which the REST API does not expose.
    param([string]$Base, [string]$Body, [Microsoft.PowerShell.Commands.WebRequestSession]$Session, [string]$Version, [bool]$Skip, [int]$TimeoutSec)
    $envelope = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' +
    "<soapenv:Body>$Body</soapenv:Body></soapenv:Envelope>"
    try {
        $r = Invoke-WebRequest -Uri "$Base/sdk" -Method Post -Body $envelope -ContentType 'text/xml; charset=utf-8' `
            -Headers @{ SOAPAction = "urn:vim25/$Version" } -WebSession $Session -SkipCertificateCheck:$Skip -NoProxy -TimeoutSec $TimeoutSec -ErrorAction Stop
    } catch {
        $detail = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { '' }
        if ($detail -match '<faultstring>(?<f>[^<]+)</faultstring>') { throw "vSphere SOAP fault: $($Matches.f)" }
        throw
    }
    return [xml]$r.Content
}

function Get-HCXmlChildText {
    param($Node, [string]$Name)
    $child = $Node.SelectSingleNode("*[local-name()='$Name']")
    if ($child) { return $child.InnerText }
    return $null
}

function Get-HCVSphereLicenses {
    param([Parameter(Mandatory)]$Context, [string]$Base, [pscredential]$Credential, [bool]$Skip, [int]$TimeoutSec, [hashtable]$Thresholds)
    $web = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $version = '7.0'
    try {
        $v = Invoke-WebRequest -Uri "$Base/sdk/vimServiceVersions.xml" -SkipCertificateCheck:$Skip -NoProxy -TimeoutSec $TimeoutSec -ErrorAction Stop
        $node = ([xml]$v.Content).SelectSingleNode("//*[local-name()='namespace'][*[local-name()='name']='urn:vim25']/*[local-name()='version']")
        if ($node) { $version = $node.InnerText }
    } catch {
        Add-HCLog $Context "vimServiceVersions.xml: $(Get-HCErrorText $_)"
    }
    $soap = @{ Base = $Base; Session = $web; Version = $version; Skip = $Skip; TimeoutSec = $TimeoutSec }

    $content = Invoke-HCVimSoap @soap -Body '<RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent>'
    $sc = $content.SelectSingleNode("//*[local-name()='returnval']")
    $licenseManager = Get-HCXmlChildText $sc 'licenseManager'
    $sessionManager = Get-HCXmlChildText $sc 'sessionManager'
    $propertyCollector = Get-HCXmlChildText $sc 'propertyCollector'
    $about = $sc.SelectSingleNode("*[local-name()='about']")
    if ($about) { Set-HCFact $Context 'vCenter' ('{0} ({1})' -f (Get-HCXmlChildText $about 'version'), (Get-HCXmlChildText $about 'build')) }

    $user = [System.Security.SecurityElement]::Escape($Credential.UserName)
    $pass = [System.Security.SecurityElement]::Escape($Credential.GetNetworkCredential().Password)
    $null = Invoke-HCVimSoap @soap -Body "<Login xmlns=`"urn:vim25`"><_this type=`"SessionManager`">$sessionManager</_this><userName>$user</userName><password>$pass</password></Login>"
    try {
        $body = "<RetrievePropertiesEx xmlns=`"urn:vim25`"><_this type=`"PropertyCollector`">$propertyCollector</_this>" +
        '<specSet><propSet><type>LicenseManager</type><pathSet>licenses</pathSet></propSet>' +
        "<objectSet><obj type=`"LicenseManager`">$licenseManager</obj></objectSet></specSet><options/></RetrievePropertiesEx>"
        $result = Invoke-HCVimSoap @soap -Body $body
        $count = 0
        foreach ($info in $result.SelectNodes("//*[local-name()='LicenseManagerLicenseInfo']")) {
            $key = Get-HCXmlChildText $info 'licenseKey'
            $name = Get-HCXmlChildText $info 'name'
            $total = [int](Get-HCXmlChildText $info 'total')
            $used = [int](Get-HCXmlChildText $info 'used')
            $unit = Get-HCXmlChildText $info 'costUnit'
            $properties = @{}
            foreach ($prop in $info.SelectNodes("*[local-name()='properties']")) {
                $properties[(Get-HCXmlChildText $prop 'key')] = Get-HCXmlChildText $prop 'value'
            }
            $evaluation = $key -eq '00000-00000-00000-00000-00000'
            if ($evaluation -and $used -eq 0) { continue }
            $expires = if ($properties['expirationDate']) { ConvertTo-HCDateTime $properties['expirationDate'] } else { $null }
            $status = 'OK'; $statusText = 'Valid'; $notes = @()
            if ($evaluation) { $status = 'Warning'; $statusText = 'Evaluation mode'; $notes += 'evaluation mode in use' }
            if ($total -gt 0 -and $used -gt $total) { $status = 'Warning'; $statusText = 'Over-allocated'; $notes += "using $used of $total" }
            if ($key -and -not $evaluation) { $notes += ('key ...{0}' -f $key.Substring([math]::Max(0, $key.Length - 5))) }
            $usage = if ($total -gt 0) { '{0}/{1} {2}' -f $used, $total, $unit } else { '{0} {1}' -f $used, $unit }
            $null = Add-HCLicense -Context $Context -Name $name -Status $status -StatusText $statusText -Expires $expires -Usage $usage `
                -Note ($notes -join '; ') -Thresholds $Thresholds
            $count++
        }
        if ($count -eq 0) { Add-HCCheck $Context 'Licenses' 'Warning' 'No license keys returned by the LicenseManager' }
    } finally {
        try { $null = Invoke-HCVimSoap @soap -Body "<Logout xmlns=`"urn:vim25`"><_this type=`"SessionManager`">$sessionManager</_this></Logout>" } catch { Write-Verbose 'SOAP logout failed' }
    }
}

function Invoke-HCCheckVCenter {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $t = $Settings.Thresholds
    $address = $Target.Address
    $port = [int](Get-HCOption $Target 'Port' 443)
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports @($port))) { return }
    $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $port -Source "HTTPS :$port" -FriendlyName 'Machine SSL (__MACHINE_CERT)'
    if (-not $Credential) {
        Add-HCMissingCredentialCheck -Context $Context -Target $Target -Name 'vSphere API'
        return
    }
    $base = "https://${address}:$port"
    $skip = [bool]$Target.SkipCertificateCheck
    $timeout = [math]::Max($Settings.TimeoutSec, 30)
    try {
        $session = Connect-HCVCenterRest -Base $base -Credential $Credential -Skip $skip -TimeoutSec $timeout
        Add-HCCheck $Context 'vSphere API' 'OK' "Logged in ($($session.Mode))"
    } catch {
        Add-HCCheck $Context 'vSphere API' 'Critical' "Login failed: $(Get-HCErrorText $_)"
        return
    }

    try {
        # --- Appliance health ----------------------------------------------------------------
        $components = @(Get-HCOption $Target 'HealthComponents' @('system', 'applmgmt', 'database-storage', 'load', 'mem', 'storage', 'swap'))
        $green = 0; $denied = $false; $problems = 0
        foreach ($component in $components) {
            try {
                $color = [string](Invoke-HCVCenterGet -Session $session -Path "appliance/health/$component")
                switch ($color.ToLowerInvariant()) {
                    'green' { $green++ }
                    'red' { Add-HCCheck $Context "Appliance health: $component" 'Critical' 'red'; $problems++ }
                    { $_ -in 'yellow', 'orange' } { Add-HCCheck $Context "Appliance health: $component" 'Warning' $color; $problems++ }
                    default { Add-HCCheck $Context "Appliance health: $component" 'Unknown' "status '$color'"; $problems++ }
                }
            } catch {
                $code = Get-HCHttpStatus $_
                if ($code -in 401, 403) { $denied = $true }
                elseif ($code -ne 404) { Add-HCCheck $Context "Appliance health: $component" 'Unknown' (Get-HCErrorText $_); $problems++ }
            }
        }
        if ($denied -and $green -eq 0) {
            Add-HCCheck $Context 'Appliance health' 'Unknown' 'Access denied - this account cannot read appliance health (see README, vCenter permissions)'
        } elseif ($green -gt 0 -and $problems -eq 0) {
            Add-HCCheck $Context 'Appliance health' 'OK' ('All {0} components green' -f $green)
        }

        try {
            $version = Invoke-HCVCenterGet -Session $session -Path 'appliance/system/version'
            if ($version.version) { Set-HCFact $Context 'vCenter' ('{0} ({1})' -f $version.version, $version.build) }
        } catch {
            Add-HCLog $Context "appliance version: $(Get-HCErrorText $_)"
        }

        # --- vCenter services ------------------------------------------------------------------
        if ($session.Mode -eq 'api') {
            try {
                $services = Invoke-HCVCenterGet -Session $session -Path 'vcenter/services'
                $list = foreach ($p in $services.PSObject.Properties) {
                    [pscustomobject]@{ Name = $p.Name; State = $p.Value.state; Health = $p.Value.health; Startup = $p.Value.startup_type }
                }
                $stopped = @($list | Where-Object { $_.Startup -eq 'AUTOMATIC' -and $_.State -ne 'STARTED' })
                $degraded = @($list | Where-Object { $_.State -eq 'STARTED' -and $_.Health -and $_.Health -notin 'HEALTHY', 'HEALTHY_WITH_WARNINGS' })
                foreach ($s in $stopped) { Add-HCCheck $Context "Service $($s.Name)" 'Critical' "State $($s.State) (startup AUTOMATIC)" }
                foreach ($s in $degraded) { Add-HCCheck $Context "Service $($s.Name)" 'Warning' "Health $($s.Health)" }
                if (-not $stopped -and -not $degraded) {
                    Add-HCCheck $Context 'vCenter services' 'OK' ('{0} automatic services started' -f @($list | Where-Object Startup -eq 'AUTOMATIC').Count)
                }
            } catch {
                if ((Get-HCHttpStatus $_) -ne 404) { Add-HCCheck $Context 'vCenter services' 'Unknown' (Get-HCErrorText $_) }
            }
        }

        # --- ESXi hosts ----------------------------------------------------------------------------
        try {
            $hosts = @(Invoke-HCVCenterGet -Session $session -Path 'vcenter/host')
            $bad = 0
            foreach ($h in $hosts) {
                if ($h.connection_state -eq 'CONNECTED') { continue }
                $bad++
                $status = if ($h.connection_state -eq 'DISCONNECTED') { 'Warning' } else { 'Critical' }
                Add-HCCheck $Context "ESXi $($h.name)" $status ('{0}, power {1}' -f $h.connection_state, $h.power_state)
            }
            Set-HCFact $Context 'Hosts' ('{0}/{1} connected' -f ($hosts.Count - $bad), $hosts.Count)
            if ($bad -eq 0) { Add-HCCheck $Context 'ESXi hosts' 'OK' ('{0} hosts connected' -f $hosts.Count) }
        } catch {
            Add-HCCheck $Context 'ESXi hosts' 'Unknown' (Get-HCErrorText $_)
        }

        # --- Datastores ----------------------------------------------------------------------------
        try {
            $datastores = @(Invoke-HCVCenterGet -Session $session -Path 'vcenter/datastore')
            $issues = 0; $fullest = $null
            foreach ($d in $datastores) {
                if (Test-HCIgnored -Value @($d.name) -Pattern $Target.IgnoreDatastores) { continue }
                if (-not $d.capacity) { Add-HCCheck $Context "Datastore $($d.name)" 'Warning' 'No capacity reported (inaccessible?)'; $issues++; continue }
                $pct = [math]::Round(100 * ([double]$d.capacity - [double]$d.free_space) / [double]$d.capacity, 1)
                if ($null -eq $fullest -or $pct -gt $fullest.Pct) { $fullest = @{ Name = $d.name; Pct = $pct } }
                $status = Get-HCThresholdStatus -Value $pct -Warning $t.DatastoreUsedWarningPct -Critical $t.DatastoreUsedCriticalPct
                if ($status -ne 'OK') { Add-HCCheck $Context "Datastore $($d.name)" $status ('{0}% used, {1} free' -f $pct, (Format-HCBytes $d.free_space)); $issues++ }
            }
            if ($issues -eq 0 -and $fullest) { Add-HCCheck $Context 'Datastores' 'OK' ('{0} datastores, fullest {1} at {2}%' -f $datastores.Count, $fullest.Name, $fullest.Pct) }
        } catch {
            Add-HCCheck $Context 'Datastores' 'Unknown' (Get-HCErrorText $_)
        }

        try {
            $vmPath = if ($session.Mode -eq 'api') { 'vcenter/vm?power_states=POWERED_ON' } else { 'vcenter/vm?filter.power_states=POWERED_ON' }
            Set-HCFact $Context 'VMs on' @(Invoke-HCVCenterGet -Session $session -Path $vmPath).Count
        } catch {
            Add-HCLog $Context "VM count: $(Get-HCErrorText $_)"
        }

        # --- File-based backup -----------------------------------------------------------------------
        if ($Target.CheckBackup -ne $false) {
            try {
                $jobs = @(Invoke-HCVCenterGet -Session $session -Path 'appliance/recovery/backup/job' | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.id } })
                if ($jobs.Count -eq 0) {
                    Add-HCCheck $Context 'File-based backup' 'Warning' 'No backup jobs found on the appliance'
                } else {
                    $latestId = $jobs | Sort-Object -Descending | Select-Object -First 1
                    $job = Invoke-HCVCenterGet -Session $session -Path "appliance/recovery/backup/job/$latestId"
                    $end = ConvertTo-HCDateTime $job.end_time
                    $age = if ($end) { ((Get-Date) - $end).TotalHours } else { $null }
                    if ($job.state -eq 'FAILED') {
                        $msg = @($job.messages | ForEach-Object { $_.default_message } | Where-Object { $_ }) -join '; '
                        Add-HCCheck $Context 'File-based backup' 'Warning' ('Last backup FAILED {0}{1}' -f (Format-HCAgo $end), $(if ($msg) { ": $msg" }))
                    } elseif ($null -ne $age -and $age -gt $t.BackupMaxAgeHours) {
                        Add-HCCheck $Context 'File-based backup' 'Warning' ('Last backup ({0}) is {1}' -f $job.state, (Format-HCAgo $end))
                    } else {
                        Add-HCCheck $Context 'File-based backup' 'OK' ('Last backup {0} {1}' -f ([string]$job.state).ToLowerInvariant(), (Format-HCAgo $end))
                    }
                }
            } catch {
                $code = Get-HCHttpStatus $_
                if ($code -in 401, 403) { Add-HCCheck $Context 'File-based backup' 'Unknown' 'Access denied - this account cannot read backup jobs' }
                elseif ($code -ne 404) { Add-HCCheck $Context 'File-based backup' 'Unknown' (Get-HCErrorText $_) }
            }
        }

        # --- STS / SSO signing certificate (vCenter 7.0 U3+) -----------------------------------------
        try {
            $signing = Invoke-HCVCenterGet -Session $session -Path 'vcenter/certificate-management/vcenter/signing-certificate'
            $pem = @($signing.active_cert_chain.cert_chain)[0]
            $leaf = ConvertFrom-HCPem -Pem $pem | Select-Object -First 1
            if ($leaf) {
                $null = Add-HCCertificate -Context $Context -Source 'SSO token signing' -Certificate $leaf -FriendlyName 'STS signing certificate' `
                    -Thresholds $t -Ignore $Target.IgnoreCertificates
            }
        } catch {
            Add-HCLog $Context "STS signing certificate: $(Get-HCErrorText $_)"
        }
    } finally {
        try {
            $sessionPath = if ($session.Mode -eq 'api') { '/api/session' } else { '/rest/com/vmware/cis/session' }
            $null = Invoke-HCRest -Method DELETE -Uri ($base + $sessionPath) -Headers $session.Headers -SkipCertificateCheck:$skip -TimeoutSec 10
        } catch {
            Write-Verbose 'vCenter logout failed'
        }
    }

    # --- Licenses (SOAP) ---------------------------------------------------------------------------
    if ($Target.CheckLicenses -ne $false) {
        try {
            Get-HCVSphereLicenses -Context $Context -Base $base -Credential $Credential -Skip $skip -TimeoutSec $timeout -Thresholds $t
        } catch {
            Add-HCCheck $Context 'Licenses' 'Unknown' (Get-HCErrorText $_)
        }
    }
}
