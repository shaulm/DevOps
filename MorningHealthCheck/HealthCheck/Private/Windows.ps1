# Checks shared by every Windows-based system (DCs, Forcepoint manager, Portnox, ePO, ...):
# services, disk space, uptime, Windows activation and the LocalMachine\My certificate store.
# Uses CIM over WinRM (falls back to DCOM) and PowerShell remoting for the certificate store.

function New-HCCimSession {
    param([Parameter(Mandatory)][string]$ComputerName, [pscredential]$Credential, [int]$TimeoutSec = 30)
    $common = @{ ComputerName = $ComputerName; OperationTimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
    if ($Credential) { $common.Credential = $Credential }
    try {
        return New-CimSession @common
    } catch {
        $wsmanError = Get-HCErrorText $_
        try {
            return New-CimSession @common -SessionOption (New-CimSessionOption -Protocol Dcom)
        } catch {
            throw "WinRM: $wsmanError / DCOM: $(Get-HCErrorText $_)"
        }
    }
}

function Test-HCWindowsServices {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$CimSession,
        [string[]]$Services,
        [string[]]$OptionalServices,
        [string[]]$ServicePatterns,
        [string[]]$ExcludeServices,
        [int]$TimeoutSec = 30
    )
    try {
        $all = @(Get-CimInstance -CimSession $CimSession -ClassName Win32_Service -Property Name, DisplayName, State, StartMode -OperationTimeoutSec $TimeoutSec -ErrorAction Stop)
    } catch {
        Add-HCCheck $Context 'Services' 'Unknown' "Cannot read services: $(Get-HCErrorText $_)"
        return
    }
    $find = { param($n) $all | Where-Object { $_.Name -eq $n -or $_.DisplayName -eq $n } | Select-Object -First 1 }
    $monitored = [System.Collections.Generic.List[object]]::new()
    $add = { param($svc) if ($svc -and -not ($monitored | Where-Object Name -eq $svc.Name)) { $monitored.Add($svc) } }

    foreach ($name in @($Services | Where-Object { $_ })) {
        $svc = & $find $name
        if ($svc) { & $add $svc } else { Add-HCCheck $Context "Service $name" 'Warning' 'Not installed' }
    }
    foreach ($name in @($OptionalServices | Where-Object { $_ })) { & $add (& $find $name) }
    foreach ($pattern in @($ServicePatterns | Where-Object { $_ })) {
        foreach ($svc in $all) {
            if (($svc.Name -like $pattern -or $svc.DisplayName -like $pattern) -and $svc.StartMode -eq 'Auto') { & $add $svc }
        }
    }
    $checked = @($monitored | Where-Object { -not (Test-HCIgnored -Value @($_.Name, $_.DisplayName) -Pattern $ExcludeServices) })
    if ($checked.Count -eq 0) {
        if ($ServicePatterns) { Add-HCCheck $Context 'Services' 'Warning' ('No automatic services match ' + ($ServicePatterns -join ', ')) }
        return
    }
    $stopped = @($checked | Where-Object State -ne 'Running')
    foreach ($svc in $stopped) {
        Add-HCCheck $Context "Service $($svc.DisplayName)" 'Critical' ('{0} (start mode {1})' -f $svc.State, $svc.StartMode)
    }
    if ($stopped.Count -eq 0) {
        Add-HCCheck $Context 'Services' 'OK' ('All {0} monitored services running' -f $checked.Count)
    }
}

function Test-HCWindowsDisks {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$CimSession, [hashtable]$Thresholds, [int]$TimeoutSec = 30)
    try {
        $disks = @(Get-CimInstance -CimSession $CimSession -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -Property DeviceID, Size, FreeSpace -OperationTimeoutSec $TimeoutSec -ErrorAction Stop)
    } catch {
        Add-HCCheck $Context 'Disk space' 'Unknown' "Cannot read disks: $(Get-HCErrorText $_)"
        return
    }
    $fine = @()
    foreach ($d in $disks) {
        if (-not $d.Size) { continue }
        $freePct = [math]::Round(100 * $d.FreeSpace / $d.Size, 1)
        $status = if ($freePct -le $Thresholds.DiskFreeCriticalPct) { 'Critical' } elseif ($freePct -le $Thresholds.DiskFreeWarningPct) { 'Warning' } else { 'OK' }
        if ($status -eq 'OK') {
            $fine += ('{0} {1}% free' -f $d.DeviceID, [math]::Round($freePct))
        } else {
            Add-HCCheck $Context "Disk $($d.DeviceID)" $status ('{0}% free ({1} of {2})' -f $freePct, (Format-HCBytes $d.FreeSpace), (Format-HCBytes $d.Size))
        }
    }
    if ($fine) { Add-HCCheck $Context 'Disk space' 'OK' ($fine -join ', ') }
}

function Test-HCWindowsActivation {
    # Windows licensing: activation state, channel (KMS/MAK/...) and expiry where one exists.
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$CimSession, [hashtable]$Thresholds, [int]$TimeoutSec = 60)
    try {
        $filter = "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
        $products = @(Get-CimInstance -CimSession $CimSession -ClassName SoftwareLicensingProduct -Filter $filter `
                -Property Name, Description, LicenseStatus, GracePeriodRemaining -OperationTimeoutSec ([math]::Max($TimeoutSec, 90)) -ErrorAction Stop)
    } catch {
        Add-HCCheck $Context 'Windows activation' 'Unknown' "Cannot read licensing status: $(Get-HCErrorText $_)"
        return
    }
    if ($products.Count -eq 0) {
        $null = Add-HCLicense -Context $Context -Name 'Windows activation' -Status 'Critical' -StatusText 'No product key installed' -Source 'Device' -Thresholds $Thresholds
        return
    }
    $p = $products | Sort-Object { if ($_.LicenseStatus -eq 1) { 0 } else { 1 } } | Select-Object -First 1
    $states = @{
        0 = @('Unlicensed', 'Critical'); 1 = @('Licensed', 'OK'); 2 = @('Initial grace period', 'Warning')
        3 = @('Out-of-tolerance grace', 'Warning'); 4 = @('Non-genuine grace', 'Critical'); 5 = @('Notification mode', 'Critical')
        6 = @('Extended grace', 'Warning')
    }
    $state = if ($states.ContainsKey([int]$p.LicenseStatus)) { $states[[int]$p.LicenseStatus] } else { @("Status $($p.LicenseStatus)", 'Warning') }
    $channel = switch -Regex ($p.Description) {
        'KMSCLIENT' { 'KMS client'; break }
        'VIRTUAL_MACHINE_ACTIVATION' { 'AVMA'; break }
        'MAK' { 'MAK'; break }
        'TIMEBASED_EVAL' { 'Evaluation'; break }
        'OEM' { 'OEM'; break }
        'RETAIL' { 'Retail'; break }
        default { '' }
    }
    $expires = $null
    if ([int]$p.GracePeriodRemaining -gt 0) { $expires = (Get-Date).AddMinutes([int]$p.GracePeriodRemaining) }
    $status = $state[1]
    $note = $p.Name
    $licenseParams = @{}
    if ($channel -in 'KMS client', 'AVMA' -and $p.LicenseStatus -eq 1) {
        # Renewed automatically every 7 days; only the renewal itself needs watching.
        $note = 'renews automatically (180-day validity)'
        $days = Get-HCDaysLeft $expires
        if ($null -ne $days -and $days -lt $Thresholds.KmsRenewalWarningDays) {
            $status = 'Warning'
            $licenseParams.Issue = "'Windows activation': $channel activation has not renewed (expires in $days days) - check KMS host reachability"
        }
    }
    $label = if ($channel) { "$($state[0]) ($channel)" } else { $state[0] }
    $null = Add-HCLicense -Context $Context -Name 'Windows activation' -Status $status -StatusText $label -Expires $expires `
        -Source 'Device' -Note $note -Thresholds $Thresholds @licenseParams
}

function Get-HCWindowsStoreCertificates {
    <#
      Reads Cert:\LocalMachine\My on a remote server via PowerShell remoting and records every certificate
      that has a private key (the server's own identities) with its friendly name and template.
      Expired certificates that were already renewed (newer cert, same subject and template) are shown as
      Info so old leftovers do not raise alarms every morning.
    #>
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$ComputerName,
        [pscredential]$Credential,
        [Parameter(Mandatory)][hashtable]$Settings,
        [object[]]$Ignore,
        [switch]$IncludeWithoutPrivateKey
    )
    $scriptBlock = {
        Get-ChildItem -Path 'Cert:\LocalMachine\My' | ForEach-Object {
            $template = ''
            foreach ($ext in $_.Extensions) {
                if ($ext.Oid.Value -in '1.3.6.1.4.1.311.21.7', '1.3.6.1.4.1.311.20.2') { $template = $ext.Format($false) }
            }
            [pscustomobject]@{
                RawData       = [Convert]::ToBase64String($_.RawData)
                FriendlyName  = $_.FriendlyName
                HasPrivateKey = $_.HasPrivateKey
                Template      = $template
            }
        }
    }
    $params = @{ ComputerName = $ComputerName; ScriptBlock = $scriptBlock; ErrorAction = 'Stop' }
    try { $params.SessionOption = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 120000 } catch { Write-Verbose 'WinRM session timeouts not supported here' }
    if ($Credential) { $params.Credential = $Credential }
    try {
        $items = @(Invoke-Command @params)
    } catch {
        Add-HCCheck $Context 'Certificate store' 'Unknown' "Cannot read LocalMachine\My via WinRM: $(Get-HCErrorText $_)"
        return
    }
    $certs = foreach ($item in $items) {
        if (-not $IncludeWithoutPrivateKey -and -not $item.HasPrivateKey) { continue }
        $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($item.RawData))
        $template = [string]$item.Template
        if ($template -match 'Template=(?<name>[^(,]+)') { $template = $Matches.name.Trim() }
        [pscustomobject]@{ X509 = $x509; FriendlyName = $item.FriendlyName; Template = $template }
    }
    $warnDays = $Settings.Thresholds.CertWarningDays
    foreach ($c in $certs) {
        $force = ''
        $note = ''
        $days = Get-HCDaysLeft $c.X509.NotAfter
        if ($days -le $warnDays) {
            $cn = $c.X509.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            $renewed = $certs | Where-Object {
                $_.X509.Thumbprint -ne $c.X509.Thumbprint -and $_.Template -eq $c.Template -and
                $_.X509.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq $cn -and
                (Get-HCDaysLeft $_.X509.NotAfter) -gt $warnDays
            } | Select-Object -First 1
            if ($renewed) {
                $force = 'Info'
                $note = "superseded by renewed certificate $($renewed.X509.Thumbprint.Substring(0, 8))... - safe to delete"
            }
        }
        $null = Add-HCCertificate -Context $Context -Source 'LocalMachine\My' -Certificate $c.X509 -FriendlyName $c.FriendlyName `
            -Template $c.Template -Note $note -ForceStatus $force -Thresholds $Settings.Thresholds -Ignore $Ignore
    }
    if (@($certs).Count -eq 0) { Add-HCCheck $Context 'Certificate store' 'Info' 'No certificates with a private key in LocalMachine\My' }
}

function Invoke-HCWindowsChecks {
    <#
      Runs the selected Windows checks against $Target.Address. $Credential may be $null to use the
      identity of the scheduled task (recommended for domain-joined servers: Kerberos, no stored password).
    #>
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][hashtable]$Target,
        [pscredential]$Credential,
        [Parameter(Mandatory)][hashtable]$Settings,
        [string[]]$Services,
        [string[]]$OptionalServices,
        [string[]]$ServicePatterns,
        [switch]$Disks,
        [switch]$Activation,
        [switch]$CertificateStore
    )
    $computer = $Target.Address
    $timeout = [math]::Max($Settings.TimeoutSec, 30)
    $cim = $null
    try {
        $cim = New-HCCimSession -ComputerName $computer -Credential $Credential -TimeoutSec $timeout
    } catch {
        Add-HCCheck $Context 'Windows management (CIM)' 'Unknown' "Cannot connect: $(Get-HCErrorText $_)"
    }
    if ($cim) {
        try {
            try {
                $os = Get-CimInstance -CimSession $cim -ClassName Win32_OperatingSystem -Property Caption, LastBootUpTime -OperationTimeoutSec $timeout -ErrorAction Stop
                Set-HCFact $Context 'OS' (Get-HCShortOsName $os.Caption)
                if ($os.LastBootUpTime) { Set-HCFact $Context 'Uptime' (Format-HCDuration ((Get-Date) - $os.LastBootUpTime)) }
            } catch {
                Add-HCLog $Context "Win32_OperatingSystem: $(Get-HCErrorText $_)"
            }
            if ($Services -or $OptionalServices -or $ServicePatterns) {
                Test-HCWindowsServices -Context $Context -CimSession $cim -Services $Services -OptionalServices $OptionalServices `
                    -ServicePatterns $ServicePatterns -ExcludeServices $Target.ExcludeServices -TimeoutSec $timeout
            }
            if ($Disks) { Test-HCWindowsDisks -Context $Context -CimSession $cim -Thresholds $Settings.Thresholds -TimeoutSec $timeout }
            if ($Activation) { Test-HCWindowsActivation -Context $Context -CimSession $cim -Thresholds $Settings.Thresholds -TimeoutSec $timeout }
        } finally {
            Remove-CimSession -CimSession $cim -ErrorAction SilentlyContinue
        }
    }
    if ($CertificateStore) {
        Get-HCWindowsStoreCertificates -Context $Context -ComputerName $computer -Credential $Credential -Settings $Settings `
            -Ignore $Target.IgnoreCertificates -IncludeWithoutPrivateKey:([bool]$Target.IncludeCertificatesWithoutPrivateKey)
    }
}
