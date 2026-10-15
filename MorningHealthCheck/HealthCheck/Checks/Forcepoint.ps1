# Forcepoint Web Security (on-premises).
#
# ForcepointProxy (Content Gateway)
#   Functionality : proxy port, real browsing test THROUGH the proxy, optional "is a blocked URL really
#                   blocked" test, optional SSL-inspection test
#   Certificates  : Content Gateway Manager (8081) + the SSL-inspection CA users actually receive
# ForcepointManager (Forcepoint Security Manager, Windows)
#   Functionality : web console, Websense/Forcepoint Windows services, disks
#   Certificates  : console certificate (9443) + optional LocalMachine\My
# License           : the subscription key expiry is not exposed by an API -> list it under Licenses in the config.

function Test-HCThroughProxy {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$ProxyUri,
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][hashtable]$Settings,
        [pscredential]$ProxyCredential,
        [switch]$UseDefaultCredentials,
        [switch]$SkipCertificateCheck
    )
    $name = 'Browse via proxy: ' + ([uri]$Url).Host
    $p = @{ Uri = $Url; Proxy = $ProxyUri; TimeoutSec = $Settings.TimeoutSec; SkipHttpErrorCheck = $true; MaximumRedirection = 3; ErrorAction = 'Stop' }
    if ($ProxyCredential) { $p.ProxyCredential = $ProxyCredential } elseif ($UseDefaultCredentials) { $p.ProxyUseDefaultCredentials = $true }
    if ($SkipCertificateCheck) { $p.SkipCertificateCheck = $true }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = Invoke-WebRequest @p
        $ms = $sw.ElapsedMilliseconds
        $code = [int]$r.StatusCode
        if ($code -in 200, 204) {
            $status = if ($ms -gt $Settings.Thresholds.HttpSlowMs) { 'Warning' } else { 'OK' }
            Add-HCCheck $Context $name $status ('HTTP {0} in {1} ms' -f $code, $ms)
        } elseif ($code -eq 407) {
            Add-HCCheck $Context $name 'Warning' 'HTTP 407 proxy authentication required - set UseDefaultCredentials or a Credential for this target'
        } else {
            Add-HCCheck $Context $name 'Critical' "HTTP $code for an allowed test URL"
        }
    } catch {
        Add-HCCheck $Context $name 'Critical' (Get-HCErrorText $_)
    }
}

function Test-HCProxyBlock {
    # The block-test URL must NOT be delivered: a 403, a block page (keyword) or a refused CONNECT is a pass.
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$ProxyUri,
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][hashtable]$Settings,
        [string]$Keyword,
        [pscredential]$ProxyCredential,
        [switch]$UseDefaultCredentials
    )
    $p = @{ Uri = $Url; Proxy = $ProxyUri; TimeoutSec = $Settings.TimeoutSec; SkipHttpErrorCheck = $true; SkipCertificateCheck = $true; ErrorAction = 'Stop' }
    if ($ProxyCredential) { $p.ProxyCredential = $ProxyCredential } elseif ($UseDefaultCredentials) { $p.ProxyUseDefaultCredentials = $true }
    try {
        $r = Invoke-WebRequest @p
        $code = [int]$r.StatusCode
        $content = [string]$r.Content
        if ($code -in 403, 451 -or ($Keyword -and $content -match [regex]::Escape($Keyword))) {
            Add-HCCheck $Context 'Filtering enforcement' 'OK' "Test URL blocked as expected (HTTP $code)"
        } elseif ($code -eq 407) {
            Add-HCCheck $Context 'Filtering enforcement' 'Unknown' 'HTTP 407 proxy authentication required for the block test'
        } else {
            Add-HCCheck $Context 'Filtering enforcement' 'Critical' "Test URL $Url was NOT blocked (HTTP $code)"
        }
    } catch {
        $text = Get-HCErrorText $_
        if ($text -match '\b403\b|Forbidden') { Add-HCCheck $Context 'Filtering enforcement' 'OK' 'Test URL blocked as expected (CONNECT refused)' }
        else { Add-HCCheck $Context 'Filtering enforcement' 'Unknown' "Block test failed: $text" }
    }
}

function Test-HCSslInspection {
    # Opens a TLS session to a public site through the proxy and records which CA re-signed it.
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [Parameter(Mandatory)][hashtable]$Settings, [int]$ProxyPort, [pscredential]$ProxyCredential)
    $testHost = $Target.SslInspectionTestHost
    try {
        $tls = Get-HCTlsCertificate -HostName $testHost -Port 443 -ProxyHost $Target.Address -ProxyPort $ProxyPort -ProxyCredential $ProxyCredential -TimeoutMs ($Settings.TimeoutSec * 1000)
    } catch {
        Add-HCCheck $Context 'SSL inspection' 'Unknown' (Get-HCErrorText $_)
        return
    }
    $issuer = Get-HCDistinguishedNameCN $tls.Certificate.Issuer
    $expected = $Target.SslInspectionCAName
    if ($expected -and $tls.Certificate.Issuer -notlike "*$expected*") {
        Add-HCCheck $Context 'SSL inspection' 'Warning' "$testHost is not being inspected (issued by '$issuer', expected '$expected')"
        return
    }
    Add-HCCheck $Context 'SSL inspection' 'OK' "$testHost re-signed by '$issuer'"
    $ca = @($tls.Chain) | Select-Object -Skip 1 | Select-Object -First 1
    if ($ca) {
        $null = Add-HCCertificate -Context $Context -Source "SSL inspection CA (via proxy)" -Certificate $ca -FriendlyName 'SSL inspection CA' `
            -Thresholds $Settings.Thresholds -Ignore $Target.IgnoreCertificates
    } else {
        Add-HCCheck $Context 'SSL inspection CA' 'Info' "The proxy did not send its CA certificate and '$issuer' is not in this server's store - expiry not visible"
    }
}

function Invoke-HCCheckForcepointProxy {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $proxyPort = [int](Get-HCOption $Target 'ProxyPort' 8080)
    $managerPort = [int](Get-HCOption $Target 'ManagerPort' 8081)
    $ports = @($proxyPort) + @(Get-HCOption $Target 'Ports' @()) + @($(if ($managerPort) { $managerPort }))
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports $ports)) { return }
    if ($managerPort) {
        $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $managerPort -Source "Content Gateway Manager :$managerPort"
    }
    $proxyUri = "http://$($Target.Address):$proxyPort"
    $useDefault = [bool]$Target.UseDefaultCredentials
    foreach ($url in @(Get-HCOption $Target 'TestUrls' @('https://www.google.com/generate_204', 'http://www.msftconnecttest.com/connecttest.txt'))) {
        Test-HCThroughProxy -Context $Context -ProxyUri $proxyUri -Url $url -Settings $Settings -ProxyCredential $Credential `
            -UseDefaultCredentials:$useDefault -SkipCertificateCheck:([bool]$Target.SkipCertificateCheckThroughProxy)
    }
    if ($Target.BlockTestUrl) {
        Test-HCProxyBlock -Context $Context -ProxyUri $proxyUri -Url $Target.BlockTestUrl -Settings $Settings -Keyword $Target.BlockPageKeyword `
            -ProxyCredential $Credential -UseDefaultCredentials:$useDefault
    }
    if ($Target.SslInspectionTestHost) {
        Test-HCSslInspection -Context $Context -Target $Target -Settings $Settings -ProxyPort $proxyPort -ProxyCredential $Credential
    }
}

function Invoke-HCCheckForcepointManager {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $consolePort = [int](Get-HCOption $Target 'ConsolePort' 9443)
    $ports = @($consolePort) + @(Get-HCOption $Target 'Ports' @())
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports $ports)) { return }
    $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $consolePort -Source "Security Manager :$consolePort"
    Invoke-HCWebCheck -Context $Context -Settings $Settings -Url (Get-HCOption $Target 'WebUrl' "https://$($Target.Address):$consolePort/") `
        -Name 'Security Manager console' -ExpectedStatus (Get-HCOption $Target 'ExpectedStatus' @(200, 401, 403)) -Keyword $Target.Keyword -SkipCertificateCheck
    if ($Target.Windows -ne $false) {
        $windowsCredential = Get-HCNamedCredential -Settings $Settings -Name $Target.WindowsCredential -Context $Context -Purpose 'Windows'
        Invoke-HCWindowsChecks -Context $Context -Target $Target -Credential $windowsCredential -Settings $Settings `
            -ServicePatterns (Get-HCOption $Target 'ServicePatterns' @('Websense*', 'Forcepoint*', 'TRITON*')) -Services $Target.Services `
            -Disks -CertificateStore:([bool]$Target.CheckCertificateStore)
    }
}
