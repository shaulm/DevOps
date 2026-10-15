# Generic targets, usable for anything not covered by a dedicated check.
#
# WebService    : URL check (status code, optional keyword, response time) + TLS certificate,
#                 optional Windows checks when the service runs on a Windows server you can reach via WinRM
# WindowsServer : services, disks, uptime, Windows activation and LocalMachine\My

function Invoke-HCCheckWebService {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $url = if ($Target.Url) { [string]$Target.Url } else { "https://$($Target.Address)/" }
    $uri = [uri]$url
    $ports = @(Get-HCOption $Target 'Ports' @($uri.Port))
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports $ports -HostName $uri.Host)) { return }
    if ($uri.Scheme -eq 'https') {
        $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -HostName $uri.Host -Port $uri.Port -Source "HTTPS :$($uri.Port)"
    }
    foreach ($extra in @(Get-HCOption $Target 'TlsPorts' @())) {
        if ($extra -ne $uri.Port) { $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $extra }
    }
    Invoke-HCWebCheck -Context $Context -Settings $Settings -Url $url -Name (Get-HCOption $Target 'WebCheckName' 'Console') `
        -ExpectedStatus (Get-HCOption $Target 'ExpectedStatus' @(200, 401, 403)) -Keyword $Target.Keyword `
        -SkipCertificateCheck:([bool](Get-HCOption $Target 'SkipCertificateCheck' $true))
    if ($Target.Windows) {
        $windowsCredential = Get-HCNamedCredential -Settings $Settings -Name $Target.WindowsCredential -Context $Context -Purpose 'Windows'
        Invoke-HCWindowsChecks -Context $Context -Target $Target -Credential $windowsCredential -Settings $Settings `
            -ServicePatterns $Target.ServicePatterns -Services $Target.Services -Disks -CertificateStore:([bool]$Target.CheckCertificateStore)
    }
}

function Invoke-HCCheckWindowsServer {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $ports = @(Get-HCOption $Target 'Ports' @(5985))
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports $ports)) { return }
    foreach ($p in @(Get-HCOption $Target 'TlsPorts' @())) {
        $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $p
    }
    Invoke-HCWindowsChecks -Context $Context -Target $Target -Credential $Credential -Settings $Settings `
        -Services $Target.Services -OptionalServices $Target.OptionalServices -ServicePatterns $Target.ServicePatterns `
        -Disks:($Target.CheckDisks -ne $false) -Activation:($Target.CheckActivation -ne $false) `
        -CertificateStore:($Target.CheckCertificateStore -ne $false)
}
