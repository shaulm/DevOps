# Portnox CORE (on-premises NAC).
#
# Functionality : web console, Portnox Windows services, disks, optional real RADIUS authentication test
# Certificates  : web console certificate + LocalMachine\My (includes the RADIUS/EAP server certificate)
# License       : the Portnox license expiry is listed under Licenses in the config.

function Invoke-HCCheckPortnox {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [pscredential]$Credential, [Parameter(Mandatory)][hashtable]$Settings)
    $consolePort = [int](Get-HCOption $Target 'ConsolePort' 443)
    $ports = @($consolePort) + @(Get-HCOption $Target 'Ports' @())
    if (-not (Invoke-HCReachability -Context $Context -Target $Target -Settings $Settings -Ports $ports)) { return }
    $null = Add-HCTlsCertificateCheck -Context $Context -Settings $Settings -Target $Target -Port $consolePort -Source "Web console :$consolePort"
    Invoke-HCWebCheck -Context $Context -Settings $Settings -Url (Get-HCOption $Target 'WebUrl' "https://$($Target.Address):$consolePort/") `
        -Name 'Portnox console' -ExpectedStatus (Get-HCOption $Target 'ExpectedStatus' @(200, 401, 403)) -Keyword $Target.Keyword -SkipCertificateCheck
    if ($Target.Radius) { Invoke-HCRadiusCheck -Context $Context -Target $Target -Settings $Settings }
    if ($Target.Windows -ne $false) {
        $windowsCredential = Get-HCNamedCredential -Settings $Settings -Name $Target.WindowsCredential -Context $Context -Purpose 'Windows'
        Invoke-HCWindowsChecks -Context $Context -Target $Target -Credential $windowsCredential -Settings $Settings `
            -ServicePatterns (Get-HCOption $Target 'ServicePatterns' @('*Portnox*')) -Services $Target.Services `
            -Disks -CertificateStore:($Target.CheckCertificateStore -ne $false)
    }
}
