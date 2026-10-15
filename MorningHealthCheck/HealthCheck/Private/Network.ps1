# Network helpers: ping, TCP ports, TLS certificate probe, HTTP/REST calls.

function Test-HCPing {
    param([Parameter(Mandatory)][string]$HostName, [int]$TimeoutMs = 1500, [int]$Count = 2)
    $ping = [System.Net.NetworkInformation.Ping]::new()
    $lastError = $null
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $reply = $ping.Send($HostName, $TimeoutMs)
                if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    return [pscustomobject]@{ Success = $true; RoundtripMs = $reply.RoundtripTime; Error = $null }
                }
                $lastError = $reply.Status.ToString()
            } catch {
                $lastError = Get-HCErrorText $_
            }
        }
        return [pscustomobject]@{ Success = $false; RoundtripMs = $null; Error = $lastError }
    } finally {
        $ping.Dispose()
    }
}

function Test-HCTcpPort {
    param([Parameter(Mandatory)][string]$HostName, [Parameter(Mandatory)][int]$Port, [int]$TimeoutMs = 3000)
    $client = [System.Net.Sockets.TcpClient]::new()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $task = $client.ConnectAsync($HostName, $Port)
        if (-not $task.Wait($TimeoutMs)) {
            return [pscustomobject]@{ Port = $Port; Open = $false; LatencyMs = $null; Error = 'timeout' }
        }
        return [pscustomobject]@{ Port = $Port; Open = $client.Connected; LatencyMs = $sw.ElapsedMilliseconds; Error = $null }
    } catch {
        return [pscustomobject]@{ Port = $Port; Open = $false; LatencyMs = $null; Error = (Get-HCErrorText $_) }
    } finally {
        $client.Dispose()
    }
}

function Invoke-HCProxyConnect {
    # Opens an HTTP CONNECT tunnel on an already connected stream (used for the SSL-inspection probe).
    param(
        [Parameter(Mandatory)][System.IO.Stream]$Stream,
        [Parameter(Mandatory)][string]$HostName,
        [int]$Port = 443,
        [pscredential]$Credential
    )
    $request = "CONNECT ${HostName}:$Port HTTP/1.1`r`nHost: ${HostName}:$Port`r`nUser-Agent: MorningHealthCheck`r`n"
    if ($Credential) {
        $pair = '{0}:{1}' -f $Credential.UserName, $Credential.GetNetworkCredential().Password
        $request += 'Proxy-Authorization: Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pair)) + "`r`n"
    }
    $request += "`r`n"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($request)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()

    $header = [System.Text.StringBuilder]::new()
    $buffer = [byte[]]::new(1)
    while ($true) {
        $read = $Stream.Read($buffer, 0, 1)
        if ($read -le 0) { throw 'proxy closed the connection during CONNECT' }
        [void]$header.Append([char]$buffer[0])
        if ($header.Length -ge 4 -and $header.ToString($header.Length - 4, 4) -eq "`r`n`r`n") { break }
        if ($header.Length -gt 16384) { throw 'proxy CONNECT response header too large' }
    }
    $statusLine = ($header.ToString() -split "`r`n")[0]
    if ($statusLine -notmatch '^HTTP/\d(\.\d)?\s+200\b') { throw "proxy refused CONNECT: $statusLine" }
}

function Get-HCTlsCertificate {
    <#
      Connects to host:port, performs a TLS handshake and returns the server certificate, the chain the
      client built (leaf first), whether the chain is trusted by this machine and whether the name matches.
      -ProxyHost tunnels through an HTTP proxy (CONNECT) to see the certificate a user behind the proxy gets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [int]$Port = 443,
        [string]$ServerName,
        [int]$TimeoutMs = 10000,
        [string]$ProxyHost,
        [int]$ProxyPort = 8080,
        [pscredential]$ProxyCredential
    )
    $sni = if ($ServerName) { $ServerName } else { $HostName }
    $attempts = @(
        [System.Security.Authentication.SslProtocols]::None,   # operating-system default (TLS 1.2 / 1.3)
        [System.Security.Authentication.SslProtocols]::Tls12,
        ([System.Security.Authentication.SslProtocols]::Tls11 -bor [System.Security.Authentication.SslProtocols]::Tls)   # legacy appliances
    )
    $lastError = 'no attempt made'
    foreach ($protocols in $attempts) {
        $state = @{ Chain = @(); Errors = [System.Net.Security.SslPolicyErrors]::None }
        $callback = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            $state.Errors = $sslPolicyErrors
            if ($null -ne $chain) {
                # Copy the elements: the chain object is disposed once the callback returns.
                $state.Chain = @(foreach ($element in $chain.ChainElements) {
                        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($element.Certificate.RawData)
                    })
            }
            return $true
        }.GetNewClosure()

        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ssl = $null
        try {
            $connectHost = if ($ProxyHost) { $ProxyHost } else { $HostName }
            $connectPort = if ($ProxyHost) { $ProxyPort } else { $Port }
            $connect = $tcp.ConnectAsync($connectHost, $connectPort)
            if (-not $connect.Wait($TimeoutMs)) { throw "TCP connect to ${connectHost}:$connectPort timed out" }
            $stream = $tcp.GetStream()
            $stream.ReadTimeout = $TimeoutMs
            $stream.WriteTimeout = $TimeoutMs
            if ($ProxyHost) { Invoke-HCProxyConnect -Stream $stream -HostName $HostName -Port $Port -Credential $ProxyCredential }
            $ssl = [System.Net.Security.SslStream]::new($stream, $false, [System.Net.Security.RemoteCertificateValidationCallback]$callback)
            $ssl.AuthenticateAsClient($sni, $null, $protocols, $false)
            $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate.GetRawCertData())
            $chainErrors = [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors
            $nameErrors = [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch
            return [pscustomobject]@{
                Certificate  = $leaf
                Chain        = @($state.Chain)
                PolicyErrors = $state.Errors
                Protocol     = $ssl.SslProtocol.ToString()
                Trusted      = -not ($state.Errors -band $chainErrors)
                NameMatch    = -not ($state.Errors -band $nameErrors)
            }
        } catch {
            $lastError = Get-HCErrorText $_
            # Network-level failures will not get better with another TLS version.
            if ($lastError -match 'timed out|refused|resolve|unreachable|proxy') { break }
        } finally {
            if ($ssl) { $ssl.Dispose() }
            $tcp.Dispose()
        }
    }
    throw "TLS handshake with ${HostName}:$Port failed: $lastError"
}

function ConvertFrom-HCPem {
    # Returns every certificate found in a PEM string (tolerates JSON-escaped "\n").
    param([string]$Pem)
    if (-not $Pem) { return }
    foreach ($m in [regex]::Matches($Pem, '-----BEGIN CERTIFICATE-----(?<b64>[\s\S]+?)-----END CERTIFICATE-----')) {
        $b64 = $m.Groups['b64'].Value -replace '\\[rn]', '' -replace '\s', ''
        try {
            [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64))
        } catch {
            Write-Verbose "Skipping unreadable PEM block: $($_.Exception.Message)"
        }
    }
}

function Invoke-HCRest {
    <#
      Thin wrapper around Invoke-RestMethod / Invoke-WebRequest with the options every check needs.
      The system proxy is bypassed (these are internal management interfaces).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')][string]$Method = 'GET',
        [hashtable]$Headers,
        $Body,
        [pscredential]$Credential,
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [int]$TimeoutSec = 30,
        [switch]$SkipCertificateCheck,
        [string]$ContentType = 'application/json',
        [switch]$Raw
    )
    $params = @{ Uri = $Uri; Method = $Method; TimeoutSec = $TimeoutSec; NoProxy = $true; ErrorAction = 'Stop' }
    if ($Headers) { $params.Headers = $Headers }
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $params.Body = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 10 -Compress }
        $params.ContentType = $ContentType
    }
    if ($Credential) { $params.Credential = $Credential; $params.Authentication = 'Basic' }
    if ($WebSession) { $params.WebSession = $WebSession }
    if ($SkipCertificateCheck) { $params.SkipCertificateCheck = $true }
    if ($Raw) { return Invoke-WebRequest @params }
    Invoke-RestMethod @params
}

function Invoke-HCReachability {
    <#
      Ping (optional) + TCP port checks. Returns $true when the host answers on anything, so the caller
      can skip slow API checks for a host that is down.
    #>
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][hashtable]$Target,
        [Parameter(Mandatory)][hashtable]$Settings,
        [int[]]$Ports,
        [string]$HostName
    )
    $addr = if ($HostName) { $HostName } else { $Target.Address }
    $pingResult = $null
    if ($Target.Ping -ne $false) {
        $pingResult = Test-HCPing -HostName $addr
        if ($pingResult.Success) { Add-HCCheck $Context 'Ping' 'OK' ('Reply in {0} ms' -f $pingResult.RoundtripMs) }
        else { Add-HCCheck $Context 'Ping' 'Warning' ('No reply' + $(if ($pingResult.Error) { " ($($pingResult.Error))" })) }
    }
    $open = @(); $closed = @()
    foreach ($port in @($Ports | Where-Object { $_ } | Select-Object -Unique)) {
        $r = Test-HCTcpPort -HostName $addr -Port $port -TimeoutMs $Settings.TcpTimeoutMs
        if ($r.Open) { $open += $port } else { $closed += "$port ($($r.Error))" }
    }
    if ($open.Count -or $closed.Count) {
        if ($closed.Count -eq 0) { Add-HCCheck $Context 'TCP ports' 'OK' ('Open: ' + ($open -join ', ')) }
        else { Add-HCCheck $Context 'TCP ports' 'Critical' ('Not reachable: ' + ($closed -join ', ')) }
    }
    $reachable = ($pingResult -and $pingResult.Success) -or $open.Count -gt 0 -or ($null -eq $pingResult -and $closed.Count -eq 0)
    foreach ($c in $Context.Checks) {
        if ($c.Name -ne 'Ping' -or $c.Status -eq 'OK') { continue }
        if (-not $reachable) {
            $c.Status = 'Critical'; $c.Message = 'Host unreachable (no ping reply and no open ports)'
        } elseif ($open.Count -gt 0) {
            # ICMP filtered by a firewall is common for appliances - not worth a daily warning.
            $c.Status = 'Info'; $c.Message = 'No ping reply, but the host answers on TCP (ICMP probably filtered)'
        }
    }
    if (-not $reachable) { Add-HCLog $Context "$addr is unreachable - skipping remaining checks" }
    return [bool]$reachable
}

function Add-HCTlsCertificateCheck {
    # Probes a TLS port and records the certificate it presents.
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][hashtable]$Settings,
        [hashtable]$Target = @{},
        [string]$HostName,
        [int]$Port = 443,
        [string]$Source,
        [string]$FriendlyName
    )
    $hostToProbe = if ($HostName) { $HostName } else { $Target.Address }
    $sni = if ($Target.TlsServerName) { $Target.TlsServerName } else { $hostToProbe }
    if (-not $Source) { $Source = "TLS :$Port" }
    try {
        $tls = Get-HCTlsCertificate -HostName $hostToProbe -Port $Port -ServerName $sni -TimeoutMs ($Settings.TimeoutSec * 1000)
        $notes = @()
        if (-not $tls.NameMatch) { $notes += "name does not match $sni" }
        if ($tls.Protocol -in 'Tls', 'Tls11', 'Ssl3') { $notes += "legacy protocol $($tls.Protocol)" }
        $null = Add-HCCertificate -Context $Context -Source $Source -Certificate $tls.Certificate -FriendlyName $FriendlyName `
            -Trusted $tls.Trusted -Note ($notes -join ', ') -Thresholds $Settings.Thresholds -Ignore $Target.IgnoreCertificates
        return $tls
    } catch {
        Add-HCCheck $Context "TLS certificate :$Port" 'Unknown' (Get-HCErrorText $_)
        return $null
    }
}

function Invoke-HCWebCheck {
    # GET a URL and verify status code, optional keyword and response time.
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][hashtable]$Settings,
        [string]$Name = 'Web console',
        [int[]]$ExpectedStatus = @(200, 401, 403),
        [string]$Keyword,
        [switch]$SkipCertificateCheck
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $p = @{
            Uri = $Url; TimeoutSec = $Settings.TimeoutSec; SkipHttpErrorCheck = $true; NoProxy = $true
            MaximumRedirection = 5; ErrorAction = 'Stop'
        }
        if ($SkipCertificateCheck) { $p.SkipCertificateCheck = $true }
        $resp = Invoke-WebRequest @p
        $ms = $sw.ElapsedMilliseconds
        $code = [int]$resp.StatusCode
        if ($code -notin $ExpectedStatus) {
            Add-HCCheck $Context $Name 'Critical' ('HTTP {0} from {1} (expected {2})' -f $code, $Url, ($ExpectedStatus -join '/'))
            return
        }
        if ($Keyword -and ([string]$resp.Content) -notmatch [regex]::Escape($Keyword)) {
            Add-HCCheck $Context $Name 'Warning' ("HTTP $code but the page does not contain '$Keyword'")
            return
        }
        $status = if ($ms -gt $Settings.Thresholds.HttpSlowMs) { 'Warning' } else { 'OK' }
        Add-HCCheck $Context $Name $status ('HTTP {0} in {1} ms' -f $code, $ms)
    } catch {
        Add-HCCheck $Context $Name 'Critical' ("$Url - $(Get-HCErrorText $_)")
    }
}
