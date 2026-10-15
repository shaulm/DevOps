# Minimal RADIUS (RFC 2865) Access-Request probe.
# Any valid answer (Accept, Reject or Challenge) proves the RADIUS service is up and that the shared
# secret is right. The monitoring server must be defined as a RADIUS client on the server being tested.

function Add-HCRadiusAttribute {
    param([System.Collections.Generic.List[byte]]$Buffer, [byte]$Type, [byte[]]$Value)
    if ($Value.Length -gt 253) { throw "RADIUS attribute $Type is too long" }
    $Buffer.Add($Type)
    $Buffer.Add([byte]($Value.Length + 2))
    $Buffer.AddRange($Value)
}

function Test-HCRadius {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [int]$Port = 1812,
        [Parameter(Mandatory)][string]$SharedSecret,
        [Parameter(Mandatory)][string]$UserName,
        [string]$Password = '',
        [string]$NasIdentifier = 'MorningHealthCheck',
        [int]$TimeoutMs = 5000
    )
    $secret = [System.Text.Encoding]::UTF8.GetBytes($SharedSecret)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $requestAuthenticator = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
    $id = [byte](Get-Random -Minimum 0 -Maximum 256)

    # User-Password hiding (RFC 2865 section 5.2)
    $pwBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $padLength = [math]::Max(16, [int]([math]::Ceiling($pwBytes.Length / 16.0) * 16))
    $padded = [byte[]]::new($padLength)
    [Array]::Copy($pwBytes, $padded, $pwBytes.Length)
    $hidden = [byte[]]::new($padLength)
    $previous = $requestAuthenticator
    for ($i = 0; $i -lt $padLength; $i += 16) {
        $hash = $md5.ComputeHash([byte[]]($secret + $previous))
        for ($j = 0; $j -lt 16; $j++) { $hidden[$i + $j] = $padded[$i + $j] -bxor $hash[$j] }
        $previous = [byte[]]$hidden[$i..($i + 15)]
    }

    $attributes = [System.Collections.Generic.List[byte]]::new()
    Add-HCRadiusAttribute -Buffer $attributes -Type 80 -Value ([byte[]]::new(16))       # Message-Authenticator (filled below)
    Add-HCRadiusAttribute -Buffer $attributes -Type 1 -Value ([System.Text.Encoding]::UTF8.GetBytes($UserName))
    Add-HCRadiusAttribute -Buffer $attributes -Type 2 -Value $hidden
    Add-HCRadiusAttribute -Buffer $attributes -Type 32 -Value ([System.Text.Encoding]::UTF8.GetBytes($NasIdentifier))
    Add-HCRadiusAttribute -Buffer $attributes -Type 61 -Value ([byte[]](0, 0, 0, 5))        # NAS-Port-Type = Virtual

    $attrBytes = $attributes.ToArray()
    $length = 20 + $attrBytes.Length
    $packet = [byte[]]::new($length)
    $packet[0] = 1                                   # Access-Request
    $packet[1] = $id
    $packet[2] = [byte](($length -shr 8) -band 0xFF)
    $packet[3] = [byte]($length -band 0xFF)
    [Array]::Copy($requestAuthenticator, 0, $packet, 4, 16)
    [Array]::Copy($attrBytes, 0, $packet, 20, $attrBytes.Length)
    $hmac = [System.Security.Cryptography.HMACMD5]::new($secret)
    $messageAuthenticator = $hmac.ComputeHash($packet)
    [Array]::Copy($messageAuthenticator, 0, $packet, 22, 16)   # value of the first attribute

    $udp = [System.Net.Sockets.UdpClient]::new()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($Server, $Port)
        [void]$udp.Send($packet, $packet.Length)
        $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $response = $udp.Receive([ref]$remote)
    } catch {
        $text = Get-HCErrorText $_
        if ($text -match 'timed out|did not properly respond') { $text = "no answer within $TimeoutMs ms" }
        return [pscustomobject]@{ Responded = $false; Code = $null; CodeName = $null; AuthenticatorValid = $false; LatencyMs = $null; ReplyMessage = $null; Error = $text }
    } finally {
        $udp.Dispose()
        $hmac.Dispose()
    }
    $latency = $sw.ElapsedMilliseconds

    $codeNames = @{ 2 = 'Access-Accept'; 3 = 'Access-Reject'; 11 = 'Access-Challenge' }
    $code = [int]$response[0]
    $valid = $false
    $reply = $null
    if ($response.Length -ge 20 -and $response[1] -eq $id) {
        $check = [byte[]]::new($response.Length)
        [Array]::Copy($response, $check, $response.Length)
        [Array]::Copy($requestAuthenticator, 0, $check, 4, 16)
        $expected = $md5.ComputeHash([byte[]]($check + $secret))
        $valid = ([Convert]::ToBase64String($expected) -eq [Convert]::ToBase64String([byte[]]$response[4..19]))
        # Reply-Message (18), informational only
        $pos = 20
        while ($pos + 2 -le $response.Length) {
            $type = $response[$pos]; $len = $response[$pos + 1]
            if ($len -lt 2 -or $pos + $len -gt $response.Length) { break }
            if ($type -eq 18 -and $len -gt 2) { $reply = [System.Text.Encoding]::UTF8.GetString($response, $pos + 2, $len - 2) }
            $pos += $len
        }
    }
    $md5.Dispose()
    [pscustomobject]@{
        Responded          = $true
        Code               = $code
        CodeName           = $(if ($codeNames.ContainsKey($code)) { $codeNames[$code] } else { "code $code" })
        AuthenticatorValid = $valid
        LatencyMs          = $latency
        ReplyMessage       = $reply
        Error              = $null
    }
}

function Invoke-HCRadiusCheck {
    <#
      Config (inside a target):
        Radius = @{
            SecretCredential = 'portnox-radius-secret'   # stored credential; its password is the shared secret
            Credential       = 'portnox-radius-user'     # optional test user; without it a random user is sent
            Port             = 1812
            ExpectAccept     = $false                    # $true when Credential is a real account that must be accepted
            Servers          = @('10.0.0.21')            # optional, defaults to the target address
        }
    #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Target, [Parameter(Mandatory)][hashtable]$Settings)
    $radius = $Target.Radius
    if (-not $radius) { return }
    $secretCred = Get-HCNamedCredential -Settings $Settings -Name $radius.SecretCredential -Context $Context -Purpose 'RADIUS shared secret'
    if (-not $secretCred) {
        if (-not $radius.SecretCredential) { Add-HCCheck $Context 'RADIUS' 'Unknown' 'Radius.SecretCredential is not set in the config' }
        return
    }
    $userCred = Get-HCNamedCredential -Settings $Settings -Name $radius.Credential -Context $Context -Purpose 'RADIUS test user'
    $user = if ($userCred) { $userCred.UserName } else { 'healthcheck-probe' }
    $pass = if ($userCred) { $userCred.GetNetworkCredential().Password } else { [guid]::NewGuid().ToString('N') }
    $port = [int](Get-HCOption $radius 'Port' 1812)
    foreach ($server in @(Get-HCOption $radius 'Servers' @($Target.Address))) {
        $name = "RADIUS ${server}:$port"
        $r = Test-HCRadius -Server $server -Port $port -SharedSecret $secretCred.GetNetworkCredential().Password `
            -UserName $user -Password $pass -NasIdentifier (Get-HCOption $radius 'NasIdentifier' 'MorningHealthCheck') -TimeoutMs 5000
        if (-not $r.Responded) {
            Add-HCCheck $Context $name 'Critical' "$($r.Error) - service down, UDP $port blocked, this server not defined as a RADIUS client, or wrong shared secret (servers silently drop those)"
        } elseif (-not $r.AuthenticatorValid) {
            Add-HCCheck $Context $name 'Warning' "$($r.CodeName) with an invalid response authenticator - shared secret mismatch?"
        } elseif ($radius.ExpectAccept -and $r.Code -ne 2) {
            Add-HCCheck $Context $name 'Critical' ("Test user was not accepted: {0}{1}" -f $r.CodeName, $(if ($r.ReplyMessage) { " ($($r.ReplyMessage))" }))
        } else {
            Add-HCCheck $Context $name 'OK' ('{0} in {1} ms' -f $r.CodeName, $r.LatencyMs)
        }
    }
}
