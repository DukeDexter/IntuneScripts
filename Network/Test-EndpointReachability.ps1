
<# 

Author:  Duke Dexter (https://github.com/DukeDexter)

.SYNOPSIS
    Tests DNS resolution and network reachability for Microsoft/Intune/Windows Update endpoints.

.DESCRIPTION
    - DNS resolution (A/AAAA) via Resolve-DnsName
    - TCP port reachability via System.Net.Sockets.TcpClient with timeout
    - HTTPS HEAD with SNI via HttpClient (no cert validation)
    - UDP NTP (123) check for time.windows.com (best-effort)
    - Handles wildcard endpoints (*.domain.tld) with notes
    - Optional proxy support (-ProxyUrl)
    - CSV export (-OutputPath)
    - Clear results with StatusReason for troubleshooting

.EXAMPLE
    .\Test-EndpointReachability.ps1 -OutputPath .\endpoint_check.csv

.EXAMPLE
    .\Test-EndpointReachability.ps1 -ProxyUrl http://proxy.corp:8080 -TimeoutMs 3000

#>

[CmdletBinding()]
param(
    [int]$TimeoutMs = 5000,
    [string]$OutputPath,
    [string]$ProxyUrl
)

# ------------------------------
# Input: Endpoints to validate
# ------------------------------
$Endpoints = @(
    '*.manage.microsoft.com',
    'manage.microsoft.com',
    '*.dl.delivery.mp.microsoft.com',
    '*.do.dsp.mp.microsoft.com',
    '*.update.microsoft.com',
    '*.windowsupdate.com',
    'adl.windows.com',
    'dl.delivery.mp.microsoft.com',
    'tsfe.trafficshaping.dsp.mp.microsoft.com',
    'time.windows.com',
    '*.s-microsoft.com',
    'clientconfig.passport.net',
    'windowsphone.com',
    'approdimedatahotfix.azureedge.net',
    'approdimedatapri.azureedge.net',
    'approdimedatasec.azureedge.net',
    'euprodimedatahotfix.azureedge.net',
    'euprodimedatapri.azureedge.net',
    'euprodimedatasec.azureedge.net',
    'naprodimedatahotfix.azureedge.net',
    'naprodimedatapri.azureedge.net',
    'naprodimedatasec.azureedge.net',
    'swda01-mscdn.azureedge.net',
    'swda02-mscdn.azureedge.net',
    'swdb01-mscdn.azureedge.net',
    'swdb02-mscdn.azureedge.net',
    'swdc01-mscdn.azureedge.net',
    'swdc02-mscdn.azureedge.net',
    'swdd01-mscdn.azureedge.net',
    'swdd02-mscdn.azureedge.net',
    'swdin01-mscdn.azureedge.net',
    'swdin02-mscdn.azureedge.net',
    '*.notify.windows.com',
    '*.wns.windows.com',
    'ekcert.spserv.microsoft.com',
    'ekop.intel.com',
    'ftpm.amd.com',
    'intunecdnpeasd.azureedge.net',
    '*.monitor.azure.com',
    '*.support.services.microsoft.com',
    '*.trouter.communication.microsoft.com',
    '*.trouter.skype.com',
    '*.trouter.teams.microsoft.com',
    'api.flightproxy.skype.com',
    'ecs.communication.microsoft.com',
    'edge.microsoft.com',
    'edge.skype.com',
    'remoteassistanceprodacs.communication.azure.com',
    'remoteassistanceprodacseu.communication.azure.com',
    'remotehelp.microsoft.com',
    'wcpstatic.microsoft.com',
    'lgmsapeweu.blob.core.windows.net',
    'intunemaape1.eus.attest.azure.net',
    'intunemaape10.weu.attest.azure.net',
    'intunemaape11.weu.attest.azure.net',
    'intunemaape12.weu.attest.azure.net',
    'intunemaape13.jpe.attest.azure.net',
    'intunemaape17.jpe.attest.azure.net',
    'intunemaape18.jpe.attest.azure.net',
    'intunemaape19.jpe.attest.azure.net',
    'intunemaape2.eus2.attest.azure.net',
    'intunemaape3.cus.attest.azure.net',
    'intunemaape4.wus.attest.azure.net',
    'intunemaape5.scus.attest.azure.net',
    'intunemaape7.neu.attest.azure.net',
    'intunemaape8.neu.attest.azure.net',
    'intunemaape9.neu.attest.azure.net',
    '*.webpubsub.azure.com',
    '*.gov.teams.microsoft.us',
    'remoteassistanceweb.usgov.communication.azure.us',
    'config.edge.skype.com',
    'contentauthassetscdn-prod.azureedge.net',
    'contentauthassetscdn-prodeur.azureedge.net',
    'contentauthrafcontentcdn-prod.azureedge.net',
    'contentauthrafcontentcdn-prodeur.azureedge.net',
    'fd.api.orgmsg.microsoft.com',
    'ris.prod.api.personalization.ideas.microsoft.com'
)

# ------------------------------
# Port map (default 443, overrides below)
# ------------------------------
$PortMap = @{
    'time.windows.com' = @(123)        # UDP NTP
    'windowsupdate.com' = @(443,80)
    'update.microsoft.com' = @(443,80)
    'dl.delivery.mp.microsoft.com' = @(443,80)
}
$DefaultPorts = @(443)

# ------------------------------
# Utilities
# ------------------------------

function Test-Dns {
    param([string]$Host)
    $result = [ordered]@{
        Host             = $Host
        DnsResolvable    = $false
        IPs              = ''
        DnsReason        = ''
    }
    try {
        $dns = Resolve-DnsName -Name $Host -Type A,AAAA -ErrorAction Stop
        $ips = ($dns | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        if ($ips) {
            $result.DnsResolvable = $true
            $result.IPs = ($ips -join ',')
        } else {
            $result.DnsReason = 'No A/AAAA records'
        }
    } catch {
        $result.DnsReason = $_.Exception.Message
    }
    return $result
}

function Test-TcpPort {
    param(
        [string]$Host,
        [int]$Port,
        [int]$TimeoutMs
    )
    $tcpStatus = [ordered]@{
        PortReachable   = $false
        PortReason      = ''
        LatencyMs       = $null
    }
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($Host, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.Close()
            throw "Timeout after ${TimeoutMs}ms"
        }
        $client.EndConnect($async)
        $sw.Stop()
        $tcpStatus.PortReachable = $true
        $tcpStatus.LatencyMs = [int]$sw.Elapsed.TotalMilliseconds
        $client.Close()
    } catch {
        $tcpStatus.PortReason = $_.Exception.Message
    }
    return $tcpStatus
}

function Get-HttpClient {
    param([string]$ProxyUrl)
    $handler = New-Object System.Net.Http.HttpClientHandler
    # Do NOT validate server cert (reachability focus)
    $handler.ServerCertificateCustomValidationCallback = { param($req,$cert,$chain,$errors) return $true }
    if ($ProxyUrl) {
        $handler.UseProxy = $true
        $handler.Proxy = New-Object System.Net.WebProxy($ProxyUrl, $true)
    }
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMilliseconds(8000)
    return $client
}

$GlobalHttpClient = Get-HttpClient -ProxyUrl $ProxyUrl

function Test-HttpsHead {
    param(
        [string]$Host,
        [int]$TimeoutMs
    )
    $httpStatus = [ordered]@{
        HttpsHeadOk   = $false
        HttpCode      = ''
        HttpReason    = ''
    }
    try {
        $uri = [Uri]("https://$Host/")
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head, $uri)
        $cts = New-Object System.Threading.CancellationTokenSource($TimeoutMs)
        $resp = $GlobalHttpClient.SendAsync($req, $cts.Token).GetAwaiter().GetResult()
        $httpStatus.HttpCode = [int]$resp.StatusCode
        # Consider reachable if we got any HTTP response
        $httpStatus.HttpsHeadOk = $true
        $resp.Dispose()
    } catch {
        $httpStatus.HttpReason = $_.Exception.Message
    }
    return $httpStatus
}

function Test-NTP {
    param(
        [string]$Host,
        [int]$TimeoutMs = 4000
    )
    $ntpStatus = [ordered]@{
        NtpReachable = $false
        NtpReason    = ''
    }
    try {
        # Basic UDP 123 probe (best-effort; not a full NTP parse)
        $endpoint = New-Object System.Net.IPEndPoint ([System.Net.Dns]::GetHostAddresses($Host)[0]), 123
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($endpoint)
        # Minimal NTP request packet (48 bytes)
        $bytes = New-Object byte[] 48
        $bytes[0] = 0x1B # LI=0, VN=3, Mode=3 (client)
        [void]$udp.Send($bytes, $bytes.Length)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remote)
        if ($resp.Length -ge 48) {
            $ntpStatus.NtpReachable = $true
        } else {
            $ntpStatus.NtpReason = "Unexpected response length: $($resp.Length)"
        }
        $udp.Close()
    } catch {
        $ntpStatus.NtpReason = $_.Exception.Message
    }
    return $ntpStatus
}

function Expand-EndpointForWildcard {
    param([string]$Endpoint)
    $isWildcard = $Endpoint.StartsWith('*.')
    if ($isWildcard) {
        $suffix = $Endpoint.Substring(2)
        # For wildcard suffixes, test the suffix note + try apex if sensible
        # Many CDNs/service endpoints use FQDNs only; apex may not respond to HTTPS.
        return [PSCustomObject]@{
            DisplayHost = $Endpoint
            HostToTest  = $suffix     # attempt apex; may fail on purpose but gives data
            IsWildcard  = $true
        }
    } else {
        return [PSCustomObject]@{
            DisplayHost = $Endpoint
            HostToTest  = $Endpoint
            IsWildcard  = $false
        }
    }
}

# ------------------------------
# Main execution
# ------------------------------
$results = New-Object System.Collections.Generic.List[object]

foreach ($ep in $Endpoints) {
    $expanded = Expand-EndpointForWildcard -Endpoint $ep
    $host = $expanded.HostToTest
    $isWildcard = $expanded.IsWildcard

    $dns = Test-Dns -Host $host

    # Decide ports
    $ports = $DefaultPorts
    foreach ($key in $PortMap.Keys) {
        if ($host -like "*$key") {
            $ports = $PortMap[$key]
            break
        }
    }

    # Special NTP case (time.windows.com)
    $ntp = $null
    if ($host -eq 'time.windows.com') {
        $ntp = Test-NTP -Host $host
    }

    # TCP + HTTPS (only if TCP 443 reachable or if port list includes 80/443)
    $portChecks = @()
    foreach ($p in $ports) {
        $tcp = Test-TcpPort -Host $host -Port $p -TimeoutMs $TimeoutMs
        $http = $null
        if ($p -eq 443) {
            $http = Test-HttpsHead -Host $host -TimeoutMs $TimeoutMs
        } elseif ($p -eq 80) {
            # Try HTTP HEAD over port 80
            try {
                $uri = [Uri]("http://$host/")
                $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head, $uri)
                $cts = New-Object System.Threading.CancellationTokenSource($TimeoutMs)
                $resp = $GlobalHttpClient.SendAsync($req, $cts.Token).GetAwaiter().GetResult()
                $http = [ordered]@{
                    HttpsHeadOk = $true  # Reuse field; indicates HTTP HEAD succeeded
                    HttpCode    = [int]$resp.StatusCode
                    HttpReason  = ''
                }
                $resp.Dispose()
            } catch {
                $http = [ordered]@{
                    HttpsHeadOk = $false
                    HttpCode    = ''
                    HttpReason  = $_.Exception.Message
                }
            }
        }

        $portChecks += [PSCustomObject]@{
            Port          = $p
            PortReachable = $tcp.PortReachable
            LatencyMs     = $tcp.LatencyMs
            PortReason    = $tcp.PortReason
            HttpOk        = if ($http) { $http.HttpsHeadOk } else { $false }
            HttpCode      = if ($http) { $http.HttpCode } else { $null }
            HttpReason    = if ($http) { $http.HttpReason } else { '' }
        }
    }

    # Aggregate status
    $anyPortOk = ($portChecks | Where-Object { $_.PortReachable -eq $true }).Count -gt 0
    $anyHttpOk = ($portChecks | Where-Object { $_.HttpOk -eq $true }).Count -gt 0

    $statusReason = @()
    if (-not $dns.DnsResolvable) { $statusReason += "DNS failed: $($dns.DnsReason)" }
    if (-not $anyPortOk) { $statusReason += "TCP not reachable on tested ports" }
    if ($anyPortOk -and -not $anyHttpOk) { $statusReason += "HTTP/HTTPS HEAD failed" }
    if ($isWildcard) { $statusReason += "Wildcard suffix—apex tested; add specific subdomains for precise validation" }
    if ($ntp) {
        if (-not $ntp.NtpReachable) { $statusReason += "NTP UDP/123 check failed: $($ntp.NtpReason)" }
    }

    $results.Add([PSCustomObject]@{
        Endpoint          = $expanded.DisplayHost
        HostTested        = $host
        IsWildcard        = $isWildcard
        DnsResolvable     = $dns.DnsResolvable
        ResolvedIPs       = $dns.IPs
        PortsTested       = ($ports -join ',')
        TcpReachableAny   = $anyPortOk
        HttpHeadOkAny     = $anyHttpOk
        NtpReachable      = if ($ntp) { $ntp.NtpReachable } else { $null }
        StatusReason      = ($statusReason -join ' | ')
        PortDetails       = ($portChecks | ConvertTo-Json -Depth 4)
        TimestampUtc      = (Get-Date).ToUniversalTime().ToString('u')
        ProxyUsed         = [string]::IsNullOrWhiteSpace($ProxyUrl) -eq $false
        ProxyUrl          = $ProxyUrl
    })
}

# Output
$results | Format-Table -AutoSize

if ($OutputPath) {
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "CSV exported to $OutputPath" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export CSV: $($_.Exception.Message)"
    }
}

# Return objects for pipelines
$results
