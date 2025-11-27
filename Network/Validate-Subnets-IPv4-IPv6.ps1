
<# 

Author: Duke Dexter (https://github.com/DukeDexter)

.SYNOPSIS
    Validate IPv4 & IPv6 subnets: CIDR parsing, full-range scan (safe-guarded), reachability checks (ICMP + TCP).

.DESCRIPTION
    - Parses IPv4/IPv6 CIDR (no external modules).
    - Computes network & range using BigInteger.
    - Supports full-range scan (bounded by MaxScanAddresses) and sampling.
    - Tests ICMP ping and TCP port (defaults to 443).
    - Parallel scanning on PowerShell 7+, sequential fallback on PS 5.1.
    - Exports summary and/or detailed CSVs.

Defaults: Full scan is performed only when the number of addresses in the subnet is ≤ -MaxScanAddresses (default 256). Otherwise the script samples addresses evenly across the range (default 32). You can override this behavior.

.PARAMETER Subnets
    CIDR subnets (IPv4 or IPv6).

.PARAMETER TestPort
    TCP port to validate connectivity (default 443).

.PARAMETER ScanMode
    'Full' or 'Sample'. 
    - 'Full' scans every address up to MaxScanAddresses; if larger, samples.
    - 'Sample' always samples.

.PARAMETER MaxScanAddresses
    Upper bound for full scan size (default 256). If subnet size exceeds this, sampling is used.

.PARAMETER SampleCount
    Count of addresses to sample when full scan is not feasible (default 32).

.PARAMETER TimeoutMs
    Timeout for TCP connect and ICMP (per address) (default 3000 ms).

.PARAMETER Throttle
    Parallel throttle limit on PS 7 (default 64). Ignored on PS 5.1.

.PARAMETER OutputPathDetailed
    CSV file for per-address results.

.PARAMETER OutputPathSummary
    CSV file for per-subnet summary.

.EXAMPLE

Full scan for small ranges; sample for large (auto):
.\Validate-Subnets-IPv6.ps1 -ScanMode Full -MaxScanAddresses 512 -OutputPathSummary .\subnet_summary.csv -OutputPathDetailed .\subnet_details.csv

Force sampling (e.g., to be fast across all subnets):
.\Validate-Subnets-IPv6.ps1 -ScanMode Sample -SampleCount 64 -OutputPathSummary .\summary.csv


Increase TCP timeout and parallelism:
.\Validate-Subnets-IPv6.ps1 -TimeoutMs 5000 -Throttle 128


.How it decides Full vs Sample

If you set -ScanMode Full:

It will scan every address only if the subnet has ≤ -MaxScanAddresses (default 256).
If the subnet is larger (e.g., IPv6 /64 = 2^64 addresses), it automatically switches to sampling for safety.


If you set -ScanMode Sample:

It samples -SampleCount addresses (default 32) evenly across the usable range, always including first and last.

.Notes & Best Practices

ICMP/ping can be blocked by host firewalls; TCP reachability (TcpOk) is the stronger indicator of network path availability on your chosen port.
For IPv6, scanning the entire range is generally impractical except for tight prefixes (e.g., /120 → 256 addresses). The script protects you by sampling when the range is too large.
Works on PowerShell 5.1 (sequential scanning) and PowerShell 7+ (parallel scanning with -Throttle).
If you want to test multiple ports (e.g., 443 and 80), re-run with a different -TestPort or extend Test-TCP to loop through a port list.

#>

[CmdletBinding()]
param(
    [string[]]$Subnets = @(
        '4.145.74.224/27','4.150.254.64/27','4.154.145.224/27','4.200.254.32/27',
        '4.207.244.0/27','4.213.25.64/27','4.213.86.128/25','4.216.205.32/27',
        '4.237.143.128/25','13.67.13.176/28','13.67.15.128/27','13.69.67.224/28',
        '13.69.231.128/28','13.70.78.128/28','13.70.79.128/27','13.74.111.192/27',
        '13.77.53.176/28','13.86.221.176/28','13.89.174.240/28','13.89.175.192/28',
        '20.37.153.0/24','20.37.192.128/25','20.38.81.0/24','20.41.1.0/24',
        '20.42.1.0/24','20.42.130.0/24','20.42.224.128/25','20.43.129.0/24',
        '20.44.19.224/27','20.91.147.72/29','20.168.189.128/27','20.189.172.160/27',
        '20.189.229.0/25','20.191.167.0/25','20.192.159.40/29','20.192.174.216/29',
        '20.199.207.192/28','20.204.193.10/31','20.204.193.12/30','20.204.194.128/31',
        '20.208.149.192/27','20.208.157.128/27','20.214.131.176/29','40.67.121.224/27',
        '40.70.151.32/28','40.71.14.96/28','40.74.25.0/24','40.78.245.240/28',
        '40.78.247.128/27','40.79.197.64/27','40.79.197.96/28','40.80.180.208/28',
        '40.80.180.224/27','40.80.184.128/25','40.82.248.224/28','40.82.249.128/25',
        '40.84.70.128/25','40.119.8.128/25','48.218.252.128/25','52.150.137.0/25',
        '52.162.111.96/28','52.168.116.128/27','52.182.141.192/27','52.236.189.96/27',
        '52.240.244.160/27','57.151.0.192/27','57.153.235.0/25','57.154.140.128/25',
        '57.154.195.0/25','57.155.45.128/25','68.218.134.96/27','74.224.214.64/27',
        '74.242.35.0/25','104.46.162.96/27','104.208.197.64/27','172.160.217.160/27',
        '172.201.237.160/27','172.202.86.192/27','172.205.63.0/25','172.212.214.0/25',
        '172.215.131.0/27','13.107.219.0/24','13.107.227.0/24','13.107.228.0/23',
        '150.171.97.0/24','2620:1ec:40::/48','2620:1ec:49::/48','2620:1ec:4a::/47'
    ),
    [int]$TestPort = 443,
    [ValidateSet('Full','Sample')][string]$ScanMode = 'Sample',
    [int]$MaxScanAddresses = 256,
    [int]$SampleCount = 32,
    [int]$TimeoutMs = 3000,
    [int]$Throttle = 64,
    [string]$OutputPathDetailed,
    [string]$OutputPathSummary
)

# ---- Helpers: BigInteger bit ops ----
Add-Type -AssemblyName System.Numerics | Out-Null

function Convert-IPToBigInt {
    param([string]$IP)
    $addr = [System.Net.IPAddress]::Parse($IP)
    $be = $addr.GetAddressBytes()
    # BigInteger expects little-endian; ensure positive by appending a zero
    $le = $be.Clone()
    [Array]::Reverse($le)
    $le = $le + (0)
    return [System.Numerics.BigInteger]::new($le)
}

function Convert-BigIntToIP {
    param(
        [System.Numerics.BigInteger]$Value,
        [int]$Bits
    )
    $byteLen = $Bits / 8
    $be = New-Object byte[] $byteLen
    for ($i=0; $i -lt $byteLen; $i++) {
        $be[$byteLen - 1 - $i] = [byte]( ($Value >> (8 * $i)) -band 0xFF )
    }
    return [System.Net.IPAddress]::new($be).ToString()
}

function Parse-CIDR {
    param([string]$CIDR)
    $parts = $CIDR.Split('/',2)
    if ($parts.Count -ne 2) { throw "Invalid CIDR '$CIDR'" }
    $ipStr = $parts[0]
    $prefix = [int]$parts[1]
    $ipObj  = [System.Net.IPAddress]::Parse($ipStr)
    $isV6   = ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
    $bits   = if ($isV6) { 128 } else { 32 }

    if ($prefix -lt 0 -or $prefix -gt $bits) { throw "Invalid prefix /$prefix for $ipStr" }

    $ipBI   = Convert-IPToBigInt -IP $ipStr
    $hostBits = $bits - $prefix

    # Mask: ((1 << prefix) - 1) << hostBits
    $mask = (([System.Numerics.BigInteger]::One << $prefix) - 1) << $hostBits
    $network = $ipBI -band $mask
    $broadcastOrLast = $network + (([System.Numerics.BigInteger]::One << $hostBits) - 1)

    # Usable range (IPv4 special cases)
    if (-not $isV6) {
        if ($prefix -ge 31) {
            $firstUsable = $network
            $lastUsable  = $broadcastOrLast
        } else {
            $firstUsable = $network + 1
            $lastUsable  = $broadcastOrLast - 1
        }
    } else {
        # IPv6: no broadcast; treat full range as usable
        $firstUsable = $network
        $lastUsable  = $broadcastOrLast
    }

    # Total addresses (BigInteger)
    $total = ([System.Numerics.BigInteger]::One << $hostBits)
    $usable = if ($isV6) {
        $total
    } elseif ($prefix -ge 31) {
        $total
    } else {
        $total - 2
    }

    [PSCustomObject]@{
        CIDR         = $CIDR
        IPVersion    = if ($isV6) { 'IPv6' } else { 'IPv4' }
        Prefix       = $prefix
        Bits         = $bits
        NetworkIP    = Convert-BigIntToIP -Value $network -Bits $bits
        FirstUsable  = Convert-BigIntToIP -Value $firstUsable -Bits $bits
        LastUsable   = Convert-BigIntToIP -Value $lastUsable -Bits $bits
        Total        = $total
        Usable       = $usable
        NetworkBI    = $network
        FirstBI      = $firstUsable
        LastBI       = $lastUsable
    }
}

function Get-AddressesToTest {
    param(
        [PSCustomObject]$Info,
        [string]$ScanMode,
        [int]$MaxScanAddresses,
        [int]$SampleCount
    )
    $usableCount = $Info.Usable
    # Convert BigInteger to int safely where possible
    $tooLargeForFull = $false
    try {
        $usableInt = [int]$usableCount
        $tooLargeForFull = ($usableInt -gt $MaxScanAddresses)
    } catch {
        $tooLargeForFull = $true # Big range
    }

    $fullAllowed = ($ScanMode -eq 'Full' -and -not $tooLargeForFull)

    $addresses = New-Object System.Collections.Generic.List[string]

    if ($fullAllowed) {
        # Enumerate every address in usable range
        $start = $Info.FirstBI
        $end   = $Info.LastBI
        $curr  = $start
        while ($curr -le $end) {
            $addresses.Add( (Convert-BigIntToIP -Value $curr -Bits $Info.Bits) )
            $curr++
        }
    } else {
        # Sample evenly across usable range
        $samples = [Math]::Max(2, $SampleCount)
        $rangeSize = $Info.LastBI - $Info.FirstBI
        for ($i = 0; $i -lt $samples; $i++) {
            $offset = [System.Numerics.BigInteger]::Parse((($rangeSize * $i) / [Math]::Max(1, ($samples - 1))).ToString())
            $valBI = $Info.FirstBI + $offset
            $addresses.Add( (Convert-BigIntToIP -Value $valBI -Bits $Info.Bits) )
        }
        # Ensure first & last included
        if ($addresses[0] -ne $Info.FirstUsable) { $addresses[0] = $Info.FirstUsable }
        $addresses[$addresses.Count - 1] = $Info.LastUsable
    }
    return $addresses
}

function Test-ICMP {
    param([string]$IP, [int]$TimeoutMs)
    try {
        # PS 5/7 compatible: Test-Connection; map timeout to seconds (ceil)
        $sec = [Math]::Ceiling($TimeoutMs / 1000.0)
        return (Test-Connection -ComputerName $IP -Count 1 -Quiet -TimeoutSeconds $sec -ErrorAction SilentlyContinue)
    } catch { return $false }
}

function Test-TCP {
    param([string]$IP, [int]$Port, [int]$TimeoutMs)
    $af = ([System.Net.IPAddress]::Parse($IP)).AddressFamily
    $client = if ($af -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
    } else {
        New-Object System.Net.Sockets.TcpClient
    }
    try {
        $async = $client.BeginConnect($IP, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.EndConnect($async)
            $client.Close()
            return $true
        } else {
            $client.Close()
            return $false
        }
    } catch {
        try { $client.Close() } catch {}
        return $false
    }
}

function Invoke-AddressScan {
    param(
        [string[]]$Addresses,
        [int]$Port,
        [int]$TimeoutMs,
        [int]$Throttle
    )
    $list = New-Object System.Collections.Concurrent.ConcurrentBag[object]
    $ts = (Get-Date).ToUniversalTime().ToString('u')
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $Addresses | ForEach-Object -Parallel {
            param($ip,$port,$timeout,$ts)
            $ping = Test-ICMP -IP $ip -TimeoutMs $timeout
            $tcp  = Test-TCP  -IP $ip -Port $port -TimeoutMs $timeout
            [PSCustomObject]@{
                IP         = $ip
                PingOk     = $ping
                TcpOk      = $tcp
                Status     = if ($tcp) { 'Reachable' } elseif ($ping) { 'PingOnly' } else { 'Unreachable' }
                Timestamp  = $ts
            }
        } -ThrottleLimit $Throttle -ArgumentList $Port, $TimeoutMs, $ts | ForEach-Object { $list.Add($_) } | Out-Null
    } else {
        foreach ($ip in $Addresses) {
            $ping = Test-ICMP -IP $ip -TimeoutMs $TimeoutMs
            $tcp  = Test-TCP  -IP $ip -Port $Port -TimeoutMs $TimeoutMs
            $list.Add([PSCustomObject]@{
                IP         = $ip
                PingOk     = $ping
                TcpOk      = $tcp
                Status     = if ($tcp) { 'Reachable' } elseif ($ping) { 'PingOnly' } else { 'Unreachable' }
                Timestamp  = $ts
            })
        }
    }
    return $list.ToArray()
}

# ---- Main ----
$allDetails = New-Object System.Collections.Generic.List[object]
$summary    = New-Object System.Collections.Generic.List[object]

foreach ($cidr in $Subnets) {
    try {
        $info = Parse-CIDR -CIDR $cidr
    } catch {
        $summary.Add([PSCustomObject]@{
            CIDR              = $cidr
            IPVersion         = ''
            Prefix            = ''
            Network           = ''
            FirstUsable       = ''
            LastUsable        = ''
            TotalAddresses    = ''
            UsableAddresses   = ''
            AddressesTested   = 0
            ReachableTcp      = 0
            PingOnly          = 0
            Unreachable       = 0
            ScanModeApplied   = 'Error'
            Notes             = "Invalid CIDR: $($_.Exception.Message)"
        })
        continue
    }

    $addresses = Get-AddressesToTest -Info $info -ScanMode $ScanMode -MaxScanAddresses $MaxScanAddresses -SampleCount $SampleCount
    Write-Progress -Activity "Scanning $cidr ($($info.IPVersion))" -Status "Testing $($addresses.Count) addresses" -PercentComplete 0

    $results = Invoke-AddressScan -Addresses $addresses -Port $TestPort -TimeoutMs $TimeoutMs -Throttle $Throttle

    # Collect details
    foreach ($r in $results) {
        $allDetails.Add([PSCustomObject]@{
            CIDR        = $cidr
            IPVersion   = $info.IPVersion
            Prefix      = $info.Prefix
            IP          = $r.IP
            PingOk      = $r.PingOk
            TcpOk       = $r.TcpOk
            Status      = $r.Status
            Timestamp   = $r.Timestamp
        })
    }

    # Summary
    $reachableTcp = ($results | Where-Object { $_.TcpOk }).Count
    $pingOnly     = ($results | Where-Object { -not $_.TcpOk -and $_.PingOk }).Count
    $unreachable  = ($results | Where-Object { -not $_.TcpOk -and -not $_.PingOk }).Count

    # Determine applied scan mode
    $scanApplied = $ScanMode
    try {
        $usableInt = [int]$info.Usable
        if ($ScanMode -eq 'Full' -and $usableInt -gt $MaxScanAddresses) {
            $scanApplied = "Sample(due to size>$MaxScanAddresses)"
        }
    } catch {
        if ($ScanMode -eq 'Full') { $scanApplied = "Sample(due to huge size)" }
    }

    $summary.Add([PSCustomObject]@{
        CIDR              = $cidr
        IPVersion         = $info.IPVersion
        Prefix            = $info.Prefix
        Network           = $info.NetworkIP
        FirstUsable       = $info.FirstUsable
        LastUsable        = $info.LastUsable
        TotalAddresses    = $info.Total.ToString()
        UsableAddresses   = $info.Usable.ToString()
        AddressesTested   = $addresses.Count
        ReachableTcp      = $reachableTcp
        PingOnly          = $pingOnly
        Unreachable       = $unreachable
               ScanModeApplied   = $scanApplied
        Notes             = if ($info.IPVersion -eq 'IPv6' -and $scanApplied -like 'Sample*') { 'IPv6 ranges are very large; sampling used' } else { '' }
    })

    Write-Progress -Activity "Scanning $cidr ($($info.IPVersion))" -Status "Done" -Completed
}

# ---- Output ----
$summary | Format-Table -AutoSize

if ($OutputPathSummary) {
    try {
        $summary | Export-Csv -Path $OutputPathSummary -NoTypeInformation -Encoding UTF8
        Write-Host "Summary exported: $OutputPathSummary" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export summary: $($_.Exception.Message)"
    }
}

if ($OutputPathDetailed) {
    try {
        $allDetails | Export-Csv -Path $OutputPathDetailed -NoTypeInformation -Encoding UTF8
        Write-Host "Details exported: $OutputPathDetailed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export details: $($_.Exception.Message)"
    }
}

# Return objects for pipelines
