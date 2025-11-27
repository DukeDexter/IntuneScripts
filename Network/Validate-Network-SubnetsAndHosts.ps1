
<# 

Author: Duke Dexter (https://github.com/DukeDexte)

.SYNOPSIS
    Validate IPv4/IPv6 subnets and hostnames with multi-port TCP checks, optional Reverse DNS, and NTP UDP/123 probing.
    Auto-expands per-port columns in the CSV based on -Ports (e.g., TCP_443_Ok, TCP_443_LatencyMs, TCP_443_Error, UDP_123_Ok, UDP_123_Error).

.DESCRIPTION
    - Parses CIDR (IPv4/IPv6) without external modules (BigInteger math).
    - Computes usable range; scans full range for small subnets or samples for large ranges.
    - Tests ICMP ping, multi-port TCP connectivity (per-port latency), optional Reverse DNS (PTR).
    - Optional NTP UDP/123 probe for time services (IPv4/IPv6).
    - DNS forward lookup mode for hostnames (A/AAAA → test each IP).
    - Parallel scans on PowerShell 7+, sequential fallback on PS 5.1.
    - Exports per-subnet summary && per-address details; both auto-include per-port columns.

.PARAMETER Subnets
    CIDR list (IPv4 and/or IPv6) to validate. Optional if -Hosts is provided.

.PARAMETER Hosts
    Hostnames to resolve (A/AAAA) and validate. Optional if -Subnets is provided.

.PARAMETER Ports
    Port list for per-port tests (e.g., 443,80,445,123). If 123 is included, you can enable -ProbeNtp.

.PARAMETER Preset
    Port-set presets. Currently supported:
      - EdgeWU     → 443,80,445,123
      - TLSOnly    → 443
      - WebBasic   → 80,443
      - FileAndWeb → 80,443,445

.PARAMETER ProbeNtp
    If set, performs UDP/123 NTP probe (only when 123 is present in -Ports).

.PARAMETER ReverseDns
    If set, performs Reverse DNS (PTR) for each IP tested.

.PARAMETER ScanMode
    'Full' or 'Sample'. Full scans are limited by MaxScanAddresses; oversized ranges auto-sample.

.PARAMETER MaxScanAddresses
    Upper bound for full scans (default 256). Larger ranges auto-sample.

.PARAMETER SampleCount
    Addresses sampled when full scan is not feasible (default 32). Always includes first & last.

.PARAMETER TimeoutMs
    Timeout per test (TCP connect & ICMP) in milliseconds (default 3000).

.PARAMETER Throttle
    Parallel throttle in PS 7+ (default 64). Ignored on PS 5.1.

.PARAMETER OutputPathDetailed
    CSV path for per-address, per-port details (includes expanded per-port columns).

.PARAMETER OutputPathSummary
    CSV path for per-subnet / per-host summaries (includes aggregated per-port counts).

.EXAMPLE
    .\Validate-Network-SubnetsAndHosts.ps1 -Subnets '13.107.219.0/24','2620:1ec:40::/120' `
       -Preset EdgeWU -ReverseDns -ScanMode Full -MaxScanAddresses 512 `
       -OutputPathSummary .\summary.csv -OutputPathDetailed .\details.csv

.EXAMPLE
    .\Validate-Network-SubnetsAndHosts.ps1 -Hosts 'time.windows.com','dl.delivery.mp.microsoft.com' `
       -Ports 443,123 -ProbeNtp -SampleCount 64 -ReverseDns `
       -OutputPathSummary .\host_summary.csv -OutputPathDetailed .\host_details.csv
#>

[CmdletBinding()]
param(
    [string[]]$Subnets,
    [string[]]$Hosts,
    [int[]]$Ports,
    [ValidateSet('EdgeWU','TLSOnly','WebBasic','FileAndWeb')][string]$Preset,
    [switch]$ProbeNtp,
    [switch]$ReverseDns,
    [ValidateSet('Full','Sample')][string]$ScanMode = 'Sample',
    [int]$MaxScanAddresses = 256,
    [int]$SampleCount = 32,
    [int]$TimeoutMs = 3000,
    [int]$Throttle = 64,
    [string]$OutputPathDetailed,
    [string]$OutputPathSummary
)

# ----------------- Preset ports -----------------
function Resolve-PresetPorts {
    param([string]$Preset)
    switch ($Preset) {
        'EdgeWU'     { return @(443,80,445,123) }
        'TLSOnly'    { return @(443) }
        'WebBasic'   { return @(80,443) }
        'FileAndWeb' { return @(80,443,445) }
        default      { return $null }
    }
}

$resolvedPreset = $null
if ($Preset) { $resolvedPreset = Resolve-PresetPorts -Preset $Preset }

if (-not $Ports -and $resolvedPreset) {
    $Ports = $resolvedPreset
} elseif ($Ports -and $resolvedPreset) {
    # Merge and deduplicate
    $Ports = @($Ports + $resolvedPreset | Sort-Object -Unique)
} elseif (-not $Ports -and -not $resolvedPreset) {
    # Sensible default
    $Ports = @(443)
}

# ----------------- Validate NTP flag vs ports -----------------
$doNtp = $ProbeNtp.IsPresent -and ($Ports -contains 123)

# ----------------- BigInteger Helpers -----------------
Add-Type -AssemblyName System.Numerics | Out-Null

function Convert-IPToBigInt {
    param([string]$IP)
    $addr = [System.Net.IPAddress]::Parse($IP)
    $be = $addr.GetAddressBytes()
    [Array]::Reverse($be)                            # to little-endian
    $leWithSign = $be + (0)                          # ensure positive BigInteger
    return [System.Numerics.BigInteger]::new($leWithSign)
}

function Convert-BigIntToIP {
    param(
        [System.Numerics.BigInteger]$Value,
        [int]$Bits
    )
    $byteLen = [int]($Bits / 8)
    $be = New-Object byte[] $byteLen
    for ($i = 0; $i -lt $byteLen; $i++) {
        $shift = 8 * ($byteLen - 1 - $i)
        $be[$i] = [byte](($Value >> $shift) -band 0xFF)
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

    # Network = (ip >> hostBits) << hostBits (zero host bits)
    $networkBI = ($ipBI >> $hostBits) << $hostBits
    $lastBI    = $networkBI + (([System.Numerics.BigInteger]::One << $hostBits) - 1)

    # Usable range
    if (-not $isV6) {
        if ($prefix -ge 31) {
            $firstBI = $networkBI
            $lastUsableBI = $lastBI
        } else {
            $firstBI = $networkBI + 1
            $lastUsableBI = $lastBI - 1
        }
    } else {
        $firstBI = $networkBI
        $lastUsableBI = $lastBI
    }

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
        NetworkIP    = Convert-BigIntToIP -Value $networkBI -Bits $bits
        FirstUsable  = Convert-BigIntToIP -Value $firstBI -Bits $bits
        LastUsable   = Convert-BigIntToIP -Value $lastUsableBI -Bits $bits
        Total        = $total
        Usable       = $usable
        NetworkBI    = $networkBI
        FirstBI      = $firstBI
        LastBI       = $lastUsableBI
    }
}

function Get-AddressesFromSubnet {
    param(
        [PSCustomObject]$Info,
        [string]$ScanMode,
        [int]$MaxScanAddresses,
        [int]$SampleCount
    )
    $tooLargeForFull = $false
    try {
        $usableInt = [int]$Info.Usable
        $tooLargeForFull = ($usableInt -gt $MaxScanAddresses)
    } catch {
        $tooLargeForFull = $true # Huge ranges
    }
    $fullAllowed = ($ScanMode -eq 'Full' -and -not $tooLargeForFull)

    $addresses = New-Object System.Collections.Generic.List[string]

    if ($fullAllowed) {
        $curr = $Info.FirstBI
        while ($curr -le $Info.LastBI) {
            $addresses.Add( (Convert-BigIntToIP -Value $curr -Bits $Info.Bits) )
            $curr++
        }
    } else {
        $samples = [Math]::Max(2, $SampleCount)
        $rangeSize = $Info.LastBI - $Info.FirstBI
        for ($i = 0; $i -lt $samples; $i++) {
            $ratio = if ($samples -gt 1) { $i / ($samples - 1.0) } else { 0 }
            $offset = [System.Numerics.BigInteger]::Parse([Math]::Floor(($rangeSize * $ratio)).ToString())
            $valBI = $Info.FirstBI + $offset
            $addresses.Add( (Convert-BigIntToIP -Value $valBI -Bits $Info.Bits) )
        }
        # Ensure first & last exact
        $addresses[0] = $Info.FirstUsable
        $addresses[$addresses.Count - 1] = $Info.LastUsable
    }
    return $addresses
}

# ----------------- DNS forward lookup -----------------
function Resolve-HostIPs {
    param([string]$Host)
    $ips = @()
    try {
        $dns = Resolve-DnsName -Name $Host -Type A,AAAA -ErrorAction Stop
        $ips = ($dns | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
    } catch {
        # fallback: .NET resolver
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($Host) | ForEach-Object { $_.ToString() }
        } catch {}
    }
    return ($ips | Sort-Object -Unique)
}

# ----------------- Network tests -----------------
function Test-ICMP {
    param([string]$IP, [int]$TimeoutMs)
    try {
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
    $result = [ordered]@{ Ok = $false; LatencyMs = $null; Error = '' }
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $async = $client.BeginConnect($IP, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            throw "Timeout after ${TimeoutMs}ms"
        }
        $client.EndConnect($async)
        $sw.Stop()
        $result.Ok = $true
        $result.LatencyMs = [int]$sw.Elapsed.TotalMilliseconds
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        try { $client.Close() } catch {}
    }
    return $result
}

function Test-NTP {
    param([string]$IP, [int]$TimeoutMs = 4000)
    $ret = [ordered]@{ Ok = $false; Error = '' }
    try {
        $ipObj = [System.Net.IPAddress]::Parse($IP)
        $af = $ipObj.AddressFamily
        $udp = if ($af -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        } else {
            New-Object System.Net.Sockets.UdpClient
        }
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($ipObj, 123)

        $pkt = New-Object byte[] 48
        $pkt[0] = 0x1B # LI=0, VN=3, Mode=3 (client)
        [void]$udp.Send($pkt, $pkt.Length)

        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remote)
        if ($resp.Length -ge 48) { $ret.Ok = $true } else { $ret.Error = "Unexpected response length: $($resp.Length)" }
        $udp.Close()
    } catch {
        $ret.Error = $_.Exception.Message
    }
    return $ret
}

function Get-ReverseDns {
    param([string]$IP)
    try { return [System.Net.Dns]::GetHostEntry($IP).HostName } catch { return $null }
}

# ----------------- Dynamic per-port column expansion -----------------
function New-PerPortColumnsTemplate {
    param([int[]]$Ports, [bool]$IncludeUdp123)
    $template = @{}
    foreach ($p in ($Ports | Sort-Object -Unique)) {
        if ($p -eq 123 -and $IncludeUdp123) {
            $template["UDP_${p}_Ok"]    = $false
            $template["UDP_${p}_Error"] = ''
        } else {
            $template["TCP_${p}_Ok"]        = $false
            $template["TCP_${p}_LatencyMs"] = $null
            $template["TCP_${p}_Error"]     = ''
        }
       }
    return $template
}

# ----------------- Address Scan -----------------
function Invoke-AddressScan {
    param(
        [string[]]$Addresses,
        [int[]]$Ports,
        [bool]$DoNtp,
        [bool]$DoPtr,
        [int]$TimeoutMs,
        [int]$Throttle
    )
    $bag = New-Object System.Collections.Concurrent.ConcurrentBag[object]
    $ts = (Get-Date).ToUniversalTime().ToString('u')

    $work = {
        param($ip, $ports, $doNtp, $doPtr, $timeout, $ts)
        $ping = Test-ICMP -IP $ip -TimeoutMs $timeout
        $ptr  = if ($doPtr) { Get-ReverseDns -IP $ip } else { $null }

        # Build dynamic per-port fields for this IP
        $row = @{}
        $row['IP']         = $ip
        $row['PingOk']     = $ping
        $row['ReverseDns'] = $ptr
        $row['Timestamp']  = $ts

        foreach ($p in ($ports | Sort-Object -Unique)) {
            if ($p -eq 123 -and $doNtp) {
                $ntp = Test-NTP -IP $ip -TimeoutMs ([Math]::Max($timeout, 4000))
                $row["UDP_${p}_Ok"]    = $ntp.Ok
                $row["UDP_${p}_Error"] = $ntp.Error
            } else {
                $tcp = Test-TCP -IP $ip -Port $p -TimeoutMs $timeout
                $row["TCP_${p}_Ok"]        = $tcp.Ok
                $row["TCP_${p}_LatencyMs"] = $tcp.LatencyMs
                $row["TCP_${p}_Error"]     = $tcp.Error
            }
        }

        # quick roll-ups (common ports)
        $row['Tcp443']   = ($row.ContainsKey('TCP_443_Ok')   -and $row['TCP_443_Ok'])
        $row['Tcp80']    = ($row.ContainsKey('TCP_80_Ok')    -and $row['TCP_80_Ok'])
        $row['Tcp445']   = ($row.ContainsKey('TCP_445_Ok')   -and $row['TCP_445_Ok'])
        $row['Udp123Ntp']= ($row.ContainsKey('UDP_123_Ok')   -and $row['UDP_123_Ok'])

        $bag.Add([PSCustomObject]$row)
    }

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $Addresses | ForEach-Object -Parallel $work -ThrottleLimit $Throttle -ArgumentList $Ports, $DoNtp, $DoPtr, $TimeoutMs, $ts | Out-Null
    } else {
        foreach ($ip in $Addresses) {
            & $work $ip $Ports $DoNtp $DoPtr $TimeoutMs $ts
        }
    }
    return $bag.ToArray()
}

# ----------------- Collect addresses to scan -----------------
$sourceItems = New-Object System.Collections.Generic.List[object]

# From subnets
if ($Subnets) {
    foreach ($cidr in $Subnets) {
        try {
            $info = Parse-CIDR -CIDR $cidr
        } catch {
            Write-Warning "Invalid CIDR '$cidr': $($_.Exception.Message)"
            $sourceItems.Add([PSCustomObject]@{
                SourceType     = 'Subnet'
                SourceValue    = $cidr
                IPVersion      = ''
                AddressesToTest= @()
                Notes          = "Invalid CIDR"
                ScanModeApplied= 'Error'
            })
            continue
        }

        $addresses = Get-AddressesFromSubnet -Info $info -ScanMode $ScanMode -MaxScanAddresses $MaxScanAddresses -SampleCount $SampleCount
        $scanApplied = $ScanMode
        try {
            $usableInt = [int]$info.Usable
            if ($ScanMode -eq 'Full' -and $usableInt -gt $MaxScanAddresses) {
                $scanApplied = "Sample(due to size>$MaxScanAddresses)"
            }
        } catch {
            if ($ScanMode -eq 'Full') { $scanApplied = "Sample(due to huge size)" }
        }

        $sourceItems.Add([PSCustomObject]@{
            SourceType      = 'Subnet'
            SourceValue     = $cidr
            IPVersion       = $info.IPVersion
            Network         = $info.NetworkIP
            FirstUsable     = $info.FirstUsable
            LastUsable      = $info.LastUsable
            TotalAddresses  = $info.Total.ToString()
            UsableAddresses = $info.Usable.ToString()
            AddressesToTest = $addresses
            ScanModeApplied = $scanApplied
            Notes           = if ($info.IPVersion -eq 'IPv6' -and $scanApplied -like 'Sample*') { 'IPv6 ranges are very large; sampling used' } else { '' }
        })
    }
}

# From hosts (DNS forward lookup)
if ($Hosts) {
    foreach ($h in $Hosts) {
        $ips = Resolve-HostIPs -Host $h
        if (-not $ips -or $ips.Count -eq 0) {
            Write-Warning "DNS resolution returned no IPs for host '$h'"
        }
        $sourceItems.Add([PSCustomObject]@{
            SourceType      = 'Host'
            SourceValue     = $h
            IPVersion       = 'Mixed'
            Network         = ''
            FirstUsable     = ''
            LastUsable      = ''
            TotalAddresses  = ''
            UsableAddresses = ''
            AddressesToTest = $ips
            ScanModeApplied = 'N/A (Host)'
            Notes           = if ($ips.Count -eq 0) { 'DNS resolution failed or returned none' } else { '' }
        })
    }
}

if ($sourceItems.Count -eq 0) {
    throw "No inputs provided. Specify -Subnets and/or -Hosts."
}

# ----------------- Dynamic columns template (for Details CSV) -----------------
$perPortTemplate = New-PerPortColumnsTemplate -Ports $Ports -IncludeUdp123:$doNtp

# ----------------- Scan all addresses -----------------
$details = New-Object System.Collections.Generic.List[object]
$summary = New-Object System.Collections.Generic.List[object]

foreach ($src in $sourceItems) {
    $addresses = $src.AddressesToTest
    if (-not $addresses -or $addresses.Count -eq 0) {
        # Still add a summary row reflecting the source
        $summary.Add([PSCustomObject]@{
            SourceType        = $src.SourceType
            SourceValue       = $src.SourceValue
            IPVersion         = $src.IPVersion
            Network           = $src.Network
            FirstUsable       = $src.FirstUsable
            LastUsable        = $src.LastUsable
            TotalAddresses    = $src.TotalAddresses
            UsableAddresses   = $src.UsableAddresses
            AddressesTested   = 0
            ReachableTcpAny   = 0
            Udp123NtpOk       = 0
            PingOnly          = 0
            Unreachable       = 0
            ScanModeApplied   = $src.ScanModeApplied
            Notes             = $src.Notes
        })
        continue
    }

    Write-Progress -Activity "Scanning $($src.SourceType): $($src.SourceValue)" -Status "Testing $($addresses.Count) addresses" -PercentComplete 0
    $results = Invoke-AddressScan -Addresses $addresses -Ports $Ports -DoNtp:$doNtp -DoPtr:$ReverseDns.IsPresent -TimeoutMs $TimeoutMs -Throttle $Throttle

    # Build details rows with dynamic per-port columns for each IP
    foreach ($r in $results) {
        $row = [ordered]@{
            SourceType   = $src.SourceType
            SourceValue  = $src.SourceValue
            IP           = $r.IP
            PingOk       = $r.PingOk
            ReverseDns   = $r.ReverseDns
            Timestamp    = $r.Timestamp
        }
        # Add per-port fields (ensure stable columns across all rows)
        foreach ($k in $perPortTemplate.Keys) {
            # If the scan row contains the key (e.g., TCP_443_Ok), use it; else default
            if ($r.PSObject.Properties.Name -contains $k) {
                $row[$k] = $r.$k
            } else {
                $row[$k] = $perPortTemplate[$k]
            }
        }
        # Helpful roll-ups
        $row['Tcp443']    = ($r.PSObject.Properties.Name -contains 'TCP_443_Ok') -and $r.TCP_443_Ok
        $row['Tcp80']     = ($r.PSObject.Properties.Name -contains 'TCP_80_Ok')  -and $r.TCP_80_Ok
        $row['Tcp445']    = ($r.PSObject.Properties.Name -contains 'TCP_445_Ok') -and $r.TCP_445_Ok
        $row['Udp123Ntp'] = ($r.PSObject.Properties.Name -contains 'UDP_123_Ok') -and $r.UDP_123_Ok

        $details.Add([PSCustomObject]$row)
    }

    # Summary aggregation for this source
    $reachableTcpAny = ($results | Where-Object {
        $_.Tcp443 -or $_.Tcp80 -or $_.Tcp445 -or ($Ports | Where-Object { $_ -ne 123 } | ForEach-Object { $_ } | ForEach-Object { $rPort = "TCP_${_}_Ok"; $_r = $_; $_ } | Measure-Object).Count -gt 0
    }).Count

    # More robust per-port any-TCP count
    $anyTcpCount = 0
    foreach ($p in ($Ports | Where-Object { $_ -ne 123 })) {
        $prop = "TCP_${p}_Ok"
        $anyTcpCount += ($results | Where-Object { $_.PSObject.Properties.Name -contains $prop -and $_.$prop }).Count
    }
    $udp123Ok = if ($doNtp) { ($results | Where-Object { $_.Udp123Ntp }).Count } else { 0 }
    $pingOnly = ($results | Where-Object {
        $_.PingOk -and (
            # no TCP success on any configured port
            ((($Ports | Where-Object { $_ -ne 123 } | ForEach-Object { "TCP_${_}_Ok" }) | Where-Object { $_ -in $_.PSObject.Properties.Name -and $_.($_) }) | Measure-Object).Count -eq 0)
        ) -and (-not $_.Udp123Ntp)
    }).Count
    $unreachable = ($results | Where-Object {
        (-not $_.PingOk) -and
        ((($Ports | Where-Object { $_ -ne 123 } | ForEach-Object { "TCP_${_}_Ok" }) | Where-Object { $_ -in $_.PSObject.Properties.Name -and $_.($_) }) | Measure-Object).Count -eq 0) -and
        (-not $_.Udp123Ntp)
    }).Count

    $summary.Add([PSCustomObject]@{
        SourceType        = $src.SourceType
        SourceValue       = $src.SourceValue
        IPVersion         = $src.IPVersion
        Network           = $src.Network
        FirstUsable       = $src.FirstUsable
        LastUsable        = $src.LastUsable
        TotalAddresses    = $src.TotalAddresses
        UsableAddresses   = $src.UsableAddresses
        AddressesTested   = $addresses.Count
        ReachableTcpAny   = $anyTcpCount
        Udp123NtpOk       = $udp123Ok
        PingOnly          = $pingOnly
        Unreachable       = $unreachable
        ScanModeApplied   = $src.ScanModeApplied
        Notes             = $src.Notes
    })

    Write-Progress -Activity "Scanning $($src.SourceType): $($src.SourceValue)" -Status "Done" -Completed
}

# ----------------- Output -----------------
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
        $details | Export-Csv -Path $OutputPathDetailed -NoTypeInformation -Encoding UTF8
        Write-Host "Details exported: $OutputPathDetailed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export details: $($_.Exception.Message)"
    }
}

# Return objects (pipeline)
