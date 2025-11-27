
<# 

Author: Duke Dexter (https://github.com/DukeDexter)

.SYNOPSIS
    Validate IP subnets for format and network reachability.

.DESCRIPTION
    - Checks CIDR validity
    - Expands subnet to first and last usable IP
    - Tests ICMP ping and optional TCP port (default 443)
    - Outputs summary table and optional CSV

.PARAMETER Subnets
    Array of CIDR subnets to validate.

.PARAMETER TestPort
    Optional TCP port to test (default: 443).

.PARAMETER OutputPath
    Optional CSV export path.

.EXAMPLE
    .\Validate-Subnets.ps1 -OutputPath .\subnet_check.csv
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
    [string]$OutputPath
)

function Get-SubnetRange {
    param([string]$CIDR)
    try {
        $ipNet = [System.Net.IPNetwork]::Parse($CIDR)
        return [PSCustomObject]@{
            CIDR        = $CIDR
            Network     = $ipNet.Network.ToString()
            Netmask     = $ipNet.Netmask.ToString()
            FirstUsable = $ipNet.FirstUsable.ToString()
            LastUsable  = $ipNet.LastUsable.ToString()
            TotalHosts  = $ipNet.Total.ToString()
        }
    } catch {
        return [PSCustomObject]@{
            CIDR        = $CIDR
            Network     = ''
            Netmask     = ''
            FirstUsable = ''
            LastUsable  = ''
            TotalHosts  = ''
            Error       = $_.Exception.Message
        }
    }
}

function Test-Reachability {
    param([string]$IP,[int]$Port)
    $result = [ordered]@{
        PingOk = $false
        TcpOk  = $false
    }
    try {
        if (Test-Connection -ComputerName $IP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
            $result.PingOk = $true
        }
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($IP,$Port,$null,$null)
        if ($async.AsyncWaitHandle.WaitOne(3000)) {
            $tcp.EndConnect($async)
            $result.TcpOk = $true
        }
        $tcp.Close()
    } catch {}
    return $result
}

$results = foreach ($subnet in $Subnets) {
    $info = Get-SubnetRange -CIDR $subnet
    if ($info.Error) {
        [PSCustomObject]@{
            CIDR        = $subnet
            Network     = ''
