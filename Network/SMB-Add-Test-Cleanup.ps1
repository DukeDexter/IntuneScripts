
<#
.SYNOPSIS
  Temporarily allow inbound SMB (TCP 445), test connectivity, and auto-remove the rule.
  The Server Message Block (SMB) protocol uses specific ports for file and printer sharing. Below are the key SMB ports:
  Key SMB Ports
    Port 445: Used for direct SMB communication over TCP/IP without NetBIOS. This is the default and recommended port for modern Windows systems.
    Port 139: Used for SMB communication over NetBIOS (legacy support).
    Port 138: Used for NetBIOS datagram services (UDP).
    Port 137: Used for NetBIOS name services (TCP/UDP). 

.PARAMETER TargetHost
  DNS name or IP of the SMB server you want to test.

.PARAMETER SharePath
  Optional UNC path to test (e.g., \\fileserver\share). If omitted, only port 445 is tested.

.PARAMETER LogPath
  Optional log file path. If not provided, a temp file is used.

.EXAMPLE Port-only test
.\Test-SMB-AndCleanup.ps1 -TargetHost fileserver01

.\Test-SMB-AndCleanup.ps1 -TargetHost 10.10.10.25

.EXAMPLE Port test + share access
.\Test-SMB-AndCleanup.ps1 -TargetHost fileserver01 -SharePath \\fileserver01\software

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetHost,

    [Parameter(Mandatory = $false)]
    [string]$SharePath,

    [Parameter(Mandatory = $false)]
    [string]$LogPath
)

# ----------------- Setup & Logging -----------------
$RuleName    = 'TEMP SMB Allow 445 (Any Profile)'
$CreatedRule = $false
$LogPath     = if ($LogPath) { $LogPath } else { Join-Path $env:TEMP ("SMBTest_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)) }

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')] [string]$Level = 'INFO')
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogPath -Value $line
}

try { Start-Transcript -Path $LogPath -Append -ErrorAction SilentlyContinue | Out-Null } catch { }

# ----------------- Active Profile Hint -------------
try {
    $profiles = Get-NetConnectionProfile
    $activeProfiles = $profiles | Where-Object { $_.IPv4Connectivity -ne 'Disconnected' -or $_.IPv6Connectivity -ne 'Disconnected' }
    $categories = ($activeProfiles | Select-Object -ExpandProperty NetworkCategory) -join ', '
    Write-Log ("Active network categories detected: {0}" -f ($categories -ne '' ? $categories : 'None'))
} catch {
    Write-Log ("Could not enumerate network profiles: {0}" -f $_.Exception.Message) 'WARN'
}

# ----------------- Create Temp Rule ----------------
try {
    # Clean any leftover rule from previous runs
    $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "Found existing temporary rule; removing before re-creating."
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    }

    New-NetFirewallRule -DisplayName $RuleName `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 445 `
        -Action Allow `
        -Profile Any `
        -Program Any `
        -Enabled True | Out-Null

    $CreatedRule = $true
    Write-Log "Temporary SMB allow rule created."
} catch {
    Write-Log ("Failed to create temporary rule: {0}" -f $_.Exception.Message) 'ERROR'
}

# ----------------- Test Port 445 -------------------
$portResult = $null
try {
    Write-Log ("Testing TCP 445 connectivity to {0}..." -f $TargetHost)
    $portResult = Test-NetConnection -ComputerName $TargetHost -Port 445 -WarningAction SilentlyContinue
    if ($portResult.TcpTestSucceeded) {
        Write-Log ("SUCCESS: Port 445 is reachable on {0} (Latency: {1} ms)." -f $TargetHost, ($portResult.PingLatency))
    } else {
        Write-Log ("FAIL: Port 445 is NOT reachable on {0}." -f $TargetHost) 'WARN'
    }
} catch {
    Write-Log ("Error testing port 445: {0}" -f $_.Exception.Message) 'ERROR'
}

# ----------------- Optional Share Test -------------
$shareAccessResult = $null
if ($SharePath) {
    try {
        Write-Log ("Attempting to access share path: {0}" -f $SharePath)
        # Basic existence check (non-destructive)
        $exists = Test-Path -LiteralPath $SharePath
        if ($exists) {
            Write-Log ("SUCCESS: Share path '{0}' is accessible." -f $SharePath)
            $shareAccessResult = $true
        } else {
            Write-Log ("FAIL: Share path '{0}' is NOT accessible." -f $SharePath) 'WARN'
            $shareAccessResult = $false
        }
    } catch {
        Write-Log ("Error testing share path: {0}" -f $_.Exception.Message) 'ERROR'
        $shareAccessResult = $false
    }
}

# ----------------- Cleanup Always ------------------
try {
    if ($CreatedRule) {
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        Write-Log "Temporary SMB rule removed."
    } else {
        Write-Log "No temporary rule was created; nothing to remove." 'WARN'
    }
} catch {
    Write-Log ("Failed to remove temporary rule: {0}" -f $_.Exception.Message) 'ERROR'
}

# ----------------- Summary & Exit Code ------------
Write-Log "---- SUMMARY ----"
Write-Log ("Port 445 reachable: {0}" -f ($portResult?.TcpTestSucceeded))
if ($SharePath) {
    Write-Log ("Share accessible ({0}): {1}" -f $SharePath, $shareAccessResult)
}
Write-Log ("Log saved to: {0}" -f $LogPath)

try { Stop-Transcript | Out-Null } catch { }

# Exit codes:
# 0 = port reachable (and share accessible if provided)
# 1 = port blocked/unreachable
# 2 = port reachable but share not accessible
# 3 = mixed/other error during checks
$exitCode = 0
if ($portResult -eq $null -or -not $portResult.TcpTestSucceeded) { $exitCode = 1 }
if ($SharePath -and -not $shareAccessResult) { $exitCode = if ($exitCode -eq 0) { 2 } else { 3 } }
exit $exitCode
