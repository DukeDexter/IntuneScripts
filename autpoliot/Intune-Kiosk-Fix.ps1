<#
.SYNOPSIS
Detect and remediate Intune Win32 apps stuck at "Waiting for install status" on kiosk devices.

.DESCRIPTION
- Detects apps with State=1 in IME registry (Waiting for install status)
- Restarts IME service, clears stale keys, triggers Intune sync
- Optional reboot controlled by parameter
- Outputs JSON for Intune reporting

How to Use

Proactive Remediation:

Upload this script as both detection and remediation.
Intune will interpret exit 0 as success, exit 1 as remediation applied.

Platform Script:

Upload as a single script under Devices > Scripts.
Run as SYSTEM.

Optional Parameter:

Add -SkipReboot if you don’t want kiosk devices to restart.

#>

param(
    [switch]$SkipReboot  # Use -SkipReboot to prevent reboot
)

# Define log path
$LogDir = "C:\ProgramData\IntuneFix"
$LogFile = "$LogDir\IME_Fix_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

Function Write-Log {
    param([string]$Message)
    "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) : $Message" | Tee-Object -FilePath $LogFile -Append
}

Write-Log "Starting detection..."

# Registry path for IME reporting
$RegPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\Reporting"
$StuckApps = @()

# Detect stuck apps
if (Test-Path $RegPath) {
    $Apps = Get-ChildItem -Path $RegPath
    foreach ($App in $Apps) {
        $StateKey = Join-Path $App.PSPath "State"
        if (Test-Path $StateKey) {
            $State = Get-ItemProperty -Path $StateKey | Select-Object -ExpandProperty Value
            if ($State -eq 1) { $StuckApps += $App.PSChildName }
        }
    }
}

# Prepare JSON output for Intune
$Result = @{
    StuckApps = $StuckApps
    Count     = $StuckApps.Count
    Action    = if ($StuckApps.Count -gt 0) { "Remediation Applied" } else { "No Action Needed" }
}
$Result | ConvertTo-Json -Compress | Out-File "$LogDir\Result.json"

if ($StuckApps.Count -eq 0) {
    Write-Log "No stuck apps found. Exiting."
    exit 0
}

Write-Log "Detected stuck apps: $($StuckApps -join ', ')"
Write-Log "Starting remediation..."

# Restart IME Service
Write-Log "Restarting Intune Management Extension service..."
Try {
    Restart-Service IntuneManagementExtension -Force
    Write-Log "IME service restarted successfully."
} Catch {
    Write-Log "Failed to restart IME service: $_"
}

# Clear stale reporting keys
Write-Log "Removing LastFullReportTimeUtc key..."
Try {
    Remove-ItemProperty -Path $RegPath -Name "LastFullReportTimeUtc" -ErrorAction SilentlyContinue
    Write-Log "Registry cleanup done."
} Catch {
    Write-Log "Failed to remove registry key: $_"
}

# Trigger Intune Device Sync
Write-Log "Triggering Intune device sync..."
Try {
    Invoke-Expression "Invoke-IntuneDeviceSync" | Out-Null
    Write-Log "Device sync triggered."
} Catch {
    Write-Log "Failed to trigger device sync: $_"
}

# Optional reboot
if (-not $SkipReboot) {
    Write-Log "Rebooting device in 60 seconds..."
    Shutdown.exe /r /t 60 /c "Intune remediation applied. Restarting to refresh app status."
} else {
    Write-Log "SkipReboot parameter detected. No reboot will occur."
}

Write-Log "Remediation completed."
exit 1
