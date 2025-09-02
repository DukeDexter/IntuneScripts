# Quick Defender Scan → 2‑min wait → Intune sync (with logging & error handling)

# Set exec policy for THIS process 
Set-ExecutionPolicy Bypass -Scope Process -Force

# ================================
# QuickScan-Then-IntuneSync.ps1
# ================================
[CmdletBinding()]
param(
    [int]$WaitSeconds = 120,          # 2 min wait before sync
    [string]$LogFolder = "$env:ProgramData\IntuneTools\Logs"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Logging ----------
if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
$LogFile = Join-Path $LogFolder ("QuickScan-IntuneSync_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Write-Log {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO')
    $line = ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message)
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Write-Log ("Log file: {0}" -f $LogFile)

# ---------- Helper: Run and log a scriptblock with error handling ----------
function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Log ("START: {0}" -f $Name)
    try {
        & $Action
        Write-Log ("SUCCESS: {0}" -f $Name)
        return $true
    } catch {
        Write-Log ("FAIL: {0} :: {1}" -f $Name, $_.Exception.Message) 'ERROR'
        return $false
    }
}

# ---------- Step 1: Defender Quick Scan ----------
Invoke-Step -Name "Microsoft Defender Quick Scan" -Action {
    if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
        # Optionally ensure signatures are up-to-date:
        # Update-MpSignature | Out-Null
        Start-MpScan -ScanType QuickScan       # Supported Defender cmdlet [1](https://learn.microsoft.com/en-us/powershell/module/defender/start-mpscan?view=windowsserver2025-ps)
    } else {
        throw "Start-MpScan not found. Windows Defender (Microsoft Defender Antivirus) cmdlets may be unavailable on this system."
    }
} | Out-Null

# ---------- Step 2: Wait before sync ----------
Invoke-Step -Name ("Wait {0} seconds" -f $WaitSeconds) -Action {
    Start-Sleep -Seconds $WaitSeconds
} | Out-Null

# ---------- Step 3: Intune Sync (best-effort) ----------

# 3A. Try MDM check-in via deviceenroller.exe with Enrollment ID(s)
$mdmSyncDone = $false
Invoke-Step -Name "MDM Sync via deviceenroller.exe (/o <EnrollmentID> /c /b)" -Action {
    $de = Join-Path $env:WINDIR 'System32\deviceenroller.exe'
    if (-not (Test-Path $de)) { throw "deviceenroller.exe not found" }

    # Find Enrollment IDs from EnterpriseMgmt scheduled task paths (GUIDs)
    $taskGuids = @()
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -like '\Microsoft\Windows\EnterpriseMgmt\*' }
    foreach ($t in $tasks) {
        if ($t.TaskPath -match '\\EnterpriseMgmt\\([0-9a-fA-F-]{36})\\') {
            $taskGuids += $Matches[1]
        }
    }
    $taskGuids = $taskGuids | Sort-Object -Unique

    if (-not $taskGuids -or $taskGuids.Count -eq 0) {
        throw "No Enrollment GUIDs discovered under EnterpriseMgmt scheduled tasks. (Tasks missing or device not MDM-enrolled?)"
    }

    foreach ($id in $taskGuids) {
        Write-Log ("Attempting deviceenroller.exe for EnrollmentID {0}" -f $id)
        # Community-documented way to kick off a proper MDM sync equivalent to the UI "Sync" button. [5](https://www.reddit.com/r/Intune/comments/13ppd7h/start_device_sync_via_powershell/)[6](https://www.reddit.com/r/Intune/comments/gyh1za/sync_via_command_line/)
        $args = "/o $id /c /b"
        $proc = Start-Process -FilePath $de -ArgumentList $args -PassThru -Wait -WindowStyle Hidden
        Write-Log ("deviceenroller.exe exit code for {0}: {1}" -f $id, $proc.ExitCode)
        if ($proc.ExitCode -eq 0) { $script:mdmSyncDone = $true }
    }
} | Out-Null

# 3B. Fallback: Start any EnterpriseMgmt "PushLaunch" tasks (triggers check-in via omadmclient)
if (-not $mdmSyncDone) {
    Invoke-Step -Name "Fallback: Start EnterpriseMgmt 'PushLaunch' tasks" -Action {
        $pushTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                     Where-Object { $_.TaskPath -like '\Microsoft\Windows\EnterpriseMgmt\*' -and $_.TaskName -eq 'PushLaunch' }
        if (-not $pushTasks) { throw "No 'PushLaunch' tasks found under EnterpriseMgmt." }
        foreach ($pt in $pushTasks) {
            Write-Log ("Starting task: {0}{1}" -f $pt.TaskPath, $pt.TaskName)
            Start-ScheduledTask -TaskName $pt.TaskName -TaskPath $pt.TaskPath
        }
        # These tasks are tied to WNS notifications and ultimately lead to omadmclient check-in. [2](https://techcommunity.microsoft.com/discussions/microsoft-intune/enterprise-mgmt--scheduled-tasks-missing/3444375)[3](https://call4cloud.nl/pushlaunch-queued-schedule-created-for-queued-alerts/)[4](https://joymalya.com/windows-devices-stopped-syncing-with-intune/)
    } | Out-Null
}

# 3C. Also trigger IME (Win32/app/script) sync
Invoke-Step -Name "Trigger IME sync (apps/scripts) via protocol" -Action {
    # Works for the IME agent (does not replace MDM policy sync). [7](https://github.com/okieselbach/Intune/blob/master/Create-ImeSyncBatch.ps1)[8](https://call4cloud.nl/restarting-services-no-local-admin-intune/)[9](https://learn.microsoft.com/lv-lv/intune/intune-service/apps/intune-management-extension)
    $shell = New-Object -ComObject Shell.Application
    $shell.Open('intunemanagementextension://syncapp')
    Start-Sleep -Seconds 2
    $shell.Open('intunemanagementextension://synccompliance')
} | Out-Null

Write-Log "All steps attempted. Review the log for details."
Write-Log "TIP: Verify MDM state with 'dsregcmd /status' (Managed by MDM should be YES) after a minute or two."  # [5](https://www.reddit.com/r/Intune/comments/13ppd7h/start_device_sync_via_powershell/)

# End of script# Set exec policy for THIS process (as requested)
Set-ExecutionPolicy Bypass -Scope Process -Force

# ================================
# QuickScan-Then-IntuneSync.ps1
# ================================
[CmdletBinding()]
param(
    [int]$WaitSeconds = 120,          # 2 min wait before sync
    [string]$LogFolder = "$env:ProgramData\IntuneTools\Logs"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Logging ----------
if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
$LogFile = Join-Path $LogFolder ("QuickScan-IntuneSync_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Write-Log {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO')
    $line = ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message)
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Write-Log ("Log file: {0}" -f $LogFile)

# ---------- Helper: Run and log a scriptblock with error handling ----------
function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Log ("START: {0}" -f $Name)
    try {
        & $Action
        Write-Log ("SUCCESS: {0}" -f $Name)
        return $true
    } catch {
        Write-Log ("FAIL: {0} :: {1}" -f $Name, $_.Exception.Message) 'ERROR'
        return $false
    }
}

# ---------- Step 1: Defender Quick Scan ----------
Invoke-Step -Name "Microsoft Defender Quick Scan" -Action {
    if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
        # Optionally ensure signatures are up-to-date:
        # Update-MpSignature | Out-Null
        Start-MpScan -ScanType QuickScan       # Supported Defender cmdlet [1](https://learn.microsoft.com/en-us/powershell/module/defender/start-mpscan?view=windowsserver2025-ps)
    } else {
        throw "Start-MpScan not found. Windows Defender (Microsoft Defender Antivirus) cmdlets may be unavailable on this system."
    }
} | Out-Null

# ---------- Step 2: Wait before sync ----------
Invoke-Step -Name ("Wait {0} seconds" -f $WaitSeconds) -Action {
    Start-Sleep -Seconds $WaitSeconds
} | Out-Null

# ---------- Step 3: Intune Sync (best-effort) ----------

# 3A. Try MDM check-in via deviceenroller.exe with Enrollment ID(s)
$mdmSyncDone = $false
Invoke-Step -Name "MDM Sync via deviceenroller.exe (/o <EnrollmentID> /c /b)" -Action {
    $de = Join-Path $env:WINDIR 'System32\deviceenroller.exe'
    if (-not (Test-Path $de)) { throw "deviceenroller.exe not found" }

    # Find Enrollment IDs from EnterpriseMgmt scheduled task paths (GUIDs)
    $taskGuids = @()
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -like '\Microsoft\Windows\EnterpriseMgmt\*' }
    foreach ($t in $tasks) {
        if ($t.TaskPath -match '\\EnterpriseMgmt\\([0-9a-fA-F-]{36})\\') {
            $taskGuids += $Matches[1]
        }
    }
    $taskGuids = $taskGuids | Sort-Object -Unique

    if (-not $taskGuids -or $taskGuids.Count -eq 0) {
        throw "No Enrollment GUIDs discovered under EnterpriseMgmt scheduled tasks. (Tasks missing or device not MDM-enrolled?)"
    }

    foreach ($id in $taskGuids) {
        Write-Log ("Attempting deviceenroller.exe for EnrollmentID {0}" -f $id)
        # Community-documented way to kick off a proper MDM sync equivalent to the UI "Sync" button. [5](https://www.reddit.com/r/Intune/comments/13ppd7h/start_device_sync_via_powershell/)[6](https://www.reddit.com/r/Intune/comments/gyh1za/sync_via_command_line/)
        $args = "/o $id /c /b"
        $proc = Start-Process -FilePath $de -ArgumentList $args -PassThru -Wait -WindowStyle Hidden
        Write-Log ("deviceenroller.exe exit code for {0}: {1}" -f $id, $proc.ExitCode)
        if ($proc.ExitCode -eq 0) { $script:mdmSyncDone = $true }
    }
} | Out-Null

# 3B. Fallback: Start any EnterpriseMgmt "PushLaunch" tasks (triggers check-in via omadmclient)
if (-not $mdmSyncDone) {
    Invoke-Step -Name "Fallback: Start EnterpriseMgmt 'PushLaunch' tasks" -Action {
        $pushTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                     Where-Object { $_.TaskPath -like '\Microsoft\Windows\EnterpriseMgmt\*' -and $_.TaskName -eq 'PushLaunch' }
        if (-not $pushTasks) { throw "No 'PushLaunch' tasks found under EnterpriseMgmt." }
        foreach ($pt in $pushTasks) {
            Write-Log ("Starting task: {0}{1}" -f $pt.TaskPath, $pt.TaskName)
            Start-ScheduledTask -TaskName $pt.TaskName -TaskPath $pt.TaskPath
        }
        # These tasks are tied to WNS notifications and ultimately lead to omadmclient check-in. [2](https://techcommunity.microsoft.com/discussions/microsoft-intune/enterprise-mgmt--scheduled-tasks-missing/3444375)[3](https://call4cloud.nl/pushlaunch-queued-schedule-created-for-queued-alerts/)[4](https://joymalya.com/windows-devices-stopped-syncing-with-intune/)
    } | Out-Null
}

# 3C. Also trigger IME (Win32/app/script) sync
Invoke-Step -Name "Trigger IME sync (apps/scripts) via protocol" -Action {
    # Works for the IME agent (does not replace MDM policy sync). [7](https://github.com/okieselbach/Intune/blob/master/Create-ImeSyncBatch.ps1)[8](https://call4cloud.nl/restarting-services-no-local-admin-intune/)[9](https://learn.microsoft.com/lv-lv/intune/intune-service/apps/intune-management-extension)
    $shell = New-Object -ComObject Shell.Application
    $shell.Open('intunemanagementextension://syncapp')
    Start-Sleep -Seconds 2
    $shell.Open('intunemanagementextension://synccompliance')
} | Out-Null

Write-Log "All steps attempted. Review the log for details."
Write-Log "TIP: Verify MDM state with 'dsregcmd /status' (Managed by MDM should be YES) after a minute or two."  # [5](https://www.reddit.com/r/Intune/comments/13ppd7h/start_device_sync_via_powershell/)

# End of script
