
<# 
.SYNOPSIS
  Uninstalls Slack (MSI), both machine-wide and per-user, with logging and safe process shutdown.

.NOTES
  Author: Convergys Corp – Endpoint Management
  Tested on: Windows 10/11 (x64)
  Run as: System (recommended for machine-wide); User for per-user remnants if needed

  Log: C:\ProgramData\Company\Logs\Slack-Uninstall.log
  Exit codes:
    0  = Success (Slack not present or removed)
    10 = Slack running could not be terminated
    20 = Uninstall command failed
    30 = Permissions/context issue
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [switch]$RemoveRemnants,   # Deletes leftover folders/files after uninstall
  [switch]$NoKill            # Skip stopping Slack processes (use only if coordinated shutdown)
)

# region Logging ---------------------------------------------------------------
$LogDir = 'C:\ProgramData\Company\Logs'
$Log    = Join-Path $LogDir 'Slack-Uninstall.log'
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

# Tee-Object for both console and file
function Write-Log {
  param([string]$Message, [string]$Level = 'INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[$ts][$Level] $Message"
  $line | Tee-Object -FilePath $Log -Append
}

Write-Log "Starting Slack uninstall..."

# region Helpers ---------------------------------------------------------------
function Get-UninstallItemsFromRegistry {
  param(
    [ValidateSet('HKLM','HKCU','HKU')]
    [string]$Hive = 'HKLM'
  )
  $paths = @()

  switch ($Hive) {
    'HKLM' {
      $paths += 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
      $paths += 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    }
    'HKCU' {
      $paths += 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    }
    'HKU' {
      # Enumerate all user profiles for per-user MSI
      Get-ChildItem 'HKU:' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '_Classes$' } |
        ForEach-Object {
          "$($_.Name)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        }
    }
  }

  $items = @()
  foreach ($p in $paths) {
    try {
      if (Test-Path $p) {
        $items += Get-ChildItem $p -ErrorAction SilentlyContinue
      }
    } catch { }
  }
  return $items
}

function Find-SlackMsi {
  # Returns objects with DisplayName, UninstallString, QuietUninstallString, ProductCode, RegPath
  $candidates = @()

  foreach ($h in @('HKLM','HKCU','HKU')) {
    foreach ($key in Get-UninstallItemsFromRegistry -Hive $h) {
      try {
        $props = Get-ItemProperty $key.PSPath -ErrorAction Stop

        $name = $props.DisplayName
        if ($null -ne $name -and $name -match '(?i)^Slack|Slack.*MSI|Slack \(Machine.*\)|Slack Deployment Tool') {
          $obj = [PSCustomObject]@{
            DisplayName           = $props.DisplayName
            UninstallString       = $props.UninstallString
            QuietUninstallString  = $props.QuietUninstallString
            ProductCode           = $props.PSChildName  # often the GUID under Uninstall
            RegPath               = $key.PSPath
            Hive                  = $h
          }
          $candidates += $obj
        }
      } catch { }
    }
  }

  # Prefer machine-wide entries first, then per-user
  $ordered = $candidates | Sort-Object {
    if ($_.Hive -eq 'HKLM') { 0 } elseif ($_.Hive -eq 'HKU') { 1 } else { 2 }
  }
  return $ordered
}

function Expand-MsiUninstallCommand {
  param([string]$UninstallString, [string]$ProductCode)

  # Normalize typical MSI strings to "msiexec /x {GUID} /qn"
  if ($UninstallString -match '(?i)msiexec\.exe|msiexec') {
    # If GUID present in key name, prefer it
    if ($ProductCode -match '^\{[0-9A-F-]+\}$') {
      return "msiexec.exe /x $ProductCode /qn /norestart"
    }
    # Extract GUID from command if available
    $guidMatch = :Match($UninstallString, '\{[0-9A-F-]+\}')
    if ($guidMatch.Success) {
      return "msiexec.exe /x $($guidMatch.Value) /qn /norestart"
    }
    # Fallback: run original with silent switches appended
    return "$UninstallString /qn /norestart"
  }

  # Some entries use helper EXEs; try quiet string first
  if ($UninstallString) { return "$UninstallString /quiet /norestart" }
  return $null
}

function Stop-SlackProcesses {
  if ($NoKill) { 
    Write-Log "Skipping process stop due to -NoKill."
    return $true 
  }

  $procNames = @('slack','Update','Squirrel','SlackHelper','Slack.exe','Update.exe')
  $ok = $true

  foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
    if ($procNames -contains $p.Name -or $p.Path -match '(?i)\\Slack\\') {
      try {
        Write-Log "Stopping process: $($p.Name) (PID $($p.Id))"
        $p.CloseMainWindow() | Out-Null
        Start-Sleep -Milliseconds 400
        if (!$p.HasExited) { $p.Kill() }
      } catch {
        Write-Log "Failed to stop $($p.Name): $($_.Exception.Message)" 'WARN'
        $ok = $false
      }
    }
  }
  return $ok
}

# endregion Helpers ------------------------------------------------------------

# region Uninstall -------------------------------------------------------------
# 1) Detect MSI entries related to Slack
$slackEntries = Find-SlackMsi
if (-not $slackEntries -or $slackEntries.Count -eq 0) {
  Write-Log "Slack MSI not found in uninstall registry keys. Assuming already removed."
  exit 0
}

# 2) Stop running Slack processes
if (-not (Stop-SlackProcesses)) {
  Write-Log "Could not terminate all Slack processes." 'ERROR'
  # proceed anyway to let MSI handle; set non-blocking error code at end
  $procIssue = $true
}

$overallSuccess = $true

foreach ($entry in $slackEntries) {
  Write-Log "Found: [$($entry.Hive)] $($entry.DisplayName) @ $($entry.RegPath)"

  $cmd = Expand-MsiUninstallCommand -UninstallString $entry.UninstallString -ProductCode $entry.ProductCode
  if (-not $cmd) {
    Write-Log "No usable uninstall command for: $($entry.DisplayName)" 'WARN'
    $overallSuccess = $false
    continue
  }

  Write-Log "Executing: $cmd"
  $p = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $cmd" -Wait -PassThru -WindowStyle Hidden
  $code = $p.ExitCode

  if ($code -eq 0) {
    Write-Log "Uninstall completed with exit code $code."
  } else {
    Write-Log "Uninstall returned non-zero exit code: $code." 'ERROR'
    $overallSuccess = $false
  }
}

# 3) Optional cleanup
if ($RemoveRemnants) {
  $paths = @(
    "$Env:ProgramFiles\Slack",
    "${Env:ProgramFiles(x86)}\Slack",
    "$Env:LOCALAPPDATA\slack",
    "$Env:APPDATA\Slack",
    "C:\Users\Default\AppData\Local\slack"
  )
  foreach ($path in $paths) {
    try {
      if (Test-Path $path) {
        Write-Log "Removing remnants: $path"
        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
      }
    } catch {
      Write-Log "Failed to remove $path: $($_.Exception.Message)" 'WARN'
    }
  }
}

# 4) Final status
if ($overallSuccess) {
  if ($procIssue) { exit 10 }
  Write-Log "Slack uninstall finished successfully."
  exit 0
} else {
  Write-Log "Slack uninstall completed with errors." 'ERROR'
  exit 20
}
# endregion Uninstall ----------------------------------------------------------
