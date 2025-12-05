
<#
.SYNOPSIS
  Creates a desktop shortcut for Slack when deployed as MSIX (PFN auto-detected).

.DESCRIPTION
  - Locates Slack MSIX via Get-AppxPackage; falls back to Start apps for hints.
  - Creates a .lnk on the current user's Desktop (default) or Public Desktop with -PublicDesktop.
  - Fails fast if Slack is MSI or MSIX is not found.

.PARAMETERS
  -ShortcutName    Optional. Shortcut base name; default "Slack".
  -PublicDesktop   Optional. Write to C:\Users\Public\Desktop instead of current user's Desktop.
  -Verbose         Shows detailed output.
#>

[CmdletBinding()]
param(
  [string]$ShortcutName = "Slack",
  [switch]$PublicDesktop
)

function Get-DesktopPath {
  if ($PublicDesktop) { return "C:\\Users\\Public\\Desktop" }
  try {
    $path = [Environment]::GetFolderPath('Desktop')
    if (-not [string]::IsNullOrWhiteSpace($path)) { return $path }
  } catch {}
  return (Join-Path $env:USERPROFILE 'Desktop')
}

function Get-SlackPFN {
  # 1) Try direct MSIX package query
  $pkg = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
    //microsoftapc-m.Name -like '*Slack*' -or //microsoftapc-m.Publisher -like '*Slack*'
  } | Select-Object -First 1

  if ($pkg -and $pkg.PackageFamilyName) {
    Write-Verbose "Found PFN via Get-AppxPackage: $($pkg.PackageFamilyName)"
    return $pkg.PackageFamilyName
  }

  # 2) Fallback hint: Start menu entry (display name). PFN still required for shell:AppsFolder.
  $startApp = Get-StartApps | Where-Object {
    //microsoftapc-m.Name -match '(?i)^Slack -or //microsoftapc-m.AppID -match '(?i)Slack'
  } | Select-Object -First 1

  if ($startApp) {
    Write-Verbose "Slack appears in Start apps: Name='$($startApp.Name)', AppID='$($startApp.AppID)'."
  }

  return $null
}

# Resolve desktop location
$desktop = Get-DesktopPath
if (-not (Test-Path $desktop)) { New-Item -ItemType Directory -Path $desktop -Force | Out-Null }

# Detect PFN
$PFN = Get-SlackPFN
if (-not $PFN) {
  Write-Error "Slack MSIX package was not found. If Slack is installed via MSI, uninstall it and install the MSIX package first, then rerun this script."
  exit 1
}

# Build target and create shortcut
$target = "shell:AppsFolder\\$PFN!App"
$lnkPath = Join-Path $desktop ("{0}.lnk" -f $ShortcutName)

try {
  $wsh = New-Object -ComObject WScript.Shell
  $shortcut = $wsh.CreateShortcut($lnkPath)
  $shortcut.TargetPath   = $target
  $shortcut.IconLocation = "$target,0"
  $shortcut.Description  = "Shortcut to $ShortcutName"
  $shortcut.Save()
  Write-Host "Created shortcut: $lnkPath"
  exit 0
}
catch {
  Write-Error "Failed to create shortcut at '$lnkPath': $(//microsoftapc-m.Exception.Message)"
  exit 2
}
