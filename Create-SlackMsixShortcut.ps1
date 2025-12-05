
<#
.SYNOPSIS
  Creates a desktop shortcut for Slack when deployed as MSIX (PFN auto-detected).
.DESCRIPTION
Locates Slack MSIX via Get-AppxPackage; falls back to Start apps for hints.
Creates a .lnk on the current user's Desktop (default) or Public Desktop with -PublicDesktop.
Fails fast if Slack is MSI or MSIX is not found.
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
if ($PublicDesktop) { return "C:\Users\Public\Desktop" }
try {
$path = :GetFolderPath('Desktop')
if (-not :IsNullOrWhiteSpace($path)) { return $path }
} catch { }
return (Join-Path $env:USERPROFILE 'Desktop')
}
function Get-SlackTarget {
1) Try direct MSIX package query
$pkg = Get-AppxPackage -ErrorAction SilentlyContinue |
Where-Object {
$.Name -like 'Slack' -or $.Publisher -like 'Slack'
} |
Select-Object -First 1
if ($pkg -and $pkg.PackageFamilyName) {
Write-Verbose "Found PFN via Get-AppxPackage: $($pkg.PackageFamilyName)"
# Typical MSIX launch target
return "shell:AppsFolder$($pkg.PackageFamilyName)!App"
}
2) Fallback: Start menu entry (AppID may already include PFN!App)
$startApp = Get-StartApps | Where-Object {
$.Name -match '(?i)^Slack' -or $.AppID -match '(?i)Slack'
} | Select-Object -First 1
if ($startApp) {
Write-Verbose "Slack appears in Start apps: Name='$($startApp.Name)', AppID='$($startApp.AppID)'."
# If AppID looks like PFN!something, use it directly
if ($startApp.AppID -match '^[A-Za-z0-9.]+_[A-Za-z0-9]+!') {
return "shell:AppsFolder$($startApp.AppID)"
}
}
return $null
}
Resolve desktop location
$desktop = Get-DesktopPath
if (-not (Test-Path $desktop)) {
New-Item -ItemType Directory -Path $desktop -Force | Out-Null
Write-Verbose "Created desktop folder: $desktop"
}
Detect target for Slack MSIX
$target = Get-SlackTarget
if (-not $target) {
Write-Error "Slack MSIX package was not found. If Slack is installed via MSI, uninstall it and install the MSIX package first, then rerun this script."
exit 1
}
Build .lnk path and create shortcut
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
Write-Error ("Failed to create shortcut at '{0}': {1}" -f $lnkPath, $.Exception.Message)
exit 2
}

