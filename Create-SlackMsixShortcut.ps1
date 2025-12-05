
<#
.SYNOPSIS
  Creates a desktop shortcut for Slack when deployed as MSIX (PFN auto-detected),
  with MSI fallback if MSIX is not found.

.Author
Duke Dexter (https://github.com/DukeDexter)
 
.DESCRIPTION
Tries to locate Slack MSIX via Get-AppxPackage; if found, uses AppsFolder PFN!App target.
Falls back to Get-StartApps; if AppID already includes PFN!<app>, uses that.
If no MSIX is found, auto-detects MSI installation (common slack.exe paths) and targets the EXE.
Creates a .lnk on the current user's Desktop (default) or Public Desktop with -PublicDesktop.
.PARAMETERS
-ShortcutName    Optional. Shortcut name; default "Slack".
-PublicDesktop   Optional. Write to C:\Users\Public\Desktop (requires elevation to be useful).
-Verbose         Shows detailed output.
.NOTES
Tested on PowerShell 5.1+ (Windows). Requires COM object WScript.Shell.
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
function Get-SlackTargetMsix {
1) Try direct MSIX package query
$pkg = Get-AppxPackage -ErrorAction SilentlyContinue |
Where-Object { $.Name -like 'Slack' -or $.Publisher -like 'Slack' } |
Select-Object -First 1
if ($pkg -and $pkg.PackageFamilyName) {
Write-Verbose "Found Slack PFN via Get-AppxPackage: $($pkg.PackageFamilyName)"
return "shell:AppsFolder$($pkg.PackageFamilyName)!App"
}
2) Fallback: Start menu entry (AppID may already include PFN!<app>)
$startApp = Get-StartApps |
Where-Object { $.Name -match '(?i)^Slack' -or $.AppID -match '(?i)Slack' } |
Select-Object -First 1
if ($startApp) {
Write-Verbose "Slack appears in Start apps: Name='$($startApp.Name)', AppID='$($startApp.AppID)'."
if ($startApp.AppID -match '^[A-Za-z0-9.]+_[A-Za-z0-9]+!') {
# This is already PFN!<app>; AppsFolder can launch it directly
return "shell:AppsFolder$($startApp.AppID)"
}
}
return $null
}
function Get-SlackExe {
Common MSI install/extract locations
$candidates = @(
"$env:LOCALAPPDATA\slack\slack.exe",
"$env:LOCALAPPDATA\Programs\slack\slack.exe",
"C:\Program Files\Slack\slack.exe",
"C:\Program Files (x86)\Slack\slack.exe"
)
foreach ($p in $candidates) {
if (Test-Path -LiteralPath $p) {
Write-Verbose "Found Slack MSI executable: $p"
return $p
}
}
Optional: look up via registry (uncomment if desired)
try {
$regPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\slack.exe'
$regAlt  = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\slack.exe'
foreach ($r in @($regPath, $regAlt)) {
$exe = (Get-ItemProperty -Path $r -ErrorAction SilentlyContinue).'(Default)'
if ($exe -and (Test-Path -LiteralPath $exe)) { return $exe }
}
} catch { }
return $null
}
---------------------------
Resolve Desktop destination
---------------------------
$desktop = Get-DesktopPath
if (-not (Test-Path -LiteralPath $desktop)) {
New-Item -ItemType Directory -Path $desktop -Force | Out-Null
Write-Verbose "Created desktop folder: $desktop"
}
---------------------------
Determine target (MSIX first, then MSI)
---------------------------
$target = Get-SlackTargetMsix
if (-not $target) {
Write-Verbose "MSIX target not found; attempting MSI fallback."
$exe = Get-SlackExe
if ($exe) {
$target = $exe
} else {
Write-Error "Slack was not found as MSIX (Store/MSIX) or MSI executable. Install Slack and re-run."
exit 1
}
}
---------------------------
Create the shortcut (.lnk)
---------------------------
$lnkPath = Join-Path $desktop ("{0}.lnk" -f $ShortcutName)
try {
$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut($lnkPath)
$shortcut.TargetPath   = $target
Icon for MSI target: prefer app icon; otherwise default to target,0
if ($target -like '*.exe') {
$shortcut.IconLocation = "$target,0"
} else {
# MSIX AppFolder targets can use themselves
$shortcut.IconLocation = "$target,0"
}
$shortcut.Description  = "Shortcut to $ShortcutName"
$shortcut.Save()
Write-Host "Created shortcut: $lnkPath"
exit 0
}
catch {
Write-Error ("Failed to create shortcut at '{0}': {1}" -f $lnkPath, $_.Exception.Message)
exit 2
}

