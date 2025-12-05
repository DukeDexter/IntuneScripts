
<# Creates a desktop shortcut for Slack (MSIX) #>

param(
  [Parameter(Mandatory=$true)]
  [string]$PackageFamilyName,     # e.g. SlackTechnologies.Slack_8wekyb3d8bbwe (example – use actual PFN)
  [string]$ShortcutName = "Slack" # .lnk file name
)

# Resolve current user's Desktop
$desktop = :GetFolderPath('Desktop')
if (-not (Test-Path $desktop)) {
  $desktop = Join-Path $env:USERPROFILE 'Desktop'
}

# Target packaged app via shell:AppsFolder
$target = "shell:AppsFolder\$PackageFamilyName!App"

# Create .lnk using WScript.Shell
$wsh = New-Object -ComObject WScript.Shell
$lnkPath = Join-Path $desktop ("{0}.lnk" -f $ShortcutName)
$shortcut = $wsh.CreateShortcut($lnkPath)
$shortcut.TargetPath   = $target
$shortcut.IconLocation = "$target,0"
$shortcut.Description  = "Shortcut to Slack"
$shortcut.Save()
Write-Host "Created shortcut: $lnkPath"
