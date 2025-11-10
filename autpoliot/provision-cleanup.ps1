# Run in elevated PowerShell

# --- A. Stop provisioning services/tasks that may lock objects
Get-ScheduledTask -TaskName *Prov* -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue

# --- B. Clear Provisioning registry state (safe reset of provisioning history/state)
$provRegPaths = @(
  "HKLM:\SOFTWARE\Microsoft\Provisioning",
  "HKLM:\SOFTWARE\Microsoft\Provisioning\Autopilot",
  "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics"
)
foreach ($p in $provRegPaths) {
  if (Test-Path $p) { 
    Write-Host "Removing $p"
    Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue 
  }
}

# --- C. Remove old PPKG staging folders (if present)
$ppkgDirs = @(
  "C:\Windows\Provisioning\Packages",
  "C:\Windows\Provisioning\Logs\Packages"
)
foreach ($d in $ppkgDirs) {
  if (Test-Path $d) {
    Write-Host "Cleaning $d"
    Get-ChildItem $d -Recurse -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
  }
}

# --- D. Optional: remove a known duplicate Wi-Fi profile (replace 'CorpWiFi' with your SSID)
# netsh wlan delete profile name="CorpWiFi"

# --- E. Optional: remove a known duplicate local account that PPKG creates (replace 'ppkgadmin')
# $u = Get-LocalUser -Name "ppkgadmin" -ErrorAction SilentlyContinue
# if ($u) { Remove-LocalUser -Name "ppkgadmin" }

# --- F. Optional: remove a known certificate subject you import in PPKG (example subject string)
# $subjectContains = "CN=Contoso-Root"
# Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*$subjectContains*"} | 
#   ForEach-Object { Write-Host "Removing cert $($_.Thumbprint)"; Remove-Item $_.PSPath }

# --- G. OS image health (safe to run)
DISM /Online /Cleanup-Image /RestoreHealth

# --- H. Reboot to flush handles
Restart-Computer
