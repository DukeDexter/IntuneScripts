# Script V1 - I will work on enhancing it to include additional functions.

# Uninstall SCCM Client
$ccmUninstallPath = "C:\Windows\ccmsetup\ccmsetup.exe"
 
if (Test-Path $ccmUninstallPath) {
    try {
        Start-Process -FilePath $ccmUninstallPath -ArgumentList "/uninstall" -Wait -Verb RunAs
        Write-Output "SCCM client uninstall initiated."
    } catch {
        Write-Output "Uninstall failed: $_"
        exit 1
    }
} else {
    Write-Output "ccmsetup.exe not found."
}
 
# Wait for uninstall to complete
Start-Sleep -Seconds 30
 
# Registry Cleanup
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\CCM",
    "HKLM:\SOFTWARE\Microsoft\SMS",
    "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client",
    "HKLM:\SOFTWARE\Microsoft\SMS\Components",
    "HKLM:\SOFTWARE\Microsoft\SMS\Tracing",
    "HKLM:\SOFTWARE\Microsoft\SMS\Setup",
    "HKLM:\SOFTWARE\Microsoft\SMS\Task Sequence",
    "HKLM:\SOFTWARE\Microsoft\SMS\DP",
    "HKLM:\SOFTWARE\Microsoft\SMS\MP"
)
 
foreach ($path in $regPaths) {
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force
            Write-Output "Removed registry path: $path"
        } catch {
            Write-Output "Failed to remove registry path: $path - $_"
        }
    }
}
 
# Optional: Remove leftover folders
$folders = @("C:\Windows\CCM", "C:\Windows\CCMSetup", "C:\Windows\SMSCFG.ini")
foreach ($folder in $folders) {
    if (Test-Path $folder) {
        try {
            Remove-Item -Path $folder -Recurse -Force
            Write-Output "Removed folder: $folder"
        } catch {
            Write-Output "Failed to remove folder: $folder - $_"
        }
    }
}

# Reboot the machine after cleanup

<#
\\ Write-Output "Rebooting the machine to complete cleanup..."
\\ Restart-Computer -Force
#>
