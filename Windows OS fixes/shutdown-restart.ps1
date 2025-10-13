<#
.SYNOPSIS
Audits and fixes missing Shutdown/Restart options caused by policy settings.
Logs results for reporting.

.DESCRIPTION
Checks registry and local policy for "NoClose" value that hides shutdown/restart.
Removes the restriction if present and logs actions to a file.

#>

# Define log file path (adjust as needed)
$LogPath = "C:\Temp\ShutdownRestartPolicy_Audit.log"

# Ensure log directory exists
if (!(Test-Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force
}

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "$timestamp | $env:COMPUTERNAME | $env:USERNAME | $Message"
    Add-Content -Path $LogPath -Value $entry
}

function Fix-ShutdownRestartPolicy {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $valueName = "NoClose"

    Write-Host "Auditing shutdown/restart policy..." -ForegroundColor Cyan
    Write-Log "Audit started."

    if (Test-Path $regPath) {
        $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

        if ($null -ne $currentValue.$valueName -and $currentValue.$valueName -eq 1) {
            Write-Host "Restriction found! Removing NoClose value..." -ForegroundColor Yellow
            Remove-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
            Write-Host "Policy fixed. Shutdown/Restart options should now be visible." -ForegroundColor Green
            Write-Log "Restriction found and removed."
        }
        else {
            Write-Host "No restriction found. Settings are OK." -ForegroundColor Green
            Write-Log "No restriction found."
        }
    }
    else {
        Write-Host "Registry path not found. No restriction applied." -ForegroundColor Green
        Write-Log "Registry path not found."
    }

    # Optional: Force Group Policy update
    Write-Host "Refreshing Group Policy..." -ForegroundColor Cyan
    gpupdate /force | Out-Null
    Write-Log "Group Policy refreshed."
    Write-Log "Audit completed."
}

# Run the function
Fix-ShutdownRestartPolicy

Write-Host "`nLog saved to: $LogPath" -ForegroundColor Cyan
