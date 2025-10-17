# Check and Refresh Appraiser Data
$TaskName = "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
$LogFile = "C:\Temp\AppraiserRefresh.log"

# Ensure log directory exists
if (!(Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" }

# Get task details
$task = Get-ScheduledTask -TaskName "Microsoft Compatibility Appraiser" -TaskPath "\Microsoft\Windows\Application Experience\" -ErrorAction SilentlyContinue

if ($task) {
    $lastRun = (Get-ScheduledTaskInfo -TaskName "Microsoft Compatibility Appraiser" -TaskPath "\Microsoft\Windows\Application Experience\").LastRunTime
    $status = (Get-ScheduledTaskInfo -TaskName "Microsoft Compatibility Appraiser" -TaskPath "\Microsoft\Windows\Application Experience\").LastTaskResult

    # Log current status
    Add-Content $LogFile "[$(Get-Date)] Task found. LastRun: $lastRun, Status: $status"

    # If last run was more than 7 days ago or status not 0 (success), trigger refresh
    if (([datetime]::Now - $lastRun).Days -gt 7 -or $status -ne 0) {
        Add-Content $LogFile "[$(Get-Date)] Triggering Appraiser refresh..."
        schtasks /run /tn $TaskName | Out-Null
        Add-Content $LogFile "[$(Get-Date)] Task triggered."
    } else {
        Add-Content $LogFile "[$(Get-Date)] Appraiser data is up-to-date."
    }
} else {
    Add-Content $LogFile "[$(Get-Date)] Task not found. Attempting to register..."
    # Re-register task if missing
    sfc /scannow
    DISM /Online /Cleanup-Image /RestoreHealth
    Add-Content $LogFile "[$(Get-Date)] System repair initiated for missing task."
}

Write-Host "Appraiser check complete. Log saved to $LogFile"
