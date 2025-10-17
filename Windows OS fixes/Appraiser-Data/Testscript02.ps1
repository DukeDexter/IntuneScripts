# Extended Script: Refresh Appraiser Data + Validate Intune Enrollment + Trigger Sync
$TaskName = "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
$LogFile = "C:\Temp\Appraiser_Intune_Check.log"

# Ensure log directory exists
if (!(Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" }

Add-Content $LogFile "`n[$(Get-Date)] Starting Appraiser and Intune checks..."

# --- Check Appraiser Task ---
$task = Get-ScheduledTask -TaskName "Microsoft Compatibility Appraiser" -TaskPath "\Microsoft\Windows\Application Experience\" -ErrorAction SilentlyContinue
if ($task) {
    $info = Get-ScheduledTaskInfo -TaskName "Microsoft Compatibility Appraiser" -TaskPath "\Microsoft\Windows\Application Experience\"
    Add-Content $LogFile "Appraiser Task Found. LastRun: $($info.LastRunTime), Status: $($info.LastTaskResult)"
    
    if (([datetime]::Now - $info.LastRunTime).Days -gt 7 -or $info.LastTaskResult -ne 0) {
        Add-Content $LogFile "Triggering Appraiser refresh..."
        schtasks /run /tn $TaskName | Out-Null
        Add-Content $LogFile "Appraiser task triggered."
    } else {
        Add-Content $LogFile "Appraiser data is up-to-date."
    }
} else {
    Add-Content $LogFile "Appraiser task missing. Attempting system repair..."
    sfc /scannow
    DISM /Online /Cleanup-Image /RestoreHealth
}

# --- Validate Intune Enrollment ---
Add-Content $LogFile "`nChecking Intune Enrollment Status..."
$dsreg = dsregcmd /status
$aadJoined = ($dsreg | Select-String "AzureAdJoined").ToString()
$mdmUrl = ($dsreg | Select-String "MdmUrl").ToString()
$prtStatus = ($dsreg | Select-String "AzureAdPrt").ToString()

Add-Content $LogFile "AAD Join: $aadJoined"
Add-Content $LogFile "MDM URL: $mdmUrl"
Add-Content $LogFile "PRT Status: $prtStatus"

if ($aadJoined -match "YES" -and $mdmUrl -match "manage.microsoft.com") {
    Add-Content $LogFile "Device is enrolled in Intune."
} else {
    Add-Content $LogFile "Device NOT properly enrolled. Consider running dsregcmd /join."
}

# --- Trigger Intune Sync ---
Add-Content $LogFile "`nTriggering Intune Sync..."
Invoke-Expression "Start-Process -FilePath 'IntuneManagementExtension.exe' -ArgumentList '-sync' -NoNewWindow"
Add-Content $LogFile "Intune sync initiated."

Write-Host "Process complete. Log saved to $LogFile"
