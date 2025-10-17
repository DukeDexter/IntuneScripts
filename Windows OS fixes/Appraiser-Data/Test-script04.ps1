# Full Script: Appraiser Refresh + Intune Validation + Auto-Remediation + Reporting
$TaskName = "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
$LogFile = "C:\Temp\Appraiser_Intune_Remediation.log"
$ReportFile = "C:\Temp\Appraiser_Intune_Report.csv"

# Ensure directories exist
if (!(Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" }

# Initialize report array
$Report = @()

Add-Content $LogFile "`n[$(Get-Date)] Starting Appraiser and Intune checks..."

# --- Check Appraiser Task ---
$AppraiserStatus = "OK"
$task = Get-ScheduledTask -TaskName "Microsoft Compatibility Appraiser" -TaskPath "\Microsoft\Windows\Application Experience\" -ErrorAction SilentlyContinue
if ($task) {
    $info = Get-ScheduledTaskInfo -TaskName "Microsoft Compatibility Appraiser" -TaskPath "\Microsoft\Windows\Application Experience\"
    if (([datetime]::Now - $info.LastRunTime).Days -gt 7 -or $info.LastTaskResult -ne 0) {
        schtasks /run /tn $TaskName | Out-Null
        $AppraiserStatus = "Refreshed"
    }
} else {
    $AppraiserStatus = "Missing"
    sfc /scannow
    DISM /Online /Cleanup-Image /RestoreHealth
}

# --- Validate Intune Enrollment ---
$dsreg = dsregcmd /status
$aadJoined = ($dsreg | Select-String "AzureAdJoined").ToString()
$enterpriseJoined = ($dsreg | Select-String "EnterpriseJoined").ToString()
$mdmUrl = ($dsreg | Select-String "MdmUrl").ToString()
$prtStatus = ($dsreg | Select-String "AzureAdPrt").ToString()

$EnrollmentStatus = "Healthy"
$RemediationAction = "None"

if ($aadJoined -notmatch "YES" -or $enterpriseJoined -notmatch "YES" -or $mdmUrl -notmatch "manage.microsoft.com") {
    $EnrollmentStatus = "Broken"
    try {
        dsregcmd /leave
        Restart-Computer -Force
        dsregcmd /join
        $RemediationAction = "Rejoined AAD"
    } catch {
        $RemediationAction = "Failed"
    }
}

# --- Trigger Intune Sync ---
Invoke-Expression "Start-Process -FilePath 'IntuneManagementExtension.exe' -ArgumentList '-sync' -NoNewWindow"

# --- Build Report Row ---
$Report += [PSCustomObject]@{
    DeviceName        = $env:COMPUTERNAME
    AppraiserStatus   = $AppraiserStatus
    AADJoined         = if ($aadJoined -match "YES") {"YES"} else {"NO"}
    EnterpriseJoined  = if ($enterpriseJoined -match "YES") {"YES"} else {"NO"}
    MDMUrl            = if ($mdmUrl -match "manage.microsoft.com") {"Present"} else {"Missing"}
    PRTStatus         = if ($prtStatus -match "YES") {"YES"} else {"NO"}
    EnrollmentStatus  = $EnrollmentStatus
    RemediationAction = $RemediationAction
    Timestamp         = (Get-Date)
}

# Export report
$Report | Export-Csv -Path $ReportFile -NoTypeInformation
Add-Content $LogFile "Report saved to $ReportFile"

Write-Host "Process complete. Log: $LogFile | Report: $ReportFile"
