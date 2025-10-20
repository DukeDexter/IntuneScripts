# Default report path
$ReportFile = "C:\ProgramData\IntuneComplianceReport.csv"

# Check if ProgramData is writable; fallback to C:\Temp if not
try {
    $testFile = "C:\ProgramData\test.txt"
    New-Item -Path $testFile -ItemType File -Force | Out-Null
    Remove-Item $testFile -Force
} catch {
    if (!(Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" }
    $ReportFile = "C:\Temp\IntuneComplianceReport.csv"
}

# Initialize compliance object
$Compliance = [ordered]@{
    DeviceName        = $env:COMPUTERNAME
    AppraiserStatus   = "Unknown"
    AADJoined         = "Unknown"
    EnterpriseJoined  = "Unknown"
    MDMUrl            = "Unknown"
    PRTStatus         = "Unknown"
    EnrollmentStatus  = "Unknown"
    RemediationAction = "None"
    WUReadiness       = "Unknown"
    HealthStatus      = "Unknown"
    ServiceHealth     = @{}
    Timestamp         = (Get-Date)
}

# --- Refresh Appraiser Data ---
try {
    $taskInfo = Get-ScheduledTaskInfo -TaskName "Microsoft Compatibility Appraiser" -TaskPath "\Microsoft\Windows\Application Experience\" -ErrorAction SilentlyContinue
    if ($taskInfo) {
        if (([datetime]::Now - $taskInfo.LastRunTime).Days -gt 7 -or $taskInfo.LastTaskResult -ne 0) {
            schtasks /run /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
            $Compliance.AppraiserStatus = "Refreshed"
        } else { $Compliance.AppraiserStatus = "OK" }
    } else { $Compliance.AppraiserStatus = "Missing" }
} catch { $Compliance.AppraiserStatus = "Error" }

# --- Validate Intune Enrollment ---
try {
    $dsreg = dsregcmd /status
    $Compliance.AADJoined        = if ($dsreg -match "AzureAdJoined.*YES") {"YES"} else {"NO"}
    $Compliance.EnterpriseJoined = if ($dsreg -match "EnterpriseJoined.*YES") {"YES"} else {"NO"}
    $Compliance.MDMUrl           = if ($dsreg -match "manage.microsoft.com") {"Present"} else {"Missing"}
    $Compliance.PRTStatus        = if ($dsreg -match "AzureAdPrt.*YES") {"YES"} else {"NO"}

    if ($Compliance.AADJoined -eq "YES" -and $Compliance.MDMUrl -eq "Present") {
        $Compliance.EnrollmentStatus = "Healthy"
    } else {
        $Compliance.EnrollmentStatus = "Broken"
        try {
            dsregcmd /leave
            Restart-Computer -Force
            dsregcmd /join
            $Compliance.RemediationAction = "Rejoined AAD"
        } catch { $Compliance.RemediationAction = "Failed" }
    }
} catch { $Compliance.EnrollmentStatus = "Error" }

# --- Trigger Intune Sync ---
Start-Process "IntuneManagementExtension.exe" -ArgumentList "-sync" -NoNewWindow -ErrorAction SilentlyContinue

# --- Windows Update Readiness ---
try {
    $WUScan = Get-WindowsUpdateLog
    $Compliance.WUReadiness = if ($WUScan -match "Feature update eligibility") {"Eligible"} elseif ($WUScan -match "Not eligible") {"NotEligible"} else {"Unknown"}
} catch { $Compliance.WUReadiness = "CheckFailed" }

# --- Health Attestation ---
try {
    $HealthCheck = Get-CimInstance -Namespace root\\cimv2\\mdm\\dmmap -ClassName MDM_HealthAttestation
    $Compliance.HealthStatus = if ($HealthCheck.HealthStatus -eq "Attestable") {"Healthy"} else {"Failed"}
} catch { $Compliance.HealthStatus = "Unavailable" }

# --- Critical Services Check ---
$CriticalServices = 'DiagTrack','dmwappushservice','wuauserv','BITS','UsoSvc','Winmgmt','Schedule'
foreach ($svc in $CriticalServices) {
    try {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Running') {
                try {
                    Start-Service $svc -ErrorAction SilentlyContinue
                } catch {}
            }
            $Compliance.ServiceHealth[$svc] = "$($service.Status) / $($service.StartType)"
        } else {
            $Compliance.ServiceHealth[$svc] = "NotFound"
        }
    } catch {
        $Compliance.ServiceHealth[$svc] = "Error"
    }
}

# --- Export Report ---
$Compliance | Export-Csv -Path $ReportFile -NoTypeInformation
Write-Output ($Compliance | ConvertTo-Json -Compress)
