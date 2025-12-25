# Parameters (hardcoded for SCCM Script execution)
$SiteCode = "  "
$MP = "  "
$AADClientAppId = ""
$AADTenantId = " "
$CCMSetupPaths = @("C:\Windows\ccmsetup\ccmsetup.exe", "C:\ProgramData\Installers\MECM\ccmsetup.exe")
 
function Start-Log {
    param([string]$Prefix)
    $global:logFile = "$env:SystemRoot\CCM\Logs\${Prefix}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    if ($TranscriptEnabled) { Stop-Transcript | Out-Null }
    Start-Transcript -Path $logFile -Append
}
 
function Stop-Log {
    if ($TranscriptEnabled) { Stop-Transcript | Out-Null }
}
 
function Get-DsregStatus {
    $dsregCmdPath = "$env:SystemRoot\System32\dsregcmd.exe"
    if (-not (Test-Path $dsregCmdPath)) {
        Write-Output "[ERROR] dsregcmd.exe not found at $dsregCmdPath"
        return [PSCustomObject]@{
            AzureAdJoined = "Not Found"
            DeviceName    = "Not Found"
            DeviceId      = "Not Found"
        }
    }
 
    try {
        $dsregOutput = & $dsregCmdPath /status
    } catch {
        Write-Output "[ERROR] Failed to run dsregcmd.exe: $_"
        return [PSCustomObject]@{
            AzureAdJoined = "Not Found"
            DeviceName    = "Not Found"
            DeviceId      = "Not Found"
        }
    }
 
    function Get-DsregValue {
        param ([string]$Key)
        $line = $dsregOutput | Where-Object { $_ -match "$Key\s*:\s*(.+)" }
        if ($line) {
            return ($line -replace ".*$Key\s*:\s*", "").Trim()
        } else {
            return "Not Found"
        }
    }
 
    return [PSCustomObject]@{
        AzureAdJoined = Get-DsregValue "AzureAdJoined"
        DeviceName    = Get-DsregValue "Device Name"
        DeviceId      = Get-DsregValue "DeviceId"
    }
}
 
function Read-CoMgmtFlags {
    try {
        return Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\CCM" -Name CoManagementFlags
    } catch {
        Write-Output "[ERROR] Failed to read CoManagementFlags: $_"
        return $null
    }
}
 
function Reset-WMIAndReinstallCCM {
    Start-Log -Prefix "WMI_Reset"
    Write-Output "[INFO] Starting WMI reset and CCM remediation..."
 
    Stop-Service -Name ccmexec -Force -ErrorAction SilentlyContinue
    Stop-Service -Name winmgmt -Force -ErrorAction SilentlyContinue
 
    Start-Sleep -Seconds 5
    winmgmt /resetrepository
 
    $mofPath = "C:\Program Files\Microsoft Policy Platform\ExtendedStatus.mof"
    if (Test-Path $mofPath) {
        mofcomp "`"$mofPath`""
    }
 
    $dlls = @("atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll", "jscript.dll",
              "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll", "msxml6.dll", "actxprxy.dll",
              "softpub.dll", "wintrust.dll", "dssenh.dll", "rsaenh.dll", "gpkcsp.dll", "sccbase.dll",
              "slbcsp.dll", "cryptdlg.dll", "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll",
              "wuapi.dll", "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
              "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll")
 
    foreach ($dll in $dlls) {
        $dllPath = "$env:SystemRoot\System32\$dll"
        if (Test-Path $dllPath) {
            regsvr32 /s $dllPath
        }
    }
 
    Get-Process -Name ccmsetup -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() }
 
    $ccmSetupExe = $CCMSetupPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $ccmSetupExe) {
        Write-Output "[ERROR] ccmsetup.exe not found. Aborting."
        Stop-Log
        exit 1
    }
 
    $args = "/nocrlcheck /MP:HTTPS://$MP SMSSiteCode=$SiteCode CCMHOSTNAME=$MP AADCLIENTAPPID=$AADClientAppId AADTENANTID=$AADTenantId /UsePKICert CCMALWAYSINF=1 /AllowMetered"
 
    try {
        Start-Process -FilePath $ccmSetupExe -ArgumentList $args -Wait -ErrorAction Stop
        Start-Sleep -Seconds 900
    } catch {
        Write-Output "[ERROR] Failed to launch ccmsetup.exe: $_"
        Stop-Log
        exit 1
    }
 
    foreach ($svc in @("BITS", "wuauserv", "ccmexec")) {
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
 
    Write-Output "[INFO] WMI reset and CCM remediation completed."
    Stop-Log
}
 
function Cleanup-MDMEnrollment {
    Write-Output "[INFO] Starting MDM cleanup..."
    $taskRoot = "\Microsoft\Windows\EnterpriseMgmt"
    $taskGuids = Get-ScheduledTask -TaskPath $taskRoot -ErrorAction SilentlyContinue |
        ForEach-Object { $_.TaskPath.TrimEnd('\') } |
        Get-Unique |
        ForEach-Object { Split-Path $_ -Leaf } |
        Where-Object { $_ -match '^[0-9a-fA-F-]{36}$' }
 
    $regGuids = Get-ChildItem -ea SilentlyContinue 'HKLM:\SOFTWARE\Microsoft\Enrollments' |
        Where-Object { $_.PSChildName -match '^[0-9a-fA-F-]{36}$' } |
        Select-Object -ExpandProperty PSChildName
 
    $guids = @($taskGuids + $regGuids) | Sort-Object -Unique
 
    foreach ($g in $guids) {
        Get-ScheduledTask -TaskPath "$taskRoot\$g\" -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
 
        try {
            $svc = New-Object -ComObject Schedule.Service
            $svc.Connect()
            $folder = $svc.GetFolder($taskRoot)
            $folder.DeleteFolder($g,$null)
        } catch {}
    }
 
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Enrollments',
        'HKLM:\SOFTWARE\Microsoft\Enrollments\Status',
        'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts',
        'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger',
        'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions',
        'HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked'
    )
    foreach ($root in $roots) {
        if (Test-Path $root) {
            Get-ChildItem $root -ErrorAction SilentlyContinue |
                Where-Object { $guids -contains $_.PSChildName } |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
 
    $pmRoots = @(
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers',
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled'
    )
    foreach ($root in $pmRoots) {
        if (Test-Path $root) {
            Get-ChildItem $root -ErrorAction SilentlyContinue |
                Where-Object { $guids -contains $_.PSChildName } |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
 
    Start-Sleep -Seconds 5
    Start-Process -FilePath "$env:WINDIR\System32\DeviceEnroller.exe" -ArgumentList "/C /AutoEnrollMDM" -Wait -NoNewWindow
 
    Stop-Service -Name ccmexec -Force -ErrorAction SilentlyContinue
    Start-Service -Name ccmexec -ErrorAction SilentlyContinue
 
    Write-Output "[INFO] MDM cleanup and CCM restart completed."
}
 
# --- Main Execution ---
Start-Log -Prefix "DeviceRemediation"
$dsreg = Get-DsregStatus
$coMgmt = Read-CoMgmtFlags
 
Write-Output "[INFO] AzureAdJoined: $($dsreg.AzureAdJoined)"
Write-Output "[INFO] Device Name: $($dsreg.DeviceName)"
Write-Output "[INFO] DeviceId: $($dsreg.DeviceId)"
Write-Output "[INFO] CoManagementFlags: $coMgmt"
 
if ($dsreg.AzureAdJoined -eq "YES") {
    if ($coMgmt -eq 8197) {
        Reset-WMIAndReinstallCCM
    } else {
        Cleanup-MDMEnrollment
    }
} else {
    Write-Output "[INFO] Device is NOT Azure AD Joined."
}
 
Stop-Log
