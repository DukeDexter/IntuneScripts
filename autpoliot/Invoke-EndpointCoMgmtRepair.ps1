
<# ========================================================================
  Device Remediation (Production-Safe) with Interactive Parameters
  - Parameters can come from: CLI > JSON config > Environment variables > Defaults > Interactive prompt
  - Interactive prompt: only fires for parameters still missing after earlier sources
  - Safer WMI repair (salvage before reset; reset only if forced/needed)
  - Controlled MDM cleanup (delete only corroborated GUIDs)
  - Robust logging & transcript state tracking
  - Bitmask visibility for CoManagementFlags
  - Rich comments throughout

$SiteCode: SCCM site code used by ccmsetup.
$MP: Management Point hostname (with proxy mutual auth and a GUID path). Passed to client install as MP and CCMHOSTNAME.
$AADClientAppId, $AADTenantId: AAD parameters used by ccmsetup for AAD‑aware client authentication.
$CCMSetupPaths: Potential paths to ccmsetup.exe (first existing one is used).

Note: Keep these values consistent with your SCCM infra. If you rotate app registrations or tenant settings, update here to avoid enrollment/auth errors.

  USAGE EXAMPLES:
    # 1) CLI override:
    .\Remediate.ps1 -SiteCode GT001 -MP 'MPCMGPROD.../CCM_PROXY_MUTUALAUTH/...GUID...' `
                    -AADClientAppId '0207aced-f123-4567-bdb8-8123456f5093' `
                    -AADTenantId 'E2BA81B8-1234-45678-96A1-F4BC01234567'

    # 2) JSON config:
    .\Remediate.ps1 -ConfigPath 'C:\Config\sccm-remediation.json'

       JSON example:
       {
         "SiteCode": "GT1",
         "MP": "MPG.RGROUP.COM/CCM_PROXY_MUTUALAUTH/1234567890",
         "AADClientAppId": "0207aced-f123-4567-bdb8-8123456f5093",
         "AADTenantId": "E2BA81B8-1234-45678-96A1-F4BC0123456",
         "CCMSetupPaths": [
           "C:\\Windows\\ccmsetup\\ccmsetup.exe",
           "C:\\ProgramData\\Installers\\MECM\\ccmsetup.exe"
         ]
       }

    # 3) Environment variables:
       setx SCCM_SITECODE "GT1"
       setx SCCM_MP "MPG.RGROUP.COM/CCM_PROXY_MUTUALAUTH/72057594037927941"
       setx AAD_CLIENT_APPID "0207aced-f123-4567-bdb8-8123456f5093"
       setx AAD_TENANT_ID "E2BA81B8-1234-45678-96A1-F4BC0123456"

    # 4) Interactive:
       Just run .\Remediate.ps1 and follow prompts for missing values.

  IMPORTANT:
    • Run elevated (Administrator).
    • Test in pilot rings before broad deployment.
    • Keep values aligned with SCCM/PKI/AAD.

Notes on the interactive experience

The script only prompts when a critical parameter is missing or invalid after evaluating CLI/JSON/env/defaults.
GUIDs (AADClientAppId, AADTenantId) are validated. Prompts repeat until the value is correct.

========================================================================= #>

[CmdletBinding(SupportsShouldProcess)]
param(
    # --- Primary parameter sources (CLI) ---
    [string]$SiteCode,
    [string]$MP,
    [string]$AADClientAppId,
    [string]$AADTenantId,

    # Optional JSON configuration path
    [string]$ConfigPath,

    # Optional ccmsetup locations
    [string[]]$CCMSetupPaths,

    # --- Safety toggles ---
    [switch]$EnableLegacyDllRegistration, # Rarely needed on modern Windows; opt-in
    [switch]$ForceWmiReset,               # Force reset even if salvage could work
    [int]$ClientInstallWaitSeconds = 600  # Default ~10 minutes
)

# ------------------------------
# Defaults (lowest precedence)
# ------------------------------
$defaults = @{
    SiteCode       = "GT1"
    MP             = "MPGGTCMGPROD.MANPOWERGROUP.COM/CCM_PROXY_MUTUALAUTH/72057594037927941"
    AADClientAppId = "0207aced-f557-4813-bdb8-8b7a8aff5093"
    AADTenantId    = "E2BA81B8-03FE-407C-96A1-F4BC0F512E7D"
    CCMSetupPaths  = @(
        "C:\Windows\ccmsetup\ccmsetup.exe",
        "C:\ProgramData\Installers\MECM\ccmsetup.exe"
    )
}

# ------------------------------
# Load from JSON config (if provided)
# ------------------------------
$config = @{}
if ($ConfigPath) {
    if (-not (Test-Path $ConfigPath)) { throw "ConfigPath does not exist: $ConfigPath" }
    try {
        $jsonText = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
        $config   = $jsonText | ConvertFrom-Json -ErrorAction Stop
        Write-Output "[INFO] Loaded JSON config from $ConfigPath"
    } catch {
        throw "Failed to parse JSON config at $ConfigPath: $($_.Exception.Message)"
    }
}

# ------------------------------
# Load from environment variables
# ------------------------------
$envParams = @{
    SiteCode       = $env:SCCM_SITECODE
    MP             = $env:SCCM_MP
    AADClientAppId = $env:AAD_CLIENT_APPID
    AADTenantId    = $env:AAD_TENANT_ID
}

# ------------------------------
# Resolve with precedence: CLI > JSON > ENV > defaults
# ------------------------------
function Resolve-Param([string]$name) {
    switch ($name) {
        'SiteCode'       { if ($PSBoundParameters.ContainsKey('SiteCode') -and $SiteCode) { $SiteCode } elseif ($config.SiteCode) { $config.SiteCode } elseif ($envParams.SiteCode) { $envParams.SiteCode } else { $defaults.SiteCode } }
        'MP'             { if ($PSBoundParameters.ContainsKey('MP') -and $MP) { $MP } elseif ($config.MP) { $config.MP } elseif ($envParams.MP) { $envParams.MP } else { $defaults.MP } }
        'AADClientAppId' { if ($PSBoundParameters.ContainsKey('AADClientAppId') -and $AADClientAppId) { $AADClientAppId } elseif ($config.AADClientAppId) { $config.AADClientAppId } elseif ($envParams.AADClientAppId) { $envParams.AADClientAppId } else { $defaults.AADClientAppId } }
        'AADTenantId'    { if ($PSBoundParameters.ContainsKey('AADTenantId') -and $AADTenantId) { $AADTenantId } elseif ($config.AADTenantId) { $config.AADTenantId } elseif ($envParams.AADTenantId) { $envParams.AADTenantId } else { $defaults.AADTenantId } }
        'CCMSetupPaths'  { if ($PSBoundParameters.ContainsKey('CCMSetupPaths') -and $CCMSetupPaths) { $CCMSetupPaths } elseif ($config.CCMSetupPaths) { [string[]]$config.CCMSetupPaths } else { $defaults.CCMSetupPaths } }
        default { $null }
    }
}

# Effective parameters after non-interactive sources
$SiteCodeEff       = Resolve-Param 'SiteCode'
$MPEff             = Resolve-Param 'MP'
$AADClientAppIdEff = Resolve-Param 'AADClientAppId'
$AADTenantIdEff    = Resolve-Param 'AADTenantId'
$CCMSetupPathsEff  = Resolve-Param 'CCMSetupPaths'

# ------------------------------
# Interactive prompts for missing/invalid parameters
# ------------------------------
function Is-Guid([string]$s) {
    # Strict GUID validator (canonical 8-4-4-4-12 hex format)
    return $s -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
}

function Prompt-Until([string]$label, [ScriptBlock]$validator, [string]$hint) {
    <#
      Purpose: prompt user until a value passes validator
      Why: avoid proceeding with empty/invalid critical parameters
    #>
    do {
        $val = Read-Host $label
        if (& $validator $val) { return $val }
        Write-Warning "Invalid input. $hint"
    } while ($true)
}

# SiteCode: non-empty; alphanumeric (SCCM codes are typically 3 letters/numbers)
if ([string]::IsNullOrWhiteSpace($SiteCodeEff)) {
    $SiteCodeEff = Prompt-Until -label "Enter SCCM Site Code (e.g., GT1)" -validator { param($v) -not [string]::IsNullOrWhiteSpace($v) } -hint "Site code cannot be empty."
}

# MP: non-empty; allow any hostname/path; basic sanity check for spaces
if ([string]::IsNullOrWhiteSpace($MPEff)) {
    $MPEff = Prompt-Until -label "Enter Management Point (e.g., MPGGTCMGPROD.../CCM_PROXY_MUTUALAUTH/...)" -validator { param($v) -not [string]::IsNullOrWhiteSpace($v) -and ($v -notmatch '\s') } -hint "MP cannot be empty or contain spaces."
}

# AAD AppId: must be GUID
if (-not (Is-Guid $AADClientAppIdEff)) {
    Write-Warning "AADClientAppId is missing or not a GUID."
    $AADClientAppIdEff = Prompt-Until -label "Enter AAD Client App Id (GUID)" -validator { param($v) Is-Guid $v } -hint "Provide a GUID like 0207aced-f557-4813-bdb8-8b7a8aff5093."
}

# AAD TenantId: must be GUID
if (-not (Is-Guid $AADTenantIdEff)) {
    Write-Warning "AADTenantId is missing or not a GUID."
    $AADTenantIdEff = Prompt-Until -label "Enter AAD Tenant Id (GUID)" -validator { param($v) Is-Guid $v } -hint "Provide a GUID like E2BA81B8-03FE-407C-96A1-F4BC0F512E7D."
}

# Confirm effective paths (keep defaults if none supplied)
if (-not $CCMSetupPathsEff -or $CCMSetupPathsEff.Count -eq 0) {
    Write-Output "[INFO] Using default CCMSetupPaths."
    $CCMSetupPathsEff = $defaults.CCMSetupPaths
}

# Show resolved parameters (for transparency)
Write-Output "[INFO] Effective parameters:"
Write-Output "       SiteCode       = $SiteCodeEff"
Write-Output "       MP             = $MPEff"
Write-Output "       AADClientAppId = $AADClientAppIdEff"
Write-Output "       AADTenantId    = $AADTenantIdEff"
Write-Output "       CCMSetupPaths  = $([string]::Join(', ', $CCMSetupPathsEff))"

# ------------------------------
# Global transcript state
# ------------------------------
$script:Transcribing = $false
$script:LogFile = $null

function Ensure-Admin {
    # Validate elevation (required for WMI/registry/scheduled tasks)
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run elevated (Administrator)."
    }
}

function Start-Log { param([string]$Prefix)
    # Start transcript capture; track state to avoid Stop-Transcript errors
    try {
        $script:LogFile = Join-Path $env:SystemRoot "CCM\Logs\${Prefix}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Start-Transcript -Path $script:LogFile -Append | Out-Null
        $script:Transcribing = $true
        Write-Output "[INFO] Transcript started: $script:LogFile"
    } catch {
        Write-Warning "[WARN] Failed to start transcript: $($_.Exception.Message)"
        $script:Transcribing = $false
    }
}

function Stop-Log {
    # Stop transcript cleanly only when active
    if ($script:Transcribing) {
        try { Stop-Transcript | Out-Null } catch {}
        $script:Transcribing = $false
    }
}

function Get-DsregStatus {
    # Parse dsregcmd /status for AAD join, device name, device id
    $dsregCmdPath = "$env:SystemRoot\System32\dsregcmd.exe"
    if (-not (Test-Path $dsregCmdPath)) {
        Write-Output "[ERROR] dsregcmd.exe not found at $dsregCmdPath"
        return [PSCustomObject]@{ AzureAdJoined="Not Found"; DeviceName="Not Found"; DeviceId="Not Found" }
    }
    try {
        $out = & $dsregCmdPath /status
        function Get-DsVal([string]$Key) {
            $line = $out | Where-Object { $_ -match "$Key\s*:\s*(.+)" }
            if ($line) { return ($line -replace ".*$Key\s*:\s*", "").Trim() } else { "Not Found" }
        }
        return [PSCustomObject]@{
            AzureAdJoined = Get-DsVal "AzureAdJoined"
            DeviceName    = Get-DsVal "Device Name"
            DeviceId      = Get-DsVal "DeviceId"
        }
    } catch {
        Write-Output "[ERROR] dsregcmd.exe /status failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ AzureAdJoined="Not Found"; DeviceName="Not Found"; DeviceId="Not Found" }
    }
}

function Get-CoManagementFlags {
    # Read SCCM CoManagementFlags bitmask
    try {
        $val = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\CCM" -Name CoManagementFlags -ErrorAction Stop
        return [int]$val
    } catch {
        Write-Output "[WARN] CoManagementFlags not found: $($_.Exception.Message)"
        return $null
    }
}

function Show-FlagsBits([int]$flags) {
    # Display which bits are set; helpful for workload awareness later
    if ($null -eq $flags) { Write-Output "[INFO] CoManagementFlags: <null>"; return }
    $bits = 0..31 | Where-Object { ($flags -band (1 -shl $_)) -ne 0 }
    $hex = ('0x{0:X8}' -f $flags)
    Write-Output "[INFO] CoManagementFlags: $flags ($hex) | Bits set: $(($bits -join ','))"
}

function Test-WmiHealth {
    # Probe CIM/WMI health; avoid unnecessary reset
    try {
        $null = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        Write-Output "[INFO] WMI/CIM query succeeded."
        return $true
    } catch {
        Write-Output "[WARN] WMI/CIM query failed: $($_.Exception.Message)"
        return $false
    }
}

function Repair-WMI {
    # Conservative repair sequence: stop → verify/salvage → (optional) reset → start
    Write-Output "[INFO] Starting WMI repair sequence..."
    foreach ($s in @('ccmexec','winmgmt')) { try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue } catch {} }
    Start-Sleep -Seconds 3

    $wmip = "$env:SystemRoot\System32\wbem\winmgmt.exe"
    if (-not (Test-Path $wmip)) { throw "winmgmt.exe not found: $wmip" }

    try {
        & $wmip /verifyrepository | Out-Null
        Write-Output "[INFO] winmgmt /verifyrepository completed."
        & $wmip /salvagerepository | Out-Null
        Write-Output "[INFO] winmgmt /salvagerepository attempted."
    } catch {
        Write-Warning "[WARN] winmgmt verification/salvage failed: $($_.Exception.Message)"
    }

    $healthy = Test-WmiHealth
    if ($ForceWmiReset -or -not $healthy) {
        Write-Warning "[WARN] Proceeding with WMI reset (destructive)."
        try { & $wmip /resetrepository | Out-Null } catch { throw "winmgmt /resetrepository failed: $($_.Exception.Message)" }

        # Optional MOF compilation for specific providers
        $mofPath = "C:\Program Files\Microsoft Policy Platform\ExtendedStatus.mof"
        if (Test-Path $mofPath) {
            try { mofcomp "`"$mofPath`"" | Out-Null } catch { Write-Warning "[WARN] mofcomp failed: $($_.Exception.Message)" }
        }

        if ($EnableLegacyDllRegistration) {
            $dlls = @('atl.dll','urlmon.dll','mshtml.dll','shdocvw.dll','browseui.dll','jscript.dll','vbscript.dll','scrrun.dll','msxml.dll','msxml3.dll','msxml6.dll','actxprxy.dll','softpub.dll','wintrust.dll','dssenh.dll','rsaenh.dll','gpkcsp.dll','sccbase.dll','slbcsp.dll','cryptdlg.dll','oleaut32.dll','ole32.dll','shell32.dll','initpki.dll','wuapi.dll','wuaueng.dll','wuaueng1.dll','wucltui.dll','wups.dll','wups2.dll','wuweb.dll','qmgr.dll','qmgrprxy.dll','wucltux.dll','muweb.dll','wuwebv.dll')
            foreach ($dll in $dlls) { $p = "$env:SystemRoot\System32\$dll"; if (Test-Path $p) { try { regsvr32 /s $p } catch {} } }
            Write-Output "[INFO] Legacy DLL registration executed."
        }
    } else {
        Write-Output "[INFO] Skipped WMI reset—salvage appears sufficient."
    }

    foreach ($svc in @('winmgmt','BITS','wuauserv','ccmexec')) { try { Start-Service -Name $svc -ErrorAction SilentlyContinue } catch {} }
    Write-Output "[INFO] WMI repair sequence completed."
}

function Find-CcmSetupExe {
    # Resolve ccmsetup.exe from candidate paths
    $path = $CCMSetupPathsEff | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $path) { throw "ccmsetup.exe not found in: $([string]::Join(', ', $CCMSetupPathsEff))" }
    return $path
}

function Install-CcmClient {
    # (Re)install SCCM/MECM client using effective parameters
    $ccmExe = Find-CcmSetupExe
    $args = @(
        "/MP:HTTPS://$MPEff",
        "SMSSiteCode=$SiteCodeEff",
        "CCMHOSTNAME=$MPEff",
        "AADCLIENTAPPID=$AADClientAppIdEff",
        "AADTENANTID=$AADTenantIdEff",
        "/UsePKICert",
        "CCMALWAYSINF=1",
        "/AllowMetered"
    )
    # Consider enabling /nocrlcheck only if PKI troubleshooting requires it
    # $args += "/nocrlcheck"

    Write-Output "[INFO] Launching ccmsetup: $ccmExe $($args -join ' ')"
    try { Start-Process -FilePath $ccmExe -ArgumentList ($args -join ' ') -Wait -ErrorAction Stop }
    catch { throw "Failed to run ccmsetup.exe: $($_.Exception.Message)" }

    $deadline = (Get-Date).AddSeconds($ClientInstallWaitSeconds)
    do {
        Start-Sleep -Seconds 10
        try {
            $svc = Get-Service -Name ccmexec -ErrorAction Stop
            if ($svc.Status -ne 'Running') { Start-Service -Name ccmexec -ErrorAction SilentlyContinue }
        } catch {}
    } while ((Get-Date) -lt $deadline)

    Write-Output "[INFO] CCM client install wait complete (~$ClientInstallWaitSeconds s)."
}

function Get-EnrollmentGuids {
    # Intersect GUIDs found in both Tasks and Enrollment registry to avoid over-deletion
    $taskRoot = "\Microsoft\Windows\EnterpriseMgmt"
    $taskGuids = Get-ScheduledTask -TaskPath $taskRoot -ErrorAction SilentlyContinue |
        ForEach-Object { $_.TaskPath.TrimEnd('\') } | Get-Unique |
        ForEach-Object { Split-Path $_ -Leaf } |
        Where-Object { $_ -match '^[0-9a-fA-F-]{36}$' }

    $regGuids = Get-ChildItem -ea SilentlyContinue 'HKLM:\SOFTWARE\Microsoft\Enrollments' |
        Where-Object { $_.PSChildName -match '^[0-9a-fA-F-]{36}$' } |
        Select-Object -ExpandProperty PSChildName

    $intersection = $taskGuids | Where-Object { $regGuids -contains $_ }
    Write-Output "[INFO] Enrollment GUIDs (intersection): $($intersection -join ', ')"
    return $intersection
}

function Backup-EnrollmentRegistry { param([string]$BackupDir)
    # Export registry hives before cleanup for rollback
    try {
        if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $cmds = @(
            "reg export HKLM\SOFTWARE\Microsoft\Enrollments `"$BackupDir\Enrollments_$stamp.reg`" /y",
            "reg export HKLM\SOFTWARE\Microsoft\PolicyManager\Providers `"$BackupDir\Providers_$stamp.reg`" /y",
            "reg export HKLM\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled `"$BackupDir\AdmxInstalled_$stamp.reg`" /y"
        )
        foreach ($c in $cmds) { cmd.exe /c $c | Out-Null }
        Write-Output "[INFO] Enrollment registry backup saved to: $BackupDir"
    } catch {
        Write-Warning "[WARN] Registry backup failed: $($_.Exception.Message)"
    }
}

function Cleanup-MDMEnrollment {
    # Delete tasks/registry for corroborated GUIDs only; backup first
    Write-Output "[INFO] Starting MDM cleanup..."
    $guids = Get-EnrollmentGuids
    $backupDir = Join-Path $env:SystemRoot "CCM\Logs\MDMRegistryBackup"
    Backup-EnrollmentRegistry -BackupDir $backupDir

    $taskRoot = "\Microsoft\Windows\EnterpriseMgmt"
    foreach ($g in $guids) {
        try {
            Get-ScheduledTask -TaskPath "$taskRoot\$g\" -ErrorAction SilentlyContinue |
                Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
            $svc = New-Object -ComObject Schedule.Service
            $svc.Connect()
            $folder = $svc.GetFolder($taskRoot)
            $folder.DeleteFolder($g, $null)
        } catch {
            Write-Warning "[WARN] Failed to remove task/folder for GUID $g: $($_.Exception.Message)"
        }
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
                ForEach-Object { try { Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
        }
    }

    $pmRoots = @('HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers','HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled')
    foreach ($root in $pmRoots) {
        if (Test-Path $root) {
            Get-ChildItem $root -ErrorAction SilentlyContinue |
                Where-Object { $guids -contains $_.PSChildName } |
                ForEach-Object { try { Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
        }
    }

    Write-Output "[INFO] MDM cleanup completed."
}

function Trigger-AutoEnrollMDM {
    # Re-initiate auto enrollment on AAD-joined devices
    $enroller = "$env:WINDIR\System32\DeviceEnroller.exe"
    if (-not (Test-Path $enroller)) { Write-Warning "[WARN] DeviceEnroller.exe not found."; return }
    try { Start-Process -FilePath $enroller -ArgumentList "/C /AutoEnrollMDM" -Wait -NoNewWindow; Write-Output "[INFO] Auto-enrollment triggered." }
    catch { Write-Warning "[WARN] Auto-enrollment failed: $($_.Exception.Message)" }
}

function Restart-CcmAgent {
    # Restart SCCM agent to pick up fresh state
    try {
        Stop-Service -Name ccmexec -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Service -Name ccmexec -ErrorAction SilentlyContinue
        Write-Output "[INFO] ccmexec restarted."
    } catch {
        Write-Warning "[WARN] Failed to restart ccmexec: $($_.Exception.Message)"
    }
}

# ------------------------------
# MAIN EXECUTION
# ------------------------------
try {
    Ensure-Admin
    Start-Log -Prefix "DeviceRemediationSafe"

    $dsreg  = Get-DsregStatus
    $flags  = Get-CoManagementFlags
    Write-Output "[INFO] AzureAdJoined: $($dsreg.AzureAdJoined)"
    Write-Output "[INFO] Device Name:    $($dsreg.DeviceName)"
    Write-Output "[INFO] DeviceId:      $($dsreg.DeviceId)"
    Show-FlagsBits -flags $flags

    if ($dsreg.AzureAdJoined -eq "YES") {
        if ($flags -eq 8197) {
            Write-Output "[INFO] Branch A: AAD Joined + CoManagementFlags==8197 → WMI repair + CCM reinstall"
            Repair-WMI
            Install-CcmClient
        } else {
            Write-Output "[INFO] Branch B: AAD Joined + CoManagementFlags!=8197 → MDM cleanup + AutoEnrollMDM + SCCM agent restart"
            Cleanup-MDMEnrollment
            Trigger-AutoEnrollMDM
            Restart-CcmAgent
        }
    } else {
        Write-Output "[INFO] Device is NOT Azure AD Joined. No remediation performed."
    }
}
catch {
    Write-Error "[ERROR] Unhandled exception: $($_.Exception.Message)"
}
finally {
    Stop-Log
}
