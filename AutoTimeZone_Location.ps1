
<#

Author: Duke Dexter (https://github.com/DukeDexter)

.SYNOPSIS
  This owerShell script configures Automatic Time Zone "Set time zone automatically" and Location access at the device level, with built‑in verification, logging, and Intune‑friendly exit codes.

.DESCRIPTION
  - Enables or disables Set time zone automatically by setting HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate\Starttzautoupdate service Start: 3 = Enable auto time zone, 4 = Disable.
  - Forces Location access for apps by setting Location capability consent: "Allow" or "Deny" at HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Value.
  - Ensures Geolocation Service (lfsvc) is set to Automatic and running (required for auto time zone)
  - Intune-friendly logging and exit codes. Writes a log to C:\ProgramData\Intune\Logs\AutoTimeZone_Location.ps1.log Returns exit code 0 on success, 1 on failure (ideal for Intune script deployment or Proactive Remediations)

.PARAMETER EnableAutoTimeZone
  Sets HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate\Start to 3.

.PARAMETER DisableAutoTimeZone
  Sets HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate\Start to 4.

.PARAMETER LocationAccess
  Sets HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Value
  to "Allow" or "Deny". Default: "Allow".

.NOTES
  Requires elevation (run as System in Intune or as Admin).

.Intune deployment tips

Run as System: Deploy via Devices → Scripts or Proactive Remediations (as remediation script), run in System context.
Detection script (optional): Return exit code 0 when:

tzautoupdate\Start = 3 (Enable) or 4 (Disable) according to your policy, and
ConsentStore\location\Value = "Allow" (or "Deny" as desired), and
lfsvc Start = 2 and service Running.
Return 1 otherwise.

.usage exmples

# Enable auto time zone and force location ON
.\AutoTimeZone_Location.ps1 -EnableAutoTimeZone -LocationAccess Allow

# Disable auto time zone and force location OFF
.\AutoTimeZone_Location.ps1 -DisableAutoTimeZone -LocationAccess Deny

# Only enable auto time zone, keep location ON (default)
.\AutoTimeZone_Location.ps1 -EnableAutoTimeZone

# Only adjust location access, leave time zone unchanged
.\AutoTimeZone_Location.ps1 -LocationAccess Allow


#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName = 'Enable')]
    [switch] $EnableAutoTimeZone,

    [Parameter(ParameterSetName = 'Disable')]
    [switch] $DisableAutoTimeZone,

    [ValidateSet('Allow','Deny')]
    [string] $LocationAccess = 'Allow'
)

# -------------------- Constants --------------------
$LogDir  = 'C:\ProgramData\Intune\Logs'
$LogFile = Join-Path $LogDir 'AutoTimeZone_Location.ps1.log'

$TZRegPath        = 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate'
$TZRegValueName   = 'Start'         # 3 = enable auto TZ, 4 = disable
$LFRegPath        = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc'
$LFRegValueName   = 'Start'         # 2 = Automatic
$LocRegPath       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
$LocRegValueName  = 'Value'         # "Allow" or "Deny"

# -------------------- Helpers --------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line  = "[$stamp][$Level] $Message"
    $line | Tee-Object -FilePath $LogFile -Append
}

function Require-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log 'Script must run elevated. Exiting.' 'ERROR'
        exit 1
    }
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)]$Value,
        [ValidateSet('DWord','String')][string]$Type = 'DWord'
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log "Created missing key: $Path"
        }
        if ($Type -eq 'DWord') {
            New-ItemProperty -Path $Path -Name $Name -Value ([int]$Value) -PropertyType DWord -Force | Out-Null
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value ([string]$Value) -PropertyType String -Force | Out-Null
        }
        Write-Log "Set $Path\$Name = $Value ($Type)"
        return $true
    } catch {
        Write-Log "Failed to set $Path\$Name. $_" 'ERROR'
        return $false
    }
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        $null
    }
}

# -------------------- Start --------------------
Require-Admin
Write-Log '----- Starting Auto Time Zone & Location configuration -----'

$overallSuccess = $true

# 1) Geolocation Service (lfsvc) must be Automatic and running
try {
    $svc = Get-Service -Name 'lfsvc' -ErrorAction Stop
    Write-Log "lfsvc current status: Status=$($svc.Status), StartType (registry pending)"

    # Ensure Start type = Automatic (2)
    $lfSet = Set-RegistryValue -Path $LFRegPath -Name $LFRegValueName -Value 2 -Type 'DWord'
    if (-not $lfSet) { $overallSuccess = $false }

    # Start/Restart service if needed
    if ($svc.Status -ne 'Running') {
        Write-Log 'Starting Geolocation Service (lfsvc)...'
        try {
            Start-Service -Name 'lfsvc' -ErrorAction Stop
            Write-Log 'lfsvc started.'
        } catch {
            Write-Log "Failed to start lfsvc. $_" 'ERROR'
            $overallSuccess = $false
        }
    } else {
        Write-Log 'lfsvc already running.'
    }
} catch {
    Write-Log "lfsvc service not found or inaccessible. $_" 'ERROR'
    $overallSuccess = $false
}

# 2) Automatic Time Zone toggle (tzautoupdate Start = 3 enable, 4 disable)
if ($EnableAutoTimeZone.IsPresent -and $DisableAutoTimeZone.IsPresent) {
    Write-Log 'Both EnableAutoTimeZone and DisableAutoTimeZone provided. Choose one.' 'ERROR'
    exit 1
}

if ($EnableAutoTimeZone.IsPresent) {
    $tzSet = Set-RegistryValue -Path $TZRegPath -Name $TZRegValueName -Value 3 -Type 'DWord'
    if (-not $tzSet) { $overallSuccess = $false }
} elseif ($DisableAutoTimeZone.IsPresent) {
    $tzSet = Set-RegistryValue -Path $TZRegPath -Name $TZRegValueName -Value 4 -Type 'DWord'
    if (-not $tzSet) { $overallSuccess = $false }
} else {
    Write-Log 'No Auto Time Zone switch provided; leaving tzautoupdate value unchanged.'
}

# 3) Location capability consent (HKLM) -> "Allow" or "Deny"
$locSet = Set-RegistryValue -Path $LocRegPath -Name $LocRegValueName -Value $LocationAccess -Type 'String'
if (-not $locSet) { $overallSuccess = $false }

# 4) Verification snapshot
$tzCurrent  = Get-RegistryValue -Path $TZRegPath -Name $TZRegValueName
$lfCurrent  = Get-RegistryValue -Path $LFRegPath -Name $LFRegValueName
$locCurrent = Get-RegistryValue -Path $LocRegPath -Name $LocRegValueName
$svcState   = (Get-Service -Name 'lfsvc' -ErrorAction SilentlyContinue).Status

Write-Log "Verify: tzautoupdate Start=$tzCurrent (3=Enable, 4=Disable)"
Write-Log "Verify: lfsvc Start(DWord)=$lfCurrent (2=Automatic), Status=$svcState"
Write-Log "Verify: location consent Value='$locCurrent' ('Allow' or 'Deny')"

Write-Log '----- Completed configuration -----'

if ($overallSuccess) {
    exit 0
} else {
    exit 1
}
