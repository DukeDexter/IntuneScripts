
<#
.SYNOPSIS
Rotates BitLocker recovery passwords on one or more volumes by creating a new RecoveryPassword protector,
removing older RecoveryPassword protectors, and backing up the new protector to Microsoft Entra ID.

.DESCRIPTION
This script is intended for deployment via Microsoft Intune (Endpoint Manager) as a PowerShell Script running in SYSTEM context.
For each targeted volume, it:
  1) Adds a new RecoveryPassword protector
  2) Removes all existing RecoveryPassword protectors except the newly created one
  3) Escrows (backs up) the new protector to Microsoft Entra ID, when configured

It produces a CSV log with per-volume results. Default target is the OS drive (C:). You can optionally include all fixed data drives.

AUTHOR:        Duke Dexter (https://github.com/DukeDexter)
CREATED:       2025-12-25
VERSION:       1.0

.PARAMETER DriveLetters
One or more drive letters to process (e.g., 'C:', 'D:'). Defaults to 'C:'.
Note: Use the format 'C:' (with colon). Case-insensitive.

.PARAMETER IncludeFixedDataDrives
When specified, the script will also process all fixed, BitLocker-enabled data volumes discovered on the device.

.PARAMETER RequireAADEscrowSuccess
When specified, the script will mark rotation as failed if escrow to Microsoft Entra ID does not succeed (recommended for strict compliance).

.PARAMETER OutputLog
Full path for the CSV audit log. Defaults to: C:\ProgramData\Intune\Logs\BitLockerRotation_<timestamp>.csv
Directory will be created if it does not exist.

.PARAMETER WhatIf
Simulate actions without actually changing protectors. Useful for validation.

.EXAMPLE
# Rotate only the OS drive (default)
.\Rotate-BitLockerRecoveryKey.ps1

.EXAMPLE
# Rotate C: and D:, and require escrow success
.\Rotate-BitLockerRecoveryKey.ps1 -DriveLetters 'C:', 'D:' -RequireAADEscrowSuccess

.EXAMPLE
# Rotate OS drive plus all fixed data volumes
.\Rotate-BitLockerRecoveryKey.ps1 -IncludeFixedDataDrives

Intune Deployment:
- Devices → Windows → PowerShell Scripts → Add
- Run this script using logged-on credentials: No (runs as SYSTEM)
- Run script in 64-bit PowerShell: Yes
- Assign to Windows device groups

Prerequisites:
- Windows 10 1909+ or Windows 11
- BitLocker policy enables Client-driven recovery password rotation
- Save and store recovery info in Microsoft Entra ID before enabling BitLocker
- Devices are Entra-joined (or hybrid) so escrow succeeds

.NOTES
- Run in 64-bit PowerShell and SYSTEM context when deployed via Intune.
- Ensure BitLocker policies are configured to store and rotate recovery info in Microsoft Entra ID.
- Tested on Windows 10 1909+ and Windows 11.
- Logging location: C:\ProgramData\Intune\Logs\

CHANGE LOG
2025-12-25 v1.0  Initial release aligned to logging, escrow verification, multi-drive support.

#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string[]]$DriveLetters = @('C:'),

    [Parameter(Mandatory=$false)]
    [switch]$IncludeFixedDataDrives,

    [Parameter(Mandatory=$false)]
    [switch]$RequireAADEscrowSuccess,

    [Parameter(Mandatory=$false)]
    [string]$OutputLog = ("C:\ProgramData\Intune\Logs\BitLockerRotation_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss")),

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

#region -- Initialization & Helpers --

# Ensure 64-bit PowerShell (BitLocker cmdlets require 64-bit)
if (-not [Environment]::Is64BitProcess) {
    Write-Warning "This script should run in 64-bit PowerShell. Intune setting 'Run script in 64-bit PowerShell' must be enabled."
}

# Ensure BitLocker cmdlets are available
foreach ($cmd in 'Get-BitLockerVolume','Add-BitLockerKeyProtector','Remove-BitLockerKeyProtector') {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "Required cmdlet '$cmd' not found. Aborting."
        exit 1
    }
}

# 'BackupToAAD-BitLockerKeyProtector' may not exist on older builds; check and warn
$hasBackupCmd = $false
if (Get-Command 'BackupToAAD-BitLockerKeyProtector' -ErrorAction SilentlyContinue) { $hasBackupCmd = $true }

function Ensure-Directory {
    param([string]$Path)
    try {
        $dir = Split-Path -Path $Path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    } catch {
        Write-Warning "Failed to ensure directory for path '$Path'. $_"
    }
}

function Get-TargetVolumes {
    param(
        [string[]]$DriveLetters,
        [switch]$IncludeFixedDataDrives
    )
    $targets = @()

    # Normalize input drive letters
    $normalized = @()
    foreach ($d in $DriveLetters) {
        if ($d) { $normalized += ($d.Trim().ToUpper() -replace '\s','') }
    }

    # Add specified volumes
    foreach ($d in $normalized) {
        $vol = Get-BitLockerVolume -MountPoint $d -ErrorAction SilentlyContinue
        if ($vol) { $targets += $vol } else { Write-Warning "Volume '$d' not found or not BitLocker-compatible." }
    }

    # Optionally add all fixed, BitLocker-enabled data drives
    if ($IncludeFixedDataDrives) {
        $all = Get-BitLockerVolume -ErrorAction SilentlyContinue
        foreach ($v in $all) {
            if ($v.VolumeType -eq 'Data' -and $v.MountPoint -and $v.VolumeStatus -ne 'FullyDecrypted') {
                # Avoid duplicates
                if (-not ($targets | Where-Object { $_.MountPoint -eq $v.MountPoint })) { $targets += $v }
            }
        }
    }

    # Filter to volumes that are actually encrypted / encrypting
    $targets = $targets | Where-Object {
        $_.VolumeStatus -in @('EncryptionInProgress','EncryptionSuspended','FullyEncrypted')
    }

    return $targets
}

function Rotate-RecoveryPassword {
    param(
        [Microsoft.BitLocker.Structures.BitLockerVolume]$Volume,
        [switch]$RequireAADEscrowSuccess,
        [switch]$WhatIf
    )

    $drive = $Volume.MountPoint
    $result = [pscustomobject]@{
        MountPoint        = $drive
        AddedProtectorId  = $null
        RemovedCount      = 0
        EscrowAttempted   = $false
        EscrowSucceeded   = $false
        Status            = 'Pending'
        Error             = $null
        Timestamp         = (Get-Date).ToString('s')
    }

    try {
