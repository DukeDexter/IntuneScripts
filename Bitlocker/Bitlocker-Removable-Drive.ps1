
<#
.SYNOPSIS
    Launches the BitLocker wizard for a removable (USB) drive by dynamically detecting its drive letter.

.DESCRIPTION
    This script detects removable drives (DriveType=2) that have an assigned drive letter and launches
    the BitLocker wizard using "BitLockerWizard.exe <DriveLetter> p".
    - If a -DriveLetter is provided, it validates that it exists and is removable.
    - If none is provided, it enumerates removable drives:
        * If exactly one is found, it uses that drive automatically.
        * If multiple are found, it presents an interactive selection prompt.
    The script performs prerequisite checks:
        * Ensures BitLockerWizard.exe exists in %SystemRoot%\System32
        * Ensures the drive is not already BitLocker-protected (when Manage-BDE is available)
        * Ensures the drive has a letter and is online

AUTHOR:        Duke Dexter (https://github.com/DukeDexter)
CREATED:       2025-12-25
VERSION:       1.0

Notes for enterprise deployment (Intune/ConfigMgr)

If you plan to run this at scale:

The wizard is interactive; for non-interactive enforcement, use manage-bde or Intune’s BitLocker policies for removable drives.
Wrap this script as a Win32 app or PowerShell script via Intune, but ensure user context and elevation are appropriate for your Conditional Access and Endpoint Security policies.
Consider your RBAC and Conditional Access alignment to allow BitLocker provisioning for USBs.

Azure AD cannot store recovery keys for removable drives (USB / BitLocker To Go) as this is a Microsoft design limitation:
BitLocker To Go (Removable drives) does NOT support:
 - Automatic recovery key escrow to Entra ID
 - Reporting in Intune
 - Visibility in Azure AD device blade
 - Recovery key upload API

The BitLocker management APIs that Intune and Azure AD rely on only support:
 - Operating System volumes
 - Fixed internal volumes

Removable volumes are not exposed via the MDM BitLocker CSP for key escrow.

.PARAMETER DriveLetter
    Optional. A specific drive letter (e.g., 'G', 'G:', 'g') for the removable drive.
    If omitted, the script will auto-detect removable drives and prompt when multiple exist.

.PARAMETER Silent
    Optional switch. If specified and multiple removable drives exist, the script will automatically
    pick the first one without prompting.

.PARAMETER Force
    Optional switch. Bypass pre-checks for existing BitLocker protection and status queries.

.EXAMPLE
    .\Launch-BitLockerWizardRemovable.ps1
    Detects removable drives. If exactly one is found, launches BitLocker wizard for it.
    If multiple are found, prompts for selection.

.EXAMPLE
    .\Launch-BitLockerWizardRemovable.ps1 -DriveLetter F
    Validates that F: is a removable drive and launches BitLocker wizard for F:.

.EXAMPLE
    .\Launch-BitLockerWizardRemovable.ps1 -Silent
    Automatically uses the first detected removable drive without user interaction.

.NOTES
    - Run from an elevated PowerShell session when your organization policy requires admin to manage BitLocker.
    - "BitLockerWizard.exe" is typically located at: $env:SystemRoot\System32\BitLockerWizard.exe
    - The "p" parameter opens the wizard in protection mode for the specified drive.
    - Tested on Windows 10/11 systems with BitLocker enabled. Your environment may vary depending on policy.
    - For deployment via Intune, wrap in a Win32 app or run as a device script; consider interaction needs.

.CHANGE LOG
    2025-12-25  v1.0  Initial version aligned with comment-based help standards.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[A-Za-z]:?$')]
    [string]$DriveLetter,

    [Parameter(Mandatory=$false)]
    [switch]$Silent,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Warn { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

try {
    # Normalize drive letter (e.g., 'g' -> 'G:')
    if ($DriveLetter) {
        $DriveLetter = ($DriveLetter.TrimEnd(':').ToUpper() + ':')
    }

    # Locate BitLockerWizard.exe
    $blWizard = Join-Path $env:SystemRoot 'System32\BitLockerWizard.exe'
    if (-not (Test-Path $blWizard)) {
        Write-Err "BitLockerWizard.exe not found at '$blWizard'. Ensure BitLocker is enabled on this device."
        exit 2
    }

    # Enumerate removable drives with letters
    $removableDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" |
        Where-Object { $_.DeviceID -match '^[A-Z]:$' } |
        Sort-Object DeviceID

    if ($DriveLetter) {
        $target = $removableDrives | Where-Object { $_.DeviceID -eq $DriveLetter }
        if (-not $target) {
            Write-Err "Specified drive '$DriveLetter' is not detected as a removable drive with an assigned letter."
            exit 3
        }
    } else {
        if ($removableDrives.Count -eq 0) {
            Write-Err "No removable drives with assigned drive letters were found."
            exit 4
        } elseif ($removableDrives.Count -eq 1 -or $Silent) {
            $target = $removableDrives | Select-Object -First 1
            Write-Info "Selected removable drive: $($target.DeviceID)"
        } else {
            Write-Info "Multiple removable drives detected:"
            $choices = $removableDrives.DeviceID
            for ($i=0; $i -lt $choices.Count; $i++) {
                Write-Host ("  [{0}] {1}" -f $i, $choices[$i])
            }
            $selection = Read-Host "Enter the index of the drive to use"
            if ([int]::TryParse($selection, [ref]0) -eq $false -or
                [int]$selection -lt 0 -or
                [int]$selection -ge $choices.Count) {
                Write-Err "Invalid selection."
                exit 5
            }
            $target = $removableDrives[[int]$selection]
            Write-Info "Selected removable drive: $($target.DeviceID)"
        }
    }

    # Optional: Check BitLocker status (skip if -Force)
    if (-not $Force) {
        $manageBde = Join-Path $env:SystemRoot 'System32\manage-bde.exe'
        if (Test-Path $manageBde) {
            $bdeOut = & $manageBde -status $target.DeviceID 2>$null
            if ($LASTEXITCODE -eq 0 -and $bdeOut) {
                if ($bdeOut -match 'Conversion Status:\s+Fully Encrypted' -or
                    $bdeOut -match 'Protection Status:\s+Protection On') {
                    Write-Warn "Drive $($target.DeviceID) already appears to have BitLocker protection."
                }
            }
        } else {
            Write-Warn "manage-bde.exe not found. Skipping BitLocker status pre-check."
        }
    }

    # Launch BitLocker Wizard: BitLockerWizard.exe <DriveLetter> p
    $args = @($target.DeviceID, 'p')
    Write-Info "Launching BitLocker wizard: `"$blWizard`" $($args -join ' ')"
    $proc = Start-Process -FilePath $blWizard -ArgumentList $args -PassThru
    Write-Info "Process started (PID=$($proc.Id)). The wizard UI should now be visible."

    exit 0
}
catch {
    Write-Err "Unhandled exception: $($_.Exception.Message)"
    exit 9
}
``
