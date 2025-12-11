
<#
.SYNOPSIS
  Safely cleans Intune/MDM enrollment artifacts for GUID(s) discovered under EnterpriseMgmt.

.DESCRIPTION
  - Finds enrollment GUID(s) from \Microsoft\Windows\EnterpriseMgmt tasks (pattern: 36-char GUID).
  - Deletes corroborated scheduled tasks and matching registry keys.
  - Optionally removes Intune MDM certificates from LocalMachine\My.
  - Includes elevation check, WhatIf mode, error handling, and optional registry backup.

.PARAMETER WhatIf
  Run in preview mode; show actions without making changes.

.PARAMETER Confirm
  Prompt for confirmation before destructive operations.

.PARAMETER BackupRegistryPath
  Directory to export registry hives before deletion (optional).

.NOTES
  Run Elevated (Administrator).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$WhatIf,
    [switch]$Confirm,
    [string]$BackupRegistryPath
)

function Ensure-Admin {
    # Ensure the script runs elevated—required for scheduled tasks, registry, cert ops.
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run as Administrator."
    }
}

function Get-EnrollmentGuidsFromTasks {
    <#
      Purpose: Robustly retrieve enrollment GUIDs from EnterpriseMgmt scheduled tasks.
      Rather than relying on a single task name, we search for any TaskPath with a GUID.
    #>
    $root = "\Microsoft\Windows\EnterpriseMgmt"
    $tasks = Get-ScheduledTask -TaskPath $root -ErrorAction SilentlyContinue
    if (-not $tasks) { return @() }

    # Extract GUIDs from task paths by regex: 8-4-4-4-12 hex format
    $guids = @()
    foreach ($t in $tasks) {
        $m = [regex]::Match($t.TaskPath, '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}')
        if ($m.Success) { $guids += $m.Value }
    }
    $guids | Sort-Object -Unique
}

function Get-EnrollmentGuidsFromRegistry {
    <#
      Purpose: List GUIDs under HKLM:\SOFTWARE\Microsoft\Enrollments as ground truth.
    #>
    $regRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path $regRoot)) { return @() }
    Get-ChildItem $regRoot -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^[0-9a-fA-F-]{36}$' } |
        Select-Object -ExpandProperty PSChildName |
        Sort-Object -Unique
}

function Backup-Registry([string]$Dir) {
    <#
      Purpose: Optional registry export before destructive changes.
      Why: Provides a rollback path if something goes wrong.
    #>
    if (-not $Dir) { return }
    try {
        if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $cmds = @(
            "reg export HKLM\SOFTWARE\Microsoft\Enrollments `"$Dir\Enrollments_$stamp.reg`" /y",
            "reg export HKLM\SOFTWARE\Microsoft\PolicyManager\Providers `"$Dir\Providers_$stamp.reg`" /y",
            "reg export HKLM\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled `"$Dir\AdmxInstalled_$stamp.reg`" /y",
            "reg export HKLM\SOFTWARE\Microsoft\Provisioning\OMADM `"$Dir\OMADM_$stamp.reg`" /y"
        )
        foreach ($c in $cmds) { cmd.exe /c $c | Out-Null }
        Write-Host "[INFO] Registry backup exported to $Dir"
    } catch {
        Write-Warning "[WARN] Registry backup failed: $($_.Exception.Message)"
    }
}

function Remove-EnrollmentScheduledTasks([string]$Guid) {
    <#
      Purpose: Delete all tasks under EnterpriseMgmt\<GUID>\
    #>
    $taskFolder = "\Microsoft\Windows\EnterpriseMgmt\$Guid\"
    $tasks = Get-ScheduledTask -TaskPath $taskFolder -ErrorAction SilentlyContinue
    if (-not $tasks) { Write-Host "[INFO] No scheduled tasks found for GUID $Guid"; return }

    foreach ($t in $tasks) {
        Write-Host "Deleting task: $($t.TaskName)"
        if ($PSCmdlet.ShouldProcess($t.TaskName, "Unregister scheduled task")) {
            Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $taskFolder -Confirm:$Confirm -ErrorAction SilentlyContinue
        }
    }

    # Delete empty folder via COM API (some versions keep the folder)
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $folder = $svc.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
        if ($PSCmdlet.ShouldProcess("EnterpriseMgmt\$Guid", "Delete task folder")) {
            $folder.DeleteFolder($Guid, $null)
        }
    } catch {
        Write-Warning "[WARN] Failed to delete EnterpriseMgmt\$Guid folder: $($_.Exception.Message)"
    }
}

function Remove-EnrollmentRegistry([string]$Guid) {
    <#
      Purpose: Delete enrollment-scoped registry keys for a given GUID.
    #>
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Enrollments\$Guid",
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$Guid",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$Guid",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$Guid",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$Guid",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$Guid",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$Guid",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$Guid"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Write-Host "Deleting registry: $p"
            if ($PSCmdlet.ShouldProcess($p, "Remove-Item -Recurse -Force")) {
                Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Remove-IntuneMdMCerts {
    <#
      Purpose: Remove MDM enrollment certs from LocalMachine\My if they match Intune issuer.
      Note: You may tighten detection by Subject, Thumbprint allow-list, or EKU/OIDs (e.g., 1.3.6.1.4.1.311.76.6.1).
    #>
    Set-Location Cert:\LocalMachine\My
    $certs = Get-ChildItem
    foreach ($c in $certs) {
        $issuer = $c.Issuer
        # Basic issuer match used in your script:
        $isIntuneIssuer = ($issuer -like "*Microsoft Intune*" -and $issuer -like "*MDM Device CA*")
        if ($isIntuneIssuer) {
            Write-Host "Deleting cert: Issuer='$issuer' Thumbprint=$($c.Thumbprint)"
            if ($PSCmdlet.ShouldProcess($c.Thumbprint, "Remove Intune MDM cert")) {
                try {
                    Remove-Item -Path ("Cert:\LocalMachine\My\{0}" -f $c.Thumbprint) -ErrorAction SilentlyContinue
                } catch {
                    Write-Warning "[WARN] Failed to remove cert $($c.Thumbprint): $($_.Exception.Message)"
                }
            }
        }
    }
}

# ---------------- MAIN ----------------
try {
    Ensure-Admin

    Write-Host "[INFO] Discovering enrollment GUIDs from tasks..."
    $taskGuids = Get-EnrollmentGuidsFromTasks
    Write-Host "[INFO] Task GUIDs: $($taskGuids -join ', ')"

    Write-Host "[INFO] Discovering enrollment GUIDs from registry..."
    $regGuids  = Get-EnrollmentGuidsFromRegistry
    Write-Host "[INFO] Registry GUIDs: $($regGuids -join ', ')"

    # Prefer GUIDs present in BOTH tasks and registry to minimize risk
    $targetGuids = $taskGuids | Where-Object { $regGuids -contains $_ }
    if (-not $targetGuids -or $targetGuids.Count -eq 0) {
        Write-Warning "[WARN] No corroborated GUIDs found (Tasks ∩ Registry)."
        # Fallback: if you still want to proceed, uncomment the next line:
        # $targetGuids = $taskGuids + $regGuids | Sort-Object -Unique
    } else {
        Write-Host "[INFO] Target GUIDs (intersection): $($targetGuids -join ', ')"
    }

    if ($BackupRegistryPath) {
        Backup-Registry -Dir $BackupRegistryPath
    }

    foreach ($g in $targetGuids) {
        Remove-EnrollmentScheduledTasks -Guid $g
        Remove-EnrollmentRegistry -Guid $g
    }

    # Optional: uncomment if you always want to remove certs in the same pass
    Remove-IntuneMdMCerts

    Write-Host "[INFO] Enrollment cleanup script completed."
}
catch {
       Write-Error "[ERROR] Unhandled exception: $($_.Exception.Message)"
