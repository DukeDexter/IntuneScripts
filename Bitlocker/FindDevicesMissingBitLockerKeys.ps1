
<#
.SYNOPSIS

Identifies Intune‑managed Windows devices that do not have BitLocker recovery keys escrowed to Entra ID (Azure AD).
Helps admins quickly detect non‑compliant or misconfigured devices.
Produces a CSV report in the script directory (or current directory if pasted/run inline).

.DESCRIPTION

Connects to Microsoft Graph using delegated permissions.
Retrieves:
 - All BitLocker recovery keys.
 - All Intune‑managed devices within the last 30 days.
Filters devices:
 - Windows OS only.
 - Not virtual or VMware/Hyper‑V.
 - MDM or ConfigMgr‑co‑managed.
Compares Intune devices vs. devices that have escrowed recovery keys.
Outputs a CSV of devices missing recovery keys.
Always produces a run artifact CSV (empty or header‑only if no issues).

.EXAMPLE
    .\FindDevicesMissingBitLockerKeys.ps1

.NOTES
    Author: Duke Dexter (https://github.com/DukeDexter)
    Updated by: M365 Copilot for Himanshu (console-safe + resilience + output suppression)
    Date: 23-Dec-2025
    Requires:
      - PowerShell 5.1+ / 7+
      - Microsoft.Graph.DeviceManagement
      - Microsoft.Graph.Identity.SignIns
      - Tenant consent for: DeviceManagementManagedDevices.Read.All, BitLockerKey.Read.All
#>

# ----------------------------
# Helpers
# ----------------------------
function Is-NullOrWhiteSpace {
    param([string]$s)
    # Use .NET string check via type accelerator for reliability
    return [string]::IsNullOrWhiteSpace($s)
}

function Get-OutputDirectory {
    $dir = $PSScriptRoot
    if (Is-NullOrWhiteSpace $dir) {
        try {
            if (-not (Is-NullOrWhiteSpace $PSCommandPath)) {
                $dir = Split-Path -Path $PSCommandPath -ErrorAction SilentlyContinue
            }
        } catch { $dir = $null }
    }
    if (Is-NullOrWhiteSpace $dir) {
        $dir = (Get-Location).Path
    }
    return $dir
}

# ----------------------------
# Top-level control flow
# ----------------------------
try {
    # ---- Resilient output path handling ----
    $directory = Get-OutputDirectory
    $date      = Get-Date -Format "ddMMyyyy-HHmmss"
    $OutputCsv = Join-Path -Path $directory -ChildPath "IntuneDevicesMissingBitlockerkeys_$date.csv"
    Write-Host "Output will be written to: $OutputCsv" -ForegroundColor Cyan

    # ---- Ensure required modules ----
    $modulesToCheck = @(
        'Microsoft.Graph.DeviceManagement',
        'Microsoft.Graph.Identity.SignIns'
    )

    foreach ($moduleName in $modulesToCheck) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Host "Module '$moduleName' not found. Installing..." -ForegroundColor Yellow
            try {
                Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            } catch {
                Write-Host "Failed to install module '$moduleName'. Error: $($_.Exception.Message)" -ForegroundColor Red
                # Create artifact for traceability; return instead of exit
                "" | Out-File -FilePath $OutputCsv
                return
            }
        }
        try {
            Import-Module -Name $moduleName -Force -ErrorAction Stop
        } catch {
            Write-Host "Failed to import module '$moduleName'. Error: $($_.Exception.Message)" -ForegroundColor Red
            "" | Out-File -FilePath $OutputCsv
            return
        }
    }

    # ---- Connect to Microsoft Graph ----
    $GraphConnected = $false
    try {
        # Ensure TLS 1.2 in Windows PowerShell
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }

        $scopes = @(
            'DeviceManagementManagedDevices.Read.All',
            'BitLockerKey.Read.All'
        )
        # Suppress the returned context object to avoid printing ClientId/TenantId etc.
        $null = Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        $GraphConnected = $true
        Write-Host "Connected to Microsoft Graph." -ForegroundColor Green
    } catch {
        Write-Host "Unable to connect to Microsoft Graph. Error: $($_.Exception.Message)" -ForegroundColor Red
        "" | Out-File -FilePath $OutputCsv
        Write-Host "Script execution ended early. See file '$OutputCsv' for status." -ForegroundColor Yellow
        return
    }

    if (-not $GraphConnected) {
        Write-Host "Failed to connect to Microsoft Graph." -ForegroundColor Red
        "" | Out-File -FilePath $OutputCsv
        return
    }

    # ---- Retrieve BitLocker keys ----
    Write-Host "Retrieving BitLocker recovery keys..." -ForegroundColor Green
    $allRecoveryKeys = $null
    try {
        $allRecoveryKeys = Get-MgInformationProtectionBitlockerRecoveryKey -All -ErrorAction Stop
    } catch {
        Write-Host "Error retrieving BitLocker recovery keys: $($_.Exception.Message)" -ForegroundColor Red
        "" | Out-File -FilePath $OutputCsv
        Write-Host "Script execution completed with errors. See '$OutputCsv'." -ForegroundColor Yellow
        return
    }

    if ($null -eq $allRecoveryKeys -or $allRecoveryKeys.Count -eq 0) {
        Write-Host "No BitLocker recovery keys found in Entra/Graph." -ForegroundColor Yellow
        # Write an empty CSV artifact to mark the run
        "" | Out-File -FilePath $OutputCsv
        Write-Host "Script execution completed. See file '$OutputCsv' for status." -ForegroundColor Green
        return
    }

    # ---- Latest key per device ----
    $latestRecoveryKeys = $allRecoveryKeys |
        Group-Object -Property DeviceId |
        ForEach-Object {
            $_.Group | Sort-Object -Property CreatedDateTime -Descending | Select-Object -First 1
        }

    # HashSet for quick lookup
    $latestRecoveryKeyDeviceIds = [System.Collections.Generic.HashSet[string]]::new()
    $latestRecoveryKeys | ForEach-Object { [void]$latestRecoveryKeyDeviceIds.Add($_.DeviceId) }

    # ---- Retrieve Intune managed devices ----
    Write-Host "Retrieving Intune managed devices (filtered to physical Windows)..." -ForegroundColor Green

    # Consider devices that synced in the last 30 days
    $Daysolder = (Get-Date).AddDays(-30)

    $IntuneDevices = $null
    try {
        $IntuneDevices = Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop
    } catch {
        Write-Host "Error retrieving Intune managed devices: $($_.Exception.Message)" -ForegroundColor Red
        "" | Out-File -FilePath $OutputCsv
        Write-Host "Script execution completed with errors. See '$OutputCsv'." -ForegroundColor Yellow
        return
    }

    # Filter to physical Windows, Intune/co-managed, recently synced
    $FilteredIntuneDevices = $IntuneDevices | Where-Object {
        ($_.LastSyncDateTime -ge $Daysolder) -and
        ($_.OperatingSystem -eq 'Windows') -and
        (
            $_.ManagementAgent -eq 'MDM' -or
            $_.ManagementAgent -eq 'configurationManagerClientMdm'
        ) -and
        ($_.Model -notlike '*Virtual*') -and
        ($_.Model -notlike '*Vmware*') -and
        ($_.Model -notlike '*Hyper-V*') -and
        ($_.Model -notlike '*Virtual Machine*')
    }

    # ---- Devices without keys ----
    $devicesWithoutKeys = $FilteredIntuneDevices | Where-Object {
        -not $latestRecoveryKeyDeviceIds.Contains($_.AzureAdDeviceId)
    }

    if ($devicesWithoutKeys.Count -ge 1) {
        Write-Host "Total devices found in Intune without BitLocker keys: $($devicesWithoutKeys.Count)." -ForegroundColor Yellow

        # Export details to CSV
        $devicesWithoutKeys |
            Select-Object `
                AzureAdDeviceId,
                DeviceName,
                UserPrincipalName,
                EmailAddress,
                EnrolledDateTime,
                LastSyncDateTime,
                Id,
                ManagementAgent,
                Model,
                OSVersion,
                SerialNumber |
            Export-Csv -Path $OutputCsv -NoTypeInformation

        Write-Host "Script execution completed. See file '$OutputCsv' for details." -ForegroundColor Green
    } else {
        # Write a header-only CSV to mark a clean run
        $header = 'AzureAdDeviceId,DeviceName,UserPrincipalName,EmailAddress,EnrolledDateTime,LastSyncDateTime,Id,ManagementAgent,Model,OSVersion,SerialNumber'
        $header | Out-File -FilePath $OutputCsv -Encoding utf8

        Write-Host "No devices found that are missing BitLocker keys. YOU ARE GOOD TO GO." -ForegroundColor Green
        Write-Host "A header-only CSV was created at '$OutputCsv' as a run artifact." -ForegroundColor Cyan
    }

} catch {
    # Top-level error handling keeps console open
    Write-Error $_
} finally {
    # ---- Optional: Disconnect Graph ----
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch { }

    # ---- Optional: keep window open for double-click runs ----
    # Comment this block out if you run from existing consoles or CI
    if ($Host.Name -notlike '*Visual Studio Code*' -and $Host.Name -notlike '*ConsoleHost*') {
        Read-Host "Press Enter to close..."
    }
}
``
