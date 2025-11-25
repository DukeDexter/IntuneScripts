
<# =====================================================================
 Intune Device Category Assignment (Android/iOS, Corporate-owned)
 Method: PUT v1.0 …/managedDevices/{id}/deviceCategory/$ref (relationship binding)
 Verifies each update; exports pre-change list; includes simple retry/backoff.

PowerShell script assigns Android/iOS, corporate‑owned managed devices to the “Intune – Corporately Owned Devices” category using the stable $ref relationship binding on Microsoft Graph v1.0, with verification, CSV export, and basic retry/backoff.

Prerequisites

PowerShell 5+ 
Microsoft.Graph.DeviceManagement module (script will install if missing).
App registration has Application Graph permissions: DeviceManagementManagedDevices.ReadWrite.All (and, typically, DeviceManagementConfiguration.ReadWrite.All).
Admin consent granted.
The app’s service principal is assigned to an Intune RBAC role that includes Managed devices → Update device and is scoped to the target devices (e.g., “All devices” or the right groups).

 ===================================================================== #>

# ---------------------------
# CONFIGURATION
# ---------------------------
$tenantId  = ""             # e.g., "00000000-0000-0000-0000-000000000000"
$clientId  = ""             # App (client) ID
$clientSecretPlain = ""     # Client Secret (store securely; this is for demo)

# Target device category display name (exact match)
$targetCategoryDisplayName = "Intune - Corporately Owned Devices"

# Export location for the "unassigned before change" snapshot
$exportFolder = "C:\temp"

# Device platform/ownership filter (defaults target Android/iOS company-owned)
$includeAndroid = $true
$includeIos     = $true
$ownerType      = "company"   # typically "company" for corporate-owned; use exact Intune value

# Operation mode
$whatIf         = $false       # Set $true to simulate (no writes), $false to perform writes

# Retry config for transient Graph errors
$maxAttempts    = 3
$initialDelayMs = 1500         # first backoff delay


# ---------------------------
# HELPER FUNCTIONS
# ---------------------------

function IsNullOrWhiteSpace([string]$s) { return [string]::IsNullOrWhiteSpace($s) }

function New-BackoffDelayMs([int]$attempt, [int]$initialMs) {
    # Exponential backoff with jitter
    $base = [math]::Pow(2, ($attempt - 1)) * $initialMs
    $jitter = Get-Random -Minimum 0 -Maximum ([int]($initialMs / 2))
    return [int]($base + $jitter)
}

function Invoke-GraphWithRetry {
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('PUT','POST','PATCH')]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [string] $Uri,

        [Parameter(Mandatory = $false)]
        [string] $Body,

        [int] $MaxAttempts = 3,
        [int] $InitialDelayMs = 1500
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            if ($Method -eq 'PUT')   { return Invoke-MgGraphRequest -Method PUT   -Uri $Uri -Body $Body }
            if ($Method -eq 'POST')  { return Invoke-MgGraphRequest -Method POST  -Uri $Uri -Body $Body }
            if ($Method -eq 'PATCH') { return Invoke-MgGraphRequest -Method PATCH -Uri $Uri -Body $Body }
        } catch {
            $msg = $_.Exception.Message
            $code = ""
            if ($_.Exception.Response -ne $null) {
                try {
                    $reader    = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                    $errorBody = $reader.ReadToEnd()
                    Write-Warning "Graph error body: $errorBody"
                    # Try to extract code from JSON
                    $parsed = $null
                    try { $parsed = $errorBody | ConvertFrom-Json } catch {}
                    if ($parsed -and $parsed.error -and $parsed.error.code) { $code = $parsed.error.code }
                } catch {}
            }

            # Retry on transient conditions: 429, 5xx, or throttling hints
            $shouldRetry = ($msg -match 'TooManyRequests|StatusCode:\s*429') -or
                           ($msg -match 'StatusCode:\s*5\d\d') -or
                           ($code -match 'TooManyRequests')

            if ($shouldRetry -and $attempt -lt $MaxAttempts) {
                $delay = New-BackoffDelayMs -attempt $attempt -initialMs $InitialDelayMs
                Write-Warning "Transient error ('$msg'). Retrying attempt $attempt/$MaxAttempts after $delay ms…"
                Start-Sleep -Milliseconds $delay
                continue
            }

            throw  # rethrow after max attempts or non-retryable error
        }
        break
    }
}

# ---------------------------
# MODULES & AUTH
# ---------------------------

# Install required module if needed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement)) {
    Write-Host "Installing Microsoft.Graph.DeviceManagement module…"
    Install-Module Microsoft.Graph.DeviceManagement -Force -AllowClobber
}
Import-Module Microsoft.Graph.DeviceManagement

# Connect with app-only (client secret)
$secureSecret = ConvertTo-SecureString $clientSecretPlain -AsPlainText -Force
Write-Host "Connecting to Microsoft Graph (app-only)…"
Connect-MgGraph -TenantId $tenantId -ClientId $clientId -ClientSecret $secureSecret
Select-MgProfile -Name "v1.0"

# ---------------------------
# STEP 1: Resolve target device category
# ---------------------------
Write-Host "Resolving device category '$targetCategoryDisplayName'…"
$targetCategory = Get-MgDeviceManagementDeviceCategory | Where-Object {
    $_.DisplayName -eq $targetCategoryDisplayName
}
if (-not $targetCategory) {
    Write-Error "Device category '$targetCategoryDisplayName' not found. Aborting."
    return
}
Write-Host "Target Category: $($targetCategory.DisplayName) (Id: $($targetCategory.Id))"

# ---------------------------
# STEP 2: Query devices (Android/iOS, corporate-owned)
# ---------------------------
$osFilterParts = @()
if ($includeAndroid) { $osFilterParts += "(operatingSystem eq 'Android')" }
if ($includeIos)     { $osFilterParts += "(operatingSystem eq 'iOS')" }
if ($osFilterParts.Count -eq 0) {
    Write-Warning "Both platforms disabled via config. Nothing to do."; return
}
$osFilter = $osFilterParts -join " or "

$filter = "(($osFilter) and managedDeviceOwnerType eq '$ownerType')"

Write-Host "Querying managed devices with filter: $filter"
$devices = Get-MgDeviceManagementManagedDevice -All `
    -Filter  $filter `
    -Property "id,deviceName,operatingSystem,managedDeviceOwnerType,deviceCategoryDisplayName,userPrincipalName"

Write-Host "Total candidate devices: $($devices.Count)"

# ---------------------------
# STEP 3: Filter devices not already in the target category
# ---------------------------
$unassignedDevices = $devices | Where-Object {
    IsNullOrWhiteSpace($_.DeviceCategoryDisplayName) -or
    $_.DeviceCategoryDisplayName -ne $targetCategory.DisplayName
}

Write-Host "Devices needing assignment: $($unassignedDevices.Count)"

# ---------------------------
# STEP 4: Export snapshot (pre-change)
# ---------------------------
if (-not (Test-Path -Path $exportFolder)) {
    New-Item -ItemType Directory -Path $exportFolder | Out-Null
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath   = Join-Path $exportFolder "UnassignedIntuneMobileDevices-$timestamp.csv"

$unassignedDevices | Select-Object `
    @{Name='DeviceId';Expression={$_.Id}},
    @{Name='DeviceName';Expression={$_.DeviceName}},
    @{Name='OperatingSystem';Expression={$_.OperatingSystem}},
    @{Name='OwnerType';Expression={$_.ManagedDeviceOwnerType}},
    @{Name='DeviceCategoryDisplayName';Expression={$_.DeviceCategoryDisplayName}},
    @{Name='UserPrincipalName';Expression={$_.UserPrincipalName}} |
    Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "Exported snapshot to: $csvPath"

# ---------------------------
# STEP 5: Assign category via $ref (v1.0) and verify
# ---------------------------
$refSegment = '$ref'  # avoid escaping issues by composing the segment separately
$successCount = 0
$failureCount = 0

foreach ($device in $unassignedDevices) {
    $deviceId   = $device.Id
    $deviceName = $device.DeviceName

    $uri  = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId/deviceCategory/$refSegment"
    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCategories/$($targetCategory.Id)"
    } | ConvertTo-Json

    try {
        if ($whatIf) {
            Write-Host "[WhatIf] Would PUT $uri with body @odata.id=$($targetCategory.Id)"
        } else {
            # PUT the relationship with basic retry/backoff
            Invoke-GraphWithRetry -Method PUT -Uri $uri -Body $body -MaxAttempts $maxAttempts -InitialDelayMs $initialDelayMs
        }

        # Brief delay to allow propagation
        Start-Sleep -Seconds 2

        # Verify (source of truth is Graph)
        $updated = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $deviceId `
                    -Property "id,deviceName,deviceCategoryDisplayName,operatingSystem,managedDeviceOwnerType"

        if ($updated.DeviceCategoryDisplayName -eq $targetCategory.DisplayName) {
            Write-Host "Assigned '$deviceName' → '$($targetCategory.DisplayName)'."
            $successCount++
        } else {
            Write-Warning "PUT $ref succeeded but device '$deviceName' still shows '$($updated.DeviceCategoryDisplayName)'. OS=$($updated.OperatingSystem), OwnerType=$($updated.ManagedDeviceOwnerType), Id=$($updated.Id)"
            $failureCount++
        }
    } catch {
        Write-Warning "Failed to assign device '$deviceName' (Id: $deviceId): $($_.Exception.Message)"
        if ($_.Exception.Response -ne $null) {
            try {
                $reader    = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errorBody = $reader.ReadToEnd()
                Write-Warning "Graph error body: $errorBody"
            } catch {}
        }
        $failureCount++
    }
}

Write-Host "Done. Success: $successCount, Failed/Not updated: $failureCount"

# Optional: exit code for automation (0 = all good; 1 = some failures)
if (-not $whatIf -and $failureCount -gt 0)
