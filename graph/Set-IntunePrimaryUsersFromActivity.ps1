<#
.SYNOPSIS
  Bulk-assign Intune primary users based on last 30 days activity using Microsoft Graph (app authentication).

.DESCRIPTION
  - Authenticates with Client Credentials (no interactive login).
  - Pulls sign-in logs (v1.0) from auditLogs/signIns and aggregates by (deviceId, userId).
  - Maps audit log deviceId (AAD device GUID) to Intune managedDevice via azureADDeviceId.
  - Assigns primary user using POST .../managedDevices('{id}')/users/$ref
  - Supports CSV import/export, dry-run, throttling/backoff, and detailed logging.

.PARAMETERS
  -TenantId          : Entra ID tenant (GUID or domain).
  -ClientId          : App registration (Application ID).
  -ClientSecret      : Client secret (string or secure string; env var supported).
  -LookbackDays      : Activity window (default: 30).
  -DataSource        : 'Graph' (default) or 'Csv'.
  -CsvPath           : When DataSource='Csv', path to CSV with columns: DeviceAadId, UserId, UserPrincipalName, CreatedDateTime.
  -MinEventsPerDevice: Minimum successful sign-ins for a user to qualify as primary (default: 2).
  -ExcludeUpnPattern : Regex to discard service/bot accounts (e.g., '^(svc-|system_)').
  -DryRun            : Switch; show actions without performing assignment.
  -OutDir            : Folder for output logs (CSV + JSON); default: ./output
  -Verbose           : Switch; detailed progress.

.EXAMPLE
  # Graph-only (recommended)
  .\Set-IntunePrimaryUsersFromActivity.ps1 `
    -TenantId "contoso.com" `
    -ClientId "00000000-0000-0000-0000-000000000000" `
    -ClientSecret (Get-Content env:GRAPH_APP_SECRET) `
    -LookbackDays 30 `
    -MinEventsPerDevice 3 `
    -ExcludeUpnPattern '^(svc-|system_)' `
    -DryRun

.EXAMPLE
  # Use previously exported CSV from Intune Device Usage (or your own aggregation)
  .\Set-IntunePrimaryUsersFromActivity.ps1 -DataSource Csv -CsvPath .\activity.csv -DryRun

.NOTES
  Required app permissions (Application):
    - AuditLog.Read.All        (read sign-ins)
    - Directory.Read.All       (resolve users; optional if using userId from logs)
    - DeviceManagementManagedDevices.ReadWrite.All (set primary user)
#>

param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [int]$LookbackDays = 30,
  [ValidateSet('Graph','Csv')][string]$DataSource = 'Graph',
  [string]$CsvPath,
  [int]$MinEventsPerDevice = 2,
  [string]$ExcludeUpnPattern,
  [switch]$DryRun,
  [string]$OutDir = "./output",
  [switch]$Verbose
)

# region Helpers ---------------------------------------------------------------

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Host "Installing module $Name..." -ForegroundColor Cyan
    Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
  }
}

function Connect-GraphApp {
  param([string]$TenantId,[string]$ClientId,[string]$ClientSecret)

  # Use app-only (client credentials) authentication
  Write-Host "Connecting to Microsoft Graph (app auth)..." -ForegroundColor Cyan
  Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -NoWelcome -ErrorAction Stop

  # Default profile is v1.0; we use v1.0 APIs for signIns and managedDevices
  Select-MgProfile -Name "v1.0"
  $ctx = Get-MgContext
  Write-Host "Connected as App: $($ctx.ClientId) Tenant: $($ctx.TenantId)" -ForegroundColor Green
}

# Exponential backoff wrapper
function Invoke-WithRetry {
  param(
    [scriptblock]$Script,
    [int]$MaxRetries = 6,
    [int]$BaseDelaySeconds = 2
  )
  $attempt = 0
  while ($true) {
    try {
      return & $Script
    } catch {
      $attempt++
      $status = $_.Exception.Response.StatusCode.Value__  # may be null
      $isTransient = ($status -in 429,500,503,504) -or $_.Exception.Message -match 'throttl|tempor|timeout'
      if ($attempt -le $MaxRetries -and $isTransient) {
        $delay = [math]::Min(60, $BaseDelaySeconds * [math]::Pow(2, ($attempt-1)))
        Write-Warning "Transient error (HTTP $status). Retrying in $delay sec... ($attempt/$MaxRetries)"
        Start-Sleep -Seconds $delay
        continue
      }
      throw
    }
  }
}

# endregion Helpers ------------------------------------------------------------

# region Setup -----------------------------------------------------------------

# Modules
Ensure-Module -Name Microsoft.Graph
Ensure-Module -Name Microsoft.Graph.Reports
Ensure-Module -Name Microsoft.Graph.DeviceManagement

# Output
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$logCsv = Join-Path $OutDir "PrimaryUserAssignment_$timestamp.csv"
$logJson = Join-Path $OutDir "PrimaryUserAssignment_$timestamp.json"

# Connect
Connect-GraphApp -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

# endregion Setup --------------------------------------------------------------

# region Data acquisition ------------------------------------------------------

function Get-ActivityFromGraph {
  param([int]$LookbackDays)

  $start = (Get-Date).AddDays(-$LookbackDays).ToString("o")
  $filter = "createdDateTime ge $start and status/errorCode eq 0"

  Write-Host "Fetching sign-in logs since $start ..." -ForegroundColor Cyan
  $pageSize = 1000

  $events = Invoke-WithRetry -Script {
    Get-MgAuditLogSignIn -Filter $filter -All -PageSize $pageSize `
      -Property @('id','createdDateTime','userId','userPrincipalName','deviceDetail/deviceId','deviceDetail/displayName','status/errorCode')
  }

  # Normalize and keep only rows with deviceId
  $clean = foreach ($e in $events) {
    $devId = $e.DeviceDetail.DeviceId
    if ([string]::IsNullOrWhiteSpace($devId)) { continue } # device must be registered/known
    [pscustomobject]@{
      CreatedDateTime     = [datetime]$e.CreatedDateTime
      DeviceAadId         = $devId
      DeviceName          = $e.DeviceDetail.DisplayName
      UserId              = $e.UserId
      UserPrincipalName   = $e.UserPrincipalName
    }
  }

  if ($ExcludeUpnPattern) {
    $clean = $clean | Where-Object { $_.UserPrincipalName -notmatch $ExcludeUpnPattern }
  }

  $clean
}

function Get-ActivityFromCsv {
  param([string]$CsvPath)

  if (-not (Test-Path $CsvPath)) {
    throw "CSV path not found: $CsvPath"
  }

  $rows = Import-Csv $CsvPath
  # Expect columns: DeviceAadId, UserId, UserPrincipalName, CreatedDateTime
  foreach ($r in $rows) {
    [pscustomobject]@{
      CreatedDateTime     = [datetime]$r.CreatedDateTime
      DeviceAadId         = $r.DeviceAadId
      DeviceName          = $r.DeviceName
      UserId              = $r.UserId
      UserPrincipalName   = $r.UserPrincipalName
    }
  }
}

$activity =
  if ($DataSource -eq 'Graph') { Get-ActivityFromGraph -LookbackDays $LookbackDays }
  else { Get-ActivityFromCsv -CsvPath $CsvPath }

if (-not $activity -or $activity.Count -eq 0) {
  throw "No activity rows found for the selected data source."
}

# endregion Data acquisition ---------------------------------------------------

# region Aggregation -----------------------------------------------------------

# Group by device, then user; pick the user with max events (tie-breaker = latest sign-in)
$deviceTopUser = @{}

$byDevice = $activity | Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $devId = $devGroup.Name
  $byUser = $devGroup.Group | Group-Object UserId
  $ranked = $byUser | Sort-Object Count -Descending
  $winner = $ranked | Select-Object -First 1

  if ($winner.Count -lt $MinEventsPerDevice) { continue }

  # Tie-breaker on latest sign-in among tied users
  $candidates = $ranked | Where-Object { $_.Count -eq $winner.Count }
  if ($candidates.Count -gt 1) {
    $latest = $null
    $latestUser = $null
    foreach ($c in $candidates) {
      $recent = ($c.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
      if (-not $latest -or $recent -gt $latest) {
        $latest = $recent
        $latestUser = $c
      }
    }
    $winner = $latestUser
  }

  $userId = $winner.Group[0].UserId
  $upn    = $winner.Group[0].UserPrincipalName
  $deviceName = ($devGroup.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).DeviceName

  $deviceTopUser[$devId] = [pscustomobject]@{
    DeviceAadId = $devId
    DeviceName  = $deviceName
    UserId      = $userId
    UserPrincipalName = $upn
    EventCount  = $winner.Count
  }
}

if ($deviceTopUser.Count -eq 0) {
  throw "After applying thresholds, no devices have a qualifying top user."
}

# endregion Aggregation --------------------------------------------------------

# region Resolution: AAD device -> Intune managedDevice ------------------------

function Resolve-ManagedDevice {
  param([string]$AzureAdDeviceId)

  # Filter by azureADDeviceId (GUID) to get the Intune managed device object
  $md = Invoke-WithRetry -Script {
    Get-MgDeviceManagementManagedDevice -Filter "azureADDeviceId eq '$AzureAdDeviceId'" -Top 1 `
      -Property @('id','azureADDeviceId','deviceName','userId','userPrincipalName')
  }

  if (-not $md) { return $null }
  return $md[0]
}

# Build work items
$work = @()
foreach ($kvp in $deviceTopUser.GetEnumerator()) {
  $aadDevId = $kvp.Key
  $tu       = $kvp.Value

  $md = Resolve-ManagedDevice -AzureAdDeviceId $aadDevId
  if (-not $md) {
    $work += [pscustomobject]@{
      DeviceAadId = $aadDevId; DeviceName = $tu.DeviceName
      ManagedDeviceId = $null
      CurrentPrimaryUserId = $null
      TargetUserId = $tu.UserId; TargetUpn = $tu.UserPrincipalName
      EventCount = $tu.EventCount
      Action = "Skip_NoManagedDevice"
      Result = "No Intune managedDevice found for AAD device"
    }
    continue
  }

  $currentUserId = $md.UserId
  $action = if ($currentUserId -eq $tu.UserId) { "Skip_AlreadyPrimary" } else { "Assign_PrimaryUser" }

  $work += [pscustomobject]@{
    DeviceAadId = $aadDevId; DeviceName = $md.DeviceName
    ManagedDeviceId = $md.Id
    CurrentPrimaryUserId = $currentUserId
    TargetUserId = $tu.UserId; TargetUpn = $tu.UserPrincipalName
    EventCount = $tu.EventCount
    Action = $action
    Result = ""
  }
}

# endregion Resolution ---------------------------------------------------------

# region Assignment ------------------------------------------------------------

function Assign-PrimaryUser {
  param([string]$ManagedDeviceId,[string]$TargetUserId)

  # POST reference to users/$ref per Intune guidance
  $uri  = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"
  $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$TargetUserId" } | ConvertTo-Json

  Invoke-WithRetry -Script {
    Invoke-MgGraphRequest -Uri $uri -Method POST -Body $body -ContentType 'application/json'
  }
}

$results = @()

foreach ($item in $work) {
  if ($item.Action -eq 'Skip_NoManagedDevice' -or $item.Action -eq 'Skip_AlreadyPrimary') {
    $item.Result = $item.Action
    $results += $item
    continue
  }

  if ($DryRun) {
    $item.Result = "DryRun_Assign_PrimaryUser"
    $results += $item
    continue
  }

  try {
    Assign-PrimaryUser -ManagedDeviceId $item.ManagedDeviceId -TargetUserId $item.TargetUserId
    $item.Result = "Success_Assigned"
    $results += $item
    Start-Sleep -Milliseconds 200  # gentle pacing to avoid throttling
  }
  catch {
    $item.Result = "Error: $($_.Exception.Message)"
    $results += $item
  }
}

# Persist logs
$results | Export-Csv -NoTypeInformation -Path $logCsv
$results | ConvertTo-Json -Depth 6 | Out-File -FilePath $logJson -Encoding utf8

Write-Host "`nCompleted. Results:" -ForegroundColor Green
Write-Host "  CSV : $logCsv"
Write-Host "  JSON: $logJson"

# Summary
$summary = $results | Group-Object Result | Select-Object Name,Count
$summary | Format-Table -AutoSize

# endregion Assignment ---------------------------------------------------------
