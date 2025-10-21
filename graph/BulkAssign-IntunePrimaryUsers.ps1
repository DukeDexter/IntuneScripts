<#
.SYNOPSIS
  Bulk assign Intune primary users based on last 30 days of user sign-ins (app-only auth).

.REQUIREMENTS (Application permissions on your app registration)
  - AuditLog.Read.All                  (read sign-ins)
  - DeviceManagementManagedDevices.ReadWrite.All   (set primary user)
  - Directory.Read.All                 (optional; for user lookups)

.REFERENCES
  List signIns API: https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-1.0
  deviceDetail schema: https://learn.microsoft.com/graph/api/resources/devicedetail?view=graph-rest-1.0
  managedDevice resource: https://learn.microsoft.com/graph/api/resources/intune-devices-manageddevice?view=graph-rest-1.0
  Assign primary user (users/$ref): https://learn.microsoft.com/answers/questions/2153820/how-do-you-re-assign-a-primary-user-to-an-intune-d
#>

param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [int]$LookbackDays = 30,
  [int]$MinEventsPerDevice = 2,     # minimum successful sign-ins to qualify
  [string]$ExcludeUpnPattern,       # e.g. '^(svc-|system_)' to skip service accounts
  [switch]$DryRun                   # preview without committing changes
)

# --- Module setup (single pass) ----------------------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
  Install-Module Microsoft.Graph -Scope CurrentUser -Force -ErrorAction Stop
}
Import-Module Microsoft.Graph -ErrorAction Stop  # meta-module autoloads submodules

# --- App-only authentication --------------------------------------------------
Write-Host "Connecting to Microsoft Graph using app credentials..." -ForegroundColor Cyan
$secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$credential   = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -ErrorAction Stop

$ctx = Get-MgContext
Write-Host "Connected. Tenant: $($ctx.TenantId) AppId: $($ctx.ClientId)" -ForegroundColor Green

# --- Helper: transient retry wrapper -----------------------------------------
function Invoke-WithRetry {
  param([scriptblock]$Script,[int]$MaxRetries=6,[int]$BaseDelaySeconds=2)
  $n=0
  while ($true) {
    try { return & $Script } catch {
      $n++
      $status = $_.Exception.Response.StatusCode.Value__
      $transient = ($status -in 429,500,503,504) -or ($_.Exception.Message -match 'throttl|tempor|timeout')
      if ($n -le $MaxRetries -and $transient) {
        $delay = [math]::Min(60, $BaseDelaySeconds * [math]::Pow(2, ($n-1)))
        Write-Warning "Transient HTTP $status. Retrying in $delay sec... ($n/$MaxRetries)"
        Start-Sleep -Seconds $delay; continue
      }
      throw
    }
  }
}

# --- Fetch last-30-days sign-ins (no -Property to avoid OData % errors) ------
$startIso = (Get-Date).AddDays(-$LookbackDays).ToString("o")
Write-Host "Fetching sign-in logs since $startIso ..." -ForegroundColor Cyan

try {
  # NOTE: List signIns returns interactive/federated successful sign-ins. Non-interactive are limited. [1](https://microsoft.service-now.com/sp?id=kb_article_view&sys_id=d8be56fe1b5a91d0a29d2fc8b04bcbb5)[3](https://microsoft.service-now.com/sp?id=kb_article_view&sys_id=40bc75fa0d2f402ea9ae4c0dd08a64bd)
  $signIns = Invoke-WithRetry {
    Get-MgAuditLogSignIn -Filter "createdDateTime ge $startIso and status/errorCode eq 0" -All
  }
} catch {
  Write-Error "Failed to read sign-ins: $($_.Exception.Message)"
  throw
}

# Normalize rows, filter to entries with AAD device GUID present
$activity = foreach ($e in $signIns) {
  $devId = $e.DeviceDetail.DeviceId
  if ([string]::IsNullOrWhiteSpace($devId)) { continue }
  if ($ExcludeUpnPattern -and ($e.UserPrincipalName -match $ExcludeUpnPattern)) { continue }

  [pscustomobject]@{
    CreatedDateTime     = [datetime]$e.CreatedDateTime
    DeviceAadId         = $devId
    DeviceName          = $e.DeviceDetail.DisplayName
    UserId              = $e.UserId
    UserPrincipalName   = $e.UserPrincipalName
  }
}

if (-not $activity -or $activity.Count -eq 0) {
  Write-Warning "No sign-in rows with deviceId found in the selected window. Nothing to assign."
  $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $emptyPath = ".\PrimaryUserAssignment_$timestamp.csv"
  @() | Export-Csv -NoTypeInformation -Path $emptyPath
  Write-Host "Empty results written to $emptyPath" -ForegroundColor Yellow
  return
}

# --- Aggregate: per-device, pick most active user -----------------------------
$assignments = @()
$byDevice = $activity | Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $userGroups = $devGroup.Group | Group-Object UserId | Sort-Object Count -Descending
  $winner = $userGroups | Select-Object -First 1
  if ($winner.Count -lt $MinEventsPerDevice) { continue }

  # Tie-breaker by latest sign-in if counts equal
  $candidates = $userGroups | Where-Object { $_.Count -eq $winner.Count }
  if ($candidates.Count -gt 1) {
    $winner = $candidates |
      Sort-Object @{Expression={($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime}}, Descending |
      Select-Object -First 1
  }

  $assignments += [pscustomobject]@{
    DeviceAadId    = $devGroup.Name
    DeviceName     = ($devGroup.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).DeviceName
    TargetUserId   = $winner.Name
    TargetUpn      = ($winner.Group | Select-Object -First 1).UserPrincipalName
    EventCount     = $winner.Count
  }
}

Write-Host "Devices with qualifying primary users: $($assignments.Count)" -ForegroundColor Cyan
if ($assignments.Count -eq 0) {
  $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $emptyPath = ".\PrimaryUserAssignment_$timestamp.csv"
  @() | Export-Csv -NoTypeInformation -Path $emptyPath
  Write-Host "Empty results written to $emptyPath" -ForegroundColor Yellow
  return
}

# --- Resolve to Intune managedDevice via azureADDeviceId ----------------------
function Resolve-ManagedDevice {
  param([string]$AzureAdDeviceId)
  Invoke-WithRetry {
    Get-MgDeviceManagementManagedDevice -Filter "azureADDeviceId eq '$AzureAdDeviceId'" -Top 1 `
      -Property @('id','azureADDeviceId','deviceName','userId','userPrincipalName')
  }
}

$work = @()
foreach ($item in $assignments) {
  $md = Resolve-ManagedDevice -AzureAdDeviceId $item.DeviceAadId
  if (-not $md) {
    $work += [pscustomobject]@{
      DeviceAadId = $item.DeviceAadId; DeviceName = $item.DeviceName
      ManagedDeviceId = $null
      CurrentPrimaryUserId = $null
      TargetUserId = $item.TargetUserId; TargetUpn = $item.TargetUpn
      EventCount = $item.EventCount
      Action = "Skip_NoManagedDevice"; Result = "No Intune object"
    }
    continue
  }

  $action = if ($md.UserId -eq $item.TargetUserId) { "Skip_AlreadyPrimary" } else { "Assign_PrimaryUser" }
  $work += [pscustomobject]@{
    DeviceAadId = $item.DeviceAadId; DeviceName = $md.DeviceName
    ManagedDeviceId = $md.Id
    CurrentPrimaryUserId = $md.UserId
    TargetUserId = $item.TargetUserId; TargetUpn = $item.TargetUpn
    EventCount = $item.EventCount
    Action = $action; Result = ""
  }
}

# --- Assign primary user via users/$ref ---------------------------------------
function Assign-PrimaryUser {
  param([string]$ManagedDeviceId,[string]$UserId)
  $uri  = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"
  $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$UserId" } | ConvertTo-Json
  Invoke-WithRetry { Invoke-MgGraphRequest -Uri $uri -Method POST -Body $body -ContentType 'application/json' }
}

$results = @()
foreach ($row in $work) {
  if ($row.Action -like 'Skip_*') {
    $row.Result = $row.Action
    $results += $row
    continue
  }

  if ($DryRun) {
    $row.Result = "DryRun_Assign_PrimaryUser"
    $results += $row
    continue
  }

  try {
    Assign-PrimaryUser -ManagedDeviceId $row.ManagedDeviceId -UserId $row.TargetUserId
    $row.Result = "Success_Assigned"
  } catch {
    $row.Result = "Error: $($_.Exception.Message)"
  }
  $results += $row
  Start-Sleep -Milliseconds 200  # gentle pacing
}

# --- Export -------------------------------------------------------------------
$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$csvPath = ".\PrimaryUserAssignment_$ts.csv"
$results | Export-Csv -NoTypeInformation -Path $csvPath

Write-Host "Completed. Results saved to $csvPath" -ForegroundColor Green
