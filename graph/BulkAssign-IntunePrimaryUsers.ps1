<#
.SYNOPSIS
  Bulk-assign Intune primary users based on last 30 days of user sign-ins using Microsoft Graph (client credentials).
  No Microsoft.Graph modules are imported—avoids session function capacity overflow.

.PARAMETERS
  -TenantId           : Entra tenant (GUID or domain, e.g., contoso.com)
  -ClientId           : App registration (Application ID)
  -ClientSecret       : App client secret (secure storage recommended)
  -LookbackDays       : Window in days (default: 30)
  -MinEventsPerDevice : Minimum successful sign-ins by a user to qualify (default: 2)
  -ExcludeUpnPattern  : Regex to exclude service/bot accounts (e.g., '^(svc-|system_)')
  -DryRun             : Preview assignments without committing
  -OutputDir          : Folder to write CSV results (default: current dir)
 - AuditLog.Read.All
  - DeviceManagementManagedDevices.ReadWrite.All
  - Directory.Read.All (optional; not strictly required if you use userId from sign-ins)

.REFERENCES
  List signIns API: https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-1.0
  deviceDetail schema: https://learn.microsoft.com/graph/api/resources/devicedetail?view=graph-rest-1.0
  managedDevice resource: https://learn.microsoft.com/graph/api/resources/intune-devices-manageddevice?view=graph-rest-1.0
  Assign primary user: https://learn.microsoft.com/answers/questions/2153820/how-do-you-re-assign-a-primary-user-to-an-intune-d
#>

param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [int]$LookbackDays = 30,
  [int]$MinEventsPerDevice = 2,
  [string]$ExcludeUpnPattern,
  [switch]$DryRun,
  [string]$OutputDir = ".",
  [string]$GraphEndpoint = "https://graph.microsoft.com"
)

# ------------------------------ Helpers --------------------------------------

function Get-GraphToken {
  param([string]$TenantId,[string]$ClientId,[string]$ClientSecret,[string]$GraphEndpoint)

  $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  if ($GraphEndpoint -like "https://microsoftgraph.chinacloudapi.cn") {
    $tokenUri = "https://login.partner.microsoftonline.cn/$TenantId/oauth2/v2.0/token"
  }

  $body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
    scope         = "$GraphEndpoint/.default"
  }

  try {
    $resp = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    return $resp.access_token
  } catch {
    throw "Failed to obtain token: $($_.Exception.Message)"
  }
}

function Invoke-Graph {
  param(
    [string]$Method, [string]$Uri, [hashtable]$Headers, [object]$Body = $null,
    [int]$MaxRetries = 6
  )

  $attempt = 0
  while ($true) {
    try {
      if ($Method -eq "GET") {
        return Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -ErrorAction Stop
      } elseif ($Method -eq "POST") {
        return Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers -ErrorAction Stop -Body $Body -ContentType "application/json"
      } elseif ($Method -eq "PATCH") {
        return Invoke-RestMethod -Method PATCH -Uri $Uri -Headers $Headers -ErrorAction Stop -Body $Body -ContentType "application/json"
      } elseif ($Method -eq "DELETE") {
        return Invoke-RestMethod -Method DELETE -Uri $Uri -Headers $Headers -ErrorAction Stop
      } else {
        throw "Unsupported method: $Method"
      }
    } catch {
      $attempt++
      $webResp = $_.Exception.Response
      $status = $null
      $retryAfter = 0
      if ($webResp) {
        $status = [int]$webResp.StatusCode
        $raHdr = $webResp.Headers["Retry-After"]
        if ($raHdr) { [int]::TryParse($raHdr, [ref]$retryAfter) | Out-Null }
      }
      $transient = $status -in 429,500,503,504
      if ($attempt -le $MaxRetries -and $transient) {
        $delay = ($retryAfter -gt 0) ? $retryAfter : [math]::Min(60, [math]::Pow(2,$attempt))
        Write-Warning "Transient HTTP $status calling $Uri. Retrying in $delay sec... ($attempt/$MaxRetries)"
        Start-Sleep -Seconds $delay
        continue
      }
      throw "Graph call failed (HTTP $status): $($_.Exception.Message)"
    }
  }
}

function Get-GraphPaged {
  param([string]$Uri,[hashtable]$Headers)
  $items = @()
  $next  = $Uri
  while ($next) {
    $resp = Invoke-Graph -Method GET -Uri $next -Headers $Headers
    if ($resp.value) { $items += $resp.value }
    $next = $resp.'@odata.nextLink'
  }
  return $items
}

# ------------------------------ Auth -----------------------------------------

Write-Host "Authenticating to Graph ($GraphEndpoint)..." -ForegroundColor Cyan
$token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
$headers = @{ "Authorization" = "Bearer $token" }

# ------------------------------ Fetch sign-ins -------------------------------

# Use UTC with milliseconds at most: yyyy-MM-ddTHH:mm:ssZ (Graph filter requirement)
$startIso = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "Fetching sign-ins since $startIso ..." -ForegroundColor Cyan

# Request up to 1000 per page; $select keeps payload small. deviceDetail is nested, returned by default; selecting it is valid.
$signInsUri = "$GraphEndpoint/v1.0/auditLogs/signIns" +
              "?`$filter=createdDateTime ge $startIso and status/errorCode eq 0" +
              "&`$select=createdDateTime,userId,userPrincipalName,deviceDetail" +
              "&`$top=1000"

$signIns = Get-GraphPaged -Uri $signInsUri -Headers $headers

# Normalize rows; keep entries with deviceDetail.deviceId present
$activity = foreach ($e in $signIns) {
  $devId = $e.deviceDetail.deviceId
  if ([string]::IsNullOrWhiteSpace($devId)) { continue }
  $upn = $e.userPrincipalName
  if ($ExcludeUpnPattern -and $upn -match $ExcludeUpnPattern) { continue }

  [pscustomobject]@{
    CreatedDateTime   = [datetime]$e.createdDateTime
    DeviceAadId       = $devId
    DeviceName        = $e.deviceDetail.displayName
    UserId            = $e.userId
    UserPrincipalName = $upn
  }
}

if (-not $activity -or $activity.Count -eq 0) {
  $ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @() | Export-Csv -NoTypeInformation -Path $csvPath
  Write-Warning "No sign-in rows with deviceId found. Empty results written to $csvPath"
  exit 0
}

# ------------------------------ Aggregate winners ----------------------------

$assignments = @()
$byDevice = $activity | Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $userGroups = $devGroup.Group | Group-Object UserId | Sort-Object Count -Descending
  $winner = $userGroups | Select-Object -First 1

  if ($winner.Count -lt $MinEventsPerDevice) { continue }

  # Tie-breaker by most recent sign-in
  $ties = $userGroups | Where-Object { $_.Count -eq $winner.Count }
  if ($ties.Count -gt 1) {
    $winner = $ties |
      Sort-Object @{Expression={($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime}}, Descending |
      Select-Object -First 1
  }

  $assignments += [pscustomobject]@{
    DeviceAadId  = $devGroup.Name
    DeviceName   = ($devGroup.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).DeviceName
    TargetUserId = $winner.Name
    TargetUpn    = ($winner.Group | Select-Object -First 1).UserPrincipalName
    EventCount   = $winner.Count
  }
}

Write-Host "Devices with qualifying primary users: $($assignments.Count)" -ForegroundColor Cyan
if ($assignments.Count -eq 0) {
  $ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @() | Export-Csv -NoTypeInformation -Path $csvPath
  Write-Warning "No qualifying users found. Empty results written to $csvPath"
  exit 0
}

# ------------------------------ Resolve managedDevices -----------------------

function Get-ManagedDeviceByAadId {
  param([string]$AadDeviceId,[hashtable]$Headers,[string]$GraphEndpoint)

  # Filter on azureADDeviceId; select small set of properties
  $uri = "$GraphEndpoint/v1.0/deviceManagement/managedDevices" +
         "?`$filter=azureADDeviceId eq '$AadDeviceId'" +
         "&`$select=id,azureADDeviceId,deviceName,userId,userPrincipalName" +
         "&`$top=1"

  $resp = Invoke-Graph -Method GET -Uri $uri -Headers $Headers
  if ($resp.value -and $resp.value.Count -ge 1) { return $resp.value[0] }
  return $null
}

$work = @()
foreach ($item in $assignments) {
  $md = Get-ManagedDeviceByAadId -AadDeviceId $item.DeviceAadId -Headers $headers -GraphEndpoint $GraphEndpoint
  if (-not $md) {
    $work += [pscustomobject]@{
      DeviceAadId = $item.DeviceAadId; DeviceName = $item.DeviceName
      ManagedDeviceId = $null; CurrentPrimaryUserId = $null
      TargetUserId = $item.TargetUserId; TargetUpn = $item.TargetUpn
      EventCount = $item.EventCount
      Action = "Skip_NoManagedDevice"; Result = "No Intune object found"
    }
    continue
  }
  $action = if ($md.userId -eq $item.TargetUserId) { "Skip_AlreadyPrimary" } else { "Assign_PrimaryUser" }
  $work += [pscustomobject]@{
    DeviceAadId = $item.DeviceAadId; DeviceName = $md.deviceName
    ManagedDeviceId = $md.id
    CurrentPrimaryUserId = $md.userId
    TargetUserId = $item.TargetUserId; TargetUpn = $item.TargetUpn
    EventCount = $item.EventCount
    Action = $action; Result = ""
  }
}

# ------------------------------ Assign primary user --------------------------

function Assign-PrimaryUser {
  param([string]$ManagedDeviceId,[string]$UserId,[hashtable]$Headers,[string]$GraphEndpoint)

  $uri  = "$GraphEndpoint/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"
  $body = @{ '@odata.id' = "$GraphEndpoint/v1.0/users/$UserId" } | ConvertTo-Json

  Invoke-Graph -Method POST -Uri $uri -Headers $Headers -Body $body | Out-Null
}

$results = @()
foreach ($row in $work) {
  if ($row.Action -like "Skip_*") {
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
    Assign-PrimaryUser -ManagedDeviceId $row.ManagedDeviceId -UserId $row.TargetUserId -Headers $headers -GraphEndpoint $GraphEndpoint
    $row.Result = "Success_Assigned"
  } catch {
    $row.Result = "Error: $($_.Exception.Message)"
  }
  $results += $row

  Start-Sleep -Milliseconds 200  # gentle pacing
}

# ------------------------------ Export results -------------------------------

$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
$results | Export-Csv -NoTypeInformation -Path $csvPath
Write-Host "Completed. Results saved to $csvPath" -ForegroundColor Green  -GraphEndpoint      : Graph base URL (default: https://graph.microsoft.com)
                         For 21Vianet tenants, use: https://microsoftgraph.chinacloudapi.cn

.REQUIREMENTS (Application permissions, with admin consent)
 
