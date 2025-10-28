# Bulk assign Intune primary users based on sign-in activity
# Compatible with PowerShell 5.1 and 7+

& {
param(
  [string]$TenantId = "yourtenant.onmicrosoft.com",
  [string]$ClientId = "11111111-2222-3333-4444-555555555555",
  [string]$ClientSecret = "your-client-secret",
  [int]$LookbackDays = 30,
  [int]$MinEventsPerDevice = 3,
  [string]$ExcludeUpnPattern = "",
  [switch]$DryRun = $true,
  [string]$OutputDir = "C:\Intune\PrimaryUser",
  [string]$LogPath = "C:\Intune\PrimaryUser\bulkassign.log",
  [string]$CheckpointPath = "C:\Intune\PrimaryUser\checkpoint.json",
  [switch]$Resume = $false,
  [string]$GraphEndpoint = "https://graph.microsoft.com",
  [int]$MaxPages = 100,
  [int]$BatchSize = 100,
  [int]$AssignmentDelayMs = 200,
  [int]$AssignmentMaxRetries = 3
)

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
  New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Logging function
function Write-Log {
  param([string]$Level, [string]$Message)
  $line = "$(Get-Date -Format o) [$Level] $Message"
  Add-Content -Path $LogPath -Value $line
}

# Load checkpoint
function Load-Checkpoint {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return @{} }
  try {
    $json = Get-Content -Path $Path -Raw
    $data = ConvertFrom-Json -InputObject $json
    $set = @{}; foreach ($id in $data) { $set[$id] = $true }
    return $set
  } catch {
    Write-Log "WARN" "Failed to read checkpoint: $($_.Exception.Message)"
    return @{}
  }
}

# Save checkpoint
function Save-Checkpoint {
  param([string]$Path, [array]$ManagedDeviceIds)
  try {
    $ManagedDeviceIds | ConvertTo-Json -Depth 3 | Set-Content -Path $Path
    Write-Log "INFO" "Checkpoint saved ($($ManagedDeviceIds.Count)) -> $Path"
  } catch {
    Write-Log "ERROR" "Failed to save checkpoint: $($_.Exception.Message)"
  }
}

# Get token
function Get-GraphToken {
  param($TenantId,$ClientId,$ClientSecret,$GraphEndpoint)
  if ($GraphEndpoint -like "*chinacloudapi.cn*") {
    $tokenUri = "https://login.partner.microsoftonline.cn/$TenantId/oauth2/v2.0/token"
  } else {
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  }
  $body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
    scope         = "$GraphEndpoint/.default"
  }
  try {
    $tok = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    Write-Log "INFO" "Access token obtained."
    return $tok.access_token
  } catch {
    Write-Log "ERROR" "Token request failed: $($_.Exception.Message)"
    throw
  }
}

# Graph call with retry
function Invoke-Graph {
  param([string]$Method,[string]$Uri,[hashtable]$Headers,[object]$Body = $null,[int]$MaxRetries = 6)
  $attempt = 0
  while ($true) {
    try {
      if ($Method -eq "GET") {
        return Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -ErrorAction Stop
      } elseif ($Method -eq "POST") {
        return Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers -Body $Body -ContentType "application/json" -ErrorAction Stop
      } else {
        throw "Unsupported method: $Method"
      }
    } catch {
      $attempt++
      $status = $_.Exception.Response.StatusCode.value__
      if ($status -eq 401) {
        Write-Log "WARN" "401 Unauthorized. Refreshing token..."
        $global:token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
        $Headers["Authorization"] = "Bearer $global:token"
        continue
      }
      if ($attempt -ge $MaxRetries) {
        Write-Log "ERROR" "Graph call failed after $attempt attempts: $($_.Exception.Message)"
        throw
      }
      Start-Sleep -Seconds (2 * $attempt)
    }
  }
}

# Get paged results
function Get-GraphPaged {
  param($Uri,[hashtable]$Headers,[int]$MaxPages,[string]$ActivityName)
  $items = @(); $next = $Uri; $page = 0
  while ($next -and $page -lt $MaxPages) {
    $page++
    Write-Log "INFO" "$ActivityName - requesting page $page"
    $resp = Invoke-Graph -Method GET -Uri $next -Headers $Headers
    if ($resp.value) { $items += $resp.value }
    $next = $resp.'@odata.nextLink'
  }
  Write-Log "INFO" "$ActivityName - collected $($items.Count) records across $page page(s)."
  return $items
}

# Normalize device ID
function Normalize-DeviceId {
  param([string]$RawId)
  $id = $RawId -replace '[\{\}"'']',''
  $id = $id.Trim()
  return $id
}

# Get managed device
function Get-ManagedDeviceByAadId {
  param($AadDeviceId,[hashtable]$Headers,$GraphEndpoint)
  $id = Normalize-DeviceId $AadDeviceId
  if ($id -notmatch '^[0-9a-fA-F-]{36}$') {
    Write-Log "WARN" "Invalid device ID format: $AadDeviceId -> $id"
    return @{ value = @() }
  }
  $filterRaw = "azureADDeviceId eq '$id'"
  $filterEnc = [uri]::EscapeDataString($filterRaw)
  $uri = "$GraphEndpoint/v1.0/deviceManagement/managedDevices?%24filter=$filterEnc"
  Write-Log "INFO" "ManagedDevice lookup URI: $uri"
  return Invoke-Graph -Method GET -Uri $uri -Headers $Headers
}

# Main logic
$token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
$headers = @{ "Authorization" = "Bearer $token" }

$startUtc = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filterEnc = [uri]::EscapeDataString("createdDateTime ge $startUtc")
$signInsUri = "$GraphEndpoint/v1.0/auditLogs/signIns?%24filter=$filterEnc"
Write-Log "INFO" "Sign-ins filtered URI: $signInsUri"

$signIns = Get-GraphPaged -Uri $signInsUri -Headers $headers -MaxPages $MaxPages -ActivityName "Fetching sign-ins (filtered)"
$signIns = $signIns | Where-Object { $_.status.errorCode -eq 0 -or -not $_.status }

# Normalize sign-ins
$activity = foreach ($e in $signIns) {
  $devId = $e.deviceDetail.deviceId
  if ([string]::IsNullOrWhiteSpace($devId)) { continue }
  if ($ExcludeUpnPattern -and $e.userPrincipalName -match $ExcludeUpnPattern) { continue }
  [pscustomobject]@{
    CreatedDateTime   = [datetime]$e.createdDateTime
    DeviceAadId       = $devId
    DeviceName        = $e.deviceDetail.displayName
    UserId            = $e.userId
    UserPrincipalName = $e.userPrincipalName
  }
}

# Aggregate winners
$assignments = @()
$byDevice = $activity | Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $userGroups = $devGroup.Group | Group-Object UserId | Sort-Object Count -Descending
  $winner = $userGroups | Select-Object -First 1
  if ($winner.Count -lt $MinEventsPerDevice) { continue }
  $assignments += [pscustomobject]@{
    DeviceAadId  = $devGroup.Name
    DeviceName   = ($devGroup.Group | Select-Object -First 1).DeviceName
    TargetUserId = $winner.Name
    TargetUpn    = ($winner.Group | Select-Object -First 1).UserPrincipalName
    EventCount   = $winner.Count
  }
}

Write-Log "INFO" "Devices to process: $($assignments.Count)"

# Resolve managed devices
$work = @()
foreach ($item in $assignments) {
  $resp = Get-ManagedDeviceByAadId -AadDeviceId $item.DeviceAadId -Headers $headers -GraphEndpoint $GraphEndpoint
  $md = $null
  if ($resp.value -and $resp.value.Count -ge 1) { $md = $resp.value[0] }
  if (-not $md) {
    $work += [pscustomobject]@{
      DeviceAadId=$item.DeviceAadId; DeviceName=$item.DeviceName;
      ManagedDeviceId=$null; CurrentPrimaryUserId=$null;
      TargetUserId=$item.TargetUserId; TargetUpn=$item.TargetUpn;
      EventCount=$item.EventCount; Action="Skip_NoManagedDevice"; Result="No Intune object found"
    }
    continue
  }
  $action = if ($md.userId -eq $item.TargetUserId) { "Skip_AlreadyPrimary" } else { "Assign_PrimaryUser" }
  $work += [pscustomobject]@{
    DeviceAadId=$item.DeviceAadId; DeviceName=$md.deviceName;
    ManagedDeviceId=$md.id; CurrentPrimaryUserId=$md.userId;
    TargetUserId=$item.TargetUserId; TargetUpn=$item.TargetUpn;
    EventCount=$item.EventCount; Action=$action; Result=""
  }
}

# Assignment loop
$results = @()
foreach ($row in $work) {
  if ($row.Action -like "Skip_*") { $row.Result = $row.Action; $results += $row; continue }
  if ($DryRun) { $row.Result = "DryRun_Assign_PrimaryUser"; $results += $row; continue }
  $uri = "$GraphEndpoint/v1.0/deviceManagement/managedDevices('$($row.ManagedDeviceId)')/users/`$ref"
  $body = @{ '@odata.id' = "$GraphEndpoint/v1.0/users/$($row.TargetUserId)" } | ConvertTo-Json
  try {
    Invoke-Graph -Method POST -Uri $uri -Headers $headers -Body $body
    $row.Result = "Success_Assigned"
  } catch {
    $row.Result = "Error: $($_.Exception.Message)"
  }
  $results += $row
  Start-Sleep -Milliseconds $AssignmentDelayMs
}

# Export CSV
$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
$errPath = Join-Path $OutputDir "PrimaryUserAssignment_Errors_$ts.csv"
try {
  $results | Export-Csv -NoTypeInformation -Path $csvPath
  $results | Where-Object { $_.Result -like 'Error:*' } | Export-Csv -NoTypeInformation -Path $errPath
  Write-Log "INFO" "Results exported to $csvPath"
  Write-Log "INFO" "Errors exported to $errPath"
} catch {
  Write-Log "ERROR" "Failed to export CSV: $($_.Exception.Message)"
}

# Save checkpoint
$successIds = $results | Where-Object { $_.Result -eq 'Success_Assigned' -and $_.ManagedDeviceId } |
              Select-Object -ExpandProperty ManagedDeviceId -Unique
Save-Checkpoint -Path $CheckpointPath -ManagedDeviceIds $successIds
}
