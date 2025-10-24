& {
param(
  [string]$TenantId = "yourtenant.onmicrosoft.com",
  [string]$ClientId = "11111111-2222-3333-4444-555555555555",
  [string]$ClientSecret = "your-client-secret",
  [int]$LookbackDays = 30,
  [int]$MinEventsPerDevice = 2,
  [string]$ExcludeUpnPattern = "",
  [switch]$DryRun = $true,
  [string]$OutputDir = "C:\Intune\PrimaryUser",
  [string]$LogPath = "C:\Intune\PrimaryUser\bulkassign.log",
  [string]$CheckpointPath = "C:\Intune\PrimaryUser\checkpoint.json",
  [switch]$Resume = $false,
  [string]$GraphEndpoint = "https://graph.microsoft.com",
  [int]$MaxPages = 100,
  [int]$BatchSize = 50,
  [int]$AssignmentDelayMs = 200,
  [int]$BatchPauseSeconds = 2,
  [int]$AssignmentMaxRetries = 3,
  [switch]$UseParallel = $true,
  [int]$ThrottleLimit = 8
)

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
New-Item -ItemType File -Path $LogPath -Force | Out-Null

function Write-Log {
  param([string]$Level, [string]$Message)
  $line = "$(Get-Date -Format o) [$Level] $Message"
  Add-Content -Path $LogPath -Value $line
}

function Get-GraphToken {
  $tokenUri = if ($GraphEndpoint -like "*chinacloudapi.cn*") {
    "https://login.partner.microsoftonline.cn/$TenantId/oauth2/v2.0/token"
  } else {
    "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  }
  $body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
    scope         = "$GraphEndpoint/.default"
  }
  try {
    $response = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    Write-Log "INFO" "Access token obtained."
    return $response.access_token
  } catch {
    Write-Log "ERROR" "Token request failed: $($_.Exception.Message)"
    throw
  }
}

function Invoke-Graph {
  param([string]$Method, [string]$Uri, [hashtable]$Headers, [object]$Body = $null, [int]$MaxRetries = 6)
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
      $status = $_.Exception.Response.StatusCode.Value__
      $retryAfter = 0
      $respBody = ""
      try {
        $stream = $_.Exception.Response.GetResponseStream()
        if ($stream) {
          $reader = New-Object System.IO.StreamReader($stream)
          $respBody = $reader.ReadToEnd()
        }
      } catch {}
      if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken|token is expired|Lifetime validation failed')) {
        Write-Log "WARN" "401 Unauthorized. Refreshing token..."
        $global:token = Get-GraphToken
        $Headers["Authorization"] = "Bearer $global:token"
        $attempt--
        continue
      }
      if ($attempt -le $MaxRetries -and ($status -eq 429 -or $status -eq 500 -or $status -eq 503 -or $status -eq 504)) {
        if ($retryAfter -gt 0) {
          $delay = $retryAfter
        } else {
          $delay = [math]::Min(60, [math]::Pow(2, $attempt))
        }
        Write-Log "WARN" "Transient HTTP $status. Retrying in $delay sec... ($attempt/$MaxRetries)"
        Start-Sleep -Seconds $delay
        continue
      }
      $msg = "Graph call failed (HTTP $status): $($_.Exception.Message)"
      if ($respBody) { $msg = "$msg`nResponse body: $respBody" }
      Write-Log "ERROR" $msg
      throw $msg
    }
  }
}

function Get-ManagedDeviceByAadId {
  param(
    [string]$AadDeviceId,
    [hashtable]$Headers,
    [string]$GraphEndpoint
  )
  $id = $AadDeviceId -replace '[\{\}"'']',''
  $id = $id.Trim()
  if ($id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Log "WARN" "Invalid azureADDeviceId format after normalization: '$AadDeviceId' -> '$id'. Skipping lookup."
    return @{ value = @() }
  }
  $filterRaw = "azureADDeviceId eq '$id'"
  $filterEnc = [uri]::EscapeDataString($filterRaw)
  $uri = "$GraphEndpoint/v1.0/deviceManagement/managedDevices?%24filter=$filterEnc"
  Write-Log "INFO" "ManagedDevice lookup URI: $uri"
  $resp = Invoke-Graph -Method GET -Uri $uri -Headers $Headers
  return $resp
}

# Acquire token
$global:token = Get-GraphToken
$script:Headers = @{ "Authorization" = "Bearer $global:token" }

# Placeholder for full logic: sign-in processing, assignment, CSV export
Write-Log "INFO" "Script logic would continue here: sign-in processing, assignment, CSV export..."
}

# --------------------
# Sign-in aggregation: determine most active user per device
# --------------------
$assignments = @()
$byDevice = $activity | Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $userGroups = $devGroup.Group | Group-Object UserId | Sort-Object Count -Descending
  $winner = $userGroups | Select-Object -First 1
  if ($winner.Count -lt $MinEventsPerDevice) { continue }

  $ties = $userGroups | Where-Object { $_.Count -eq $winner.Count }
  if ($ties.Count -gt 1) {
    $winner = $ties |
      Sort-Object @{ Expression = { ($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime } } -Descending |
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

# --------------------
# Assignment loop: resolve managedDevices and assign primary users
# --------------------
$results = @()
foreach ($item in $assignments) {
  $resp = Get-ManagedDeviceByAadId -AadDeviceId $item.DeviceAadId -Headers $Headers -GraphEndpoint $GraphEndpoint
  $md = $null
  if ($resp.value -and $resp.value.Count -ge 1) { $md = $resp.value[0] }

  if (-not $md) {
    $results += [pscustomobject]@{
      DeviceAadId = $item.DeviceAadId
      DeviceName = $item.DeviceName
      TargetUserId = $item.TargetUserId
      TargetUpn = $item.TargetUpn
      EventCount = $item.EventCount
      Action = "Skip_NoManagedDevice"
      Result = "No Intune object found"
    }
    continue
  }

  if ($md.userId -eq $item.TargetUserId) {
    $results += [pscustomobject]@{
      DeviceAadId = $item.DeviceAadId
      DeviceName = $md.deviceName
      TargetUserId = $item.TargetUserId
      TargetUpn = $item.TargetUpn
      EventCount = $item.EventCount
      Action = "Skip_AlreadyPrimary"
      Result = "Already assigned"
    }
    continue
  }

  if ($DryRun) {
    $results += [pscustomobject]@{
      DeviceAadId = $item.DeviceAadId
      DeviceName = $md.deviceName
      TargetUserId = $item.TargetUserId
      TargetUpn = $item.TargetUpn
      EventCount = $item.EventCount
      Action = "Assign_PrimaryUser"
      Result = "DryRun"
    }
    continue
  }

  try {
    $uri = "$GraphEndpoint/v1.0/deviceManagement/managedDevices('$($md.id)')/users/`$ref"
    $body = @{ '@odata.id' = "$GraphEndpoint/v1.0/users/$($item.TargetUserId)" } | ConvertTo-Json
    Invoke-Graph -Method POST -Uri $uri -Headers $Headers -Body $body | Out-Null
    $results += [pscustomobject]@{
      DeviceAadId = $item.DeviceAadId
      DeviceName = $md.deviceName
      TargetUserId = $item.TargetUserId
      TargetUpn = $item.TargetUpn
      EventCount = $item.EventCount
      Action = "Assign_PrimaryUser"
      Result = "Success"
    }
  } catch {
    $results += [pscustomobject]@{
      DeviceAadId = $item.DeviceAadId
      DeviceName = $md.deviceName
      TargetUserId = $item.TargetUserId
      TargetUpn = $item.TargetUpn
      EventCount = $item.EventCount
      Action = "Assign_PrimaryUser"
      Result = "Error: $($_.Exception.Message)"
    }
  }

  Start-Sleep -Milliseconds $AssignmentDelayMs
}
