<#
Bulk assign Intune primary users based on last N days of sign-ins via Microsoft Graph REST. 
Features:
 - Token refresh on 401
 - Defensive paging with progress + max pages cap
 - File logging + CSV audit

USAGE (preview first):
.\BulkAssign-IntunePrimaryUsers.ps1 `
  -TenantId "contoso.com" `
  -ClientId "11111111-2222-3333-4444-555555555555" `
  -ClientSecret "SuperSecretValue" `
  -LookbackDays 30 `
  -MinEventsPerDevice 3 `
  -BatchSize 50 `
  -MaxPages 100 `
  -UseParallel `
  -ThrottleLimit 8 `
  -DryRun `
  -LogPath "C:\Intune\PrimaryUser\bulkassign.log" `
  -OutputDir "C:\Intune\PrimaryUser"

PowerShell script have below features:

Robust error handling for failed assignments (per‑item retries with backoff, rich error messages captured into results)
File logging for script progress (Write-Log to a configurable log file)
Parallel processing (optional) for the assignment phase (PowerShell 7+ with ForEach-Object -Parallel; safe sequential fallback)
Token refresh on 401 (expired token)
Defensive paging + maximum pages cap with progress bars
Fallback query (re-query without server-side $filter if initial call returns no sign-ins)
CSV output for auditing results

Queries last N days of successful sign-ins → determines most active user per device → maps Entra deviceDetail.deviceId to 
Intune managedDevice.azureADDeviceId → assigns primary user via POST …/deviceManagement/managedDevices/{id}/users/$ref (in batches or parallel).

Error handling for failed assignments

Each assignment runs through Invoke-Assign with -AssignmentMaxRetries (default 3) and linear backoff.
On 401, workers refresh their token and retry.
All failures are captured in the CSV and also exported to a separate *_Errors_*.csv.

Logging

File log at -LogPath with timestamps and levels (INFO/WARN/ERROR).
Major steps (token, paging, batches, per-attempt failures) are logged.
Write-Progress provides visual progress in the console for paging and batches.

Parallel assignments (PS7+)

Enable with -UseParallel (requires PowerShell 7+).
Control concurrency with -ThrottleLimit (default 8).
Each parallel worker maintains its own headers and token refresh.

Batching (sequential mode)

Use -BatchSize (default 100) and -BatchPauseSeconds to control pacing.
-AssignmentDelayMs controls per‑item spacing (200 ms by default).

Paging controls

-MaxPages caps how many pages to fetch from Graph in any paged call.
Defensive check stops paging if Graph returns an invalid/expired skiptoken.

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
  [string]$GraphEndpoint = "https://graph.microsoft.com",   # 21Vianet: https://microsoftgraph.chinacloudapi.cn

  # Paging + progress
  [int]$MaxPages = 200,

  # Assignment controls
  [int]$BatchSize = 100,
  [int]$AssignmentDelayMs = 200,
  [int]$BatchPauseSeconds = 2,
  [int]$AssignmentMaxRetries = 3,

  # Parallel (PS7+ only)
  [switch]$UseParallel,
  [int]$ThrottleLimit = 8,

  # Logging
  [string]$LogPath = ".\BulkAssign-PrimaryUsers.log"
)

# -------------------- Logging --------------------
function Write-Log {
  param(
    [ValidateSet('INFO','WARN','ERROR')] [string]$Level = 'INFO',
    [Parameter(Mandatory)][string]$Message
  )
  $line = "$(Get-Date -Format o) [$Level] $Message"
  Add-Content -Path $LogPath -Value $line
}

# Ensure output paths exist
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
New-Item -ItemType File -Path $LogPath -Force | Out-Null
Write-Log -Level INFO -Message "Script start. Tenant=$TenantId LookbackDays=$LookbackDays DryRun=$DryRun UseParallel=$UseParallel"

# -------------------- Script-scope for helpers --------------------
$script:TenantId      = $TenantId
$script:ClientId      = $ClientId
$script:ClientSecret  = $ClientSecret
$script:GraphEndpoint = $GraphEndpoint
$script:Headers       = @{}  # populated after initial token

# -------------------- Helper: Get Token --------------------
function Get-GraphToken {
  param($TenantId,$ClientId,$ClientSecret,$GraphEndpoint)

  $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  if ($GraphEndpoint -like "*chinacloudapi.cn*") {
    $tokenUri = "https://login.partner.microsoftonline.cn/$TenantId/oauth2/v2.0/token"
  }

  $body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
    scope         = "$GraphEndpoint/.default"
  }

  try {
    $tok = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    Write-Log -Level INFO -Message "Obtained access token."
    return $tok.access_token
  } catch {
    Write-Log -Level ERROR -Message "Token request failed: $($_.Exception.Message)"
    throw
  }
}

# -------------------- Helper: Invoke Graph with Retry + Token Refresh --------
function Invoke-Graph {
  param(
    [string]$Method,
    [string]$Uri,
    [hashtable]$Headers,
    [object]$Body = $null,
    [int]$MaxRetries = 6
  )

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
      $status     = $null
      $retryAfter = 0
      $respBody   = $null

      if ($_.Exception.Response) {
        $status = [int]$_.Exception.Response.StatusCode
        try {
          $stream = $_.Exception.Response.GetResponseStream()
          if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            $respBody = $reader.ReadToEnd()
          }
        } catch { }
        $raHdr = $_.Exception.Response.Headers["Retry-After"]
        if ($raHdr) { [int]::TryParse($raHdr, [ref]$retryAfter) | Out-Null }
      }

      # Token refresh on 401
      if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken' -or $respBody -match 'token is expired' -or $respBody -match 'Lifetime validation failed')) {
        Write-Log -Level WARN -Message "401 Invalid/Expired token. Refreshing token and retrying..."
        $newTok = Get-GraphToken -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $script:ClientSecret -GraphEndpoint $script:GraphEndpoint
        $Headers["Authorization"]     = "Bearer $newTok"
        $script:Headers["Authorization"] = "Bearer $newTok"
        $attempt--  # neutralize this attempt for pure refresh
        continue
      }

      # Transient backoff
      $isTransient = $status -in 429,500,503,504
      if ($attempt -le $MaxRetries -and $isTransient) {
        $delay = if ($retryAfter -gt 0) { $retryAfter } else { [math]::Min(60, [math]::Pow(2, $attempt)) }
        Write-Log -Level WARN -Message "Transient HTTP $status for $Uri. Retrying in $delay sec... ($attempt/$MaxRetries)"
        Start-Sleep -Seconds $delay
        continue
      }

      $msg = "Graph call failed (HTTP $status): $($_.Exception.Message)"
      if ($respBody) { $msg = "$msg`nResponse body: $respBody" }
      Write-Log -Level ERROR -Message $msg
      throw $msg
    }
  }
}

# -------------------- Helper: Defensive Paging (progress + cap) --------------
function Get-GraphPaged {
  param($Uri,[hashtable]$Headers,[int]$MaxPages,[string]$ActivityName)

  $items    = @()
  $next     = $Uri
  $page     = 0
  $maxPages = [Math]::Max(1, $MaxPages)

  while ($next -and $page -lt $maxPages) {
    $page++
    Write-Progress -Id 1 -Activity $ActivityName -Status "Page $page of $maxPages" -PercentComplete ([Math]::Min(100, ($page/$maxPages)*100))
    Write-Log -Level INFO -Message "$ActivityName - requesting page $page"

    try {
      $resp = Invoke-Graph -Method GET -Uri $next -Headers $Headers
    } catch {
      if ($_.Exception.Message -match 'Skip token is null|skiptoken') {
        Write-Log -Level WARN -Message "$ActivityName - paging halted due to skiptoken error at page $page."
        break
      }
      throw
    }

    if ($resp.value) { $items += $resp.value }

    $nl = $resp.'@odata.nextLink'
    if ($nl -and ($nl -match 'skiptoken' -or $nl -match '%24skiptoken')) {
      $next = $nl
    } else {
      $next = $null
    }
  }

  Write-Progress -Id 1 -Activity $ActivityName -Completed
  Write-Log -Level INFO -Message "$ActivityName - collected $($items.Count) records across $page page(s)."
  return $items
}

# -------------------- Authenticate (initial token) ---------------------------
Write-Host "Authenticating..." -ForegroundColor Cyan
$firstToken     = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
$script:Headers = @{ "Authorization" = "Bearer $firstToken" }

# -------------------- Dates + filtered query --------------------------------
$startUtc   = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filterRaw  = "createdDateTime ge $startUtc"
$filterEnc  = [uri]::EscapeDataString($filterRaw)

$signInsUri = "$GraphEndpoint/v1.0/auditLogs/signIns?%24filter=$filterEnc"
Write-Host "Sign-ins URI (filtered): $signInsUri" -ForegroundColor DarkGray
Write-Log -Level INFO -Message "Sign-ins filtered URI: $signInsUri"

$signIns = Get-GraphPaged -Uri $signInsUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Fetching sign-ins (filtered)"

# Fallback: unfiltered + client-side filter
if (-not $signIns -or $signIns.Count -eq 0) {
  Write-Warning "Initial query returned no results. Falling back to unfiltered query."
  Write-Log -Level WARN -Message "Fallback to unfiltered sign-ins."
  $fallbackUri = "$GraphEndpoint/v1.0/auditLogs/signIns"
  $signIns     = Get-GraphPaged -Uri $fallbackUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Fetching sign-ins (fallback)"

  $startDt = [datetime]::ParseExact($startUtc,'yyyy-MM-ddTHH:mm:ssZ',$null)
  $signIns = $signIns | Where-Object {
    ([datetime]$_.createdDateTime -ge $startDt) -and ($_.status.errorCode -eq 0 -or -not $_.status)
  }
} else {
  # Filter success client-side
  $signIns = $signIns | Where-Object { $_.status.errorCode -eq 0 -or -not $_.status }
}

# Normalize; require AAD deviceId
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

if (-not $activity) {
  Write-Log -Level WARN -Message "No sign-in rows with deviceId after filtering. Exiting."
  $ts      = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @() | Export-Csv -NoTypeInformation -Path $csvPath
  Write-Host "Empty results written to $csvPath" -ForegroundColor Yellow
  exit 0
}

# Aggregate winners per device
$assignments = @()
$byDevice    = $activity | Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $userGroups = $devGroup.Group | Group-Object UserId | Sort-Object Count -Descending
  $winner     = $userGroups | Select-Object -First 1
  if ($winner.Count -lt $MinEventsPerDevice) { continue }

  $ties = $userGroups | Where-Object { $_.Count -eq $winner.Count }
  if ($ties.Count -gt 1) {
    $winner = $ties |
      Sort-Object @{ Expression = { ($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime } }, Descending |
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

Write-Host "Devices to process: $($assignments.Count)" -ForegroundColor Cyan
Write-Log  -Level INFO -Message "Devices to process: $($assignments.Count)"
if ($assignments.Count -eq 0) {
  $ts      = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @() | Export-Csv -NoTypeInformation -Path $csvPath
  Write-Host "Empty results written to $csvPath" -ForegroundColor Yellow
  Write-Log -Level WARN -Message "No qualifying devices. Exiting."
  exit 0
}

# Resolve Intune managedDevices
function Get-ManagedDeviceByAadId {
  param($AadDeviceId,[hashtable]$Headers,$GraphEndpoint)
  $filterEnc = [uri]::EscapeDataString("azureADDeviceId eq '$AadDeviceId'")
  $uri       = "$GraphEndpoint/v1.0/deviceManagement/managedDevices?%24filter=$filterEnc"
  Invoke-Graph -Method GET -Uri $uri -Headers $Headers
}

$work = @()
$idx  = 0
foreach ($item in $assignments) {
  $idx++
  if ($idx % 100 -eq 0) { Write-Log -Level INFO -Message "Resolving managedDevices... processed $idx/$($assignments.Count)" }

  $resp = Get-ManagedDeviceByAadId -AadDeviceId $item.DeviceAadId -Headers $script:Headers -GraphEndpoint $GraphEndpoint
  $md   = $null
  if ($resp.value -and $resp.value.Count -ge 1) { $md = $resp.value[0] }

  if (-not $md) {
    $work += [pscustomobject]@{
      DeviceAadId          = $item.DeviceAadId
      DeviceName           = $item.DeviceName
      ManagedDeviceId      = $null
      CurrentPrimaryUserId = $null
      TargetUserId         = $item.TargetUserId
      TargetUpn            = $item.TargetUpn
      EventCount           = $item.EventCount
      Action               = "Skip_NoManagedDevice"
      Result               = "No Intune object found"
      Attempts             = 0
    }
    continue
  }

  $action = if ($md.userId -eq $item.TargetUserId) { "Skip_AlreadyPrimary" } else { "Assign_PrimaryUser" }
  $work += [pscustomobject]@{
    DeviceAadId          = $item.DeviceAadId
    DeviceName           = $md.deviceName
    ManagedDeviceId      = $md.id
    CurrentPrimaryUserId = $md.userId
    TargetUserId         = $item.TargetUserId
    TargetUpn            = $item.TargetUpn
    EventCount           = $item.EventCount
    Action               = $action
    Result               = ""
    Attempts             = 0
  }
}

# ---------- Assignment helpers (retry + logging) ----------
function Invoke-Assign {
  param(
    [Parameter(Mandatory)]$Row,
    [hashtable]$Headers,
    [int]$MaxRetries,
    [int]$DelayMs,
    [string]$GraphEndpoint,
    [string]$LogPathLocal
  )

  # Local logger for parallel workers
  function LogLocal([string]$lvl,[string]$msg){ $ln = "$(Get-Date -Format o) [$lvl] $msg"; Add-Content -Path $LogPathLocal -Value $ln }

  if ($Row.Action -like "Skip_*") { $Row.Result = $Row.Action; return $Row }
  if ($Row.TargetUserId -eq $null -or [string]::IsNullOrWhiteSpace($Row.TargetUserId)) {
    $Row.Result = "Error: Missing TargetUserId"; return $Row
  }

  $attempt = 0
  while ($attempt -lt [Math]::Max(1,$MaxRetries)) {
    $attempt++
    try {
      $uri  = "$GraphEndpoint/v1.0/deviceManagement/managedDevices('$($Row.ManagedDeviceId)')/users/`$ref"
      $body = @{ '@odata.id' = "$GraphEndpoint/v1.0/users/$($Row.TargetUserId)" } | ConvertTo-Json

      # Inline POST with token refresh on 401 (local)
      try {
        Invoke-RestMethod -Method POST -Uri $uri -Headers $Headers -Body $body -ContentType "application/json" -ErrorAction Stop | Out-Null
        $Row.Result   = "Success_Assigned"
        $Row.Attempts = $attempt
        return $Row
      } catch {
        # Try to refresh token locally only on 401
        $status = $null; $respBody = $null
        if ($_.Exception.Response) {
          $status = [int]$_.Exception.Response.StatusCode
          try {
            $stream = $_.Exception.Response.GetResponseStream()
            if ($stream) { $reader = New-Object System.IO.StreamReader($stream); $respBody = $reader.ReadToEnd() }
          } catch {}
        }
        if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken' -or $respBody -match 'token is expired' -or $respBody -match 'Lifetime validation failed')) {
          LogLocal "WARN" "401 in worker; refreshing token and retrying attempt $attempt for device $($Row.ManagedDeviceId)."
          $newTok = Get-GraphToken -TenantId $using:TenantId -ClientId $using:ClientId -ClientSecret $using:ClientSecret -GraphEndpoint $using:GraphEndpoint
          $Headers["Authorization"] = "Bearer $newTok"
          Start-Sleep -Milliseconds $DelayMs
          continue
        }
        throw
      }
    } catch {
      $msg = $_.Exception.Message
      LogLocal "WARN" "Attempt $attempt failed for device $($Row.ManagedDeviceId): $msg"
      if ($attempt -lt $MaxRetries) {
        Start-Sleep -Milliseconds ([math]::Max($DelayMs, 100) * $attempt)  # linear backoff
      } else {
        $Row.Result   = "Error: $msg"
        $Row.Attempts = $attempt
        return $Row
      }
    }
  }
}

# -------------------- Assignment: sequential batches or parallel -------------
$results = @()
$total   = $work.Count
$todo    = $work

# Overall progress
Write-Log -Level INFO -Message "Starting assignment phase for $total items. UseParallel=$UseParallel"

if ($UseParallel -and $PSVersionTable.PSVersion.Major -ge 7) {
  # Only assign for actionable rows; keep skips as-is
  $skips = $todo | Where-Object { $_.Action -like "Skip_*" }
  foreach ($s in $skips) { $s.Result = $s.Action; $results += $s }

  $toAssign = $todo | Where-Object { $_.Action -eq "Assign_PrimaryUser" }

  # Prepare local headers per worker (clone)
  $authVal = $script:Headers['Authorization']
  $results += $toAssign | ForEach-Object -Parallel {
      param($item)

      # Worker-local headers & params
      $hdrs = @{ 'Authorization' = $using:authVal }

      # Reuse inline assignment with local retry+refresh
      $rowResult = Invoke-Assign -Row $item -Headers $hdrs -MaxRetries $using:AssignmentMaxRetries `
                    -DelayMs $using:AssignmentDelayMs -GraphEndpoint $using:GraphEndpoint -LogPathLocal $using:LogPath
      $rowResult

    } -ThrottleLimit ([Math]::Max(1,$ThrottleLimit))

} else {
  # Sequential in batches with progress + pauses
  $batches = [Math]::Ceiling($total / [Math]::Max(1,$BatchSize))
  $processed = 0

  for ($b = 0; $b -lt $batches; $b++) {
    $start = $b * $BatchSize
    $end   = [Math]::Min($start + $BatchSize, $total)
    $batch = $todo[$start..($end-1)]

    Write-Progress -Id 2 -Activity "Assigning primary users (batch $($b+1)/$batches)" -Status "Items $start..$(($end-1))" -PercentComplete ([Math]::Min(100,(($b+1)/$batches)*100))
    Write-Log -Level INFO -Message "Processing batch $($b+1)/$batches (items $start..$(($end-1)))"

    foreach ($row in $batch) {
      if ($row.Action -like "Skip_*") { $row.Result = $row.Action; $results += $row; $processed++; continue }
      if ($DryRun) { $row.Result = "DryRun_Assign_PrimaryUser"; $results += $row; $processed++; continue }

      # Clone headers to avoid mutation while refreshing
      $localHeaders = @{'Authorization' = $script:Headers['Authorization']}

      $out = Invoke-Assign -Row $row -Headers $localHeaders -MaxRetries $AssignmentMaxRetries `
              -DelayMs $AssignmentDelayMs -GraphEndpoint $GraphEndpoint -LogPathLocal $LogPath
      $results += $out
      $processed++
      Start-Sleep -Milliseconds $AssignmentDelayMs
    }

    Write-Progress -Id 2 -Activity "Assigning primary users (batch $($b+1)/$batches)" -Completed
    if ($b -lt ($batches - 1) -and -not $DryRun) { Start-Sleep -Seconds $BatchPauseSeconds }
  }
}

# -------------------- Export results -----------------------------------------
$ts       = (Get-Date).ToString('yyyyMMdd_HHmmss')
$csvPath  = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
$errPath  = Join-Path $OutputDir "PrimaryUserAssignment_Errors_$ts.csv"

$results | Export-Csv -NoTypeInformation -Path $csvPath
$results | Where-Object { $_.Result -like 'Error:*' } | Export-Csv -NoTypeInformation -Path $errPath

Write-Host "Completed. Results: $csvPath" -ForegroundColor Green
if ((Get-Item $errPath).Length -gt 0) {
  Write-Host "Errors:   $errPath" -ForegroundColor Yellow
  Write-Log -Level WARN -Message "Completed with errors. See $errPath"
} else {
  Remove-Item $errPath -ErrorAction SilentlyContinue
  Write-Log -Level INFO -Message "Completed successfully."
} Fallback (unfiltered) query if filtered returns no data
 - Batched OR Parallel assignments (PS7+)
 - Per-item retries + backoff
 -
