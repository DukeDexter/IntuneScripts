# =========================
# BulkAssign-IntunePrimaryUsers.ps1
# =========================
# Purpose:
#   Bulk-assign Intune primary users based on last N days of sign-in activity.
#   Uses Microsoft Graph REST (no Microsoft.Graph module), supports PS 5.1 & 7+.
#   Includes token refresh, paging, fallback, batching/parallel, retries, logging, and checkpoint resume.

param(
  # --- Auth & scope ---
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  # --- Data selection ---
  [int]$LookbackDays = 30,          # Number of days of sign-ins to consider
  [int]$MinEventsPerDevice = 2,     # Minimum successful sign-ins by a user on a device to qualify as 'primary'
  [string]$ExcludeUpnPattern,       # Regex to exclude service/bot accounts (e.g. '^(svc-|system_)')

  # --- Execution mode ---
  [switch]$DryRun,                  # Preview only; do not commit primary user changes

  # --- IO paths ---
  [string]$OutputDir = ".",         # Folder for CSV outputs
  [string]$LogPath = ".\BulkAssign-PrimaryUsers.log",         # Log file path
  [string]$CheckpointPath = ".\PrimaryUserCheckpoint.json",   # Checkpoint file for resume
  [switch]$Resume,                  # Skip devices already processed in prior runs

  # --- Graph endpoint (global cloud default; 21Vianet tenants override) ---
  [string]$GraphEndpoint = "https://graph.microsoft.com",

  # --- Paging caps & progress ---
  [int]$MaxPages = 200,             # Defensive cap on how many pages to fetch from Graph

  # --- Assignment orchestration ---
  [int]$BatchSize = 100,            # Sequential batch size (ignored in parallel mode)
  [int]$AssignmentDelayMs = 200,    # Delay between assignment POSTs (helps avoid throttling)
  [int]$BatchPauseSeconds = 2,      # Pause between sequential batches
  [int]$AssignmentMaxRetries = 3,   # Per-item retries with linear backoff

  # --- Parallel (PS 7+) ---
  [switch]$UseParallel,             # Use ForEach-Object -Parallel (requires PowerShell 7+)
  [int]$ThrottleLimit = 8           # Max concurrent assignments in parallel mode
)

# Force TLS 1.2 (especially relevant on PS 5.1)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# --------------------
# Logging helper (file-based)
# --------------------
function Write-Log {
  param(
    [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO',
    [Parameter(Mandatory)][string]$Message
  )
  $line = "$(Get-Date -Format o) [$Level] $Message"
  Add-Content -Path $LogPath -Value $line
}

# --------------------
# Checkpoint helpers (resume support across runs)
# --------------------
function Load-Checkpoint {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return @{} }
  try {
    $json = Get-Content -Path $Path -Raw -ErrorAction Stop
    $data = ConvertFrom-Json -InputObject $json
    if ($data -is [array]) {
      $set = @{}; foreach ($id in $data) { $set[$id] = $true }
      return $set
    }
    return @{}
  } catch {
    Write-Log -Level WARN -Message "Failed to read checkpoint: $($_.Exception.Message). Starting fresh."
    return @{}
  }
}

function Save-Checkpoint {
  param([string]$Path, [array]$ManagedDeviceIds)
  try {
    $tmp = "$Path.tmp"
    $ManagedDeviceIds | ConvertTo-Json -Depth 3 | Set-Content -Path $tmp
    Move-Item -Path $tmp -Destination $Path -Force
    Write-Log -Level INFO -Message "Checkpoint saved ($($ManagedDeviceIds.Count) device IDs) -> $Path"
  } catch {
    Write-Log -Level WARN -Message "Failed to save checkpoint: $($_.Exception.Message)"
  }
}

# Ensure output folder & log file exist
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
New-Item -ItemType File -Path $LogPath -Force | Out-Null
Write-Log -Level INFO -Message "Start. Tenant=$TenantId LookbackDays=$LookbackDays DryRun=$DryRun UseParallel=$UseParallel Resume=$Resume"

# Script-scope copies for helper functions
$script:TenantId      = $TenantId
$script:ClientId      = $ClientId
$script:ClientSecret  = $ClientSecret
$script:GraphEndpoint = $GraphEndpoint
$script:Headers       = @{}  # Will be populated after initial token

# --------------------
# Access token acquisition (client credentials)
# --------------------
function Get-GraphToken {
  param($TenantId,$ClientId,$ClientSecret,$GraphEndpoint)

  $status = [int]$_.Exception.Response.StatusCode
        try {
          $stream = $_.Exception.Response.GetResponseStream()
          if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            $respBody = $reader.ReadToEnd()
          }
        } catch {}
        $raHdr = $_.Exception.Response.Headers["Retry-After"]
        if ($raHdr) { [int]::TryParse($raHdr, [ref]$retryAfter) | Out-Null }
      }

      # Automatic token refresh on 401 invalid/expired token
      if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken' -or $respBody -match 'token is expired' -or $respBody -match 'Lifetime validation failed')) {
        Write-Log -Level WARN -Message "401 Invalid/Expired token. Refreshing token and retrying..."
        $newTok = Get-GraphToken -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $script:ClientSecret -GraphEndpoint $script:GraphEndpoint
        $Headers["Authorization"]     = "Bearer $newTok"
        $script:Headers["Authorization"] = "Bearer $newTok"
        $attempt--  # Don't count this as a failure; retry immediately
        continue
      }

      # Transient backoff for throttling/server errors
      if ($attempt -le $MaxRetries -and ($status -in 429,500,503,504)) {
        $delay = ($retryAfter -gt 0) ? $retryAfter : [math]::Min(60, [math]::Pow(2, $attempt))
        Write-Log -Level WARN -Message "Transient HTTP $status for $Uri. Retrying in $delay sec... ($attempt/$MaxRetries)"
        Start-Sleep -Seconds $delay
        continue
      }

      # Hard failure (exhausted retries / non-transient)
      $msg = "Graph call failed (HTTP $status): $($_.Exception.Message)"
      if ($respBody) { $msg = "$msg`nResponse body: $respBody" }
      Write-Log -Level ERROR -Message $msg
      throw $msg
    }
  }
}

# --------------------
# Paged GET helper: progress + max pages cap + defensive nextLink handling
# --------------------
function Get-GraphPaged {
  param($Uri,[hashtable]$Headers,[int]$MaxPages,[string]$ActivityName)

  $items = @(); $next = $Uri; $page = 0; $cap = [Math]::Max(1, $MaxPages)

  while ($next -and $page -lt $cap) {
    $page++
    Write-Progress -Id 1 -Activity $ActivityName -Status "Page $page of $cap" -PercentComplete ([Math]::Min(100, ($page/$cap)*100))
    Write-Log -Level INFO -Message "$ActivityName - requesting page $page"
    try {
      $resp = Invoke-Graph -Method GET -Uri $next -Headers $Headers
    } catch {
      # Stop gracefully on buggy skiptoken nextLink
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

# --------------------
# Initial authentication
# --------------------
Write-Host "Authenticating..." -ForegroundColor Cyan
$firstToken     = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
$script:Headers = @{ "Authorization" = "Bearer $firstToken" }

# --------------------
# Build sign-ins query (filtered by createdDateTime >= startUtc)
# --------------------
$startUtc  = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filterEnc = [uri]::EscapeDataString("createdDateTime ge $startUtc")

$signInsUri = "$GraphEndpoint/v1.0/auditLogs/signIns?%24filter=$filterEnc"
Write-Log -Level INFO -Message "Sign-ins filtered URI: $signInsUri"

# Fetch filtered sign-ins with paging
$signIns = Get-GraphPaged -Uri $signInsUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Fetching sign-ins (filtered)"

# Fallback: unfiltered query then client-side filtering (time window + success)
if (-not $signIns -or $signIns.Count -eq 0) {
  Write-Log -Level WARN -Message "Filtered query returned no results. Fallback to unfiltered."
  $fallbackUri = "$GraphEndpoint/v1.0/auditLogs/signIns"
  $signIns     = Get-GraphPaged -Uri $fallbackUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Fetching sign-ins (fallback)"
  $startDt     = [datetime]::ParseExact($startUtc,'yyyy-MM-ddTHH:mm:ssZ',$null)
  $signIns     = $signIns | Where-Object { ([datetime]$_.createdDateTime -ge $startDt) -and ($_.status.errorCode -eq 0 -or -not $_.status) }
} else {
  # Filter success client-side to avoid nested server-side filter
  $signIns = $signIns | Where-Object { $_.status.errorCode -eq 0 -or -not $_.status }
}

# --------------------
# Normalize rows; require deviceDetail.deviceId (AAD device GUID)
# --------------------
$activity = foreach ($e in $signIns) {
  $devId = $e.deviceDetail.deviceId
  if ([string]::IsNullOrWhiteSpace($devId)) { continue }                         # must have AAD device GUID
  if ($ExcludeUpnPattern -and $e.userPrincipalName -match $ExcludeUpnPattern) { continue }   # skip service accounts
  [pscustomobject]@{
    CreatedDateTime   = [datetime]$e.createdDateTime
    DeviceAadId       = $devId
    DeviceName        = $e.deviceDetail.displayName
    UserId            = $e.userId
    UserPrincipalName = $e.userPrincipalName
  }
}

if (-not $activity) {
  Write-Log -Level WARN -Message "No sign-ins with deviceId. Exiting."
  $ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @() | Export-Csv -NoTypeInformation -Path $csvPath
  Write-Host "Empty results -> $csvPath" -ForegroundColor Yellow
  exit 0
}

# --------------------
# Aggregate winners per device (most active user; tie-breaker by most recent sign-in)
# --------------------
$assignments = @()
$byDevice = $activity | Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $userGroups = $devGroup.Group | Group-Object UserId | Sort-Object Count -Descending
  $winner     = $userGroups | Select-Object -First 1
  if ($winner.Count -lt $MinEventsPerDevice) { continue }

  # Tie-breaker: pick the user whose latest sign-in is most recent
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

Write-Log -Level INFO -Message "Devices to process: $($assignments.Count)"
if ($assignments.Count -eq 0) {
  $ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @() | Export-Csv -NoTypeInformation -Path $csvPath
  Write-Log -Level WARN -Message "No qualifying devices. Exiting."
  Write-Host "Empty results -> $csvPath" -ForegroundColor Yellow
  exit 0
}

# --------------------
# Resolve Intune managedDevice using azureADDeviceId
# --------------------
function Get-ManagedDeviceByAadId {
  param($AadDeviceId,[hashtable]$Headers,$GraphEndpoint)
  $filterEnc = [uri]::EscapeDataString("azureADDeviceId eq '$AadDeviceId'")   # string literal must be quoted in filter
  $uri       = "$GraphEndpoint/v1.0/deviceManagement/managedDevices?%24filter=$filterEnc"
  Invoke-Graph -Method GET -Uri $uri -Headers $Headers
}

$work = @(); $idx = 0
foreach ($item in $assignments) {
  $idx++; if ($idx % 100 -eq 0) { Write-Log -Level INFO -Message "Resolving managedDevices: $idx/$($assignments.Count)" }
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

# --------------------
# Optional checkpoint resume (skip devices already processed in prior runs)
# --------------------
$processedSet = @{}
if ($Resume) {
  $processedSet = Load-Checkpoint -Path $CheckpointPath
  $already = ($processedSet.Keys | Measure-Object).Count
  Write-Log -Level INFO -Message "Resume enabled. Loaded checkpoint with $already device IDs."
}

# --------------------
# Per-item assignment (POST users/$ref) + local retry + token refresh on 401
# --------------------
function Invoke-Assign {
  param(
    [Parameter(Mandatory)]$Row,
    [hashtable]$Headers,
    [int]$MaxRetries,
    [int]$DelayMs,
    [string]$GraphEndpoint,
    [string]$LogPathLocal,
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret
  )

  function LogLocal([string]$lvl,[string]$msg) {
    Add-Content -Path $LogPathLocal -Value "$(Get-Date -Format o) [$lvl] $msg"
  }

  if ($Row.Action -like "Skip_*") { $Row.Result = $Row.Action; return $Row }
  if ([string]::IsNullOrWhiteSpace($Row.TargetUserId)) { $Row.Result="Error: Missing TargetUserId"; return $Row }

  $attempt = 0
  while ($attempt -lt [Math]::Max(1,$MaxRetries)) {
    $attempt++
    try {
      $uri  = "$GraphEndpoint/v1.0/deviceManagement/managedDevices('$($Row.ManagedDeviceId)')/users/`$ref"
      $body = @{ '@odata.id' = "$GraphEndpoint/v1.0/users/$($Row.TargetUserId)" } | ConvertTo-Json

      try {
        Invoke-RestMethod -Method POST -Uri $uri -Headers $Headers -Body $body -ContentType "application/json" -ErrorAction Stop | Out-Null
        $Row.Result="Success_Assigned"; $Row.Attempts=$attempt; return $Row
      } catch {
        # Local token refresh on 401 within worker
        $status=$null; $respBody=$null
        if ($_.Exception.Response) {
          $status=[int]$_.Exception.Response.StatusCode
          try { $stream=$_.Exception.Response.GetResponseStream(); if ($stream) { $reader=New-Object System.IO.StreamReader($stream); $respBody=$reader.ReadToEnd() } } catch {}
        }
        if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken' -or $respBody -match 'token is expired' -or $respBody -match 'Lifetime validation failed')) {
          LogLocal "WARN" "401 in worker; refreshing token (attempt $attempt) for $($Row.ManagedDeviceId)"
          $newTok = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
          $Headers["Authorization"] = "Bearer $newTok"; Start-Sleep -Milliseconds $DelayMs; continue
        }
        throw
      }
    } catch {
      LogLocal "WARN" "Attempt $attempt failed for device $($Row.ManagedDeviceId): $($_.Exception.Message)"
      if ($attempt -lt $MaxRetries) {
        Start-Sleep -Milliseconds ([math]::Max($DelayMs, 100) * $attempt)   # Linear backoff
      } else {
        $Row.Result="Error: $($_.Exception.Message)"; $Row.Attempts=$attempt; return $Row
      }
    }
  }
}

# --------------------
# Assignment phase (parallel PS7+ or sequential batches PS5/PS7)
# --------------------
$results = @()
Write-Log -Level INFO -Message "Starting assignment phase. UseParallel=$UseParallel"

# Apply resume checkpoint (skip already processed) for real runs (not DryRun)
if ($Resume -and -not $DryRun) {
  $work = $work | Where-Object {
    if ($_.ManagedDeviceId -and $processedSet.ContainsKey($_.ManagedDeviceId)) {
      $_.Result = "Checkpoint_Skip"; $results += $_; $false
    } else { $true }
  }
  Write-Log -Level INFO -Message "After resume filter, items remaining: $($work.Count)"
}

if ($UseParallel -and $PSVersionTable.PSVersion.Major -ge 7) {
  # 1) Collect 'skip' rows
  $skips = $work | Where-Object { $_.Action -like "Skip_*" }
  foreach ($s in $skips) { $s.Result = $s.Action; $results += $s }

  # 2) Parallel assign for actionable rows
  $toAssign = $work | Where-Object { $_.Action -eq "Assign_PrimaryUser" }
  $authVal  = $script:Headers['Authorization']

  $parResults = $toAssign | ForEach-Object -Parallel {
      param($item)
      $hdrs = @{ 'Authorization' = $using:authVal }
      Invoke-Assign -Row $item -Headers $hdrs -MaxRetries $using:AssignmentMaxRetries `
                    -DelayMs $using:AssignmentDelayMs -GraphEndpoint $using:GraphEndpoint `
                    -LogPathLocal $using:LogPath -TenantId $using:TenantId -ClientId $using:ClientId -ClientSecret $using:ClientSecret
    } -ThrottleLimit ([Math]::Max(1,$ThrottleLimit))

  # 3) Merge & checkpoint successes
  $results += $parResults

  if (-not $DryRun) {
    $successIds = $parResults | Where-Object { $_.Result -eq 'Success_Assigned' -and $_.ManagedDeviceId } |
                  Select-Object -ExpandProperty ManagedDeviceId -Unique
    $existing = @(); if ($Resume) { $existing = $processedSet.Keys }
    $finalSet = ($existing + $successIds) | Select-Object -Unique
    Save-Checkpoint -Path $CheckpointPath -ManagedDeviceIds $finalSet
  }

} else {
  # Sequential (batched) assignments
  $batches = [Math]::Ceiling($work.Count / [Math]::Max(1,$BatchSize))
  $successIds = @()

  for ($b = 0; $b -lt $batches; $b++) {
    $start = $b * $BatchSize
    $end   = [Math]::Min($start + $BatchSize, $work.Count)
    $batch = $work[$start..($end-1)]

    Write-Progress -Id 2 -Activity "Assigning primary users (batch $($b+1)/$batches)" -Status "Items $start..$(($end-1))" -PercentComplete ([Math]::Min(100, (($b+1)/$batches)*100))
    Write-Log -Level INFO -Message "Processing batch $($b+1)/$batches (items $start..$(($end-1)))"

    foreach ($row in $batch) {
      if ($row.Action -like "Skip_*") { $row.Result = $row.Action; $results += $row; continue }
      if ($DryRun) { $row.Result = "DryRun_Assign_PrimaryUser"; $results += $row; continue }

      # Clone headers to avoid race during refresh
      $localHeaders = @{'Authorization' = $script:Headers['Authorization']}
      $out = Invoke-Assign -Row $row -Headers $localHeaders -MaxRetries $AssignmentMaxRetries -DelayMs $AssignmentDelayMs `
              -GraphEndpoint $GraphEndpoint -LogPathLocal $LogPath -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
      $results += $out
      if ($out.Result -eq 'Success_Assigned' -and $out.ManagedDeviceId) { $successIds += $out.ManagedDeviceId }
      Start-Sleep -Milliseconds $AssignmentDelayMs
    }

    Write-Progress -Id 2 -Activity "Assigning primary users (batch $($b+1)/$batches)" -Completed

    # Save checkpoint after each sequential batch (successes only)
    if (-not $DryRun) {
      $existing = @(); if ($Resume) { $existing = $processedSet.Keys }
      $finalSet = ($existing + $successIds) | Select-Object -Unique
      Save-Checkpoint -Path $CheckpointPath -ManagedDeviceIds $finalSet
    }

    if ($b -lt ($batches - 1) -and -not $DryRun) { Start-Sleep -Seconds $BatchPauseSeconds }
  }
}

# --------------------
# Export results (main + errors CSV) and wrap-up
# --------------------
$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
$errPath = Join-Path $OutputDir "PrimaryUserAssignment_Errors_$ts.csv"

$results | Export-Csv -NoTypeInformation -Path $csvPath
$results | Where-Object { $_.Result -like 'Error:*' } | Export-Csv -NoTypeInformation -Path $errPath

Write-Host "Completed. Results: $csvPath" -ForegroundColor Green
if (Test-Path $errPath -and (Get-Item $errPath).Length -gt 0) {
  Write-Host "Errors:   $errPath" -ForegroundColor Yellow
  Write-Log -Level WARN -Message "Completed with errors. See $errPath"
} else {
  Remove-Item $errPath -ErrorAction SilentlyContinue
  Write-Log -Level INFO -Message "Completed successfully."
} # Use partner login for 21Vianet tenants, else standard global login
  $tokenUri = ($GraphEndpoint -like "*chinacloudapi.cn*") ?
              "https://login.partner.microsoftonline.cn/$TenantId/oauth2/v2.0/token" :
              "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

  $body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
    scope         = "$GraphEndpoint/.default"
  }

  try {
    $tok = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    Write-Log -Level INFO -Message "Access token obtained."
    return $tok.access_token
  } catch {
    Write-Log -Level ERROR -Message "Token request failed: $($_.Exception.Message)"
    throw
  }
}

# --------------------
# Robust Graph call: retries + token refresh on 401 + response body capture
# --------------------
function Invoke-Graph {
  param(
    [string]$Method, [string]$Uri, [hashtable]$Headers, [object]$Body = $null, [int]$MaxRetries = 6
  )
  $attempt = 0
  while ($true) {
    try {
      if ($Method -eq "GET") {
        return Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -ErrorAction Stop
      } elseif ($Method -eq "POST") {
        return Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers -Body $Body -ContentType "application/json" -ErrorAction Stop
      } else { throw "Unsupported method: $Method" }
    } catch {
      $attempt++
      $status = $null; $retryAfter = 0; $respBody = $null

      # Extract status / Retry-After / response body for diagnostics
      if ($_.Exception.Response) {
       
