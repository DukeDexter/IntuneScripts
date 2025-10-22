# =========================
# BulkAssign-IntunePrimaryUsers.ps1
# =========================
# Purpose:
#   Bulk-assign Intune primary users based on last N days of sign-in activity.
#   Pure Microsoft Graph REST (no Microsoft.Graph module) => fewer dependencies and avoids function-capacity issues.
#   Supports PowerShell 5.1 (sequential) and 7+ (optional parallel).
#   Includes: token refresh, defensive paging, fallback querying, batching/parallel, per-item retries, logging, CSV audit, checkpoint resume.

param(
  # --- Authentication / App Registration ---
  [Parameter(Mandatory)][string]$TenantId,      # Tenant GUID or primary domain (e.g., contoso.com)
  [Parameter(Mandatory)][string]$ClientId,      # Entra App Registration - Application (client) ID
  [Parameter(Mandatory)][string]$ClientSecret,  # App client secret (use secure storage in production)

  # --- Data window & selection rules ---
  [int]$LookbackDays = 30,          # Sign-ins considered in past N days
  [int]$MinEventsPerDevice = 2,     # Min successful sign-ins by the "winner" on a device
  [string]$ExcludeUpnPattern,       # Regex to exclude UPNs (e.g., '^(svc-|system_)')

  # --- Execution mode ---
  [switch]$DryRun,                  # If set: preview changes, do not commit primary user assignments

  # --- IO / Paths ---
  [string]$OutputDir = ".",         # Folder for outputs (CSV files)
  [string]$LogPath = ".\BulkAssign-PrimaryUsers.log",          # Script log
  [string]$CheckpointPath = ".\PrimaryUserCheckpoint.json",    # JSON array of managedDeviceId (successes)
  [switch]$Resume,                  # If set: skip devices already in checkpoint file

  # --- Graph environment ---
  [string]$GraphEndpoint = "https://graph.microsoft.com",  # 21Vianet: https://microsoftgraph.chinacloudapi.cn

  # --- Paging / Progress ---
  [int]$MaxPages = 200,             # Defensive cap on the number of pages fetched

  # --- Assignment control (sequential) ---
  [int]$BatchSize = 100,            # Number of devices per batch in sequential mode
  [int]$AssignmentDelayMs = 200,    # Delay between POSTs (helps avoid throttling)
  [int]$BatchPauseSeconds = 2,      # Pause between sequential batches
  [int]$AssignmentMaxRetries = 3,   # Per-item POST retry attempts (linear backoff)

  # --- Parallel (PowerShell 7+ only) ---
  [switch]$UseParallel,             # Opt-in to ForEach-Object -Parallel
  [int]$ThrottleLimit = 8           # Max concurrent operations in parallel mode
)

# Force TLS 1.2 (important on PS 5.1; harmless on PS 7+)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# --------------------
# Logging helper (writes to $LogPath)
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
# Checkpoint helpers (store/read successful managedDeviceId assignments)
# --------------------
function Load-Checkpoint {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return @{} }    # Return empty set if missing
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

# Ensure output locations exist (idempotent)
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
New-Item -ItemType File -Path $LogPath -Force | Out-Null
Write-Log -Level INFO -Message "Start. Tenant=$TenantId LookbackDays=$LookbackDays DryRun=$DryRun UseParallel=$UseParallel Resume=$Resume"

# Script-scope copies for helpers (used by token refresh logic)
$script:TenantId      = $TenantId
$script:ClientId      = $ClientId
$script:ClientSecret  = $ClientSecret
$script:GraphEndpoint = $GraphEndpoint
$script:Headers       = @{}  # Populated after initial token

# --------------------
# Obtain an access token using client credentials (app authentication)
# --------------------
function Get-GraphToken {
  param($TenantId,$ClientId,$ClientSecret,$GraphEndpoint)

  # Use partner login host for 21Vianet tenants; otherwise global
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
# Core Graph caller with:
# - exponential backoff for 429/5xx
# - token refresh on 401 (invalid/expired)
# - response body capture for diagnostics
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

      # Pull status/Retry-After/body for debugging
      if ($_.Exception.Response) {
        $status = [int]$_.Exception.Response.StatusCode
        try {
          $stream = $_.Exception.Response.GetResponseStream()
          if ($stream) { $reader = New-Object System.IO.StreamReader($stream); $respBody = $reader.ReadToEnd() }
        } catch {}
        $raHdr = $_.Exception.Response.Headers["Retry-After"]
        if ($raHdr) { [int]::TryParse($raHdr, [ref]$retryAfter) | Out-Null }
      }

      # Automatic token refresh on 401
      if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken' -or $respBody -match 'token is expired' -or $respBody -match 'Lifetime validation failed')) {
        Write-Log -Level WARN -Message "401 Invalid/Expired token. Refreshing token and retrying..."
        $newTok = Get-GraphToken -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $script:ClientSecret -GraphEndpoint $script:GraphEndpoint
        $Headers["Authorization"]     = "Bearer $newTok"
        $script:Headers["Authorization"] = "Bearer $newTok"
        $attempt--  # Do not penalize on token refresh
        continue
      }

      # Transient backoff on throttling/server errors
      if ($attempt -le $MaxRetries -and ($status -in 429,500,503,504)) {
        $delay = ($retryAfter -gt 0) ? $retryAfter : [math]::Min(60, [math]::Pow(2, $attempt))
        Write-Log -Level WARN -Message "Transient HTTP $status for $Uri. Retrying in $delay sec... ($attempt/$MaxRetries)"
        Start-Sleep -Seconds $delay
        continue
      }

      # Hard fail: bubble up w/ body
      $msg = "Graph call failed (HTTP $status): $($_.Exception.Message)"
      if ($respBody) { $msg = "$msg`nResponse body: $respBody" }
      Write-Log -Level ERROR -Message $msg
      throw $msg
    }
  }
}

# --------------------
# Page through Graph results safely:
# - Progress bar
# - Max pages cap
# - Defensive nextLink handling (skiptoken bugs)
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
# Initial auth: get token and store Authorization header
# --------------------
Write-Host "Authenticating..." -ForegroundColor Cyan
$firstToken     = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
$script:Headers = @{ "Authorization" = "Bearer $firstToken" }

# --------------------
# Build sign-ins query filtered by createdDateTime >= startUtc
# (If filtered returns empty, we fallback to unfiltered and filter client-side)
# --------------------
$startUtc  = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filterEnc = [uri]::EscapeDataString("createdDateTime ge $startUtc")
$signInsUri = "$GraphEndpoint/v1.0/auditLogs/signIns?%24filter=$filterEnc"
Write-Log -Level INFO -Message "Sign-ins filtered URI: $signInsUri"

$signIns = Get-GraphPaged -Uri $signInsUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Fetching sign-ins (filtered)"

if (-not $signIns -or $signIns.Count -eq 0) {
  # Fallback path: unfiltered page-through, then client-side filter by time window and success
  Write-Log -Level WARN -Message "Filtered query returned no results. Fallback to unfiltered."
  $fallbackUri = "$GraphEndpoint/v1.0/auditLogs/signIns"
  $signIns     = Get-GraphPaged -Uri $fallbackUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Fetching sign-ins (fallback)"
  $startDt     = [datetime]::ParseExact($startUtc,'yyyy-MM-ddTHH:mm:ssZ',$null)
  $signIns     = $signIns | Where-Object { ([datetime]$_.createdDateTime -ge $startDt) -and ($_.status.errorCode -eq 0 -or -not $_.status) }
} else {
  # Keep only successful/federated successful sign-ins
  $signIns = $signIns | Where-Object { $_.status.errorCode -eq 0 -or -not $_.status }
}

# --------------------
# Normalize: we require deviceDetail.deviceId (AAD device GUID) to map to Intune
# --------------------
$activity = foreach ($e in $signIns) {
  $devId = $e.deviceDetail.deviceId
  if ([string]::IsNullOrWhiteSpace($devId)) { continue }                         # must have device GUID
  if ($ExcludeUpnPattern -and $e.userPrincipalName -match $ExcludeUpnPattern) { continue }  # skip service/bots
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
# Aggregate: choose the most active user per device (tie -> most recent sign-in)
# --------------------
$assignments = @()
$byDevice = $activity | Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $userGroups = $devGroup.Group | Group-Object UserId | Sort-Object Count -Descending
  $winner     = $userGroups | Select-Object -First 1
  if ($winner.Count -lt $MinEventsPerDevice) { continue }

  # Tie-breaker by latest sign-in among tied users
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
# Lookup Intune managedDevice via azureADDeviceId
# --------------------
function Get-ManagedDeviceByAadId {
  param($AadDeviceId,[hashtable]$Headers,$GraphEndpoint)
  $filterEnc = [uri]::EscapeDataString("azureADDeviceId eq '$AadDeviceId'")  # NOTE: string value must be quoted
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
    # No Intune object -> skip but include in results for audit
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
# Load checkpoint if resuming (skip already processed IDs in non-DryRun)
# --------------------
$processedSet = @{}
if ($Resume) {
  $processedSet = Load-Checkpoint -Path $CheckpointPath
  $already = ($processedSet.Keys | Measure-Object).Count
  Write-Log -Level INFO -Message "Resume enabled. Loaded checkpoint with $already device IDs."
}

# --------------------
# Per-item assignment: POST users/$ref with robust error handling
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

  # Worker-local logger (useful in parallel workers)
  function LogLocal([string]$lvl,[string]$msg) {
    Add-Content -Path $LogPathLocal -Value "$(Get-Date -Format o) [$lvl] $msg"
  }

  # Early exits: skip rows and missing user
  if ($Row.Action -like "Skip_*") { $Row.Result = $Row.Action; return $Row }
  if ([string]::IsNullOrWhiteSpace($Row.TargetUserId)) { $Row.Result="Error: Missing TargetUserId"; return $Row }

  # Attempt loop with linear backoff; refresh token on 401
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
        # Inspect failure; refresh token locally if 401
        $status=$null; $respBody=$null
        if ($_.Exception.Response) {
          $status=[int]$_.Exception.Response.StatusCode
          try { $stream=$_.Exception.Response.GetResponseStream(); if ($stream) { $reader=New-Object System.IO.StreamReader($stream); $respBody=$reader.ReadToEnd() } } catch {}
        }
        if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken' -or $respBody -match 'token is expired' -or $respBody -match 'Lifetime validation failed')) {
          LogLocal "WARN" "401 in worker; refreshing token (attempt $attempt) for $($Row.ManagedDeviceId)"
          $newTok = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
          $Headers["Authorization"] = "Bearer $newTok"
          Start-Sleep -Milliseconds $DelayMs
          continue
        }
        throw
      }
    } catch {
      LogLocal "WARN" "Attempt $attempt failed for device $($Row.ManagedDeviceId): $($_.Exception.Message)"
      if ($attempt -lt $MaxRetries) {
        Start-Sleep -Milliseconds ([math]::Max($DelayMs, 100) * $attempt)  # Linear backoff
      } else {
        $Row.Result="Error: $($_.Exception.Message)"; $Row.Attempts=$attempt; return $Row
      }
    }
  }
}

# --------------------
# Assignment phase
# - Parallel (PS7+ only) or Sequential (PS5.1/PS7)
# - Checkpoint resume (non-DryRun)
# --------------------
$results = @()
Write-Log -Level INFO -Message "Starting assignment phase. UseParallel=$UseParallel"

# Apply checkpoint (skip already processed) only when actually changing things (not in DryRun)
if ($Resume -and -not $DryRun) {
  $work = $work | Where-Object {
    if ($_.ManagedDeviceId -and $processedSet.ContainsKey($_.ManagedDeviceId)) {
      $_.Result = "Checkpoint_Skip"; $results += $_; $false
    } else { $true }
  }
  Write-Log -Level INFO -Message "After resume filter, items remaining: $($work.Count)"
}

if ($UseParallel -and $PSVersionTable.PSVersion.Major -ge 7) {
  # --- Parallel mode (PS 7+): collect skips, run workers, merge & checkpoint ---
  $skips = $work | Where-Object { $_.Action -like "Skip_*" }
  foreach ($s in $skips) { $s.Result = $s.Action; $results += $s }

  $toAssign = $work | Where-Object { $_.Action -eq "Assign_PrimaryUser" }
  $authVal  = $script:Headers['Authorization']  # Immutable string value for $using:

  # Launch workers; each returns its output row (no shared-state mutation inside)
  $parResults = $toAssign | ForEach-Object -Parallel {
      param($item)
      $hdrs = @{ 'Authorization' = $using:authVal }
      Invoke-Assign -Row $item -Headers $hdrs -MaxRetries $using:AssignmentMaxRetries `
                    -DelayMs $using:AssignmentDelayMs -GraphEndpoint $using:GraphEndpoint `
                    -LogPathLocal $using:LogPath -TenantId $using:TenantId -ClientId $using:ClientId -ClientSecret $using:ClientSecret
    } -ThrottleLimit ([Math]::Max(1,$ThrottleLimit))

  $results += $parResults

  if (-not $DryRun) {
    # Save checkpoint once (successes only)
    $successIds = $parResults | Where-Object { $_.Result -eq 'Success_Assigned' -and $_.ManagedDeviceId } |
                  Select-Object -ExpandProperty ManagedDeviceId -Unique
    $existing = @(); if ($Resume) { $existing = $processedSet.Keys }
    $finalSet = ($existing + $successIds) | Select-Object -Unique
    Save-Checkpoint -Path $CheckpointPath -ManagedDeviceIds $finalSet
  }

} else {
  # --- Sequential mode: process in batches, save checkpoint after each batch ---
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

      # Clone header for thread-safety if token refresh occurs
      $localHeaders = @{'Authorization' = $script:Headers['Authorization']}

      $out = Invoke-Assign -Row $row -Headers $localHeaders -MaxRetries $AssignmentMaxRetries -DelayMs $AssignmentDelayMs `
              -GraphEndpoint $GraphEndpoint -LogPathLocal $LogPath -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
      $results += $out
      if ($out.Result -eq 'Success_Assigned' -and $out.ManagedDeviceId) { $successIds += $out.ManagedDeviceId }
      Start-Sleep -Milliseconds $AssignmentDelayMs
    }

    Write-Progress -Id 2 -Activity "Assigning primary users (batch $($b+1)/$batches)" -Completed

    if (-not $DryRun) {
      # Save checkpoint cumulatively (successes only)
      $existing = @(); if ($Resume) { $existing = $processedSet.Keys }
      $finalSet = ($existing + $successIds) | Select-Object -Unique
      Save-Checkpoint -Path $CheckpointPath -ManagedDeviceIds $finalSet
    }

    if ($b -lt ($batches - 1) -and -not $DryRun) { Start-Sleep -Seconds $BatchPauseSeconds }
  }
}

# --------------------
# Export results (all + errors) and finish
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
}
