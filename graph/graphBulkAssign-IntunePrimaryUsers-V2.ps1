<#
Bulk assign Intune primary users based on last N days of sign-ins via Microsoft Graph REST.
Features:
 - Token refresh on 401
 - Defensive paging with progress + max pages cap
 - Fallback (unfiltered) query if filtered returns no data
 - Batched OR Parallel assignments (PS7+)
 - Per-item retries + backoff, detailed errors
 - File logging + CSV audit
 - Checkpoint resume (PowerShell 5.1 compatible)

USAGE (safe preview first):
.\BulkAssign-IntunePrimaryUsers.ps1 `
  -TenantId "contoso.com" `
  -ClientId "11111111-2222-3333-4444-555555555555" `
  -ClientSecret "SuperSecretValue" `
  -LookbackDays 30 `
  -MinEventsPerDevice 3 `
  -BatchSize 50 `
  -MaxPages 100 `
  -DryRun `
  -UseParallel `
  -ThrottleLimit 8 `
  -LogPath "C:\Intune\PrimaryUser\bulkassign.log" `
  -OutputDir "C:\Intune\PrimaryUser" `
  -CheckpointPath "C:\Intune\PrimaryUser\checkpoint.json" `
  -Resume
#>

param(
  # Auth & scope
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  # Activity window & selection
  [int]$LookbackDays = 30,
  [int]$MinEventsPerDevice = 2,
  [string]$ExcludeUpnPattern,

  # Execution mode
  [switch]$DryRun,

  # IO paths
  [string]$OutputDir = ".",
  [string]$LogPath = ".\BulkAssign-PrimaryUsers.log",
  [string]$CheckpointPath = ".\PrimaryUserCheckpoint.json",
  [switch]$Resume,

  # Graph endpoints
  [string]$GraphEndpoint = "https://graph.microsoft.com",  # 21Vianet: https://microsoftgraph.chinacloudapi.cn

  # Paging
  [int]$MaxPages = 200,

  # Assignments
  [int]$BatchSize = 100,
  [int]$AssignmentDelayMs = 200,
  [int]$BatchPauseSeconds = 2,
  [int]$AssignmentMaxRetries = 3,

  # Parallel (PowerShell 7+)
  [switch]$UseParallel,
  [int]$ThrottleLimit = 8
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

# -------------------- Checkpoint helpers --------------------
function Load-Checkpoint {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return @{} } # empty set
  try {
    $data = Get-Content -Path $Path -ErrorAction Stop | Out-String | ConvertFrom-Json
    if ($data -is [array]) {
      # convert to hashtable-like set for O(1) lookups
      $set = @{}
      foreach ($id in $data) { $set[$id] = $true }
      return $set
    } else { return @{} }
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

# Ensure output paths exist
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
New-Item -ItemType File -Path $LogPath -Force | Out-Null
Write-Log -Level INFO -Message "Script start. Tenant=$TenantId LookbackDays=$LookbackDays DryRun=$DryRun UseParallel=$UseParallel Resume=$Resume"

# -------------------- Script-scope copies for helpers --------------------
$script:TenantId      = $TenantId
$script:ClientId      = $ClientId
$script:ClientSecret  = $ClientSecret
$script:GraphEndpoint = $GraphEndpoint
$script:Headers       = @{}  # populated after initial token

# -------------------- Token --------------------
function Get-GraphToken {
  param($TenantId,$ClientId,$ClientSecret,$GraphEndpoint)
  $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  if ($GraphEndpoint -like "*chinacloudapi.cn*") { $tokenUri = "https://login.partner.microsoftonline.cn/$TenantId/oauth2/v2.0/token" }
  $body = @{ client_id=$ClientId; client_secret=$ClientSecret; grant_type="client_credentials"; scope="$GraphEndpoint/.default" }
  try {
    $tok = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    Write-Log -Level INFO -Message "Obtained access token."
    return $tok.access_token
  } catch {
    Write-Log -Level ERROR -Message "Token request failed: $($_.Exception.Message)"
    throw
  }
}

# -------------------- Graph call with retry + token refresh --------------------
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
          if ($stream) { $reader = New-Object System.IO.StreamReader($stream); $respBody = $reader.ReadToEnd() }
        } catch { }
        $raHdr = $_.Exception.Response.Headers["Retry-After"]
        if ($raHdr) { [int]::TryParse($raHdr,[ref]$retryAfter) | Out-Null }
      }
      # Token refresh on 401
      if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken' -or $respBody -match 'token is expired' -or $respBody -match 'Lifetime validation failed')) {
        Write-Log -Level WARN -Message "401 Invalid/Expired token. Refreshing token and retrying..."
        $newTok = Get-GraphToken -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $script:ClientSecret -GraphEndpoint $script:GraphEndpoint
        $Headers["Authorization"] = "Bearer $newTok"
        $script:Headers["Authorization"] = "Bearer $newTok"
        $attempt-- # neutralize for pure refresh
        continue
      }
      # Transient backoff
      $isTransient = $status -in 429,500,503,504
      if ($attempt -le $MaxRetries -and $isTransient) {
        if ($retryAfter -gt 0) { $delay = $retryAfter } else { $delay = [math]::Min(60, [math]::Pow(2, $attempt)) }
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

# -------------------- Defensive paging --------------------
function Get-GraphPaged {
  param($Uri,[hashtable]$Headers,[int]$MaxPages,[string]$ActivityName)
  $items=@(); $next=$Uri; $page=0; $maxPages=[Math]::Max(1,$MaxPages)
  while ($next -and $page -lt $maxPages) {
    $page++
    Write-Progress -Id 1 -Activity $ActivityName -Status "Page $page of $maxPages" -PercentComplete ([Math]::Min(100,($page/$maxPages)*100))
    Write-Log -Level INFO -Message "$ActivityName - requesting page $page"
    try { $resp = Invoke-Graph -Method GET -Uri $next -Headers $Headers }
    catch {
      if ($_.Exception.Message -match 'Skip token is null|skiptoken') {
        Write-Log -Level WARN -Message "$ActivityName - paging halted due to skiptoken error at page $page."
        break
      }
      throw
    }
    if ($resp.value) { $items += $resp.value }
    $nl = $resp.'@odata.nextLink'
    if ($nl -and ($nl -match 'skiptoken' -or $nl -match '%24skiptoken')) { $next=$nl } else { $next=$null }
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
$startUtc  = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filterRaw = "createdDateTime ge $startUtc"
$filterEnc = [uri]::EscapeDataString($filterRaw)

$signInsUri = "$GraphEndpoint/v1.0/auditLogs/signIns?%24filter=$filterEnc"
Write-Host "Sign-ins URI (filtered): $signInsUri" -ForegroundColor DarkGray
Write-Log -Level INFO -Message "Sign-ins filtered URI: $signInsUri"

$signIns = Get-GraphPaged -Uri $signInsUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Fetching sign-ins (filtered)"
if (-not $signIns -or $signIns.Count -eq 0) {
  Write-Warning "Initial query returned no results. Falling back to unfiltered query."
  Write-Log -Level WARN -Message "Fallback to unfiltered sign-ins."
  $fallbackUri = "$GraphEndpoint/v1.0/auditLogs/signIns"
  $signIns     = Get-GraphPaged -Uri $fallbackUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Fetching sign-ins (fallback)"
  $startDt = [datetime]::ParseExact($startUtc,'yyyy-MM-ddTHH:mm:ssZ',$null)
  $signIns = $signIns | Where-Object { ([datetime]$_.createdDateTime -ge $startDt) -and ($_.status.errorCode -eq 0 -or -not $_.status) }
} else {
  $signIns = $signIns | Where-Object { $_.status.errorCode -eq 0 -or -not $_.status }
}

# Normalize & require deviceId
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
  $idx++; if ($idx % 100 -eq 0) { Write-Log -Level INFO -Message "Resolving managedDevices... processed $idx/$($assignments.Count)" }
  $resp = Get-ManagedDeviceByAadId -AadDeviceId $item.DeviceAadId -Headers $script:Headers -GraphEndpoint $GraphEndpoint
  $md   = $null
  if ($resp.value -and $resp.value.Count -ge 1) { $md = $resp.value[0] }
  if (-not $md) {
    $work += [pscustomobject]@{
      DeviceAadId=$item.DeviceAadId; DeviceName=$item.DeviceName; ManagedDeviceId=$null; CurrentPrimaryUserId=$null;
      TargetUserId=$item.TargetUserId; TargetUpn=$item.TargetUpn; EventCount=$item.EventCount; Action="Skip_NoManagedDevice";
     
