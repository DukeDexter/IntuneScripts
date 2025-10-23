param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [int]$LookbackDays = 30,
  [int]$MinEventsPerDevice = 2,
  [string]$ExcludeUpnPattern,
  [switch]$DryRun,

  [string]$OutputDir = ".",
  [string]$LogPath = ".\BulkAssign-PrimaryUsers.log",
  [string]$CheckpointPath = ".\PrimaryUserCheckpoint.json",
  [switch]$Resume,

  [string]$GraphEndpoint = "https://graph.microsoft.com",

  [int]$MaxPages = 200,
  [int]$BatchSize = 100,
  [int]$AssignmentDelayMs = 200,
  [int]$BatchPauseSeconds = 2,
  [int]$AssignmentMaxRetries = 3,

  [switch]$UseParallel,
  [int]$ThrottleLimit = 8
)

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Write-Log {
  param([ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO',[Parameter(Mandatory)][string]$Message)
  Add-Content -Path $LogPath -Value "$(Get-Date -Format o) [$Level] $Message"
}

function Load-Checkpoint {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return @{} }
  try {
    $data = (Get-Content -Path $Path -Raw | ConvertFrom-Json)
    $set  = @{}; foreach ($id in $data) { $set[$id] = $true }; return $set
  } catch { Write-Log WARN "Failed to read checkpoint: $($_.Exception.Message)"; return @{} }
}

function Save-Checkpoint {
  param([string]$Path,[array]$ManagedDeviceIds)
  try {
    $tmp = "$Path.tmp"; $ManagedDeviceIds | ConvertTo-Json -Depth 3 | Set-Content -Path $tmp
    Move-Item -Path $tmp -Destination $Path -Force
    Write-Log INFO "Checkpoint saved ($($ManagedDeviceIds.Count)) -> $Path"
  } catch { Write-Log WARN "Failed to save checkpoint: $($_.Exception.Message)" }
}

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
New-Item -ItemType File -Path $LogPath -Force | Out-Null
Write-Log INFO "Start. Tenant=$TenantId LookbackDays=$LookbackDays DryRun=$DryRun UseParallel=$UseParallel Resume=$Resume"

$script:TenantId      = $TenantId
$script:ClientId      = $ClientId
$script:ClientSecret  = $ClientSecret
$script:GraphEndpoint = $GraphEndpoint
$script:Headers       = @{}

function Get-GraphToken {
  param($TenantId,$ClientId,$ClientSecret,$GraphEndpoint)
  if ($GraphEndpoint -like "*chinacloudapi.cn*") {
    $tokenUri = "https://login.partner.microsoftonline.cn/$TenantId/oauth2/v2.0/token"
  } else {
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  }
  $body = @{ client_id=$ClientId; client_secret=$ClientSecret; grant_type="client_credentials"; scope="$GraphEndpoint/.default" }
  try {
    $tok = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    Write-Log INFO "Access token obtained."; return $tok.access_token
  } catch { Write-Log ERROR "Token error: $($_.Exception.Message)"; throw }
}

function Invoke-Graph {
  param([string]$Method,[string]$Uri,[hashtable]$Headers,[object]$Body=$null,[int]$MaxRetries=6)
  $attempt=0
  while ($true) {
    try {
      if ($Method -eq "GET") { return Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -ErrorAction Stop }
      elseif ($Method -eq "POST") { return Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers -Body $Body -ContentType "application/json" -ErrorAction Stop }
      else { throw "Unsupported method: $Method" }
    } catch {
      $attempt++
      $status=$null; $retryAfter=0; $respBody=$null
      if ($_.Exception.Response) {
        $status=[int]$_.Exception.Response.StatusCode
        try { $stream=$_.Exception.Response.GetResponseStream(); if ($stream) { $reader=New-Object IO.StreamReader($stream); $respBody=$reader.ReadToEnd() } } catch {}
        $ra=$_.Exception.Response.Headers["Retry-After"]; if ($ra) { [int]::TryParse($ra,[ref]$retryAfter) | Out-Null }
      }
      if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken|token is expired|Lifetime validation failed')) {
        Write-Log WARN "401 token invalid/expired. Refreshing..."
        $newTok = Get-GraphToken -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $script:ClientSecret -GraphEndpoint $script:GraphEndpoint
        $Headers["Authorization"] = "Bearer $newTok"; $script:Headers["Authorization"] = "Bearer $newTok"; $attempt--; continue
      }
      $isTransient = $status -in 429,500,503,504
      if ($attempt -le $MaxRetries -and $isTransient) {
        if ($retryAfter -gt 0) { $delay = $retryAfter } else { $delay = [math]::Min(60,[math]::Pow(2,$attempt)) }
        Write-Log WARN "Transient $status for $Uri. Retrying in $delay sec ($attempt/$MaxRetries)"; Start-Sleep -Seconds $delay; continue
      }
      $msg = "Graph call failed (HTTP $status): $($_.Exception.Message)"; if ($respBody) { $msg = "$msg`n$respBody" }
      Write-Log ERROR $msg; throw $msg
    }
  }
}

function Get-GraphPaged {
  param($Uri,[hashtable]$Headers,[int]$MaxPages,[string]$ActivityName)
  $items=@(); $next=$Uri; $page=0; $cap=[Math]::Max(1,$MaxPages)
  while ($next -and $page -lt $cap) {
    $page++; Write-Progress -Id 1 -Activity $ActivityName -Status "Page $page/$cap" -PercentComplete ([Math]::Min(100,($page/$cap)*100))
    Write-Log INFO "$ActivityName: request page $page"
    try { $resp = Invoke-Graph -Method GET -Uri $next -Headers $Headers }
    catch { if ($_.Exception.Message -match 'Skip token is null|skiptoken') { Write-Log WARN "$ActivityName: skiptoken issue on page $page"; break } throw }
    if ($resp.value) { $items += $resp.value }
    $nl = $resp.'@odata.nextLink'; if ($nl -and ($nl -match 'skiptoken' -or $nl -match '%24skiptoken')) { $next=$nl } else { $next=$null }
  }
  Write-Progress -Id 1 -Activity $ActivityName -Completed
  Write-Log INFO "$ActivityName: collected $($items.Count) across $page page(s)"
  return $items
}

Write-Host "Authenticating..." -ForegroundColor Cyan
$firstToken     = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
$script:Headers = @{ "Authorization" = "Bearer $firstToken" }

$startUtc   = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filterEnc  = [uri]::EscapeDataString("createdDateTime ge $startUtc")
$signInsUri = "$GraphEndpoint/v1.0/auditLogs/signIns?%24filter=$filterEnc"
Write-Log INFO "Sign-ins (filtered): $signInsUri"
$signIns = Get-GraphPaged -Uri $signInsUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Sign-ins (filtered)"

if (-not $signIns -or $signIns.Count -eq 0) {
  Write-Log WARN "Filtered query returned no results. Fallback to unfiltered."
  $fallbackUri = "$GraphEndpoint/v1.0/auditLogs/signIns"
  $signIns     = Get-GraphPaged -Uri $fallbackUri -Headers $script:Headers -MaxPages $MaxPages -ActivityName "Sign-ins (fallback)"
  $startDt     = [datetime]::ParseExact($startUtc,'yyyy-MM-ddTHH:mm:ssZ',$null)
  $signIns     = $signIns | Where-Object { ([datetime]$_.createdDateTime -ge $startDt) -and ($_.status.errorCode -eq 0 -or -not $_.status) }
} else {
  $signIns = $signIns | Where-Object { $_.status.errorCode -eq 0 -or -not $_.status }
}

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
  Write-Log WARN "No sign-ins with deviceId. Exiting."
  $ts=(Get-Date).ToString('yyyyMMdd_HHmmss'); $csvPath=Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @() | Export-Csv -NoTypeInformation -Path $csvPath
  Write-Host "Empty results -> $csvPath" -ForegroundColor Yellow
  exit 0
}

$assignments=@()
$byDevice=$activity|Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $userGroups=$devGroup.Group|Group-Object UserId|Sort-Object Count -Descending
  $winner=$userGroups|Select-Object -First 1
  if ($winner.Count -lt $MinEventsPerDevice) { continue }
  $ties=$userGroups|Where-Object { $_.Count -eq $winner.Count }
  if ($ties.Count -gt 1) {
    $winner=$ties|Sort-Object @{Expression={($_.Group|Sort-Object CreatedDateTime -Descending|Select-Object -First 1).CreatedDateTime}},Descending|Select-Object -First 1
  }
  $assignments+=[pscustomobject]@{
    DeviceAadId=$devGroup.Name
    DeviceName=($devGroup.Group|Sort-Object CreatedDateTime -Descending|Select-Object -First 1).DeviceName
    TargetUserId=$winner.Name
    TargetUpn=($winner.Group|Select-Object -First 1).UserPrincipalName
    EventCount=$winner.Count
  }
}

Write-Log INFO "Devices to process: $($assignments.Count)"
if ($assignments.Count -eq 0) {
  $ts=(Get-Date).ToString('yyyyMMdd_HHmmss'); $csvPath=Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @()|Export-Csv -NoTypeInformation -Path $csvPath
  Write-Log WARN "No qualifying devices. Exiting."
  Write-Host "Empty results -> $csvPath" -ForegroundColor Yellow
  exit 0
}

# Updated function to sanitize device ID and build correct filter
function Get-ManagedDeviceByAadId {
  param([string]$AadDeviceId,[hashtable]$Headers,[string]$GraphEndpoint)
  $id=$AadDeviceId -replace '[\{\}"'']',''
  $id=$id.Trim()
  if ($id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Log WARN "Invalid azureADDeviceId format after normalization: '$AadDeviceId' -> '$id'. Skipping lookup."
    return @{ value=@() }
  }
  $filterRaw="azureADDeviceId eq '$id'"
  $filterEnc=[uri]::EscapeDataString($filterRaw)
  $uri="$GraphEndpoint/v1.0/deviceManagement/managedDevices?%24filter=$filterEnc"
  Write-Log INFO "ManagedDevice lookup URI: $uri"
  $resp=Invoke-Graph -Method GET -Uri $uri -Headers $Headers
  return $resp
}

$work=@(); $idx=0
foreach ($item in $assignments) {
  $idx++; if ($idx % 100 -eq 0) { Write-Log INFO "Resolving managedDevices: $idx/$($assignments.Count)" }
  $resp=Get-ManagedDeviceByAadId -AadDeviceId $item.DeviceAadId -Headers $script:Headers -GraphEndpoint $GraphEndpoint
  $md=$null; if ($resp.value -and $resp.value.Count -ge 1) { $md=$resp.value[0] }
  if (-not $md) {
    $work+=[pscustomobject]@{
      DeviceAadId=$item.DeviceAadId;DeviceName=$item.DeviceName;ManagedDeviceId=$null;CurrentPrimaryUserId=$null;
      TargetUserId=$item.TargetUserId;TargetUpn=$item.TargetUpn;EventCount=$item.EventCount;Action="Skip_NoManagedDevice";
      Result="No Intune object found";Attempts=0
    }
    continue
  }
  $action=if ($md.userId -eq $item.TargetUserId) {"Skip_AlreadyPrimary"}else{"Assign_PrimaryUser"}
  $work+=[pscustomobject]@{
    DeviceAadId=$item.DeviceAadId;DeviceName=$md.deviceName;ManagedDeviceId=$md.id;CurrentPrimaryUserId=$md.userId;
    TargetUserId=$item.TargetUserId;TargetUpn=$item.TargetUpn;EventCount=$item.EventCount;Action=$action;Result="";Attempts=0
  }
}

# Remaining assignment logic unchanged (sequential/parallel, checkpoint, export)...
