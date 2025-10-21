<#
Bulk assign Intune primary users based on last 30 days of sign-ins using Microsoft Graph REST API.
No Microsoft.Graph module required. Supports fallback re-query (no server-side filter) when initial call returns empty.
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
  [string]$GraphEndpoint = "https://graph.microsoft.com"  # For 21Vianet tenants: https://microsoftgraph.chinacloudapi.cn
)

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
    (Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded").access_token
  } catch {
    throw "Token request failed: $($_.Exception.Message)"
  }
}

# -------------------- Helper: Invoke Graph with Retry (prints body on error) --------------------
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
      $status = $null
      $retryAfter = 0
      $respBody = $null

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
        if ($raHdr) { [int]::TryParse($raHdr,[ref]$retryAfter) | Out-Null }
      }

      $transient = $status -in 429,500,503,504
      if ($attempt -le $MaxRetries -and $transient) {
        if ($retryAfter -gt 0) { $delay = $retryAfter } else { $delay = [math]::Min(60,[math]::Pow(2,$attempt)) }
        Write-Warning "Transient HTTP $status. Retrying in $delay sec... ($attempt/$MaxRetries)"
        Start-Sleep -Seconds $delay
        continue
      }

      $msg = "Graph call failed (HTTP $status): $($_.Exception.Message)"
      if ($respBody) { $msg = "$msg`nResponse body: $respBody" }
      throw $msg
    }
  }
}

# -------------------- Helper: Defensive Paging --------------------
function Get-GraphPaged {
  param($Uri,$Headers)

  $items = @()
  $next  = $Uri

  while ($next) {
    try {
      $resp = Invoke-Graph -Method GET -Uri $next -Headers $Headers
    } catch {
      # If nextLink paging fails due to skiptoken issues, stop gracefully and return what we have
      if ($_.Exception.Message -match 'Skip token is null|skiptoken') {
        Write-Warning "Paging halted due to an invalid/expired skiptoken. Returning collected items."
        break
      }
      throw
    }

    if ($resp.value) { $items += $resp.value }

    # Defensive: continue paging ONLY if nextLink contains a usable skiptoken
    $nl = $resp.'@odata.nextLink'
    if ($nl -and ($nl -match 'skiptoken' -or $nl -match '%24skiptoken')) {
      $next = $nl
    } else {
      $next = $null
    }
  }

  return $items
}

# -------------------- Authenticate --------------------
Write-Host "Authenticating..." -ForegroundColor Cyan
$token   = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
$headers = @{ "Authorization" = "Bearer $token" }

# -------------------- Compute dates (UTC) --------------------
$startUtc   = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filterRaw  = "createdDateTime ge $startUtc"
$filterEnc  = [uri]::EscapeDataString($filterRaw)

# -------------------- Try 1: Filtered query (server-side) --------------------
$signInsUri = "$GraphEndpoint/v1.0/auditLogs/signIns?%24filter=$filterEnc"
Write-Host "Sign-ins URI (filtered):`n$signInsUri" -ForegroundColor DarkGray

$signIns = Get-GraphPaged -Uri $signInsUri -Headers $headers

# -------------------- Fallback: Unfiltered re-query + client-side filter -----
if (-not $signIns -or $signIns.Count -eq 0) {
  Write-Warning "Initial call returned no sign-ins. Falling back to unfiltered query, then client-side filtering."
  $fallbackUri = "$GraphEndpoint/v1.0/auditLogs/signIns"
  Write-Host "Sign-ins URI (fallback):`n$fallbackUri" -ForegroundColor DarkGray
  $signIns = Get-GraphPaged -Uri $fallbackUri -Headers $headers

  # Client-side filter by time window and success status
  $startDt = [datetime]::ParseExact($startUtc,'yyyy-MM-ddTHH:mm:ssZ',$null)
  $signIns = $signIns |
    Where-Object {
      # createdDateTime is ISO 8601 string; cast to DateTime for compare
      $dt = [datetime]$_.createdDateTime
      ($dt -ge $startDt) -and ($_.status.errorCode -eq 0 -or -not $_.status)
    }
}

# -------------------- Normalize rows; keep ones with AAD device GUID ---------
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
  $ts      = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @() | Export-Csv -NoTypeInformation -Path $csvPath
  Write-Warning "No sign-in rows found. Empty results written to $csvPath"
  exit 0
}

# -------------------- Aggregate winners --------------------------------------
$assignments = @()
$byDevice    = $activity | Group-Object DeviceAadId
foreach ($devGroup in $byDevice) {
  $userGroups = $devGroup.Group | Group-Object UserId | Sort-Object Count -Descending
  $winner     = $userGroups | Select-Object -First 1
  if ($winner.Count -lt $MinEventsPerDevice) { continue }

  # Tie-breaker by latest sign-in if counts equal
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
if ($assignments.Count -eq 0) {
  $ts      = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath = Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @() | Export-Csv -NoTypeInformation -Path $csvPath
  Write-Warning "No qualifying users found. Empty results written to $csvPath"
  exit 0
}

# -------------------- Resolve managedDevices ---------------------------------
function Get-ManagedDeviceByAadId {
  param($AadDeviceId,$Headers,$GraphEndpoint)
  $filterEnc = [uri]::EscapeDataString("azureADDeviceId eq '$AadDeviceId'")  # string values need quotes
 
