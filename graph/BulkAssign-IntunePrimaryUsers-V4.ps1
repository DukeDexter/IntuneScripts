
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

function Write-Log {
  param(
    [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO',
    [Parameter(Mandatory)][string]$Message
  )
  $line = "$(Get-Date -Format o) [$Level] $Message"
  Add-Content -Path $LogPath -Value $line
}

function Get-GraphPaged {
  param($Uri,[hashtable]$Headers,[int]$MaxPages,[string]$ActivityName)
  $items = @(); $next = $Uri; $page = 0; $cap = [Math]::Max(1, $MaxPages)
  while ($next -and $page -lt $cap) {
    $page++
    Write-Progress -Id 1 -Activity $ActivityName -Status "Page $page of $cap" -PercentComplete ([Math]::Min(100, ($page/$cap)*100))
    Write-Log -Level INFO -Message "${ActivityName}: request page $page"
    try {
      $resp = Invoke-RestMethod -Method GET -Uri $next -Headers $Headers -ErrorAction Stop
    } catch {
      if ($_.Exception.Message -match 'Skip token is null|skiptoken') {
        Write-Log -Level WARN -Message "${ActivityName}: skiptoken issue on page $page"
        break
      }
      throw
    }
    if ($resp.value) { $items += $resp.value }
    $nl = $resp.'@odata.nextLink'
    if ($nl -and ($nl -match 'skiptoken' -or $nl -match '%24skiptoken')) { $next = $nl } else { $next = $null }
  }
  Write-Progress -Id 1 -Activity $ActivityName -Completed
  Write-Log -Level INFO -Message "${ActivityName}: collected $($items.Count) across $page page(s)"
  return $items
}

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
    return $tok.access_token
  } catch {
    throw "Token request failed: $($_.Exception.Message)"
  }
}

function Invoke-Graph {
  param(
    [string]$Method,[string]$Uri,[hashtable]$Headers,[object]$Body = $null,[int]$MaxRetries = 6
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
        } catch {}
        $raHdr = $_.Exception.Response.Headers["Retry-After"]
        if ($raHdr) { [int]::TryParse($raHdr, [ref]$retryAfter) | Out-Null }
      }
      if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken' -or $respBody -match 'token is expired' -or $respBody -match 'Lifetime validation failed')) {
        Write-Log -Level WARN -Message "401 Invalid/Expired token. Refreshing token and retrying..."
        $newTok = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
        $Headers["Authorization"] = "Bearer $newTok"
        $attempt--
        continue
      }
      $isTransient = $status -in 429,500,503,504
      if ($attempt -le $MaxRetries -and $isTransient) {
        if ($retryAfter -gt 0) {
          $delay = $retryAfter
        } else {
          $delay = [math]::Min(60, [math]::Pow(2, $attempt))
        }
        Write-Log -Level WARN -Message "Transient HTTP $status calling $Uri. Retrying in $delay sec... ($attempt/$MaxRetries)"
        Start-Sleep -Seconds $delay
        continue
      }
      $msg = "Graph call failed (HTTP $status): $($_.Exception.Message)"
      if ($respBody) { $msg = "$msg`nResponse body: $respBody" }
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
    Write-Log -Level WARN -Message "Invalid azureADDeviceId format after normalization: '$AadDeviceId' -> '$id'. Skipping lookup."
    return @{ value = @() }
  }
  $filterRaw = "azureADDeviceId eq '$id'"
  $filterEnc = [uri]::EscapeDataString($filterRaw)
  $uri = "$GraphEndpoint/v1.0/deviceManagement/managedDevices?%24filter=$filterEnc"
  Write-Log -Level INFO -Message "ManagedDevice lookup URI: $uri"
  $resp = Invoke-Graph -Method GET -Uri $uri -Headers $Headers
  return $resp
}
