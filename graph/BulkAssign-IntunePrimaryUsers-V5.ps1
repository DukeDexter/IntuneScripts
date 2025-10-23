
<#
PrimaryUserV4.ps1
Bulk assign Intune primary users based on sign-in activity.
Compatible with PowerShell 5.1 and 7+. Includes token refresh, paging, fallback, batching, parallel, logging, checkpoint resume.
#>

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

# Ensure TLS 1.2
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# Logging
function Write-Log {
  param([string]$Level, [string]$Message)
  $line = "$(Get-Date -Format o) [$Level] $Message"
  Add-Content -Path $LogPath -Value $line
}

# Checkpoint
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

function Save-Checkpoint {
  param([string]$Path, [array]$ManagedDeviceIds)
  try {
    $tmp = "$Path.tmp"
    $ManagedDeviceIds | ConvertTo-Json -Depth 3 | Set-Content -Path $tmp
    Move-Item -Path $tmp -Destination $Path -Force
    Write-Log "INFO" "Checkpoint saved ($($ManagedDeviceIds.Count)) -> $Path"
  } catch {
    Write-Log "WARN" "Failed to save checkpoint: $($_.Exception.Message)"
  }
}

# Token
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

# Graph call
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
      $status = $null; $retryAfter = 0; $respBody = $null
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
      if ($status -eq 401 -and ($respBody -match 'InvalidAuthenticationToken' -or $respBody -match 'token is expired')) {
        Write-Log "WARN" "401 Unauthorized. Refreshing token..."
        $newTok = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
        $Headers["Authorization"] = "Bearer $newTok"
        $attempt--
        continue
      }
      if ($attempt -le $MaxRetries -and ($status -in 429,500,503,504)) {
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

# Paging
function Get-GraphPaged {
  param($Uri,[hashtable]$Headers,[int]$MaxPages,[string]$ActivityName)
  $items = @(); $next = $Uri; $page = 0
  while ($next -and $page -lt $MaxPages) {
    $page++
    Write-Progress -Id 1 -Activity $ActivityName -Status "Page $page of $MaxPages" -PercentComplete ([Math]::Min(100, ($page/$MaxPages)*100))
    Write-Log "INFO" "$ActivityName - requesting page $page"
    try {
      $resp = Invoke-Graph -Method GET -Uri $next -Headers $Headers
    } catch {
      if ($_.Exception.Message -match 'Skip token is null|skiptoken') {
        Write-Log "WARN" "$ActivityName - paging halted due to skiptoken error at page $page."
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
  Write-Log "INFO" "$ActivityName - collected $($items.Count) records across $page page(s)."
  return $items
}

# Device lookup
function Get-ManagedDeviceByAadId {
  param([string]$AadDeviceId,[hashtable]$Headers,[string]$GraphEndpoint)
  $id = $AadDeviceId -replace '[\{\}"'']',''
  $id = $id.Trim()
  if ($id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Log "WARN" "Invalid azureADDeviceId format: '$AadDeviceId' -> '$id'. Skipping."
    return @{ value = @() }
  }
  $filterRaw = "azureADDeviceId eq '$id'"
  $filterEnc = [uri]::EscapeDataString($filterRaw)
  $uri = "$GraphEndpoint/v1.0/deviceManagement/managedDevices?%24filter=$filterEnc"
  Write-Log "INFO" "ManagedDevice lookup URI: $uri"
  $resp = Invoke-Graph -Method GET -Uri $uri -Headers $Headers
  return $resp
}
