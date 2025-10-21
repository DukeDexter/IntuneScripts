<#
Bulk assign Intune primary users based on last 30 days of sign-ins using Microsoft Graph REST API.
No Microsoft.Graph module required.
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

function Get-GraphPaged {
  param($Uri,$Headers)
  $items=@()
  $next=$Uri
  while ($next) {
    $resp=Invoke-Graph -Method GET -Uri $next -Headers $Headers
    if ($resp.value) { $items+=$resp.value }
    $next=$resp.'@odata.nextLink'
  }
  return $items
}

# -------------------- Authenticate --------------------
Write-Host "Authenticating..." -ForegroundColor Cyan
$token=Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint $GraphEndpoint
$headers=@{"Authorization"="Bearer $token"}

# -------------------- Fetch Sign-ins (safe filter & encoding) --------------------
# Graph expects DateTimeOffset literals WITHOUT quotes in filters: createdDateTime ge 2025-10-21T09:51:07Z
$startUtc = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$filterRaw = "createdDateTime ge $startUtc"
$filterEnc = [uri]::EscapeDataString($filterRaw)
$selectEnc = [uri]::EscapeDataString("createdDateTime,userId,userPrincipalName,deviceDetail")
$topEnc    = [uri]::EscapeDataString("1000")

$signInsUri="$GraphEndpoint/v1.0/auditLogs/signIns?%24filter=$filterEnc&%24select=$selectEnc&%24top=$topEnc"
Write-Host "Sign-ins URI:`n$signInsUri" -ForegroundColor DarkGray

$signIns=Get-GraphPaged -Uri $signInsUri -Headers $headers

# Filter client-side for successful events (avoid server-side nested filter on status/errorCode)
$signIns = $signIns | Where-Object { $_.status.errorCode -eq 0 -or -not $_.status }

# Normalize rows; keep ones with AAD device GUID
$activity=foreach($e in $signIns){
  $devId=$e.deviceDetail.deviceId
  if([string]::IsNullOrWhiteSpace($devId)){continue}
  if($ExcludeUpnPattern -and $e.userPrincipalName -match $ExcludeUpnPattern){continue}
  [pscustomobject]@{
    CreatedDateTime=[datetime]$e.createdDateTime
    DeviceAadId=$devId
    DeviceName=$e.deviceDetail.displayName
    UserId=$e.userId
    UserPrincipalName=$e.userPrincipalName
  }
}

if(-not $activity){
  $ts=(Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath=Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @()|Export-Csv -NoTypeInformation -Path $csvPath
  Write-Warning "No sign-in rows found. Empty results written to $csvPath"
  exit 0
}

# -------------------- Aggregate --------------------
$assignments=@()
$byDevice=$activity|Group-Object DeviceAadId
foreach($devGroup in $byDevice){
  $userGroups=$devGroup.Group|Group-Object UserId|Sort-Object Count -Descending
  $winner=$userGroups|Select-Object -First 1
  if($winner.Count -lt $MinEventsPerDevice){continue}
  # tie-breaker by latest sign-in
  $ties=$userGroups|Where-Object { $_.Count -eq $winner.Count }
  if($ties.Count -gt 1){
    $winner=$ties|
      Sort-Object @{Expression={($_.Group|Sort-Object CreatedDateTime -Descending|Select-Object -First 1).CreatedDateTime}},Descending|
      Select-Object -First 1
  }
  $assignments+=[pscustomobject]@{
    DeviceAadId=$devGroup.Name
    DeviceName=($devGroup.Group|Sort-Object CreatedDateTime -Descending|Select-Object -First 1).DeviceName
    TargetUserId=$winner.Name
    TargetUpn=($winner.Group|Select-Object -First 1).UserPrincipalName
    EventCount=$winner.Count
  }
}

Write-Host "Devices to process: $($assignments.Count)" -ForegroundColor Cyan
if($assignments.Count -eq 0){
  $ts=(Get-Date).ToString('yyyyMMdd_HHmmss')
  $csvPath=Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
  @()|Export-Csv -NoTypeInformation -Path $csvPath
  Write-Warning "No qualifying users found. Empty results written to $csvPath"
  exit 0
}

# -------------------- Resolve managedDevices --------------------
function Get-ManagedDeviceByAadId{
  param($AadDeviceId,$Headers,$GraphEndpoint)
  $filterEnc = [uri]::EscapeDataString("azureADDeviceId eq '$AadDeviceId'")  # string values need quotes
  $selectEnc = [uri]::EscapeDataString("id,deviceName,userId,userPrincipalName")
  $uri="$GraphEndpoint/v1.0/deviceManagement/managedDevices?%24filter=$filterEnc&%24select=$selectEnc&%24top=1"
  Invoke-Graph -Method GET -Uri $uri -Headers $Headers
}

$work=@()
foreach($item in $assignments){
  $resp=Get-ManagedDeviceByAadId -AadDeviceId $item.DeviceAadId -Headers $headers -GraphEndpoint $GraphEndpoint
  $md=$null
  if($resp.value -and $resp.value.Count -ge 1){ $md=$resp.value[0] }

  if(-not $md){
    $work+=[pscustomobject]@{
      DeviceAadId=$item.DeviceAadId;DeviceName=$item.DeviceName
      ManagedDeviceId=$null;CurrentPrimaryUserId=$null
      TargetUserId=$item.TargetUserId;TargetUpn=$item.TargetUpn
      EventCount=$item.EventCount
      Action="Skip_NoManagedDevice";Result="No Intune object found"
    }
    continue
  }

  $action=if($md.userId -eq $item.TargetUserId){"Skip_AlreadyPrimary"}else{"Assign_PrimaryUser"}
  $work+=[pscustomobject]@{
    DeviceAadId=$item.DeviceAadId;DeviceName=$md.deviceName
    ManagedDeviceId=$md.id
    CurrentPrimaryUserId=$md.userId
    TargetUserId=$item.TargetUserId;TargetUpn=$item.TargetUpn
    EventCount=$item.EventCount
    Action=$action;Result=""
  }
}

# -------------------- Assign Primary User --------------------
function Assign-PrimaryUser{
  param($ManagedDeviceId,$UserId,$Headers,$GraphEndpoint)
  if([string]::IsNullOrWhiteSpace($UserId)){ throw "Target UserId is empty; cannot assign." }
  $uri="$GraphEndpoint/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"
  $body=@{'@odata.id'="$GraphEndpoint/v1.0/users/$UserId"}|ConvertTo-Json
  Invoke-Graph -Method POST -Uri $uri -Headers $Headers -Body $body|Out-Null
}

$results=@()
foreach($row in $work){
  if($row.Action -like "Skip_*"){ $row.Result=$row.Action; $results+=$row; continue }
  if($DryRun){ $row.Result="DryRun_Assign_PrimaryUser"; $results+=$row; continue }
  try{
    Assign-PrimaryUser -ManagedDeviceId $row.ManagedDeviceId -UserId $row.TargetUserId -Headers $headers -GraphEndpoint $GraphEndpoint
    $row.Result="Success_Assigned"
  }catch{
    $row.Result="Error: $($_.Exception.Message)"
  }
  $results+=$row
  Start-Sleep -Milliseconds 200
}

# -------------------- Export --------------------
$ts=(Get-Date).ToString('yyyyMMdd_HHmmss')
$csvPath=Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
$results|Export-Csv -NoTypeInformation -Path $csvPath
Write-Host "Completed. Results saved to $csvPath" -ForegroundColor Green
