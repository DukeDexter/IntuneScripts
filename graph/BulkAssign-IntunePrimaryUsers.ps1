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
  [string]$GraphEndpoint = "https://graph.microsoft.com"
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

# -------------------- Helper: Invoke Graph with Retry --------------------
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
      if ($_.Exception.Response) {
        $status = [int]$_.Exception.Response.StatusCode
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
      throw "Graph call failed (HTTP $status): $($_.Exception.Message)"
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

# -------------------- Fetch Sign-ins --------------------
$startIso=(Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "Fetching sign-ins since $startIso..." -ForegroundColor Cyan
$signInsUri="$GraphEndpoint/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $startIso and status/errorCode eq 0&`$select=createdDateTime,userId,userPrincipalName,deviceDetail&`$top=1000"
$signIns=Get-GraphPaged -Uri $signInsUri -Headers $headers

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
  Write-Warning "No sign-ins found."
  exit
}

# -------------------- Aggregate --------------------
$assignments=@()
$byDevice=$activity|Group-Object DeviceAadId
foreach($devGroup in $byDevice){
  $userGroups=$devGroup.Group|Group-Object UserId|Sort-Object Count -Descending
  $winner=$userGroups|Select-Object -First 1
  if($winner.Count -lt $MinEventsPerDevice){continue}
  $assignments+=[pscustomobject]@{
    DeviceAadId=$devGroup.Name
    DeviceName=($devGroup.Group|Sort-Object CreatedDateTime -Descending|Select-Object -First 1).DeviceName
    TargetUserId=$winner.Name
    TargetUpn=($winner.Group|Select-Object -First 1).UserPrincipalName
    EventCount=$winner.Count
  }
}

Write-Host "Devices to process: $($assignments.Count)" -ForegroundColor Cyan

# -------------------- Resolve Managed Devices --------------------
function Get-ManagedDeviceByAadId{
  param($AadDeviceId,$Headers,$GraphEndpoint)
  $uri="$GraphEndpoint/v1.0/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$AadDeviceId'&`$select=id,deviceName,userId,userPrincipalName&`$top=1"
  $resp=Invoke-Graph -Method GET -Uri $uri -Headers $Headers
  if($resp.value){return $resp.value[0]}else{return $null}
}

$work=@()
foreach($item in $assignments){
  $md=Get-ManagedDeviceByAadId -AadDeviceId $item.DeviceAadId -Headers $headers -GraphEndpoint $GraphEndpoint
  if(-not $md){
    $work+=[pscustomobject]@{DeviceAadId=$item.DeviceAadId;DeviceName=$item.DeviceName;Action="Skip_NoManagedDevice";Result="No Intune object"}
    continue
  }
  $action=if($md.userId -eq $item.TargetUserId){"Skip_AlreadyPrimary"}else{"Assign_PrimaryUser"}
  $work+=[pscustomobject]@{
    DeviceAadId=$item.DeviceAadId;DeviceName=$md.deviceName;ManagedDeviceId=$md.id
    TargetUserId=$item.TargetUserId;TargetUpn=$item.TargetUpn;Action=$action;Result=""
  }
}

# -------------------- Assign Primary User --------------------
function Assign-PrimaryUser{
  param($ManagedDeviceId,$UserId,$Headers,$GraphEndpoint)
  $uri="$GraphEndpoint/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"
  $body=@{'@odata.id'="$GraphEndpoint/v1.0/users/$UserId"}|ConvertTo-Json
  Invoke-Graph -Method POST -Uri $uri -Headers $Headers -Body $body|Out-Null
}

$results=@()
foreach($row in $work){
  if($row.Action -like "Skip_*"){$row.Result=$row.Action;$results+=$row;continue}
  if($DryRun){$row.Result="DryRun";$results+=$row;continue}
  try{
    Assign-PrimaryUser -ManagedDeviceId $row.ManagedDeviceId -UserId $row.TargetUserId -Headers $headers -GraphEndpoint $GraphEndpoint
    $row.Result="Success"
  }catch{$row.Result="Error: $($_.Exception.Message)"}
  $results+=$row
  Start-Sleep -Milliseconds 200
}

# -------------------- Export --------------------
$ts=(Get-Date).ToString('yyyyMMdd_HHmmss')
$csvPath=Join-Path $OutputDir "PrimaryUserAssignment_$ts.csv"
$results|Export-Csv -NoTypeInformation -Path $csvPath
Write-Host "Completed. Results saved to $csvPath" -ForegroundColor Green
