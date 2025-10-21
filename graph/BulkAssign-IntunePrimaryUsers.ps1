<#
.SYNOPSIS
  Bulk assign Intune primary users based on last 30 days sign-in activity using Microsoft Graph (App Authentication).

.NOTES
  Required Application Permissions:
    - AuditLog.Read.All
    - DeviceManagementManagedDevices.ReadWrite.All
    - Directory.Read.All (optional for user lookups)
#>

param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [int]$LookbackDays = 30,
  [int]$MinEventsPerDevice = 2,
  [switch]$DryRun
)

# Install required module if missing
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# Create PSCredential for app authentication
$secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)

# Connect using app-only authentication
Write-Host "Connecting to Microsoft Graph using app credentials..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential
Write-Host "Connected successfully." -ForegroundColor Green

# Fetch sign-in logs for last 30 days
$startDate = (Get-Date).AddDays(-$LookbackDays).ToString("o")
Write-Host "Fetching sign-in logs since $startDate..." -ForegroundColor Cyan

$signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate and status/errorCode eq 0" -All `
    -Property @('createdDateTime','userId','userPrincipalName','deviceDetail/deviceId','deviceDetail/displayName')

# Aggregate activity
$activity = $signIns | Where-Object { $_.DeviceDetail.DeviceId } | ForEach-Object {
    [pscustomobject]@{
        DeviceAadId       = $_.DeviceDetail.DeviceId
        DeviceName        = $_.DeviceDetail.DisplayName
        UserId            = $_.UserId
        UserPrincipalName = $_.UserPrincipalName
        CreatedDateTime   = $_.CreatedDateTime
    }
}

$deviceGroups = $activity | Group-Object DeviceAadId
$assignments = @()

foreach ($group in $deviceGroups) {
    $deviceId = $group.Name
    $userGroups = $group.Group | Group-Object UserId | Sort-Object Count -Descending
    $topUser = $userGroups | Select-Object -First 1
    if ($topUser.Count -ge $MinEventsPerDevice) {
        $assignments += [pscustomobject]@{
            DeviceAadId = $deviceId
            DeviceName  = ($group.Group | Select-Object -First 1).DeviceName
            TargetUserId = $topUser.Name
            TargetUpn    = ($topUser.Group | Select-Object -First 1).UserPrincipalName
            EventCount   = $topUser.Count
        }
    }
}

Write-Host "Found $($assignments.Count) devices with qualifying primary users." -ForegroundColor Cyan

# Assign primary user in Intune
$results = @()
foreach ($item in $assignments) {
    $managedDevice = Get-MgDeviceManagementManagedDevice -Filter "azureADDeviceId eq '$($item.DeviceAadId)'" -Top 1
    if (-not $managedDevice) {
        $item | Add-Member -NotePropertyName Result -NotePropertyValue "NoManagedDevice"
        $results += $item
        continue
    }

    if ($DryRun) {
        $item | Add-Member -NotePropertyName Result -NotePropertyValue "DryRun"
        $results += $item
        continue
    }

    try {
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$($managedDevice.Id)')/users/`$ref"
        $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($item.TargetUserId)" } | ConvertTo-Json
        Invoke-MgGraphRequest -Uri $uri -Method POST -Body $body -ContentType 'application/json'
        $item | Add-Member -NotePropertyName Result -NotePropertyValue "Success"
    } catch {
        $item | Add-Member -NotePropertyName Result -NotePropertyValue "Error: $($_.Exception.Message)"
    }
    $results += $item
}

# Export results
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$results | Export-Csv -NoTypeInformation -Path ".\PrimaryUserAssignment_$timestamp.csv"
Write-Host "Completed. Results saved to PrimaryUserAssignment_$timestamp.csv" -ForegroundColor Green
