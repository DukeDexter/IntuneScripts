# BulkAssign-IntunePrimaryUsers.ps1
# Auto-generated script with default parameters and corrected Get-ManagedDeviceByAadId function

param(
  [string]$TenantId = "yourtenant.onmicrosoft.com",
  [string]$ClientId = "11111111-2222-3333-4444-555555555555",
  [string]$ClientSecret = "your-client-secret",
  [int]$LookbackDays = 30,
  [int]$MinEventsPerDevice = 3,
  [int]$BatchSize = 50,
  [int]$MaxPages = 100,
  [switch]$DryRun = $True
  [switch]$UseParallel = $True
  [int]$ThrottleLimit = 8,
  [string]$LogPath = "C:\Intune\PrimaryUser\bulkassign.log",
  [string]$OutputDir = "C:\Intune\PrimaryUser",
  [string]$CheckpointPath = "C:\Intune\PrimaryUser\checkpoint.json",
  [switch]$Resume = $False
  [string]$GraphEndpoint = "https://graph.microsoft.com"
)


# ... [Other functions and logic would go here, including token handling, paging, assignment, logging, etc.] ...

# Corrected Get-ManagedDeviceByAadId function

function Get-ManagedDeviceByAadId {
  param(
    [string]$AadDeviceId,
    [hashtable]$Headers,
    [string]$GraphEndpoint
  )

  # Normalize the device ID: remove braces, quotes, and whitespace
  $id = $AadDeviceId -replace '[\{\}"\'']',''
  $id = $id.Trim()

  # Validate GUID format
  if ($id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Log -Level WARN -Message "Invalid azureADDeviceId format after normalization: '$AadDeviceId' -> '$id'. Skipping lookup."
    return @{ value = @() }
  }

  # Build and encode the filter
  $filterRaw = "azureADDeviceId eq '$id'"
  $filterEnc = [uri]::EscapeDataString($filterRaw)
  $uri = "$GraphEndpoint/v1.0/deviceManagement/managedDevices?%24filter=$filterEnc"

  Write-Log -Level INFO -Message "ManagedDevice lookup URI: $uri"

  # Call Graph API
  $resp = Invoke-Graph -Method GET -Uri $uri -Headers $Headers
  return $resp
}


# ... [Rest of the script continues here] ...
