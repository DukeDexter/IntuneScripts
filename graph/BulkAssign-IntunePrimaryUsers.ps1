<#
.SYNOPSIS
  Bulk-assign Intune primary users based on last 30 days of user sign-ins using Microsoft Graph (client credentials).
  No Microsoft.Graph modules required—avoids session function overflow.

.PARAMETERS
  -TenantId           : Entra tenant (GUID or domain, e.g., contoso.com)
  -ClientId qualify (default: 2)
  -ExcludeUpnPattern  : Regex to exclude service/bot accounts (e.g., '^(svc-|system_)')
  -DryRun             : Preview assignments without committing
  -OutputDir          : Folder to write CSV results (default: current dir)
  -GraphEndpoint      : Graph base URL (default: https://graph.microsoft.com)
                         # For 21Vianet tenants, use: https://microsoftgraph.chinacloudapi.cn

.REQUIREMENTS (Application permissions, with admin consent)
  - AuditLog.Read.All
  - DeviceManagementManagedDevices.ReadWrite.All
  - Directory.Read.All (optional; not strictly required if you use userId from sign-ins)
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

# ------------------------------ Helpers --------------------------------------

function Get-GraphToken {
  param([string]$TenantId,[string]$ClientId,[string]$ClientSecret,[string]$GraphEndpoint)

  $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  if ($GraphEndpoint -like "https://microsoftgraph.chinacloudapi.cn") {
    $tokenUri = "https://login.partner.microsoftonline.cn/$TenantId/oauth2/v2.0/token"
  }

  $body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
    scope         = "$GraphEndpoint/.default"
  }

  try {
    $resp = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    return $resp.access_token
  } catch {
    throw "Failed to obtain token: $($_.Exception.Message)"
  }
}

function Invoke-Graph {
  param(
    [string]$Method, [string]$Uri, [hashtable]$Headers, [object]$Body = $null,
    [int]$MaxRetries = 6
  )

  $attempt = 0
  while ($true) {
    try {
      if ($Method -eq "GET") {
        return Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -ErrorAction Stop
      } elseif ($Method -eq "POST") {
        return Invoke-RestMethod -Method POST           : App registration (Application ID)
  -ClientSecret       : App client secret (secure storage recommended)
  -LookbackDays       : Window in days (default: 30)
  -MinEventsPerDevice : Minimum successful sign-ins by a user to
