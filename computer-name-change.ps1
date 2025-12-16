
<# Requires: Az.Accounts, Microsoft.Graph modules 

Intune’s setDeviceName remote action changes the OS computer name for Entra‑joined Windows devices (not Hybrid). Bulk UI supports simple variables, but for custom composites you compute and pass the final string via Graph.

Naming rule: LOC-EMPID-MODEL

- LOC: first 3 letters derived from OU path in onPremisesDistinguishedName
- EMPID: employeeId (no spaces)
- MODEL: Win32 model (sanitized, e.g., Latitude5490)

Sanitization: Only letters/digits and - Trim to ≤15 chars (Windows NetBIOS), ensure uniqueness if your policy requires.

#>
param(
    [string]$ManagedDeviceId # Intune managedDevice id
)

# 1) Connect to Graph as App
# In Automation, use Managed Identity or App Reg; here App Reg example:
$tenantId = Get-AutomationVariable -Name 'TenantId'
$appId    = Get-AutomationVariable -Name 'AppId'
$appSecret= Get-AutomationVariable -Name 'AppSecret'

Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.DeviceManagement
Import-Module Microsoft.Graph.DeviceManagement.Actions
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.DirectoryManagement

$secureSecret = ConvertTo-SecureString $appSecret -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($appId, $secureSecret)

Connect-MgGraph -TenantId $tenantId `
    -ClientId $appId `
    -ClientSecret $appSecret `
    -Scopes @(
        'DeviceManagementManagedDevices.ReadWrite.All',
        'DeviceManagementManagedDevices.Read.All',
        'User.Read.All',
        'Directory.Read.All'
    )

# 2) Get Intune managed device (model + userId + azureAdDeviceId)
$md = Get-MgDeviceManagementManagedDevice -DeviceManagementManagedDeviceId $ManagedDeviceId
if (-not $md) { throw "Managed device not found: $ManagedDeviceId" }

$azureDeviceId = $md.AzureAdDeviceId
$model         = ($md.Model) -replace '[^A-Za-z0-9]', ''  # sanitize

# 3) Read AAD device to get on-prem DN (if synced)
$aadDev = Get-MgDevice -DeviceId $azureDeviceId -Property "id,onPremisesDistinguishedName" -ConsistencyLevel eventual
$dn = $aadDev.onPremisesDistinguishedName

# Parse LOC from DN (example OU path: OU=NYC,OU=Workstations,DC=contoso,DC=com)
function Get-LocFromDN([string]$dn) {
    if ([string]::IsNullOrWhiteSpace($dn)) { return "UNK" }
    $m = [regex]::Match($dn, "OU=([A-Za-z0-9_-]{3,})", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) {
        $loc = $m.Groups[1].Value.Substring(0,3).ToUpper()
        return $loc
    }
    return "UNK"
}
$loc = Get-LocFromDN $dn

# 4) Resolve primary user → employeeId
$empId = "000000"
if ($md.UserId) {
    $u = Get-MgUser -UserId $md.UserId -Property "id,employeeId"
    if ($u.employeeId) { $empId = ($u.employeeId -replace '\s','') }
}

# 5) Compose final name; enforce max length 15
$proposed = "{0}-{1}-{2}" -f $loc, $empId, $model
# Ensure <= 15 chars; you may prefer a different truncation strategy
if ($proposed.Length -gt 15) { $proposed = $proposed.Substring(0,15) }

# 6) Call Intune remote action: set OS computer name
Update-MgDeviceManagementManagedDevice -DeviceManagementManagedDeviceId $ManagedDeviceId -DeviceName $proposed

Write-Output "Renamed to: $proposed"
``
