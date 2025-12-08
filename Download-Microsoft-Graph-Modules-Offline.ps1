
<# 
.SYNOPSIS
    Downloads Microsoft Graph PowerShell modules (meta + optional Intune submodules)
    and prerequisites (PackageManagement, PowerShellGet) to a folder and zips them
    for offline installation.

.PARAMETERS
    -OutputRoot        Folder to store modules and the final ZIP (default C:\Temp\GraphOffline)
    -IncludeIntune     Also include Microsoft.Graph.DeviceManagement* submodules (default: $true)
    -GraphVersion      Optional specific version of Microsoft.Graph (e.g. 2.16.0)
    -PrereqVersion     Optional specific version for prereqs (rare; typically not needed)
#>

param(
    [string] $OutputRoot    = "C:\Temp\GraphOffline",
    [bool]   $IncludeIntune = $true,
    [string] $GraphVersion  = "",
    [string] $PrereqVersion = ""
)

Write-Host "== Microsoft Graph Offline Package Builder ==" -ForegroundColor Cyan

# Ensure TLS 1.2 for reliable downloads
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# Create working folders
$stagePath = Join-Path $OutputRoot "modules"
$zipPath   = Join-Path $OutputRoot "MicrosoftGraph_OfflineModules.zip"
New-Item -ItemType Directory -Path $stagePath -Force | Out-Null

function Save-ModuleSafe {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string] $Path,
        [string] $RequiredVersion = ""
    )
    $params = @{ Name = $Name; Path = $Path; Force = $true }
    if ($RequiredVersion) { $params.RequiredVersion = $RequiredVersion }
    Write-Host ("Downloading module: {0} {1}" -f $Name, ($RequiredVersion ? "($RequiredVersion)" : "")) -ForegroundColor Yellow
    Save-Module @params
}

# 1) Prerequisites
try {
    if ($PrereqVersion) {
        Save-ModuleSafe -Name PackageManagement -Path $stagePath -RequiredVersion $PrereqVersion
        Save-ModuleSafe -Name PowerShellGet     -Path $stagePath -RequiredVersion $PrereqVersion
    } else {
        Save-ModuleSafe -Name PackageManagement -Path $stagePath
        Save-ModuleSafe -Name PowerShellGet     -Path $stagePath
    }
} catch {
    Write-Warning "Failed to download prerequisites: $($_.Exception.Message)"
    Write-Warning "Ensure this machine can reach PowerShell Gallery and try again."
    throw
}

# 2) Microsoft.Graph (meta module)
try {
    if ($GraphVersion) {
        Save-ModuleSafe -Name Microsoft.Graph -Path $stagePath -RequiredVersion $GraphVersion
    } else {
        Save-ModuleSafe -Name Microsoft.Graph -Path $stagePath
    }
} catch {
    Write-Warning "Failed to download Microsoft.Graph: $($_.Exception.Message)"
    throw
}

# 3) Optional: Intune/DeviceManagement submodules (smaller footprint for scenarios that only need Intune)
if ($IncludeIntune) {
    try {
        Save-ModuleSafe -Name Microsoft.Graph.DeviceManagement                -Path $stagePath
        Save-ModuleSafe -Name Microsoft.Graph.DeviceManagement.Administration -Path $stagePath
    } catch {
        Write-Warning "Failed to download Intune submodules: $($_.Exception.Message)"
        # Not fatal—meta module already includes broad coverage
    }
}

# 4) Unblock files (avoid zone identifier issues on target)
Get-ChildItem -Path $stagePath -Recurse -File | Unblock-File

# 5) Zip everything
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Write-Host ("Creating ZIP: {0}" -f $zipPath) -ForegroundColor Green
Compress-Archive -Path (Join-Path $stagePath "*") -DestinationPath $zipPath

# 6) Summary
Write-Host "`n== Done ==" -ForegroundColor Cyan
Write-Host ("Modules saved to: {0}" -f $stagePath)
Write-Host ("ZIP file:        {0}" -f $zipPath)

# 7) Print offline install instructions
$instructions = @"
Offline install steps:

1) Copy the ZIP to the offline machine and extract it (e.g., C:\GraphOffline\modules).

2) Copy each module folder to the correct PowerShell module path:

   Windows PowerShell 5.1 (All Users):
     C:\Program Files\WindowsPowerShell\Modules\

   Windows PowerShell 5.1 (Current User):
     %UserProfile%\Documents\WindowsPowerShell\Modules\

   PowerShell 7 (All Users):
     C:\Program Files\PowerShell\7\Modules\

   PowerShell 7 (Current User):
     %UserProfile%\Documents\PowerShell\Modules\

   Final structure must be:
     Modules\<ModuleName>\<Version>\*.psd1 / *.psm1

3) Verify modules are visible:
   Get-Module -ListAvailable Microsoft.Graph* | Format-Table Name,Version,ModuleBase

4) Use the modules:
   Import-Module Microsoft.Graph
   Select-MgProfile -Name v1.0
   Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All"

5) (Optional) Intune cmdlets quick test:
   Import-Module Microsoft.Graph.DeviceManagement
     Get-MgDeviceManagementManagedDevice -Top 1
"@
