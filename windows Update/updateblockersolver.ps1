# Define log path
$LogPath = "C:\ProgramData\Win11UpgradeCheck"
$LogFile = "$LogPath\UpgradeRemediation.log"
if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force }

Function Write-Log {
    param ([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
}

Write-Log "Starting Windows 11 24H2 upgrade detection and remediation..."

# Detection: Check OS version
$OSVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
$BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
Write-Log "Current OS ReleaseId: $OSVersion, Build: $BuildNumber"

# Check if already on 24H2 (build 26100 or higher)
if ($BuildNumber -ge 26100) {
    Write-Log "Device is already on Windows 11 24H2 or higher."
    exit 0
}

# Remediation: Remove rollback block if present
$RollbackKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade\Rollback"
if (Test-Path $RollbackKey) {
    try {
        Remove-Item -Path $RollbackKey -Recurse -Force
        Write-Log "Rollback registry key removed."
    } catch {
        Write-Log "Failed to remove rollback key: $_"
    }
} else {
    Write-Log "No rollback block detected."
}

# Remediation: Set AllowInplaceUpgrade registry key
$UpgradeKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
try {
    New-ItemProperty -Path $UpgradeKey -Name "AllowInplaceUpgrade" -Value 4 -PropertyType DWORD -Force | Out-Null
    Write-Log "AllowInplaceUpgrade registry key set to 4."
} catch {
    Write-Log "Failed to set AllowInplaceUpgrade key: $_"
}

# Remediation: Clear safeguard holds
$HoldKeys = @(
    "HKLM:\SYSTEM\Setup\MoSetup",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\UpgradeExperienceIndicators",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators"
)

foreach ($key in $HoldKeys) {
    if (Test-Path $key) {
        try {
            Remove-Item -Path $key -Recurse -Force
            Write-Log "Safeguard hold key removed: $key"
        } catch {
            Write-Log "Failed to remove safeguard key $key: $_"
        }
    } else {
        Write-Log "Safeguard key not found: $key"
    }
}

Write-Log "Remediation completed. Device should be eligible for upgrade within 48 hours."

exit 0
