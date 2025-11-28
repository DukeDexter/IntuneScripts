# Define log file path
$LogPath = "C:\ProgramData\BitLockerKeyBackup"
$LogFile = "$LogPath\BitLockerBackup.log"

# Ensure log directory exists
if (!(Test-Path -Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Function to write to log
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$Timestamp [$Level] $Message"
}

# Start logging
Write-Log "Starting BitLocker recovery key backup script."

# Get BitLocker volume info
try {
    $BLV = Get-BitLockerVolume -MountPoint "C:"
    Write-Log "Retrieved BitLocker volume information."
} catch {
    Write-Log "Failed to retrieve BitLocker volume info: $_" -Level "ERROR"
    exit 1
}

# Check and backup recovery key
if ($BLV -and $BLV.KeyProtector) {
    try {
        $KeyProtectorId = $BLV.KeyProtector[1].KeyProtectorId
        BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $KeyProtectorId
        Write-Log "Successfully backed up BitLocker recovery key to Azure AD."
    } catch {
        Write-Log "Failed to back up BitLocker recovery key: $_" -Level "ERROR"
    }
} else {
    Write-Log "BitLocker is not enabled or no KeyProtector found on C: drive." -Level "WARNING"
}

Write-Log "Script execution completed."
