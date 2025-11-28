
# Dell System Validation Script for PCR7, TPM, Secure Boot, and UEFI

# Check PCR7 Binding Status
Write-Host "Checking PCR7 Binding Status..."
$pcr7 = (Get-CimInstance -ClassName Win32_ComputerSystem).PCR7Configuration
Write-Host "PCR7 Configuration: $pcr7"

# Check TPM Status
Write-Host "
Checking TPM Status..."
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
if ($tpm) {
    Write-Host "TPM Manufacturer ID: $($tpm.ManufacturerID)"
    Write-Host "TPM Version: $($tpm.SpecVersion)"
    Write-Host "TPM Is Enabled: $($tpm.IsEnabled)"
    Write-Host "TPM Is Activated: $($tpm.IsActivated)"
    Write-Host "TPM Is Owned: $($tpm.IsOwned)"
} else {
    Write-Host "TPM not found or not supported."
    $tpmAlt = Get-Tpm
    if ($tpmAlt) {
        Write-Host "TPM Manufacturer ID: $($tpmAlt.ManufacturerId)"
        Write-Host "TPM Version: $($tpmAlt.TpmVersion)"
        Write-Host "TPM Ready: $($tpmAlt.TpmReady)"
    }
}

# Check Secure Boot Status
Write-Host "
Checking Secure Boot Status..."
$secureBoot = Confirm-SecureBootUEFI
if ($secureBoot) {
    Write-Host "Secure Boot is enabled."
} else {
    Write-Host "Secure Boot is disabled or not supported."
}

# Check BIOS Mode (UEFI vs Legacy)
Write-Host "
Checking BIOS Mode..."
$firmwareType = (Get-CimInstance -ClassName Win32_ComputerSystem).BootMode
Write-Host "Boot Mode: $firmwareType"

# Check Disk Partition Style
Write-Host "
Checking Disk Partition Style..."
$disk = Get-Disk | Where-Object IsSystem -eq $true
foreach ($d in $disk) {
    Write-Host "Disk Number: $($d.Number) - Partition Style: $($d.PartitionStyle)"
}

# Check for Modern Standby Support
Write-Host "
Checking Power States..."
powercfg /a

# Check BitLocker Status
Write-Host "
Checking BitLocker Status..."
manage-bde -status C:

# Check Device Encryption Support
Write-Host "
Checking Device Encryption Support..."
Get-WmiObject -Namespace root\CIMV2\Security\MicrosoftVolumeEncryption -Class Win32_EncryptableVolume | ForEach-Object {
    Write-Host "Drive: $(# Dell System Validation Script for PCR7, TPM, Secure Boot, and UEFI

# Check PCR7 Binding Status
Write-Host "Checking PCR7 Binding Status..."
$pcr7 = (Get-CimInstance -ClassName Win32_ComputerSystem).PCR7Configuration
Write-Host "PCR7 Configuration: $pcr7"
# Check TPM Status
Write-Host "
Checking TPM Status..."
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
if ($tpm) {
    Write-Host "TPM Manufacturer ID: $($tpm.ManufacturerID)"
    Write-Host "TPM Version: $($tpm.SpecVersion)"
    Write-Host "TPM Is Enabled: $($tpm.IsEnabled)"
    Write-Host "TPM Is Activated: $($tpm.IsActivated)"
    Write-Host "TPM Is Owned: $($tpm.IsOwned)"
} else {
    Write-Host "TPM not found or not supported."
}
# Check Secure Boot Status
Write-Host "
Checking Secure Boot Status..."
$secureBoot = Confirm-SecureBootUEFI
if ($secureBoot) {
    Write-Host "Secure Boot is enabled."
} else {
    Write-Host "Secure Boot is disabled or not supported."
}
# Check BIOS Mode (UEFI vs Legacy)
Write-Host "
Checking BIOS Mode..."
$firmwareType = (Get-CimInstance -ClassName Win32_ComputerSystem).BootMode
Write-Host "Boot Mode: $firmwareType"
# Check Disk Partition Style
Write-Host "
Checking Disk Partition Style..."
$disk = Get-Disk | Where-Object IsSystem -eq $true
foreach ($d in $disk) {
    Write-Host "Disk Number: $($d.Number) - Partition Style: $($d.PartitionStyle)"
}
# Check for Modern Standby Support
Write-Host "
Checking Power States..."
powercfg /a
# Check BitLocker Status
Write-Host "
Checking BitLocker Status..."
manage-bde -status C:
Write-Host "
Validation Complete."
.DriveLetter) - Encryption Status: $(# Dell System Validation Script for PCR7, TPM, Secure Boot, and UEFI
# Check PCR7 Binding Status
Write-Host "Checking PCR7 Binding Status..."
$pcr7 = (Get-CimInstance -ClassName Win32_ComputerSystem).PCR7Configuration
Write-Host "PCR7 Configuration: $pcr7"
# Check TPM Status
Write-Host "
Checking TPM Status..."
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
if ($tpm) {
    Write-Host "TPM Manufacturer ID: $($tpm.ManufacturerID)"
    Write-Host "TPM Version: $($tpm.SpecVersion)"
    Write-Host "TPM Is Enabled: $($tpm.IsEnabled)"
    Write-Host "TPM Is Activated: $($tpm.IsActivated)"
    Write-Host "TPM Is Owned: $($tpm.IsOwned)"
} else {
    Write-Host "TPM not found or not supported."
}
# Check Secure Boot Status
Write-Host "
Checking Secure Boot Status..."
$secureBoot = Confirm-SecureBootUEFI
if ($secureBoot) {
    Write-Host "Secure Boot is enabled."
} else {
    Write-Host "Secure Boot is disabled or not supported."
}
# Check BIOS Mode (UEFI vs Legacy)
Write-Host "
Checking BIOS Mode..."
$firmwareType = (Get-CimInstance -ClassName Win32_ComputerSystem).BootMode
Write-Host "Boot Mode: $firmwareType"
# Check Disk Partition Style
Write-Host "
Checking Disk Partition Style..."
$disk = Get-Disk | Where-Object IsSystem -eq $true
foreach ($d in $disk) {
    Write-Host "Disk Number: $($d.Number) - Partition Style: $($d.PartitionStyle)"
}
# Check for Modern Standby Support
Write-Host "
Checking Power States..."
powercfg /a
# Check BitLocker Status
Write-Host "
Checking BitLocker Status..."
manage-bde -status C:
Write-Host "
Validation Complete."
.ProtectionStatus)"
}

# Optional: Export results to log file
# Start-Transcript -Path "DellSystemValidationLog.txt" -Append
# [Insert all checks here]
# Stop-Transcript

Write-Host "
Validation Complete."
