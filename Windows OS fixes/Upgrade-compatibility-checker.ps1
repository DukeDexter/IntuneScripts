# Set log file path
$LogFile = "C:\Temp\Win11Readiness_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$timestamp`t$Message"
}

Write-Log "Starting Windows 11 Readiness Check on $env:COMPUTERNAME"

# Initialize result object
$Result = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    TPM_Ready    = $null
    CPU          = $null
    SecureBoot   = $null
    RAM_GB       = $null
    OS_Version   = $null
    Errors       = @()
}

# TPM Check
try {
    $TPM = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
    $Result.TPM_Ready = ($TPM.SpecVersion -ge "2.0")
    Write-Log "TPM SpecVersion: $($TPM.SpecVersion)"
} catch {
    $Result.TPM_Ready = $false
    $Result.Errors += "TPM check failed: $_"
    Write-Log "ERROR: TPM check failed: $_"
}

# CPU Check
try {
    $CPU = Get-WmiObject Win32_Processor | Select-Object -ExpandProperty Name
    $Result.CPU = $CPU
    Write-Log "CPU: $CPU"
} catch {
    $Result.Errors += "CPU check failed: $_"
    Write-Log "ERROR: CPU check failed: $_"
}

# Secure Boot Check
try {
    $SecureBoot = Confirm-SecureBootUEFI
    $Result.SecureBoot = $SecureBoot
    Write-Log "Secure Boot: $SecureBoot"
} catch {
    $Result.SecureBoot = $false
    $Result.Errors += "Secure Boot check failed: $_"
    Write-Log "ERROR: Secure Boot check failed: $_"
}

# RAM Check
try {
    $RAM = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    $Result.RAM_GB = [math]::Round($RAM,2)
    Write-Log "RAM (GB): $($Result.RAM_GB)"
} catch {
    $Result.Errors += "RAM check failed: $_"
    Write-Log "ERROR: RAM check failed: $_"
}

# OS Version Check
try {
    $OS = (Get-WmiObject Win32_OperatingSystem).Version
    $Result.OS_Version = $OS
    Write-Log "OS Version: $OS"
} catch {
    $Result.Errors += "OS Version check failed: $_"
    Write-Log "ERROR: OS Version check failed: $_"
}

# Output results to log and screen
Write-Log "Final Result: $($Result | ConvertTo-Json -Compress)"
$Result

Write-Log "Windows 11 Readiness Check completed."
