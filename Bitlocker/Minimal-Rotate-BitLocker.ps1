<#

Prerequisites
Your devices must meet BitLocker rotation requirements:


Windows 10 1909+ or Windows 11
Intune BitLocker policy configured with:
Client-driven recovery password rotation = Enabled
Save BitLocker recovery info to Microsoft Entra ID = Enabled
Store recovery info in Entra ID before enabling BitLocker = Required

Device must be:

Entra Joined OR
Hybrid Joined
(Required for AAD escrow to work)

Steps to upload:

Devices → Windows → PowerShell Scripts → Add
Upload this script. 
Run this script using logged‑on credentials → No
(Runs in SYSTEM context, required for BitLocker changes)
Enforce script signature check → No
Run script in 64‑bit PowerShell → Yes
(BitLocker cmdlets require 64‑bit)

Assign the script to:

A device group (recommended), or
All Windows 10/11 devices

Intune will:

Download the script via Intune Management Extension
Execute it silently as SYSTEM
Report results back in the script status

#>

$drive='C:'; 
$null=Add-BitLockerKeyProtector -MountPoint $drive -RecoveryPasswordProtector; 
$vol=Get-BitLockerVolume -MountPoint $drive; 
$newId=$vol.KeyProtector[-1].KeyProtectorId; 
$vol.KeyProtector | ? {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -ne $newId} | % { Remove-BitLockerKeyProtector -MountPoint $drive -KeyProtectorId $_.KeyProtectorId }; 
BackupToAAD-BitLockerKeyProtector -MountPoint $drive -KeyProtectorId $newId
