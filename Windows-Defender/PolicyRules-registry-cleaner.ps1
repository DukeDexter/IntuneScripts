<#
.SYNOPSIS
script to Detect / Remediate / Report the 'PolicyRules' REG_SZ value under:
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager

.DESCRIPTION
- Detect: exit 1 if 'PolicyRules' exists, else 0
- Remediate: remove 'PolicyRules' if present; exit 0 when absent after run, else 1
- Report: emit a JSON object showing presence/value; exit 0

.NOTES
- Run as SYSTEM (Intune) or Administrator (manual)
- Use 64-bit PowerShell (Intune “Run scripts in 64-bit PowerShell: Yes”)
- If the policy is deployed by GPO/Intune, it may reappear after sync. Fix at the source policy.

.PARAMETER Mode
Detect | Remediate | Report (default: Remediate)

.PARAMETER VerboseLogging
Writes detailed logs to %ProgramData%\Intune\Logs\PolicyRules-AIO.log

#>

# Script Start

[CmdletBinding()]
param(
    [ValidateSet('Detect','Remediate','Report')]
    [string]$Mode = 'Remediate',

    [switch]$VerboseLogging
)

# -------------------- Config --------------------
$RegPath   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
$ValueName = 'PolicyRules'
$RegProviderPath = "Registry::$RegPath"

$LogRoot  = Join-Path $env:ProgramData 'Intune\Logs'
$LogFile  = Join-Path $LogRoot 'PolicyRules-AIO.log'

# -------------------- Helpers --------------------
function Write-Log {
    param([string]$Message)
    try {
        if ($VerboseLogging) {
            if (-not (Test-Path -Path $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null }
            Add-Content -Path $LogFile -Value ("[{0}] {1}" -f (Get-Date -Format s), $Message)
        }
        # Always mirror to standard output to aid Intune diagnostics
        Write-Output $Message
    } catch {
        # Swallow logging errors; do not impact outcome
    }
}

function Ensure-64Bit {
    # Intune can run 32-bit PowerShell if not configured; prefer 64-bit for HKLM policy hives
    try {
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            $sysNative = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
            if (Test-Path $sysNative) {
                Write-Log "Re-launching in 64-bit PowerShell for proper HKLM hive access..."
                $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"","-Mode",$Mode)
                if ($VerboseLogging) { $args += '-VerboseLogging' }
                $proc = Start-Process -FilePath $sysNative -ArgumentList $args -Wait -PassThru
                exit $proc.ExitCode
            }
        }
    } catch {
        Write-Log "Ensure-64Bit error: $($_.Exception.Message)"
    }
}
Ensure-64Bit

function Get-PolicyRulesState {
    # Returns a PSCustomObject with presence, type, and value preview (if any)
    $present = $false
    $type    = $null
    $value   = $null

    if (-not (Test-Path -Path $RegProviderPath)) {
        return [pscustomobject]@{
            KeyExists = $false
            Present   = $false
            Type      = $null
            Value     = $null
        }
    }

    try {
        $item = Get-Item -Path $RegProviderPath -ErrorAction Stop
        $props = Get-ItemProperty -Path $RegProviderPath -ErrorAction Stop

        $present = $props.PSObject.Properties.Name -contains $ValueName

        if ($present) {
            # Determine value/type robustly
            $prop = ($item.Property | Where-Object { $_ -eq $ValueName })
            # Read via reg.exe to capture exact type (REG_SZ, REG_DWORD, etc.) without ambiguity
            $type = $null
            try {
                $q = & reg.exe query "$RegPath" /v "$ValueName" 2>$null
                # Parse '    PolicyRules    REG_SZ    some value'
                $line = ($q | Select-String -Pattern "^\s*$ValueName\s+REG_").Line
                if ($line) {
                    $parts = $line -split '\s{2,}'
                    if ($parts.Length -ge 3) {
                        $type  = $parts[1].Trim()
                        $value = ($parts[2..($parts.Length-1)] -join ' ').Trim()
                    }
                } else {
                    # Fallback PowerShell provider (may not expose type exactly)
                    $type  = 'Unknown'
                    $value = (Get-ItemPropertyValue -Path $RegProviderPath -Name $ValueName -ErrorAction Stop)
                }
            } catch {
                $type  = 'Unknown'
                $value = (Get-ItemPropertyValue -Path $RegProviderPath -Name $ValueName -ErrorAction SilentlyContinue)
            }
        }

        return [pscustomobject]@{
            KeyExists = $true
            Present   = $present
            Type      = $type
            Value     = $value
        }
    } catch {
        Write-Log "State query error: $($_.Exception.Message)"
        return [pscustomobject]@{
            KeyExists = $true
            Present   = $false
            Type      = $null
            Value     = $null
        }
    }
}

function Remove-PolicyRules {
    param([switch]$StrictTypeCheck) # if set, only remove when type is REG_SZ
    try {
        $state = Get-PolicyRulesState
        if (-not $state.KeyExists) {
            Write-Log "Registry key not found: $RegPath"
            return $true  # nothing to do, consider success
        }

        if (-not $state.Present) {
            Write-Log "PolicyRules not present; nothing to remove."
            return $true
        }

        if ($StrictTypeCheck -and $state.Type -ne 'REG_SZ') {
            Write-Log "PolicyRules present but type '$($state.Type)' != 'REG_SZ'. Skipping removal due to StrictTypeCheck."
            return $false
        }

        Write-Log "Found PolicyRules ($($state.Type)): '$($state.Value)'. Attempting removal..."
        Remove-ItemProperty -Path $RegProviderPath -Name $ValueName -ErrorAction Stop

        # Verify
        $after = Get-PolicyRulesState
        if ($after.Present) {
            Write-Log "Verification FAILED: PolicyRules still present."
            return $false
        } else {
            Write-Log "Verification OK: PolicyRules removed."
            return $true
        }
    } catch {
        Write-Log "Removal error: $($_.Exception.Message)"
        return $false
    }
}

# -------------------- Main --------------------
Write-Log "=== PolicyRules-AIO starting, Mode=$Mode, 64bitProcess=$([Environment]::Is64BitProcess) ==="
$state = Get-PolicyRulesState

switch ($Mode) {
    'Detect' {
        if ($state.Present) {
            Write-Log "DETECT: PolicyRules exists (Type=$($state.Type))."
            exit 1
        } else {
            Write-Log "DETECT: PolicyRules absent."
            exit 0
        }
    }

    'Remediate' {
        $ok = Remove-PolicyRules -StrictTypeCheck:$false  # remove regardless of type; change to $true to only remove when REG_SZ
        if ($ok) {
            # Final confirmation
            $final = Get-PolicyRulesState
            if ($final.Present) {
                Write-Log "REMEDIATE: Completed but PolicyRules is still present."
                exit 1
            } else {
                Write-Log "REMEDIATE: Success. PolicyRules absent."
                exit 0
            }
        } else {
            Write-Log "REMEDIATE: Removal failed."
            exit 1
        }
    }

    'Report' {
        $result = [pscustomobject]@{
                       Timestamp = (Get-Date).ToString('s')
            Path      = $RegPath
            Name      = $ValueName
            KeyExists = $state.KeyExists
            Present   = $state.Present
            Type      = $state.Type
            Value     = if ($null -ne $state.Value) { $state.Value } else { $null }
        } | ConvertTo-Json -Depth 3
        Write-Output $result
        exit 0
    }
