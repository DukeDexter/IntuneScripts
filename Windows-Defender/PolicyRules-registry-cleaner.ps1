<#
.SYNOPSIS
script to Detect / Remediate / Report the 'PolicyRules' REG_SZ value under:
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager
Then triggers an Intune/MDM device sync at the end.

.DESCRIPTION
- Detect: exit 1 if 'PolicyRules' exists, else 0
- Remediate: remove 'PolicyRules' if present; exit 0 when absent after run, else 1
- Report: emit a JSON object showing presence/value; exit 0
- Sync: runs after Remediate (and can be called in other modes if desired)

.NOTES
- Run as SYSTEM (Intune) or Administrator (manual)
- Use 64-bit PowerShell (Intune “Run scripts in 64-bit PowerShell: Yes”)
- If the policy is deployed by GPO/Intune, it may reappear after sync. Fix at the source policy.

.PARAMETER Mode
Detect | Remediate | Report (default: Remediate)

.PARAMETER VerboseLogging
Writes detailed logs to %ProgramData%\Intune\Logs\PolicyRules-AIO.log

#>

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
        Write-Output $Message
    } catch { }
}

function Ensure-64Bit {
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
    $present = $false
    $type    = $null
    $value   = $null

    if (-not (Test-Path -Path $RegProviderPath)) {
        return [pscustomobject]@{ KeyExists=$false; Present=$false; Type=$null; Value=$null }
    }

    try {
        $item  = Get-Item -Path $RegProviderPath -ErrorAction Stop
        $props = Get-ItemProperty -Path $RegProviderPath -ErrorAction Stop
        $present = $props.PSObject.Properties.Name -contains $ValueName

        if ($present) {
            try {
                $q = & reg.exe query "$RegPath" /v "$ValueName" 2>$null
                $line = ($q | Select-String -Pattern "^\s*$ValueName\s+REG_").Line
                if ($line) {
                    $parts = $line -split '\s{2,}'
                    if ($parts.Length -ge 3) {
                        $type  = $parts[1].Trim()
                        $value = ($parts[2..($parts.Length-1)] -join ' ').Trim()
                    }
                } else {
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
        return [pscustomobject]@{ KeyExists=$true; Present=$false; Type=$null; Value=$null }
    }
}

function Remove-PolicyRules {
    param([switch]$StrictTypeCheck) # if set, only remove when type is REG_SZ
    try {
        $state = Get-PolicyRulesState
        if (-not $state.KeyExists) {
            Write-Log "Registry key not found: $RegPath"
            return $true
        }
        if (-not $state.Present) {
            Write-Log "PolicyRules not present; nothing to remove."
            return $true
        }
        if ($StrictTypeCheck -and $state.Type -ne 'REG_SZ') {
            Write-Log "PolicyRules present but type '$($state.Type)' != 'REG_SZ'. Skipping removal (StrictTypeCheck)."
            return $false
        }

        Write-Log "Found PolicyRules ($($state.Type)): '$($state.Value)'. Attempting removal..."
        Remove-ItemProperty -Path $RegProviderPath -Name $ValueName -ErrorAction Stop

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

function Invoke-DeviceSync {
    <#
    Triggers device sync via:
    - Running EnterpriseMgmt scheduled tasks for each enrollment GUID
    - Restarting Intune Management Extension service
    - Refreshing AAD PRT (dsregcmd /refreshprt)
    #>
    try {
        Write-Log "Starting device sync..."

        # 1) Run MDM scheduled tasks for each enrollment
        $enrollRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
        if (Test-Path $enrollRoot) {
            $enrollKeys = Get-ChildItem $enrollRoot -ErrorAction SilentlyContinue |
                          Where-Object {
                              # Filter real enrollments (keys with UPN or AADTenantID)
                              $_.GetValue('UPN') -or $_.GetValue('AADTenantID')
                          }

            foreach ($ek in $enrollKeys) {
                $guid = $ek.PSChildName
                $taskPath = "\Microsoft\Windows\EnterpriseMgmt\$guid\"
                $taskNames = @(
                    'Schedule #3 created by enrollment client',   # immediate sync
                    'PushLaunch'                                  # push channel
                )

                foreach ($tn in $taskNames) {
                    try {
                        Write-Log "Starting scheduled task: $taskPath$tn"
                        Start-ScheduledTask -TaskPath $taskPath -TaskName $tn -ErrorAction Stop
                    } catch {
                        Write-Log "Scheduled task not found or failed: $taskPath$tn ($($_.Exception.Message))"
                    }
                }

                # Fallback: start any task that resembles 'Schedule #3*'
                try {
                    $tasks = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue |
                             Where-Object { $_.TaskName -like 'Schedule #3*' }
                    foreach ($t in $tasks) {
                        Write-Log "Starting fallback task: $taskPath$($t.TaskName)"
                        Start-ScheduledTask -TaskPath $taskPath -TaskName $t.TaskName -ErrorAction SilentlyContinue
                    }
                } catch { }
            }
        } else {
            Write-Log "Enrollments registry path not found: $enrollRoot"
        }

        # 2) Restart Intune Management Extension service
        try {
            $svc = Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue
            if ($svc) {
                Write-Log "Restarting IntuneManagementExtension service..."
                Restart-Service -Name 'IntuneManagementExtension' -Force -ErrorAction Stop
            } else {
                Write-Log "IntuneManagementExtension service not present."
            }
        } catch {
            Write-Log "Failed to restart IME service: $($_.Exception.Message)"
        }

        # 3) Refresh AAD PRT (helps compliance/policy evaluation)
        try {
            $dsreg = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
            if (Test-Path $dsreg) {
                Write-Log "Refreshing AAD PRT via dsregcmd /refreshprt..."
                Start-Process -FilePath $dsreg -ArgumentList '/refreshprt' -WindowStyle Hidden -Wait
            } else {
                Write-Log "dsregcmd.exe not found."
            }
        } catch {
            Write-Log "dsregcmd refreshprt failed: $($_.Exception.Message)"
        }

        Write-Log "Device sync routine completed."
        return $true
    } catch {
        Write-Log "Device sync error: $($_.Exception.Message)"
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
        $ok = Remove-PolicyRules -StrictTypeCheck:$false  # set to $true to only remove REG_SZ
        # Always attempt a device sync after remediation attempt
        $syncOk = Invoke-DeviceSync

        if ($ok) {
            $final = Get-PolicyRulesState
            if ($final.Present) {
                Write-Log "REMEDIATE: Completed but PolicyRules is still present."
                exit 1
            } else {
                Write-Log "REMEDIATE: Success. PolicyRules absent."
                # Sync success/failure does not change remediation exit code
                exit 0
            }
        } else {
            Write-Log "REMEDIATE: Removal failed."
            # We still attempted sync; report failure for remediation
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
            Value     = if ($null -ne $state.Value) { $state.Value } else            Value     = if ($null -ne $state.Value) { $state.Value } else { $null }
        } | ConvertTo-Json -Depth 3
        Write-Output $result
        exit 0
    }
