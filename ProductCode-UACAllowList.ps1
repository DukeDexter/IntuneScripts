<#
.SYNOPSIS
  Adds or removes MSI ProductCodes in the Windows Installer UAC allowlist.

.PREREQUISITE
  Requires September 2025 CU (or later) that introduced the allowlist:
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UACAllowList
  Ref: Microsoft Support article on unexpected UAC prompts and allowlist.

.EXAMPLES
  # Add 3 products
  .\Set-UacAllowList.ps1 -ProductCodes '{11111111-1111-1111-1111-111111111111}','22222222-2222-2222-2222-222222222222','33333333-3333-3333-3333-333333333333' -Description 'UAC allowlist via Intune'

  # Remove 2 products
  .\Set-UacAllowList.ps1 -ProductCodes '11111111-1111-1111-1111-111111111111','{22222222-2222-2222-2222-222222222222}' -Remove
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string[]]$ProductCodes,

    [string]$Description = '',

    [switch]$Remove
)

# ----- Constants -----
$KeyPath    = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UACAllowList'
$LogFolder  = Join-Path $env:ProgramData 'UACAllowList'
$LogFile    = Join-Path $LogFolder 'Allowlist.log'
$DateStamp  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

# ----- Helpers -----
function Write-Log {
    param([string]$Message)
    if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
    Add-Content -Path $LogFile -Value "[$DateStamp] $Message"
    Write-Host $Message
}

function Normalize-ProductCode {
    param([string]$Code)
    $c = $Code.Trim()
    # Strip braces for validation, then re-apply in uppercase.
    $stripped = $c.Trim('{}')
    [Guid]$g = $null
    if (-not [Guid]::TryParse($stripped, [ref]$g)) {
        throw "Invalid ProductCode GUID: '$Code'"
    }
    return ('{' + $g.ToString().ToUpper() + '}')
}

# Force 64-bit registry view explicitly (important for Intune)
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,
                                                      [Microsoft.Win32.RegistryView]::Registry64)

try {
    $installerKey = $baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Installer', $true)
    if (-not $installerKey) { throw "Installer key not found. Ensure Windows Installer is present." }

    $uacAllowKey = $baseKey.OpenSubKey($KeyPath, $true)
    if (-not $uacAllowKey) {
        Write-Log "Creating key: HKLM:\$KeyPath"
        $uacAllowKey = $baseKey.CreateSubKey($KeyPath)
    }

    $processed = @()
    foreach ($raw in $ProductCodes) {
        try {
            $pc = Normalize-ProductCode -Code $raw

            if ($Remove) {
                if ($uacAllowKey.GetValue($pc, $null) -ne $null) {
                    if ($PSCmdlet.ShouldProcess($pc, 'Remove allowlist entry')) {
                        $uacAllowKey.DeleteValue($pc, $false)
                        Write-Log "Removed allowlist entry for $pc"
                        $processed += [pscustomobject]@{ ProductCode = $pc; Action = 'Removed' }
                    }
                } else {
                    Write-Log "No existing allowlist entry found for $pc (skip)"
                    $processed += [pscustomobject]@{ ProductCode = $pc; Action = 'Skip (not present)' }
                }
            }
            else {
                if ($PSCmdlet.ShouldProcess($pc, 'Add/Update allowlist entry')) {
                    # REG_SZ with optional description
                    $uacAllowKey.SetValue($pc, $Description, [Microsoft.Win32.RegistryValueKind]::String)
                    Write-Log "Added/Updated allowlist entry for $pc (REG_SZ='${Description}')"
                    $processed += [pscustomobject]@{ ProductCode = $pc; Action = 'Added/Updated' }
                }
            }
        }
        catch {
            Write-Log "ERROR processing '$raw' : $($_.Exception.Message)"
            throw
        }
    }

    # Emit a result summary for Intune logs
    $processed | ForEach-Object { Write-Output ("{0} - {1}" -f $_.ProductCode, $_.Action) }

    # Optional: return non-zero if any failures occurred (caught above)
    exit 0
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($uacAllowKey) { $uacAllowKey.Close() }
    if ($installerKey) { $installerKey.Close() }
    if ($baseKey) { $baseKey.Close() }
}
