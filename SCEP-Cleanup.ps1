<#
SCEP-Cleanup.ps1
----------------
script to detect, report, and remove SCEP-issued certificates from Windows devices with interactive menu or parameter-driven execution.

USAGE (Examples):
  # Interactive menu:
  .\SCEP-Cleanup.ps1

  # Detect only (intended for Intune detection: exit code 1 if found, 0 if not)
  .\SCEP-Cleanup.ps1 -Action Detect -Scope Both -TemplateMatch 'SCEP','WiFi_SCEP' -IssuerMatch 'Corp-CA','NDES' -Quiet

  # Report only (CSV+JSON)
  .\SCEP-Cleanup.ps1 -Action Report -Scope Both -TemplateMatch 'SCEP' -LogPath "C:\Temp\SCEP-Cleanup"

  # Remove matched certs (dry run)
  .\SCEP-Cleanup.ps1 -Action Remove -Scope Both -TemplateMatch 'SCEP','ULX_SCEP' -WhatIf

  # Remove matched certs + private keys (no prompt; Intune remediation)
  .\SCEP-Cleanup.ps1 -Action Remove -Scope Both -TemplateMatch 'WiFi_SCEP' -RemovePrivateKey -Force

  # Full clean (Report + Remove), precise by thumbprint
  .\SCEP-Cleanup.ps1 -Action FullCleanup -ThumbprintMatch 'ABCDEF1234...','0099AABB...' -Scope LocalMachine -Force

NOTES:
  - For LocalMachine scope, run as Administrator (or as SYSTEM in Intune).
  - For CurrentUser scope, run in user context; SYSTEM cannot see user certs.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    # What to do
    [ValidateSet('Detect','Report','Remove','FullCleanup')]
    [string]$Action,

    # Where to look
    [ValidateSet('CurrentUser','LocalMachine','Both')]
    [string]$Scope = 'Both',

    # How to identify SCEP certificates (use any combination)
    [string[]]$TemplateMatch = @('SCEP','WiFi_SCEP','ULX_SCEP'),
    [string[]]$IssuerMatch   = @('NDES','Intune','Corp-CA'),  # adjust to your CA / NDES names
    [string[]]$FriendlyNameMatch = @('SCEP'),
    [string[]]$ThumbprintMatch   = @(),

    # Include expired certs in matching
    [bool]$IncludeExpired = $true,

    # Destructive options
    [switch]$RemovePrivateKey,
    [switch]$Force,      # suppress confirmation prompts
    [switch]$WhatIf,     # dry-run
    [switch]$Quiet,      # reduce console chatter (useful for Intune)

    # Reports / Logs
    [string]$LogPath = "$env:ProgramData\IntuneScripts\SCEP-Cleanup\Logs",

    # Advanced: interactive menu even if Action is provided
    [switch]$Interactive
)

# ---------------------------
# Helpers / Utilities
# ---------------------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 's'), $Level, $Message
    if (-not $Quiet) { Write-Host $line }
    try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch {}
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}

function Ensure-Paths {
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    $script:StartStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:CsvFile  = Join-Path $LogPath "SCEP-Cleanup-$StartStamp.csv"
    $script:JsonFile = Join-Path $LogPath "SCEP-Cleanup-$StartStamp.json"
    $script:ActFile  = Join-Path $LogPath "SCEP-Cleanup-Actions-$StartStamp.csv"
    $script:LogFile  = Join-Path $LogPath "SCEP-Cleanup-$StartStamp.log"
}

function Get-StoreTargets {
    switch ($Scope) {
        'CurrentUser'  { @(@{Location='CurrentUser';  Path='Cert:\CurrentUser\My';  CertutilScope='-user'}) }
        'LocalMachine' { @(@{Location='LocalMachine'; Path='Cert:\LocalMachine\My'; CertutilScope=''     }) }
        'Both'         { @(
                           @{Location='CurrentUser';  Path='Cert:\CurrentUser\My';  CertutilScope='-user'},
                           @{Location='LocalMachine'; Path='Cert:\LocalMachine\My'; CertutilScope=''     }
                         )}
    }
}

function Get-TemplateName {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $name = $null
    try {
        # OID 1.3.6.1.4.1.311.20.2 — old template name
        $ext1 = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.20.2' }
        if ($ext1) {
            $asn = New-Object System.Security.Cryptography.AsnEncodedData ($ext1.Oid, $ext1.RawData)
            $fmt = $asn.Format($false); if ($fmt) { return $fmt.Trim() }
        }
        # OID 1.3.6.1.4.1.311.21.7 — template info (name+OID)
        $ext2 = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' }
        if ($ext2) {
            $asn2 = New-Object System.Security.Cryptography.AsnEncodedData ($ext2.Oid, $ext2.RawData)
            $fmt2 = $asn2.Format($true)
            if ($fmt2 -match 'Template(?:\s*Name)?\s*=\s*([^,\r\n]+)') {
                return $Matches[1].Trim()
            }
        }
    } catch {}
    return $name
}

function Get-EKUs {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    try {
        $ekuExt = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
        if ($ekuExt) {
            $ekuParsed = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExt
            return ($ekuParsed.EnhancedKeyUsages | ForEach-Object { $_.Value })
        }
    } catch {}
    return @()
}

function Find-MatchingCertificates {
    param(
        [hashtable[]]$Stores,
        [bool]$IncludeExpired
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($s in $Stores) {
        Write-Log "Scanning store: $($s.Path)"
        try { $certs = Get-ChildItem -Path $s.Path -ErrorAction Stop } catch {
            Write-Log "Failed to open $($s.Path): $($_.Exception.Message)" 'WARN'
            continue
        }

        foreach ($c in $certs) {
            try {
                $tmpl = Get-TemplateName -Cert $c
                $ekus = Get-EKUs -Cert $c
                $isValid = ($c.NotAfter -gt (Get-Date)) -and ($c.NotBefore -lt (Get-Date))
                if (-not $IncludeExpired -and -not $isValid) { continue }

                # Build record
                $rec = [pscustomobject]@{
                    Location      = $s.Location
                    StorePath     = $s.Path
                    Subject       = $c.Subject
                    Issuer        = $c.Issuer
                    Thumbprint    = $c.Thumbprint
                    SerialNumber  = $c.SerialNumber
                    NotBefore     = $c.NotBefore
                    NotAfter      = $c.NotAfter
                    FriendlyName  = $c.FriendlyName
                    TemplateName  = $tmpl
                    EKU_OIDs      = ($ekus -join ';')
                    HasPrivateKey = $c.HasPrivateKey
                }

                # Matching logic
                $match = $false
                if ($ThumbprintMatch.Count -gt 0 -and $ThumbprintMatch -contains $c.Thumbprint) { $match = $true }

                if (-not $match -and $TemplateMatch.Count -gt 0 -and $tmpl) {
                    if ($TemplateMatch | Where-Object { $tmpl -like "*$_*" }) { $match = $true }
                }
                if (-not $match -and $IssuerMatch.Count -gt 0) {
                    if ($IssuerMatch | Where-Object { $c.Issuer -like "*$_*" }) { $match = $true }
                }
                if (-not $match -and $FriendlyNameMatch.Count -gt 0 -and $c.FriendlyName) {
                    if ($FriendlyNameMatch | Where-Object { $c.FriendlyName -like "*$_*" }) { $match = $true }
                }

                # Heuristic: Client Authentication EKU + template hint
                if (-not $match -and $ekus -contains '1.3.6.1.5.5.7.3.2' -and $tmpl -match 'SCEP') {
                    $match = $true
                }

                # Add a property for match result (helps reporting)
                $rec | Add-Member -NotePropertyName Matched -NotePropertyValue $match

                $results.Add($rec) | Out-Null
            } catch {
                Write-Log "Error reading cert $($c.Thumbprint): $($_.Exception.Message)" 'WARN'
            }
        }
    }

    return $results
}

function Export-Reports {
    param([System.Collections.Generic.List[object]]$Records, [System.Collections.Generic.List[object]]$Actions)
    if ($Records.Count -gt 0) {
        try {
            $Records | Export-Csv -NoTypeInformation -Path $script:CsvFile -Encoding UTF8
            $Records | ConvertTo-Json -Depth 4 | Out-File -FilePath $script:JsonFile -Encoding UTF8
            Write-Log "Reports exported:`n CSV : $script:CsvFile`n JSON: $script:JsonFile"
        } catch {
            Write-Log "Failed to export reports: $($_.Exception.Message)" 'WARN'
        }
    } else {
        Write-Log "No certificates enumerated to report."
    }

    if ($Actions -and $Actions.Count -gt 0) {
        try {
            $Actions | Export-Csv -NoTypeInformation -Path $script:ActFile -Encoding UTF8
            Write-Log "Actions exported: $script:ActFile"
        } catch {
            Write-Log "Failed to export actions report: $($_.Exception.Message)" 'WARN'
        }
    }
}

function Remove-MatchedCertificates {
    param([System.Collections.Generic.List[object]]$Records)

    $actions = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Records | Where-Object { $_.Matched -eq $true }) {
        $targetText = "$($r.Location) $($r.Thumbprint) [$($r.Subject)]"
        if ($PSCmdlet.ShouldProcess($targetText, "Remove certificate")) {
            $removed = $false
            $pkRemoved = $false
            $pkMsg = ''

            try {
                $storeLocation = if ($r.Location -eq 'LocalMachine') {
                    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
                } else {
                    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
                }

                # Open store via .NET for reliable removal
                $xstore = New-Object System.Security.Cryptography.X509Certificates.X509Store ('My', $storeLocation)
                $xstore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $c = $null
                # Find cert by thumbprint in the live store
                $c = ($xstore.Certificates | Where-Object { $_.Thumbprint -eq $r.Thumbprint } | Select-Object -First 1)
                if ($c) {
                    $xstore.Remove($c)
                    $removed = $true
                    Write-Log "Removed certificate: $targetText"
                } else {
                    Write-Log "Certificate not found during removal (already gone?): $targetText" 'WARN'
                }
                $xstore.Close()
            } catch {
                Write-Log "Failed to remove $targetText: $($_.Exception.Message)" 'WARN'
            }

            if ($removed -and $RemovePrivateKey -and $r.HasPrivateKey) {
                try {
                    # Re-open the store to grab a handle for key details if still present
                    # We may not be able to bind after removal; attempt certutil key deletion heuristics.
                    $scope = if ($r.Location -eq 'CurrentUser') { '-user' } else { '' }
                    # certutil -csp <ProviderName> -delkey <ContainerName> is ideal, but we may not know them.
                    # Fallback attempt: certutil -delstore My <thumbprint> sometimes cleans orphaned keys.
                    $args = @()
                    if ($scope) { $args += $scope }
                    $args += @('-repairstore','My',$r.Thumbprint)  # attempt to locate key material
                    $p1 = Start-Process -FilePath 'certutil.exe' -ArgumentList $args -NoNewWindow -PassThru -Wait
                    # Now try delete key if binding info found:
                    $args2 = @()
                    if ($scope) { $args2 += $scope }
                    $args2 += @('-delstore','My',$r.Thumbprint)
                    $p2 = Start-Process -FilePath 'certutil.exe' -ArgumentList $args2 -NoNewWindow -PassThru -Wait
                    if ($p2.ExitCode -eq 0) {
                        $pkRemoved = $true
                        $pkMsg = "Attempted private key cleanup via certutil (-repairstore/-delstore)."
                        Write-Log $pkMsg
                    } else {
                        $pkMsg = "certutil cleanup exit code: $($p2.ExitCode)."
                        Write-Log $pkMsg 'WARN'
                    }
                } catch {
                    $pkMsg = "Exception during private key cleanup: $($_.Exception.Message)"
                    Write-Log $pkMsg 'WARN'
                }
            }

            $actions.Add([pscustomobject]@{
                Thumbprint        = $r.Thumbprint
                Location          = $r.Location
                Subject           = $r.Subject
                Removed           = $removed
                PrivateKeyRemoved = $pkRemoved
                Notes             = $pkMsg
            }) | Out-Null
        }
    }

    return $actions
}

function Show-Menu {
    Clear-Host
    Write-Host "=== SCEP Cleanup Menu ===`n" -ForegroundColor Cyan
    Write-Host "1) Detect (exit code: 1 if found, else 0)"
    Write-Host "2) Report (CSV + JSON)"
    Write-Host "3) Remove matched certificates"
    Write-Host "4) Remove matched certificates + private keys"
    Write-Host "5) Full Cleanup (Report + Remove)"
    Write-Host "6) Exit`n"
    $choice = Read-Host "Choose an option (1-6)"
    return $choice
}

# ---------------------------
# Main
# ---------------------------
try {
    Ensure-Paths

    if ($Scope -match 'LocalMachine' -and -not (Test-IsAdmin)) {
        Write-Log "Warning: Not elevated but targeting LocalMachine. Removal may fail." 'WARN'
    }

    # Interactive selection if requested or no action specified
    if ($Interactive -or -not $Action) {
        $sel = Show-Menu
        switch ($sel) {
            '1' { $Action = 'Detect' }
            '2' { $Action = 'Report' }
            '3' { $Action = 'Remove' }
            '4' { $Action = 'Remove'; $RemovePrivateKey = $true }
            '5' { $Action = 'FullCleanup' }
            default { Write-Log "No action selected. Exiting."; exit 0 }
        }
        Write-Log "Selected action: $Action"
    }

    $stores = Get-StoreTargets
    $records = Find-MatchingCertificates -Stores $stores -IncludeExpired:$IncludeExpired

    $matched = @($records | Where-Object { $_.Matched -eq $true })
    $countAll = $records.Count
    $countMatched = $matched.Count

    Write-Log "Enumerated: $countAll cert(s). Matched SCEP candidates: $countMatched."

    switch ($Action) {
        'Detect' {
            # Intune detection-friendly: non-zero if matches found
            if ($countMatched -gt 0) {
                if (-not $Quiet) { Write-Output "$countMatched SCEP-like certificate(s) found." }
                exit 1
            } else {
                if (-not $Quiet) { Write-Output "No SCEP-like certificates found." }
                exit 0
            }
        }

        'Report' {
            Export-Reports -Records $records -Actions $null
            exit 0
        }

        'Remove' {
            # Honor WhatIf and Force
            if ($WhatIf) { $PSDefaultParameterValues['*:WhatIf'] = $true }
            if ($Force)  { $PSDefaultParameterValues['*:Confirm'] = $false }

            $actions = Remove-MatchedCertificates -Records $records
            Export-Reports -Records $records -Actions $actions
            exit 0
        }

        'FullCleanup' {
            Export-Reports -Records $records -Actions $null
            if ($countMatched -eq 0) {
                Write-Log "No matched certificates to remove."
                exit 0
            }

            if ($WhatIf) { $PSDefaultParameterValues['*:WhatIf'] = $true }
            if ($Force)  { $PSDefaultParameterValues['*:Confirm'] = $false }

            $actions = Remove-MatchedCertificates -Records $records
            Export-Reports -Records $records -Actions $actions
            exit 0
        }
    }

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" 'ERROR'
    exit 2
