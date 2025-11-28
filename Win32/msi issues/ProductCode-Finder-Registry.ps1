# Enumerate MSI ProductCodes from registry (HKLM x64 + x86, and HKCU)
$uninstallPaths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',             # 64-bit apps on 64-bit OS
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', # 32-bit apps on 64-bit OS
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'              # Per-user installs (current user)
)

$regexGuid = '\{[0-9A-Fa-f\-]{36}\}'

$apps = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  ForEach-Object {
    $pc = $null
    if ($_.PSObject.Properties['ProductCode']) {
      $pc = $_.ProductCode
    }
    elseif ($_.PSObject.Properties['UninstallString'] -and $_.UninstallString -match $regexGuid) {
      $pc = [regex]::Match($_.UninstallString, $regexGuid).Value
    }

    if ($pc) {
      [pscustomobject]@{
        DisplayName    = $_.DisplayName
        DisplayVersion = $_.DisplayVersion
        Publisher      = $_.Publisher
        Scope          = (if ($_.PSPath -like '*HKCU*') {'User'} else {'Machine'})
        Bitness        = (if ($_.PSPath -like '*WOW6432Node*') {'x86'} else {'x64'})
        ProductCode    = $pc
        UninstallKey   = $_.PSChildName
      }
    }
  } |
  Sort-Object DisplayName

$apps | Format-Table -Auto
# Export if needed:
# $apps | Export-Csv "$env:Public\msi_productcodes.csv" -NoTypeInformation -Encoding UTF8
