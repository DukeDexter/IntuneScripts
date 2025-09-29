$regexGuid = '\{[0-9A-Fa-f\-]{36}\}'

$allUserApps =
  # Machine-wide
  Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue +
  # Each loaded user hive
  (Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } |
    ForEach-Object {
      $base = "$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
      Get-ItemProperty -Path "Registry::$base" -ErrorAction SilentlyContinue
    })

$results = $allUserApps | Where-Object { $_.DisplayName } | ForEach-Object {
  $pc = if ($_.PSObject.Properties['ProductCode']) { $_.ProductCode }
        elseif ($_.PSObject.Properties['UninstallString'] -and $_.UninstallString -match $regexGuid) {
          [regex]::Match($_.UninstallString, $regexGuid).Value
        }
  if ($pc) {
    [pscustomobject]@{
      DisplayName    = $_.DisplayName
      DisplayVersion = $_.DisplayVersion
      Publisher      = $_.Publisher
      Scope          = (if ($_.PSPath -like '*HKU*') {'User'} else {'Machine'})
      ProductCode    = $pc
    }
  }
}

$results | Sort-Object DisplayName | Format-Table -Auto
