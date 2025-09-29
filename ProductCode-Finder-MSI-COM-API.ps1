# Enumerate MSI products via Windows Installer COM (safe; does not trigger repairs)
$installer = New-Object -ComObject WindowsInstaller.Installer
# Context filter 7 = All contexts (UserManaged, UserUnmanaged, Machine)
$products = @($installer.ProductsEx('', '', 7))

$msiList = foreach ($p in $products) {
  # Some properties may not exist for all items; wrap in try/catch
  try {
    [pscustomobject]@{
      ProductName = $p.InstallProperty('ProductName')
      ProductCode = $p.ProductCode
      Version     = $p.InstallProperty('VersionString')
      Publisher   = $p.InstallProperty('Publisher')
      InstallDate = $p.InstallProperty('InstallDate')
      Language    = $p.InstallProperty('ProductLanguage')
      Assignment  = $p.Context  # 1=UserManaged, 2=UserUnmanaged, 4=Machine (bitfield)
    }
  } catch {
    # Skip problematic entries silently
  }
}

$msiList | Sort-Object ProductName | Format-Table -Auto
# $msiList | Export-Csv "$env:Public\msi_products_com.csv" -NoTypeInformation -Encoding UTF8
