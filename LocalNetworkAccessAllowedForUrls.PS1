try {
    # Define registry path
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\LocalNetworkAccessAllowedForUrls"

    # Create the registry key if it doesn't exist
    if (-not (Test-Path $regPath)) {
        try {
            New-Item -Path $regPath -Force | Out-Null
            Write-Output "Registry key created: $regPath"
        } catch {
            Write-Error "Failed to create registry key: $regPath. Error: $_"
            exit 1
        }
    } else {
        Write-Output "Registry key already exists: $regPath"
    }

    # Define the list of URLs to allow
    $allowedUrls = @(
        "http://intranet.company.com",
        "http://printer.local",
        "http://fileserver.local"
    )

    # Write each URL as a separate REG_SZ value
    for ($i = 0; $i -lt $allowedUrls.Count; $i++) {
        $valueName = ($i + 1).ToString()
        try {
            New-ItemProperty -Path $regPath -Name $valueName -Value $allowedUrls[$i] -PropertyType String -Force | Out-Null
            Write-Output "Successfully set $valueName = $($allowedUrls[$i])"
        } catch {
            Write-Error "Failed to set registry value $valueName. Error: $_"
        }
    }

    Write-Output "All registry settings applied successfully."

} catch {
    Write-Error "Unexpected error occurred: $_"
    exit 1
}
