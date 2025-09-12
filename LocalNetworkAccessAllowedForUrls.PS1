# Define log file path
$logFile = "$env:ProgramData\EdgePolicyDeployment\EdgePolicyLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Path (Split-Path $logFile) -Force | Out-Null

function Write-Log {
    param (
        [string]$message,
        [string]$level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$level] $message"
    Write-Output $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

try {
    # Define registry path
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\LocalNetworkAccessAllowedForUrls"
    Write-Log "Starting registry configuration for Edge policy."

    # Create the registry key if it doesn't exist
    if (-not (Test-Path $regPath)) {
        try {
            New-Item -Path $regPath -Force | Out-Null
            Write-Log "Registry key created: $regPath"
        } catch {
            Write-Log "Failed to create registry key: $regPath. Error: $($_.Exception.Message)" "ERROR"
            exit 1
        }
    } else {
        Write-Log "Registry key already exists: $regPath"
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
            Write-Log "Successfully set $valueName = $($allowedUrls[$i])"
        } catch {
            Write-Log "Failed to set registry value $valueName. Error: $($_.Exception.Message)" "ERROR"
        }
    }

    Write-Log "All registry settings applied successfully."
} catch {
    Write-Log "Unexpected error occurred: $($_.Exception.Message)" "ERROR"
    exit 1
}

<#
FAQ

Q: Win32 app created for it and tested. It does properly create the keys in registry. But I guess it will not show under edge://policy?
A: Correct. Microsoft Edge does not show this policy in edge://policy. You can test it by accessing a local URL (e.g., http://printer.local) from a public site or iframe. If it works without a prompt or block, the policy is likely active.

Q: Is there another way to verify if the policy is applied?
A: Yes. Open DevTools (F12) in Edge, go to the Network tab, and try accessing a local resource from a public site. If the request succeeds without CORS or network errors, the policy is likely applied.

Q: Are prompts/blocks only active starting from version 141 of Edge?
A: Yes. If you're using Edge version 139 or earlier, the policy won’t be recognized or enforced. Edge 140 supports the policy, but the enforcement (slower performance and offline issues) begins with version 141.

Q: Is there a GUI in Edge to view the allowed URLs?
A: No. Microsoft Edge does not provide a GUI to view or manage URLs set through LocalNetworkAccessAllowedForUrls. These must be managed via Group Policy, registry, or MDM (e.g., Intune).

Q: I have version 140. Will I see any impact?
A: No. The performance degradation and offline issues begin with Edge 141. Microsoft recommends deploying the policy before version 141 rolls out (expected end of September 2025).

Q: What if I also configure LocalNetworkAccessBlockedForUrls?
A: That policy takes precedence. If a URL is listed in both Allowed and Blocked lists, it will be blocked.

#>
