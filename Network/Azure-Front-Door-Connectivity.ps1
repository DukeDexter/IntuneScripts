<#
.SYNOPSIS
    Tests connectivity to Intune Azure Front Door (AFD) endpoints.

.DESCRIPTION
    This script performs multi-layer connectivity tests to validate that Intune service
    endpoints are reachable through Azure Front Door. It tests both AFD IP addresses
    and the full domain endpoint with appropriate protocols for each.
    
    The script defaults to the Public cloud environment unless explicitly specified
    using the -CloudType parameter. Use '-CloudType gov' for Government cloud testing.
    
    Test layers include:
    - DNS resolution of Intune service endpoints
    - Outbound TCP Connectivity on ports (ports 80 and 443) to  Intune Azure Front Door (AFD) IP addresses
    - HTTPS endpoint validation to the Intune cloud service
    -  Intune Azure Front Door (AFD) IP range verification
    
    Results can be exported in JSON, CSV, or HTML formats for further analysis or
    integration with monitoring systems.

.PARAMETER CloudType
    Specifies the Azure cloud environment type.
    Valid values: 'public' or 'gov'
    Default: 'public'

.PARAMETER TCPTimeoutMs
    Specifies the timeout in milliseconds for TCP connection tests.
    Valid range: 1000-60000
    Default: 10000 (10 seconds)

.PARAMETER HTTPTimeoutSec
    Specifies the timeout in seconds for HTTP/HTTPS requests.
    Valid range: 5-300
    Default: 30 seconds

.PARAMETER OutputPath
    Specifies the directory path where result files will be saved.
    Default: Script directory ($PSScriptRoot)
    The script will create timestamped files in this location.

.PARAMETER OutputFormat
    Specifies the format(s) for exported results.
    Valid values: 'JSON', 'CSV', 'HTML', 'All'
    Default: 'JSON'
    Use 'All' to generate results in all available formats.

.PARAMETER LogLevel
    Specifies the logging verbosity level.
    Valid values: 'Minimal', 'Normal', 'Detailed'
    Default: 'Normal'
    - Minimal: Only critical information and final results
    - Normal: Test progress and summary information
    - Detailed: Comprehensive diagnostic information
    Note: Use -Verbose for even more detailed output, -Debug for troubleshooting.

.PARAMETER SkipPrerequisiteCheck
    Skips the initial system prerequisite validation checks.
    Use this switch only if you're certain the environment meets all requirements.

.EXAMPLE
    .\Test-IntuneAFDConnectivity.ps1 -CloudType public
    
    Runs connectivity tests for public cloud using default settings.
    
.EXAMPLE
    .\Test-IntuneAFDConnectivity.ps1 -CloudType gov -Verbose
    
    Runs connectivity tests for Government cloud with verbose logging enabled.
    
.EXAMPLE
    .\Test-IntuneAFDConnectivity.ps1 -CloudType gov -OutputFormat All
    
    Runs tests for Government cloud and exports results in all formats.

.EXAMPLE
    .\Test-IntuneAFDConnectivity.ps1 -LogLevel Detailed -OutputPath "C:\Logs"
    
    Runs tests with detailed logging and saves results to C:\Logs directory.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Int32
    Returns exit code indicating overall connectivity status:
    - 0: Full connectivity (all tests passed)
    - 1: Connectivity blocked or failed (any test failures)
    - 3: Script execution error (invalid parameters, prerequisites not met)

. Troubleshooting

If the script reports a failure (Exit Code 1):
- If the Azure Front Door IP Address tests show failed IPs or IP ranges: Your firewall, proxy, or VPN may be blocking outbound connections on ports 443 or 80 to those Azure Front Door IPs.
- If the Service Endpoint test shows “HTTPS endpoint unreachable”: The required Intune service FQDNs or Azure Front Door IPs may not be reachable, or a DNS, proxy, or HTTPS inspection issue is preventing connection to the Intune service FQDN.
- Review the network endpoints for Microsoft Intune (as detailed in this article) and ensure your firewall, VPN, or proxy allows all required Intune service FQDNs, Azure Front Door IP ranges, and ports.
- Check detailed results in the saved output file, or run the script with detailed logging (-LogLevel Detailed and -Verbose) to capture more diagnostic information.

.NOTES
    File Name      : Test-IntuneAFDConnectivity.ps1
    Version        : 1.0.0
    Author         : Microsoft Corporation
    Prerequisite   : PowerShell 5.1 or later
    Copyright      : (c) Microsoft Corporation. All rights reserved.
    
    REQUIREMENTS:
    - PowerShell 5.1 or later
    - Internet connectivity
    - Permissions to make outbound connections on ports 80 and 443
    - DNS resolution capabilities
    
    SECURITY:
    - This script does not require elevated privileges
    - No sensitive data is logged or transmitted
    - All connections are read-only diagnostic tests
    
    For more information, visit:
    https://techcommunity.microsoft.com/blog/intunecustomersuccess/support-tip-upcoming-microsoft-intune-network-changes/4452738

#>

[CmdletBinding(SupportsShouldProcess=$false)]
param(
    [Parameter(
        Mandatory=$false,
        HelpMessage="Specify the Azure cloud environment: 'public' or 'gov'"
    )]
    [ValidateSet('public', 'gov')]
    [string]$CloudType = 'public',
    
    [Parameter(
        Mandatory=$false,
        HelpMessage="TCP connection timeout in milliseconds (1000-60000)"
    )]
    [ValidateRange(1000, 60000)]
    [int]$TCPTimeoutMs = 10000,
    
    [Parameter(
        Mandatory=$false,
        HelpMessage="HTTP/HTTPS request timeout in seconds (5-300)"
    )]
    [ValidateRange(5, 300)]
    [int]$HTTPTimeoutSec = 30,
    
    [Parameter(
        Mandatory=$false,
        HelpMessage="Directory path for output files"
    )]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Container)) {
            throw "Output path '$_' does not exist or is not a directory."
        }
        $true
    })]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(
        Mandatory=$false,
        HelpMessage="Logging verbosity: Minimal, Normal, or Detailed"
    )]
    [ValidateSet('Minimal', 'Normal', 'Detailed')]
    [string]$LogLevel = 'Normal',
    
    [Parameter(
        Mandatory=$false,
        HelpMessage="Skip prerequisite validation checks"
    )]
    [switch]$SkipPrerequisiteCheck
)

#region Script Initialization

# Script constants
$script:SCRIPT_VERSION = "1.0.0"
$script:SCRIPT_NAME = "Intune AFD Connectivity Checker"
$script:EXIT_CODE_SUCCESS = 0
$script:EXIT_CODE_FAIL = 1
$script:EXIT_CODE_ERROR = 3

# Initialize script-level variables
$script:LogEntries = [System.Collections.ArrayList]::new()
$script:HasCriticalErrors = $false

#endregion

#region Logging Framework

function Write-Log {
    <#
    .SYNOPSIS
        Centralized logging function with multiple verbosity levels and output styles.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Debug', 'Verbose')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Normal', 'Section', 'Progress')]
        [string]$Style = 'Normal',
        
        [Parameter(Mandatory=$false)]
        [string]$Subtitle,
        
        [Parameter(Mandatory=$false)]
        [string]$Activity,
        
        [Parameter(Mandatory=$false)]
        [int]$PercentComplete = -1,
        
        [Parameter(Mandatory=$false)]
        [int]$ProgressId = 1,
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )
    
    # Handle different styles
    if ($Style -eq 'Section') {
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor Cyan
        Write-Host $Message -ForegroundColor Cyan
        if ($Subtitle) { Write-Host $Subtitle -ForegroundColor Gray }
        Write-Host ("=" * 70) -ForegroundColor Cyan
        Write-Host ""
        return
    }
    
    if ($Style -eq 'Progress') {
        if ($PercentComplete -ge 0) {
            Write-Progress -Activity $Activity -Status $Message -PercentComplete $PercentComplete -Id $ProgressId
        } else {
            Write-Progress -Activity $Activity -Status $Message -Id $ProgressId
        }
        return
    }
    
    # Store in log collection
    [void]$script:LogEntries.Add(@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Level = $Level
        Message = $Message
    })
    
    # Determine console output based on LogLevel
    $shouldOutput = switch ($script:LogLevel) {
        'Minimal' { $Level -in @('Success', 'Warning', 'Error') }
        'Normal' { $Level -in @('Info', 'Success', 'Warning', 'Error') }
        'Detailed' { $true }
    }
    
    if ($Level -eq 'Verbose' -and $VerbosePreference -eq 'Continue') { $shouldOutput = $true }
    if ($Level -eq 'Debug' -and $DebugPreference -eq 'Continue') { $shouldOutput = $true }
    
    if ($shouldOutput -and -not $NoConsole) {
        switch ($Level) {
            'Success' { Write-Host $Message -ForegroundColor Green }
            'Warning' { Write-Warning $Message }
            'Error' { Write-Error $Message; $script:HasCriticalErrors = $true }
            'Debug' { Write-Debug $Message }
            'Verbose' { Write-Verbose $Message }
            default { Write-Host $Message }
        }
    }
}

function Write-LogSection {
    [CmdletBinding()]
    param([string]$Title, [string]$Subtitle)
    Write-Log -Message $Title -Level Info -Style Section -Subtitle $Subtitle
}

function Write-LogProgress {
    [CmdletBinding()]
    param([string]$Activity, [string]$Status, [int]$PercentComplete = -1, [int]$Id = 1)
    Write-Log -Message $Status -Level Info -Style Progress -Activity $Activity -PercentComplete $PercentComplete -ProgressId $Id
}

#endregion

#region Prerequisite Checks

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates that all prerequisites are met before running tests.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    Write-Log "Validating prerequisites..." -Level Verbose
    $allChecksPassed = $true
    
    Write-Log "Checking PowerShell version..." -Level Verbose
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
        Write-Log "PowerShell 5.1 or later is required. Current version: $psVersion" -Level Error
        $allChecksPassed = $false
    } else {
        Write-Log "PowerShell version $psVersion is supported" -Level Verbose
    }
    
    Write-Log "Verifying .NET Framework components..." -Level Verbose
    try {
        $null = [System.Net.Sockets.TcpClient]
        $null = [System.Diagnostics.Stopwatch]
        Write-Log "Required .NET types are available" -Level Verbose
    } catch {
        Write-Log "Required .NET Framework components are not available: $($_.Exception.Message)" -Level Error
        $allChecksPassed = $false
    }
    
    Write-Log "Checking output path permissions..." -Level Verbose
    try {
        $testFile = Join-Path $script:OutputPath "test_write_$(Get-Random).tmp"
        [System.IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        Write-Log "Output path is writable: $script:OutputPath" -Level Verbose
    } catch {
        Write-Log "Cannot write to output path '$script:OutputPath': $($_.Exception.Message)" -Level Error
        $allChecksPassed = $false
    }
    
    Write-Log "Testing IPv6 network connectivity..." -Level Verbose
    $script:HasIPv6Connectivity = Test-IPv6Connectivity
    if ($script:HasIPv6Connectivity) {
        Write-Log "IPv6 connectivity is available" -Level Verbose
    } else {
        Write-Log "IPv6 connectivity is not available (IPv6 tests may fail)" -Level Verbose
    }
    
    Write-Log "$(if ($allChecksPassed) {'All prerequisite checks passed'} else {'One or more prerequisite checks failed'})" -Level $(if ($allChecksPassed) {'Verbose'} else {'Error'})
    
    return $allChecksPassed
}

#endregion

#region Configuration

# Cloud-specific configuration
$CloudConfig = @{
    public = @{
        DefaultASU = "amsub0502"
        Domain = "microsoft.com"
        AFDEndpoints = @(
            # SD0: 13.107.219.0/24
            @{ IP = "13.107.219.29"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.30"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.31"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.32"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.33"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.34"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.35"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.36"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.37"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.38"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.39"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.40"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.41"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.42"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.43"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.44"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.45"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.46"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.47"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.48"; Description = "AFD Public Range 13.107.219.0/24" },
            @{ IP = "13.107.219.49"; Description = "AFD Public Range 13.107.219.0/24" },
            # SD1: 13.107.227.0/24
            @{ IP = "13.107.227.29"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.30"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.31"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.32"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.33"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.34"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.35"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.36"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.37"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.38"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.39"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.40"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.41"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.42"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.43"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.44"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.45"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.46"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.47"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.48"; Description = "AFD Public Range 13.107.227.0/24" },
            @{ IP = "13.107.227.49"; Description = "AFD Public Range 13.107.227.0/24" },
            # SD2: 13.107.228.0/23
            @{ IP = "13.107.228.10"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.11"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.12"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.13"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.14"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.15"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.16"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.17"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.18"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.19"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.20"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.21"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.22"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.23"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.24"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.25"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.26"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.27"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.28"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.29"; Description = "AFD Public Range 13.107.228.0/23" },
            @{ IP = "13.107.228.30"; Description = "AFD Public Range 13.107.228.0/23" },
            # SD3: 150.171.97.0/24
            @{ IP = "150.171.97.2"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.3"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.4"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.6"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.12"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.14"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.24"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.27"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.31"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.34"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.36"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.39"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.40"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.42"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.46"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.49"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.52"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.54"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.55"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.58"; Description = "AFD Public Range 150.171.97.0/24" },
            @{ IP = "150.171.97.63"; Description = "AFD Public Range 150.171.97.0/24" },
            # SD4: 2620:1ec:40::/48
            @{ IP = "2620:1ec:40::10"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::13"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::16"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::17"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::29"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::30"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::31"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::32"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::33"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::34"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::35"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::36"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::37"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::38"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::39"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::40"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::41"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::42"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::43"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::44"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            @{ IP = "2620:1ec:40::45"; Description = "AFD Public Range 2620:1ec:40::/48 (IPv6)" },
            # SD5: 2620:1ec:49::/48
            @{ IP = "2620:1ec:49::29"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::30"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::31"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::32"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::33"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::34"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::35"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::36"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::37"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::38"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::39"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::40"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::41"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::42"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::43"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::44"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::45"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::46"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::47"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::48"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            @{ IP = "2620:1ec:49::49"; Description = "AFD Public Range 2620:1ec:49::/48 (IPv6)" },
            # SD6: 2620:1ec:4a::/47
            @{ IP = "2620:1ec:4a::10"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::11"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::12"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::13"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::14"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::15"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::16"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::17"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::18"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::19"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::20"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::21"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::22"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::23"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::24"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::25"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::26"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::27"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::28"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::29"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" },
            @{ IP = "2620:1ec:4a::30"; Description = "AFD Public Range 2620:1ec:4a::/47 (IPv6)" }
        )
        AFDCIDRs = @(
            "13.107.219.0/24",
            "13.107.227.0/24",
            "13.107.228.0/23",
            "150.171.97.0/24",
            "2620:1ec:40::/48",
            "2620:1ec:49::/48",
            "2620:1ec:4a::/47"
        )
    }
    gov = @{
        DefaultASU = "fxpasu01"
        Domain = "microsoft.us"
        AFDEndpoints = @(
            # 51.54.53.136/29 - testing 4 IPs (limited range, using available IPs)
            @{ IP = "51.54.53.137"; Description = "AFD Gov Range 51.54.53.136/29" },
            @{ IP = "51.54.53.138"; Description = "AFD Gov Range 51.54.53.136/29" },
            @{ IP = "51.54.53.140"; Description = "AFD Gov Range 51.54.53.136/29" },
            @{ IP = "51.54.53.142"; Description = "AFD Gov Range 51.54.53.136/29" },
            # 51.54.114.160/29 - testing 4 IPs (limited range, using available IPs)
            @{ IP = "51.54.114.161"; Description = "AFD Gov Range 51.54.114.160/29" },
            @{ IP = "51.54.114.162"; Description = "AFD Gov Range 51.54.114.160/29" },
            @{ IP = "51.54.114.164"; Description = "AFD Gov Range 51.54.114.160/29" },
            @{ IP = "51.54.114.166"; Description = "AFD Gov Range 51.54.114.160/29" },
            # 62.11.173.176/29 - testing 4 IPs (limited range, using available IPs)
            @{ IP = "62.11.173.177"; Description = "AFD Gov Range 62.11.173.176/29" },
            @{ IP = "62.11.173.178"; Description = "AFD Gov Range 62.11.173.176/29" },
            @{ IP = "62.11.173.180"; Description = "AFD Gov Range 62.11.173.176/29" },
            @{ IP = "62.11.173.182"; Description = "AFD Gov Range 62.11.173.176/29" }
        )
        AFDCIDRs = @(
            "51.54.53.136/29",
            "51.54.114.160/29",
            "62.11.173.176/29"
        )
    }
}

# Get cloud-specific configuration
$config = $CloudConfig[$CloudType]

# Set ASU based on CloudType (hardcoded)
$ASU = $config.DefaultASU

# AFD IP addresses to test (from cloud-specific configuration)
$script:AFDEndpoints = $config.AFDEndpoints

# Domain endpoint configuration
$script:DomainEndpoint = @{
    Hostname = "agentsn.$ASU.manage.$($config.Domain)"
    FullURL = "https://agentsn.$ASU.manage.$($config.Domain):443/TrafficGateway/TrafficRoutingService/SideCar/StatelessSideCarGatewayService/SideCarHealthReports('00000000-0000-0000-0000-000000000000')?api-version=1.5"
}

# Results collection
$script:Results = @{
    TestDate = Get-Date
    CloudType = $CloudType
    ASU = $ASU
    AFDTests = @()
    DomainTests = @()
    Summary = @{}
}

# Store AFD CIDR ranges for validation
$script:AFDCIDRs = $config.AFDCIDRs

# IPv6 connectivity status (will be set during prerequisite checks)
$script:HasIPv6Connectivity = $false

#endregion

#region Test Functions

function Test-AFDHeader {
    <#
    .SYNOPSIS
        Checks for Azure Front Door x-azure-ref header in response.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Headers,
        
        [Parameter(Mandatory=$true)]
        [int]$StatusCode
    )
    
    $baseError = "HTTP $StatusCode"
    $result = @{
        HasAFDHeader = $false
        AzureRef = $null
        Success = $false
        Error = "$baseError (x-azure-ref header not found)"
    }
    
    if ($Headers) {
        try {
            $azureRefValues = $Headers.GetValues('x-azure-ref')
            $headerValue = $azureRefValues -join ', '
            
            if (-not [string]::IsNullOrWhiteSpace($headerValue)) {
                $result.HasAFDHeader = $true
                $result.AzureRef = $headerValue
                $result.Success = $true
                $result.Error = $baseError
            } else {
                $result.Error = "$baseError (x-azure-ref header present but empty)"
            }
        } catch {
            # Header not found - keep default error
        }
    } else {
        $result.Error = "$baseError (no headers available)"
    }
    
    return $result
}

function Get-InnerException {
    <#
    .SYNOPSIS
        Unwraps nested exceptions to find the root cause.
    #>
    [CmdletBinding()]
    [OutputType([System.Exception])]
    param(
        [Parameter(Mandatory=$true)]
        [System.Exception]$Exception
    )
    
    $current = $Exception
    
    # Handle AggregateException by flattening it
    if ($current -is [System.AggregateException]) {
        $flattened = $current.Flatten()
        # Look for SocketException or use first inner exception
        foreach ($ex in $flattened.InnerExceptions) {
            if ($ex -is [System.Net.Sockets.SocketException]) {
                return $ex
            }
        }
        if ($flattened.InnerExceptions.Count -gt 0) {
            $current = $flattened.InnerExceptions[0]
        }
    }
    
    # Traverse inner exceptions to find the root cause
    while ($current.InnerException) {
        $current = $current.InnerException
        # Prefer SocketException if found
        if ($current -is [System.Net.Sockets.SocketException]) {
            break
        }
    }
    
    return $current
}

function Format-ErrorMessage {
    <#
    .SYNOPSIS
        Cleans up error messages for display.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ErrorMessage
    )
    
    $cleaned = $ErrorMessage -replace '[\r\n]+Parameter name:.*$', ''
    return $cleaned.Trim()
}

function New-TestResult {
    <#
    .SYNOPSIS
        Creates a standardized test result object.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Type,
        
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [Parameter(Mandatory=$false)]
        [bool]$Success = $false,
        
        [Parameter(Mandatory=$false)]
        [int]$Latency = 0,
        
        [Parameter(Mandatory=$false)]
        [string]$Error = $null,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$AdditionalProperties = @{}
    )
    
    $result = @{
        Type = $Type
        Target = $Target
        Success = $Success
        Latency = $Latency
        Error = $Error
    }
    
    foreach ($key in $AdditionalProperties.Keys) {
        $result[$key] = $AdditionalProperties[$key]
    }
    
    return $result
}

function ConvertTo-ErrorMessage {
    <#
    .SYNOPSIS
        Extracts and formats error message from exception.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [System.Exception]$Exception
    )
    
    $innerException = Get-InnerException -Exception $Exception
    return Format-ErrorMessage -ErrorMessage $innerException.Message
}

function Write-StatusLine {
    <#
    .SYNOPSIS
        Writes a formatted status line with label and colored status.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Label,
        
        [Parameter(Mandatory=$true)]
        [string]$Status,
        
        [Parameter(Mandatory=$false)]
        [string]$StatusColor = 'White',
        
        [Parameter(Mandatory=$false)]
        [switch]$NoNewline
    )
    
    Write-Host $Label -NoNewline
    Write-Host $Status -ForegroundColor $StatusColor -NoNewline:$NoNewline
}

function Test-TCPConnection {
    <#
    .SYNOPSIS
        Tests TCP connectivity to an IP address and port.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,
        
        [Parameter(Mandatory=$true)]
        [ValidateRange(1, 65535)]
        [int]$Port,
        
        [Parameter(Mandatory=$true)]
        [ValidateRange(1, 300000)]
        [int]$TimeoutMs
    )
    
    Write-Log "Testing TCP connection to ${IPAddress}:${Port}" -Level Debug
    
    $result = New-TestResult -Type "TCP" -Target "${IPAddress}:${Port}"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $tcpClient = $null
    
    try {
        # Determine if this is an IPv6 address
        $isIPv6 = Test-IsIPv6 -IPAddress $IPAddress
        
        # Create TcpClient with appropriate address family
        if ($isIPv6) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        } else {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
        }
        
        $connectTask = $tcpClient.ConnectAsync($IPAddress, $Port)
        
        # Poll task status instead of using Wait() to avoid exceptions during wait
        while (-not $connectTask.IsCompleted -and $stopwatch.ElapsedMilliseconds -lt $TimeoutMs) {
            Start-Sleep -Milliseconds 100
        }
        
        if ($connectTask.IsCompleted -and -not $connectTask.IsFaulted) {
            $result.Success = $true
            $result.Latency = [int]$stopwatch.ElapsedMilliseconds
            Write-Log "TCP connection successful (${result.Latency}ms)" -Level Debug
        } elseif ($connectTask.IsFaulted) {
            $result.Error = ConvertTo-ErrorMessage -Exception $connectTask.Exception
            $result.Latency = [int]$stopwatch.ElapsedMilliseconds
            Write-Log "TCP connection failed: $($result.Error)" -Level Debug
        } else {
            $result.Error = "Connection timeout after ${TimeoutMs}ms"
            $result.Latency = $TimeoutMs
            Write-Log "TCP connection timed out" -Level Debug
        }
    } catch {
        $result.Error = ConvertTo-ErrorMessage -Exception $_.Exception
        $result.Latency = [int]$stopwatch.ElapsedMilliseconds
        Write-Log "TCP connection error: $($result.Error)" -Level Debug
    } finally {
        $stopwatch.Stop()
        if ($tcpClient) { 
            $tcpClient.Close()
            $tcpClient.Dispose()
        }
    }
    
    return $result
}

function Test-HTTPSEndpoint {
    <#
    .SYNOPSIS
        Tests HTTPS connectivity to a full URL endpoint.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$URL,
        
        [Parameter(Mandatory=$true)]
        [ValidateRange(1, 600)]
        [int]$TimeoutSec
    )
    
    Write-Log "Testing HTTPS endpoint: $URL" -Level Debug
    
    $result = New-TestResult -Type "HTTPS" -Target $URL -AdditionalProperties @{
        StatusCode = $null
        HasAFDHeader = $false
        AzureRef = $null
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $response = Invoke-WebRequest -Uri $URL -Method GET -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        $result.StatusCode = $response.StatusCode
        $result.Latency = [int]$stopwatch.ElapsedMilliseconds
        
        $afdCheck = Test-AFDHeader -Headers $response.Headers -StatusCode $result.StatusCode
        $result.HasAFDHeader = $afdCheck.HasAFDHeader
        $result.AzureRef = $afdCheck.AzureRef
        $result.Success = $afdCheck.Success
        $result.Error = $afdCheck.Error
        
        if ($result.Success) {
            Write-Log "HTTPS endpoint reachable via AFD: HTTP $($result.StatusCode), x-azure-ref: $($result.AzureRef)" -Level Debug
        } else {
            Write-Log "HTTPS request succeeded but AFD header validation failed: $($result.Error)" -Level Debug
        }
    } catch {
        $result.Latency = [int]$stopwatch.ElapsedMilliseconds
        
        if ($_.Exception.Response) {
            $result.StatusCode = [int]$_.Exception.Response.StatusCode
            $afdCheck = Test-AFDHeader -Headers $_.Exception.Response.Headers -StatusCode $result.StatusCode
            $result.HasAFDHeader = $afdCheck.HasAFDHeader
            $result.AzureRef = $afdCheck.AzureRef
            $result.Success = $afdCheck.Success
            $result.Error = $afdCheck.Error
            Write-Log "HTTPS request failed: $($result.Error)" -Level Debug
        } else {
            $result.Error = $_.Exception.Message
            Write-Log "HTTPS request error: $($result.Error)" -Level Debug
        }
    } finally {
        $stopwatch.Stop()
    }
    
    return $result
}

#region Helper Functions

function Test-IsIPv6 {
    <#
    .SYNOPSIS
        Determines if an IP address is IPv6.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        return ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
    } catch {
        return $false
    }
}

function Test-IPv6Connectivity {
    <#
    .SYNOPSIS
        Tests if the network has IPv6 connectivity.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    Write-Log "Testing for IPv6 network connectivity..." -Level Debug
    
    $testEndpoints = @(
        @{ IP = "2620:1ec:c::10"; Name = "Microsoft DNS" }
    )
    
    foreach ($endpoint in $testEndpoints) {
        $tcpClient = $null
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
            $connectTask = $tcpClient.ConnectAsync($endpoint.IP, 443)
            
            if ($connectTask.Wait(3000) -and -not $connectTask.IsFaulted) {
                Write-Log "IPv6 connectivity detected via $($endpoint.Name)" -Level Debug
                return $true
            }
        } catch {
            Write-Log "IPv6 test to $($endpoint.Name) failed: $($_.Exception.Message)" -Level Debug
        } finally {
            if ($tcpClient) {
                $tcpClient.Close()
                $tcpClient.Dispose()
            }
        }
    }
    
    Write-Log "No IPv6 connectivity detected" -Level Debug
    return $false
}

#endregion

#region Testing Logic

function Test-AFDIPEndpoints {
    <#
    .SYNOPSIS
        Tests AFD IP endpoints using TCP connectivity checks.
    #>
    [CmdletBinding()]
    param()
    
    Write-LogSection -Title "Testing Azure Front Door IP address ranges"
    
    $groupedEndpoints = $script:AFDEndpoints | Group-Object -Property { $_.Description }
    $totalEndpoints = $script:AFDEndpoints.Count
    $currentEndpoint = 0
    
    foreach ($group in $groupedEndpoints) {
        $cidrRange = if ($group.Name -match '(\d+\.\d+\.\d+\.\d+/\d+|[0-9a-f:]+/\d+)') { $matches[1] } else { $group.Name }
        
        $rangeHasSuccess = $false
        $rangeIsIPv6Only = $true
        $rangeSkippedDueToNoIPv6 = $false
        
        foreach ($endpoint in $group.Group) {
            $currentEndpoint++
            $ip = $endpoint.IP
            $desc = $endpoint.Description
            
            Write-Log "Testing: $ip ($desc)" -Level Verbose
            
            $ipResult = @{
                IP = $ip
                Description = $desc
                Tests = @()
                Status = $null
            }
            
            $isIPv6 = Test-IsIPv6 -IPAddress $ip
            if (-not $isIPv6) { $rangeIsIPv6Only = $false }
            
            if ($isIPv6 -and -not $script:HasIPv6Connectivity) {
                Write-Log "Skipping IPv6 endpoint $ip (no IPv6 connectivity)" -Level Verbose
                $ipResult.Status = "IPV6_NO_NETWORK"
                $ipResult.Tests += @{ Success = $false; Error = "No IPv6 network connectivity"; Type = "SKIPPED"; Target = "${ip}:443" }
                $ipResult.Tests += @{ Success = $false; Error = "No IPv6 network connectivity"; Type = "SKIPPED"; Target = "${ip}:80" }
                $rangeSkippedDueToNoIPv6 = $true
                $script:Results.AFDTests += $ipResult
                continue
            }
            
            try {
                $tcp443 = Test-TCPConnection -IPAddress $ip -Port 443 -TimeoutMs $script:TCPTimeoutMs
                $tcp80 = Test-TCPConnection -IPAddress $ip -Port 80 -TimeoutMs $script:TCPTimeoutMs
                $ipResult.Tests += $tcp443
                $ipResult.Tests += $tcp80
                
                Write-Log "TCP:443 result for $ip : Success=$($tcp443.Success)" -Level Verbose
                Write-Log "TCP:80 result for $ip : Success=$($tcp80.Success)" -Level Verbose
            } catch {
                Write-Log "Unexpected error testing ${ip}: $($_.Exception.Message)" -Level Error
                $ipResult.Tests += @{ Success = $false; Error = $_.Exception.Message; Type = "TCP"; Target = "${ip}:443" }
                $ipResult.Tests += @{ Success = $false; Error = $_.Exception.Message; Type = "TCP"; Target = "${ip}:80" }
            }
            
            $tcp443Success = ($ipResult.Tests | Where-Object { $_.Target -like "*:443" }).Success
            $tcp80Success = ($ipResult.Tests | Where-Object { $_.Target -like "*:80" }).Success
            
            if ($tcp443Success -and $tcp80Success) {
                $ipResult.Status = "PASSED"
                $rangeHasSuccess = $true
                $script:Results.AFDTests += $ipResult
                break
            } else {
                $ipResult.Status = "FAILED"
            }
            
            $script:Results.AFDTests += $ipResult
        }
        
        if ($rangeIsIPv6Only -and $rangeSkippedDueToNoIPv6) {
            Write-Host "$cidrRange ... SKIPPED" -ForegroundColor Cyan
        } elseif ($rangeHasSuccess) {
            Write-Host "$cidrRange ... PASSED" -ForegroundColor Green
        } else {
            Write-Host "$cidrRange ... FAILED" -ForegroundColor Red
        }
    }
}

function Test-DomainEndpoint {
    <#
    .SYNOPSIS
        Tests the domain endpoint with full stack validation.
    #>
    [CmdletBinding()]
    param()
    
    Write-LogSection -Title "Testing service endpoint URL"
    
    $domainResult = @{
        Hostname = $script:DomainEndpoint.Hostname
        FullURL = $script:DomainEndpoint.FullURL
        Tests = @()
        Status = $null
    }
    
    Write-LogProgress -Activity "Testing service endpoint URL" -Status "Testing HTTPS endpoint" -PercentComplete 50
    Write-Host "  Service Endpoint ... " -NoNewline
    
    try {
        $https = Test-HTTPSEndpoint -URL $script:DomainEndpoint.FullURL -TimeoutSec $script:HTTPTimeoutSec
        $domainResult.Tests += $https
        
        if ($https.Success) {
            Write-Host "PASSED" -ForegroundColor Green
            Write-Log "HTTPS request successful: HTTP $($https.StatusCode)" -Level Verbose
            $domainResult.Status = "PASSED"
        } else {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Log "HTTPS request failed: $($https.Error)" -Level Warning
            $domainResult.Status = "HTTPS_FAILED"
        }
    } catch {
        Write-Host "Error" -ForegroundColor Red
        Write-Log "Unexpected error during HTTPS request: $($_.Exception.Message)" -Level Error
        $domainResult.Status = "HTTPS_ERROR"
        $domainResult.Tests += @{ Success = $false; Error = $_.Exception.Message; Type = "HTTPS" }
    }
    
    $script:Results.DomainTests += $domainResult
    Write-Progress -Activity "Testing service endpoint URL" -Completed
    Write-Host ""
}

#endregion

#region Reporting

function Show-Summary {
    <#
    .SYNOPSIS
        Displays test results and overall connectivity status.
    #>
    [CmdletBinding()]
    param()
    
    Write-LogSection -Title "Test Results"
    
    # Group results by CIDR range
    $rangeResults = $script:Results.AFDTests | Group-Object { 
        if ($_.Description -match '(\d+\.\d+\.\d+\.\d+/\d+|[0-9a-f:]+/\d+)') { $matches[1] } else { $_.Description }
    } | ForEach-Object {
        @{
            Range = $_.Name
            Tests = $_.Group
            HasSuccess = ($_.Group | Where-Object Status -eq "PASSED").Count -gt 0
            HasFailure = ($_.Group | Where-Object Status -eq "FAILED").Count -gt 0
            AllIPv6NoNetwork = ($_.Group | Where-Object Status -ne "IPV6_NO_NETWORK").Count -eq 0
            IsIPv6Range = $_.Name -match ':'
        }
    }
    
    # Calculate statistics using pipeline
    $stats = $rangeResults | Group-Object { 
        if ($_.AllIPv6NoNetwork) { 'Skipped' }
        elseif ($_.HasSuccess) { 'Passed' }
        else { 'Failed' }
    } | ForEach-Object { @{ $_.Name = $_.Count } }
    
    $rangesPassed = ($stats | Where-Object { $_.Passed }).Passed
    if ($null -eq $rangesPassed) { $rangesPassed = 0 }
    $rangesFailed = ($stats | Where-Object { $_.Failed }).Failed
    if ($null -eq $rangesFailed) { $rangesFailed = 0 }
    $rangesSkipped = ($stats | Where-Object { $_.Skipped }).Skipped
    if ($null -eq $rangesSkipped) { $rangesSkipped = 0 }
    $totalRanges = $rangeResults.Count
    
    $ipv4Stats = $rangeResults | Where-Object { -not $_.IsIPv6Range } | Group-Object {
        if ($_.HasSuccess) { 'Passed' } else { 'Failed' }
    } | ForEach-Object { @{ $_.Name = $_.Count } }
    
    $ipv4RangesPassed = ($ipv4Stats | Where-Object { $_.Passed }).Passed
    if ($null -eq $ipv4RangesPassed) { $ipv4RangesPassed = 0 }
    $ipv4RangesTotal = ($rangeResults | Where-Object { -not $_.IsIPv6Range }).Count
    $ipv6RangesTotal = ($rangeResults | Where-Object { $_.IsIPv6Range }).Count
    $ipv6RangesSkipped = ($rangeResults | Where-Object { $_.IsIPv6Range -and $_.AllIPv6NoNetwork }).Count
    
    $afdStatusColor = if ($rangesFailed -eq 0) { "Green" } else { "Red" }
    $domainResult = $script:Results.DomainTests[0]
    $domainStatusColor = if ($domainResult.Status -eq "PASSED") { "Green" } else { "Red" }
    
    Write-Host "Azure Front Door IP Addresses" -ForegroundColor $afdStatusColor
    
    if ($ipv4RangesTotal -gt 0) {
        $color = if ($ipv4RangesPassed -eq $ipv4RangesTotal) { "Gray" } elseif ($ipv4RangesPassed -gt 0) { "Yellow" } else { "Red" }
        Write-Host "  $ipv4RangesPassed/$ipv4RangesTotal IPv4 ranges reachable" -ForegroundColor $color
    }
    
    if ($ipv6RangesTotal -gt 0) {
        if ($ipv6RangesSkipped -gt 0) {
            Write-Host "  $ipv6RangesSkipped/$ipv6RangesTotal IPv6 ranges skipped (no IPv6 connectivity)" -ForegroundColor Cyan
        }
        $ipv6RangesTested = $ipv6RangesTotal - $ipv6RangesSkipped
        if ($ipv6RangesTested -gt 0) {
            $ipv6RangesPassed = $rangesPassed - $ipv4RangesPassed
            $color = if ($ipv6RangesPassed -eq $ipv6RangesTested) { "Gray" } elseif ($ipv6RangesPassed -gt 0) { "Yellow" } else { "Red" }
            Write-Host "  $ipv6RangesPassed/$ipv6RangesTested IPv6 ranges reachable" -ForegroundColor $color
        }
    }
    
    # Show failed IPs for ranges with no successes
    $failedRanges = $rangeResults | Where-Object { $_.HasFailure -and -not $_.HasSuccess -and -not $_.AllIPv6NoNetwork }
    foreach ($range in ($failedRanges | Sort-Object Range)) {
        $failedTests = $range.Tests | Where-Object Status -eq "FAILED"
        if ($failedTests) {
            Write-Host ""
            Write-Host "  Failed IPs in $($range.Range) :" -ForegroundColor Yellow
            foreach ($test in $failedTests) {
                $failedPorts = $test.Tests | Where-Object { -not $_.Success } | ForEach-Object {
                    if ($_.Target -match ':(\d+)$') { $matches[1] } else { 'unknown' }
                }
                Write-Host "    $($test.IP) - Ports: $($failedPorts -join ', ')" -ForegroundColor Red
            }
        }
    }
    
    Write-Host ""
    Write-Host "Service Endpoint" -ForegroundColor $domainStatusColor
    
    $endpointMessage = switch ($domainResult.Status) {
        "PASSED" { "HTTPS endpoint reachable" }
        "HTTPS_FAILED" { "HTTPS endpoint unreachable" }
        default { "HTTPS endpoint error" }
    }
    $endpointColor = if ($domainResult.Status -eq "PASSED") { "Gray" } else { "Red" }
    Write-Host "  $endpointMessage" -ForegroundColor $endpointColor
    
    Write-Host ""
    
    $allTestsPassed = ($rangesFailed -eq 0) -and ($domainResult.Status -eq "PASSED")
    Write-StatusLine -Label "Overall Status: " -Status $(if ($allTestsPassed) {"PASSED"} else {"FAILED"}) -StatusColor $(if ($allTestsPassed) {"Green"} else {"Red"})
    Write-Host ""
    
    if (-not $allTestsPassed) {
        Write-Host "Action: Review test results and update firewall rules" -ForegroundColor Yellow
    }
    
    $script:Results.Summary = @{
        OverallStatus = if ($allTestsPassed) {"PASSED"} else {"FAILED"}
        ExitCode = if ($allTestsPassed) {$script:EXIT_CODE_SUCCESS} else {$script:EXIT_CODE_FAIL}
        RangesPassed = $rangesPassed
        RangesFailed = $rangesFailed
        RangesSkipped = $rangesSkipped
        RangesTotal = $totalRanges
        DomainStatus = $domainResult.Status
        HasIPv6Connectivity = $script:HasIPv6Connectivity
    }
}

function Export-ResultsJSON {
    <#
    .SYNOPSIS
        Exports results to JSON format.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$OutputPath)
    
    try {
        $script:Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Log "JSON results saved to: $OutputPath" -Level Verbose
        return $true
    } catch {
        Write-Log "Failed to export JSON results: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Export-Results {
    <#
    .SYNOPSIS
        Exports test results to JSON format.
    #>
    [CmdletBinding()]
    param()
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "Intune_AFD_Connectivity_${timestamp}.json"
    $filepath = Join-Path $script:OutputPath $filename
    
    $success = Export-ResultsJSON -OutputPath $filepath
    
    if ($success) {
        Write-Host "Results saved to: $filename" -ForegroundColor Gray
    } else {
        Write-Log "Export failed. Check error messages above." -Level Warning
    }
    
    return $success
}

#endregion

#region Main Execution

try {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  $script:SCRIPT_NAME v$script:SCRIPT_VERSION" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host "(c) Microsoft Corporation" -ForegroundColor Gray
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    Write-Log "Starting Intune AFD Connectivity Checker v$script:SCRIPT_VERSION" -Level Verbose
    Write-Log "Configuration: CloudType=$CloudType, ASU=$ASU, Domain=$($config.Domain)" -Level Verbose
    
    if (-not $SkipPrerequisiteCheck) {
        if (-not (Test-Prerequisites)) {
            Write-Log "Prerequisite checks failed. Exiting." -Level Error
            Write-Host "Error: One or more prerequisite checks failed." -ForegroundColor Red
            Write-Host "Use -SkipPrerequisiteCheck to bypass validation (not recommended)." -ForegroundColor Yellow
            Write-Host ""
            exit $script:EXIT_CODE_ERROR
        }
    } else {
        Write-Log "Prerequisite checks skipped by user request" -Level Warning
    }
    
    Write-Log "Beginning connectivity tests" -Level Verbose
    Test-AFDIPEndpoints
    Test-DomainEndpoint
    
    Show-Summary
    
    Write-Host ""
    $exportSuccess = Export-Results
    Write-Host ""
    
    $exitCode = $script:Results.Summary.ExitCode
    if ($null -eq $exitCode) { $exitCode = $script:EXIT_CODE_ERROR }
    Write-Log "Script execution completed with exit code: $exitCode" -Level Info
    
    exit $exitCode
    
} catch {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Red
    Write-Host "CRITICAL ERROR" -ForegroundColor Red
    Write-Host ("=" * 70) -ForegroundColor Red
    Write-Host ""
    Write-Host "An unexpected error occurred during script execution:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Gray
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    Write-Host ""
    
    Write-Log "Critical error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Debug
    
    exit $script:EXIT_CODE_ERROR
}

#endregion

# SIG # Begin signature block
# MIIoQgYJKoZIhvcNAQcCoIIoMzCCKC8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBrFqAlYprXt990
# hNdG04jCuCIScJwIEV89IWBnvVYr4aCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
# 7A5ZL83XAAAAAASFMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjUwNjE5MTgyMTM3WhcNMjYwNjE3MTgyMTM3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDASkh1cpvuUqfbqxele7LCSHEamVNBfFE4uY1FkGsAdUF/vnjpE1dnAD9vMOqy
# 5ZO49ILhP4jiP/P2Pn9ao+5TDtKmcQ+pZdzbG7t43yRXJC3nXvTGQroodPi9USQi
# 9rI+0gwuXRKBII7L+k3kMkKLmFrsWUjzgXVCLYa6ZH7BCALAcJWZTwWPoiT4HpqQ
# hJcYLB7pfetAVCeBEVZD8itKQ6QA5/LQR+9X6dlSj4Vxta4JnpxvgSrkjXCz+tlJ
# 67ABZ551lw23RWU1uyfgCfEFhBfiyPR2WSjskPl9ap6qrf8fNQ1sGYun2p4JdXxe
# UAKf1hVa/3TQXjvPTiRXCnJPAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUuCZyGiCuLYE0aU7j5TFqY05kko0w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwNTM1OTAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBACjmqAp2Ci4sTHZci+qk
# tEAKsFk5HNVGKyWR2rFGXsd7cggZ04H5U4SV0fAL6fOE9dLvt4I7HBHLhpGdE5Uj
# Ly4NxLTG2bDAkeAVmxmd2uKWVGKym1aarDxXfv3GCN4mRX+Pn4c+py3S/6Kkt5eS
# DAIIsrzKw3Kh2SW1hCwXX/k1v4b+NH1Fjl+i/xPJspXCFuZB4aC5FLT5fgbRKqns
# WeAdn8DsrYQhT3QXLt6Nv3/dMzv7G/Cdpbdcoul8FYl+t3dmXM+SIClC3l2ae0wO
# lNrQ42yQEycuPU5OoqLT85jsZ7+4CaScfFINlO7l7Y7r/xauqHbSPQ1r3oIC+e71
# 5s2G3ClZa3y99aYx2lnXYe1srcrIx8NAXTViiypXVn9ZGmEkfNcfDiqGQwkml5z9
# nm3pWiBZ69adaBBbAFEjyJG4y0a76bel/4sDCVvaZzLM3TFbxVO9BQrjZRtbJZbk
# C3XArpLqZSfx53SuYdddxPX8pvcqFuEu8wcUeD05t9xNbJ4TtdAECJlEi0vvBxlm
# M5tzFXy2qZeqPMXHSQYqPgZ9jvScZ6NwznFD0+33kbzyhOSz/WuGbAu4cHZG8gKn
# lQVT4uA2Diex9DMs2WHiokNknYlLoUeWXW1QrJLpqO82TLyKTbBM/oZHAdIc0kzo
# STro9b3+vjn2809D0+SOOCVZMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGiIwghoeAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAASFXpnsDlkvzdcAAAAABIUwDQYJYIZIAWUDBAIB
# BQCggcYwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINvKgRhi0fGKUbeti2V0Sa6J
# Ma+g11d3ONsmibtNKH8xMFoGCisGAQQBgjcCAQwxTDBKoCyAKgBNAGkAYwByAG8A
# cwBvAGYAdAAgAEMAbwByAHAAbwByAGEAdABpAG8AbqEagBhodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEArNZJyYahli4bDmdI9ZZgCUPA
# ClKzbyiq/FkY4Y/vmUW3mmxQYWquatOch/nORmHuaDPzEQjPYkV/T3LB0DdoF2R1
# Dr+V+wbF1Zpd2w3p1y9l3QdIbOBOylH6WCw5zh4IUxxDf4Gdppi+HZnsyQtwjIK7
# CHuNLPdSuTjYvOlTvZq2kuB4JTDCeT7Wc6wEzK/5E/hJWjzdHQ+mOseN7FyUP+SH
# QvbId9AzFm6LV5HEFyLltr0ESw4U6xblEKuXE6ra4oI258xbig22oQF44NapmOez
# N0V8IcB8xXxZ67sKEPHgg5GI+O1ams5uUYr0adPDpSwIShshFe83xCyM+bouOqGC
# F5QwgheQBgorBgEEAYI3AwMBMYIXgDCCF3wGCSqGSIb3DQEHAqCCF20wghdpAgED
# MQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEEggE9MIIBOQIB
# AQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAOJfyL80V2COGLxwaJoaEL
# xchiKykHskzk/DylYpwIbwIGaSTlfJ67GBMyMDI1MTIwNDIxMTg0Ni4wNjlaMASA
# AgH0oIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQL
# Ex5uU2hpZWxkIFRTUyBFU046QTAwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghHqMIIHIDCCBQigAwIBAgITMwAAAgh4
# nVhdksfZUgABAAACCDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQyNTNaFw0yNjA0MjIxOTQyNTNaMIHLMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNy
# b3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBF
# U046QTAwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC1y3AI5lIz
# 3Ip1nK5BMUUbGRsjSnCz/VGs33zvY0NeshsPgfld3/Z3/3dS8WKBLlDlosmXJOZl
# FSiNXUd6DTJxA9ik/ZbCdWJ78LKjbN3tFkX2c6RRpRMpA8sq/oBbRryP3c8Q/gxp
# JAKHHz8cuSn7ewfCLznNmxqliTk3Q5LHqz2PjeYKD/dbKMBT2TAAWAvum4z/HXIJ
# 6tFdGoNV4WURZswCSt6ROwaqQ1oAYGvEndH+DXZq1+bHsgvcPNCdTSIpWobQiJS/
# UKLiR02KNCqB4I9yajFTSlnMIEMz/Ni538oGI64phcvNpUe2+qaKWHZ8d4T1Kghv
# RmSSF4YF5DNEJbxaCUwsy7nULmsFnTaOjVOoTFWWfWXvBuOKkBcQKWGKvrki976j
# 4x+5ezAP36fq3u6dHRJTLZAu4dEuOooU3+kMZr+RBYWjTHQCKV+yZ1ST0eGkbHXo
# A2lyyRDlNjBQcoeZIxWCZts/d3+nf1jiSLN6f6wdHaUz0ADwOTQ/aEo1IC85eFeP
# vyIKaxFJkGU2Mqa6Xzq3qCq5tokIHtjhogsrEgfDKTeFXTtdhl1IPtLcCfMcWOGG
# AXosVUU7G948F6W96424f2VHD8L3FoyAI9+r4zyIQUmqiESzuQWeWpTTjFYwCmgX
# aGOuSDV8cNOVQB6IPzPneZhVTjwxbAZlaQIDAQABo4IBSTCCAUUwHQYDVR0OBBYE
# FKMx4vfOqcUTgYOVB9f18/mhegFNMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
# KDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBR
# szKJKwAfswqdaQPFiaYB/ZNAYWDa040XTcQsCaCua5nsG1IslYaSpH7miTLr6eQE
# qXczZoqeOa/xvDnMGifGNda0CHbQwtpnIhsutrKO2jhjEaGwlJgOMql21r7Ik6Xn
# Bza0e3hBOu4UBkMl/LEX+AURt7i7+RTNsGN0cXPwPSbTFE+9z7WagGbY9pwUo/Nx
# kGJseqGCQ/9K2VMU74bw5e7+8IGUhM2xspJPqnSeHPhYmcB0WclOxcVIfj/ZuQvw
# orPbTEEYDVCzSN37c0yChPMY7FJ+HGFBNJxwd5lKIr7GYfq8a0gOiC2ljGYlc4rt
# 4cCed1XKg83f0l9aUVimWBYXtfNebhpfr6Lc3jD8NgsrDhzt0WgnIdnTZCi7jxjs
# IBilH99pY5/h6bQcLKK/E6KCP9E1YN78fLaOXkXMyO6xLrvQZ+uCSi1hdTufFC7o
# SB/CU5RbfIVHXG0j1o2n1tne4eCbNfKqUPTE31tNbWBR23Yiy0r3kQmHeYE1GLbL
# 4pwknqaip1BRn6WIUMJtgncawEN33f8AYGZ4a3NnHopzGVV6neffGVag4Tduy+oy
# 1YF+shChoXdMqfhPWFpHe3uJGT4GJEiNs4+28a/wHUuF+aRaR0cN5P7XlOwU1360
# iUCJtQdvKQaNAwGI29KOwS3QGriR9F2jOGPUAlpeEzCCB3EwggVZoAMCAQICEzMA
# AAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMw
# MDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3u
# nAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1
# jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZT
# fDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+
# jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c
# +gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+
# cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C6
# 26p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV
# 2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoS
# CtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxS
# UV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJp
# xq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkr
# BgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYI
# KwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9S
# ZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
# HSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1
# dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwEx
# JFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts
# 0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9I
# dQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYS
# EhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMu
# LGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT9
# 9kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2z
# AVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6Ile
# T53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6l
# MVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbh
# IurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3u
# gm2lBRDBcQZqELQdVTNYs6FwZvKhggNNMIICNQIBATCB+aGB0aSBzjCByzELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9z
# b2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNO
# OkEwMDAtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCNkvu0NKcSjdYKyrhJZcsyXOUTNKCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUA
# AgUA7NvpBDAiGA8yMDI1MTIwNDExMDMzMloYDzIwMjUxMjA1MTEwMzMyWjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDs2+kEAgEAMAcCAQACAg92MAcCAQACAhjgMAoC
# BQDs3TqEAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAL5fwAw8rLp5GPC5
# +9eCP6PlAxway42SCfSZnXYihZmtOWEFOCrk3aTvPld5hIVRfUqhweiAT6/WM/as
# uzmqloBC36Th0rcLKiCx5K2xbL6YHh8WtD9+KLy0QJen7NlaS8IYXf2DiImQHqW3
# KlWaYosZESGXgmmMQNWmd4dzScjaIL/Wnw+zak6X/3GNIl5fVFE6nLeLJgjyZbZb
# Lkj+SGdPP0ETnS53RSDtTBCY6SqQSzvjYkEmJ+B4oE5zJfD7BBfS7rJWYOzwBecq
# K++nQu8Ex4kSV7oJlWJats/zGwXAj/9ZAjKMivwbnNWJwghJwYUGo+Od2sUrL/N0
# Rp8zDckxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MAITMwAAAgh4nVhdksfZUgABAAACCDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCB9H271RjfX9kaD
# Wboi27GTO08/p16WjxO2pUG3OuFbFjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQw
# gb0EII//jm8JHa2W1O9778t9+Ft2Z5NmKqttPk6Q+9RRpmepMIGYMIGApH4wfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIIeJ1YXZLH2VIAAQAAAggw
# IgQg70N+la3A4Dqz960pgl3TGwAZWspWV/Gt/OyyVos/3n8wDQYJKoZIhvcNAQEL
# BQAEggIAWa1ljJY6wDPcqYGr6deWAt4E7sFoRu2+ffPob+ZfgTAKa8prJl/S2gcJ
# H2ewFz8PHFfH4EzQewUcQhfXyHGXFxB+j5WqGOqeD4egJXWy+VN5WlgO1MMcxHKU
# NQqhl+r1T6He853IxdkFoCi+KLq0/WbcNnu4Z/72ifuLjH+gxu6no2pBOtO8btq7
# LISm3FiwWMU/40gdLMRfZtkphhbIZ38BY5P7o8SgYesSngEeSqtxA8Zw03aveeuD
# q8ytKCTnKiUxqDyAWOlqmH6enJ8JQ1w1AvUJRbtws/LFND4d369N7talhwz5eqL9
# sbTMkIMDNogcM3Hhyd7pkOxjZXTtsEtbCb23uxH3wjoI6FoXbWoE+qC4UQSMKV+h
# XAcnz3BOd7tKSaqDZnqcUGo847LOzAJQ3bHdQSGBC8gaqTlLd5Txz1N5U8os2+Va
# kTlnkVyvLcCCtsju6eZYOaQH4oUsh3b3M16nmjXCo9xIf76sVIqsNx1652giGMPF
# i7HTsHQf3rnpVvXPzqp9vuhMpLnCJx9jSzjyv5l/ro89HrKv6MYT57y105AHmicO
# Lf0ddW9OjdES38X4hYeYmTeY3HvQ3QFTUmxEMJvG0JH8bq4F9wGrHG0PF6lAfoyR
# C8D9+U8aZ2ZxMjJij+uOs9VdgubfPAFc1Ib0i6h3xESj0EQUz6E=
# SIG # End signature block
