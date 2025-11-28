<#  MEM UR Log Collector #>
#Requires -RunAsAdministrator
#----------------------------------------------------------------------------------------------------------
#
#                                          Parameter Declarations
#
#----------------------------------------------------------------------------------------------------------

Param(
# File share to store logs, the maximum length is 130 since the script would create sub folders and files 
[Parameter(Position=1)]
[string]$LogPath,

# LogMode == 0 log to console only
# LogMode == 1 log to file and console
# LogMode == 2 log to file only
[Parameter(Position=2)]
[Int16]$LogMode = 1,

# CollectNetTrace == 0 to disable collect Net Trace, otherwise enable collect Net Trace.
[Parameter(Position=3)]
[Int16]$CollectNetTrace = 0,

# CollectUTCTrace == 0 to disable collect UTC Trace, otherwise enable collect UTC Trace.
[Parameter(Position=4)]
[Int16]$CollectUTCTrace = 0
)

#----------------------------------------------------------------------------------------------------------
#
#                                          Startup
#
#----------------------------------------------------------------------------------------------------------

# Make sure we are running x64 PS on 64-bit OS. If not then start a x64 process of PowerShell
$powerShellHome = $PSHOME.ToLower()
if ([System.Environment]::Is64BitOperatingSystem -eq $true)
{
    if ([System.Environment]::Is64BitProcess -eq $false)
    {
        Write-Verbose "Launching x64 PowerShell"
        $powerShellHome = $powerShellHome.Replace('syswow64','sysnative')
        &"$powerShellHome\powershell.exe" -ExecutionPolicy AllSigned -NonInteractive -NoProfile $myInvocation.Line
        exit $lastexistcode
    }
}

#----------------------------------------------------------------------------------------------------------
#
#                                          Parameter Intialization and Validation 
#
#----------------------------------------------------------------------------------------------------------

# Parameter: $LogPath
if([String]::IsNullOrEmpty($LogPath) -or [String]::IsNullOrWhiteSpace($LogPath))
{
    # Set to default value
    $LogPath = "$Env:SystemDrive\MemUpgradeReadinessLogs"
}
else
{
    Write-Verbose "Validating path length no more than 130: $LogPath"
    $LogPath = $LogPath.Trim().TrimEnd('\')
    if($LogPath.Length -gt 130)
    {
        throw "Failed to validate the length of the given path: $LogPath"
    }

    # Validate parameter: $LogPath
    Write-Verbose "Validating path format: $LogPath"
    $validateResult = $false

    if((Test-Path $LogPath -IsValid) -eq $true)
    {
        $testSplitArray = $LogPath.Split(':')

        if($testSplitArray.Count -eq 1)
        {
            $validateResult = $true
        }
        elseif($testSplitArray.Count -eq 2)
        {
            $targetDrv = Get-PSDrive -Name $testSplitArray[0]   

            if($targetDrv -ne $null)
            {
                $fileDrv = Get-PSProvider -PSProvider FileSystem

                if($fileDrv -ne $null)
                {
                    if($fileDrv.Drives.Contains($targetDrv) -eq $true)
                    {
                         $validateResult = $true
                    }
                }
            }
        }
    }

    if($validateResult -eq $false)
    {
        throw "Failed to validate the format of the given path: $LogPath"
    }
}

Write-Verbose "Output Path = $LogPath"

# Parameter: $LogMode
Write-Verbose "Validating log mode(0|1|2): $LogMode"

if(($LogMode -ne 0) -and ($LogMode -ne 1) -and ($LogMode -ne 2))
{
    throw "Failed to validate the given log mode: $LogMode"
}

Write-Verbose "Log Mode = $LogMode"

# Parameter: $CollectNetTrace
if($CollectNetTrace -eq 0)
{
    Write-Verbose "Collect Net Trace = No"
}
else
{
    Write-Verbose "Collect Net Trace = Yes"
}

# Parameter: $CollectUTCTrace
if($CollectUTCTrace -eq 0)
{
    Write-Verbose "Collect UTC Trace = No"
}
else
{
    Write-Verbose "Collect UTC Trace = Yes"
}


#----------------------------------------------------------------------------------------------------------
#
#                                          Global Variables
#
#----------------------------------------------------------------------------------------------------------

# Temporary file to store providers
$global:tempProviderFile = [System.IO.Path]::GetTempFileName()

# Providers info
$global:providersText = @"
{43ac453b-97cd-4b51-4376-db7c9bb963ac}	0	255
{56DC463B-97E8-4B59-E836-AB7C9BB96301}	0	255
"@

# Script folder root
$global:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path

# Set the exit code to the first exception exit code
$global:errorCode = [string]::Empty;

# Total error count while running the script
[int]$global:errorCount = 0;

# OS version
$global:osVersion = (Get-WmiObject Win32_OperatingSystem).Version

# OS name
$global:operatingSystemName = (Get-WmiObject Win32_OperatingSystem).Name

# OS Architecture
$global:osArchitecture = $ENV:Processor_Architecture

# Global utc trace name
$global:timeStart=Get-Date
$global:timeStartString=$global:timeStart.ToString("yy_MM_dd_HH_mm_ss")
$global:utcTraceName = "utctrace" + $global:timeStartString

#----------------------------------------------------------------------------------------------------------------
#
#                                                   Main
#
#----------------------------------------------------------------------------------------------------------------

$main = {
    Try
    {    
        # Initialize provider file
        InitializeProviderFile

        # Quit if System variable WINDIR is not set
        Try
        {
            $global:windir=[System.Environment]::ExpandEnvironmentVariables("%WINDIR%")
        }
        Catch
        {
            $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
            Write-Error "Failure finding system variable WINDIR. $exceptionDetails Error 23"
            [System.Environment]::Exit(23)
        }

        # Create the log file if logMode requires logging to file.
        CreateLogFile

        Log "Starting MEMURLogsCollector"
        Log "UTC DateTime: $global:utcDate"
        Log "OS: $global:osVersion"
        Log "Architecture: $global:osArchitecture"

        # Sets VerboseMode to enable appraiser logging value to the registry
        SetAppraiserVerboseMode

        # Sets RequestAllAppraiserVersions key
        if($global:osBuildNumber -lt 10240)
        {
            SetRequestAllAppraiserVersions
        }

        if($CollectNetTrace -ne 0)
        {
            # Start Netsh trace
            StartNetworkTrace
        }

        if($CollectUTCTrace -ne 0)
        {
            #Start UTC trace
            StartUTCTrace
        }

        # restart Diagtrack service
        RestartDiagtrack

        # Run Connectivity Tool
        RunConnectivityDiagnosis

        # Run Census
        RunCensus

        if($CollectNetTrace -ne 0)
        {
            # Stop Netsh trace
            StopNetworkTrace
        }        

        if($CollectUTCTrace -ne 0)
        {
            # Stop UTC trace
            StopUTCTrace
        }        

        # Run Appraiser
        RunAppraiser

        # Collect the logs
        Try
        {
            Log "Running diagnose_internal to collect logs"
            DiagnoseInternal $global:logFolder
        }
        Catch
        {
            Log "diagnose_internal failed with unexpected exception" "Error" "37" "diagnose_internal" $_.Exception.HResult $_.Exception.Message
        }

        if($global:errorCount -eq 0)
        {
            Log "Script finished successfully"
            Exit(0)
        }
    }
    Catch
    {
        Log "Unexpected error occured while executing the script" "Error" "1" "UnExpectedException" $_.Exception.HResult $_.Exception.Message
        Log "Script failed" "Failure" "1" "ScriptEnd"
        [System.Environment]::Exit(1)
    }
    Finally
    {
        # Disable appriaser verbose mode after running the appriaser
        DisableAppraiserVerboseMode

        # Restart Diagtrack service
        RestartDiagtrack

        # Cleanup temporary file
        Remove-Item -Path $global:tempProviderFile
    }
}

#----------------------------------------------------------------------------------------------------------
#
#                                          Function Definitions
#
#----------------------------------------------------------------------------------------------------------

function InitializeProviderFile
{
    $global:providersText | Out-File $global:tempProviderFile -Append -Encoding ascii
}

function DiagnoseInternal($diaLogPath)
{
    if ((test-path $diaLogPath) -eq $false)
    {
        New-Item -ItemType Directory -Path $diaLogPath -Force | Out-Null
    }

    Get-WmiObject -Query 'select * from win32_quickfixengineering' | sort hotfixid | Out-File "$diaLogPath\installedKBs.txt" -Force

    ROBOCOPY "$env:windir\appcompat" "$diaLogPath\appcompat" *.* /E /XF *.hve* /R:1  | Out-Null

    regedit /e "$diaLogPath\RegAppCompatFlags.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
    regedit /e "$diaLogPath\RegCensus.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Census"
    regedit /e "$diaLogPath\RegDiagTrack.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
    regedit /e "$diaLogPath\RegPoliciesDataCollection.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    regedit /e "$diaLogPath\RegDataCollection.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
}

function CreateLogFile
{
    Write-Verbose "Creating output folder"
    $timeStart=Get-Date
    $timeStartString=$timeStart.ToString("yy_MM_dd_HH_mm_ss")
    $logFolderName = "MEMURLogs_" + $timeStartString
    $global:logFolder = $logPath +"\"+$logFolderName

    Try
    {   
        $outputFolder = New-Item $global:logFolder -type directory
        Write-Host "Output folder created successfully: $outputFolder"
    }
    Catch
    {
        $hexHresult = "{0:X}" -f $_.Exception.HResult
        $exceptionMessage = $_.Exception.Message
        Write-Error "Could not create output folder at the given logPath: $LogPath`nException: $exceptionMessage HResult:  0x$hexHresult"
        [System.Environment]::Exit(28)
    }

    if($LogMode -ne 0)
    {
        Write-Verbose "Creating Log File"
        $fileName = $logFolderName+".txt"
        $global:logFile=$global:logFolder+"\"+$fileName

        Try
        {
            New-Item $global:logFile -type file | Out-Null
            Write-Verbose "Log File created successfully: $global:logFile"
        }
        Catch
        {
            $hexHresult = "{0:X}" -f $_.Exception.HResult
            $exceptionMessage = $_.Exception.Message
            Write-Error "Could not create log file at the given logPath: $LogPath`nException: $exceptionMessage HResult:  0x$hexHresult"
            [System.Environment]::Exit(28)
        }
    }
}

function StartNetworkTrace
{
    Try
    {
        Log "Start: StartNetworkTrace"
        netsh trace start capture=yes scenario=InternetClient provider=Microsoft-Windows-CAPI2 traceFile="$global:logFolder\nettrace.etl" | Out-Null
        Log "Passed: StartNetworkTrace"
    }
    Catch
    {
        Log "StartNetworkTrace failed with an unexpected exception." "Error" "2001" "StartNetworkTrace" $_.Exception.HResult $_.Exception.Message
    }
}

function StartUTCTrace
{
    Try
    {
        Log "Start: StartUTCTrace"

        $logmanFolder = $null
        if($global:osArchitecture.contains("64"))
        {
            $logmanFolder = "$global:windir\system32\"
        }
        else
        {
            $logmanFolder = "$global:windir\system32\"
        }

        & logman start $global:utcTraceName -pf "$global:tempProviderFile" -bs 32768 -nb 128 -ets -o "$global:logFolder\DAUTCtrace.etl" | Out-Null

        Log "Passed: StartUTCTrace"
    }
    Catch
    {
        Log "StartUTCTrace failed with an unexpected exception." "Error" "2003" "StartUTCTrace" $_.Exception.HResult $_.Exception.Message
    }   
}

function StopNetworkTrace
{
    Try
    {
        Log "Start: StopNetworkTrace"
        netsh trace stop | Out-Null
        Log "Passed: StopNetworkTrace"
    }
    Catch
    {
        Log "StopNetworkTrace failed with an unexpected exception." "Error" "2002" "StopNetworkTrace" $_.Exception.HResult $_.Exception.Message
    }
}

function StopUTCTrace
{
    Try
    {
        Log "Start: StopUTCTrace"

        $logmanFolder = $null
        if($global:osArchitecture.contains("64"))
        {
            $logmanFolder = "$global:windir\system32\"
        }
        else
        {
            $logmanFolder = "$global:windir\system32\"
        }

        & logman.exe stop $global:utcTraceName -ets | Out-Null

        Log "Passed: StopUTCTrace"
        Log "Collect DownloadedSettings to log folder"
        & takeown -f "$Env:ProgramData\Microsoft\Diagnosis\DownloadedSettings\*" | Out-Null
        & icacls "$Env:ProgramData\Microsoft\Diagnosis\DownloadedSettings\*" /grant administrators:f | Out-Null
        New-Item $global:logFolder\DownloadedSettings -type directory | Out-Null
        Copy-Item "$Env:ProgramData\Microsoft\Diagnosis\DownloadedSettings\*" -Destination $global:logFolder\DownloadedSettings | Out-Null
    }
    Catch
    {
        Log "StopUTCTrace failed with an unexpected exception." "Error" "2004" "StopUTCTrace" $_.Exception.HResult $_.Exception.Message
    } 

}

function RestartDiagtrack
{
    Log "Start: RestartDiagtrack"
    Try
    {
        & Net stop diagtrack | Out-Null
        & Reg add hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\testhooks /v ResetEventStore /t REG_DWORD /d 1 /f | Out-Null 
        & Net start diagtrack | Out-Null 
        & Reg delete hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\testhooks /v ResetEventStore /f | Out-Null
        Log "Passed: RestartDiagtrack"
    }    
    Catch
    {
        Log "RestartDiagtrack failed to execute - script will continue." "Warning" $null "RestartDiagtrack" $_.Exception.HResult $_.Exception.Message
        return
    }
}

function RunConnectivityDiagnosis
{
    Log "Start: RunConnectivityDiagnosis"
    Try
    {
        $propertyPath = "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global"
        if(Test-Path -Path $propertyPath)
        {
            if ((Get-ItemProperty -Path $propertyPath -Name LogDirectory -ErrorAction SilentlyContinue) -eq $null)
            {
	            Log "Could not find registry key LogDirectory at path HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global"
            }
            else
            {
                Try
                {
                    $logDirectoryKeyMemUr = Get-ItemProperty -Path $propertyPath -Name LogDirectory
                    $logDirectoryMemUr = $logDirectoryKeyMemUr.LogDirectory
                    $connectivitydiagnosis = $logDirectoryMemUr.ToString().Replace("Logs", "settingsplugins\connectivitydiagnosis.exe")

                    if((Test-Path -Path $connectivitydiagnosis) -eq $False)
                    {
                       $connectivitydiagnosis = $logDirectoryMemUr.ToString().Replace("Logs", "connectivitydiagnosis.exe") 
                    }

	            }
	            Catch {
		            Log "Error running RunConnectivityDiagnosis" "Warning" $null "RunConnectivityDiagnosis" $_.Exception.HResult $_.Exception.Message
                    return
	            }
            }
        }
        else {
            Log "RunConnectivityDiagnosis: HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global not found. Falling back to script root directory" "Warning"
            # fall back to see if executable exists in script root directory
            $connectivitydiagnosis = Join-Path $global:scriptRoot "connectivitydiagnosis.exe"
            if (-not (Test-Path -Path $connectivitydiagnosis)) {
                Log "Error running RunConnectivityDiagnosis" "Warning" $null "RunConnectivityDiagnosis" "Could not find ConnectivityDiagnosis.exe"
                return
            }
        }

        #Log $connectivitydiagnosis
        #Log $logDirectoryMemUr
        $currentDirectory = $global:scriptRoot
        & cd $global:logFolder
        & timeout 5 | Out-Null
        & $connectivitydiagnosis -verbose > ConnectivityDiagnosis.txt 
        & timeout 5 | Out-Null
        & cd $currentDirectory
        Log "Passed: RunConnectivityDiagnosis"

    }
    Catch
    {
	    Log "Error running RunConnectivityDiagnosis" "Warning" $null "RunConnectivityDiagnosis" $_.Exception.HResult $_.Exception.Message
    }
}

function SetAppraiserVerboseMode
{
    Log "Start: SetAppraiserVerboseMode"
    Try
    {
        $vAppraiserPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser"
        Log "Enabling Appraiser logs for debugging by setting VerboseMode property to 1 at the registry key path: $vAppraiserPath"
        if ((Get-ItemProperty -Path $vAppraiserPath -Name VerboseMode -ErrorAction SilentlyContinue) -eq $null)
        {
	    Try
            {
		New-ItemProperty -Path $vAppraiserPath -Name VerboseMode -PropertyType DWord -Value 1 | Out-Null
	    }
	    Catch
            {
		Log "SetAppraiserVerboseMode failed to write the VerboseMode property at registry key $vAppraiserPath. This is not fatal, script will continue." "Warning" $null "SetAppraiserVerboseMode" $_.Exception.HResult $_.Exception.Message
                return
	    }
        }
        else
        {
	    Log "Appraiser verbose mode is already enabled"
        }

        Log "Enabling Appraiser logs for debugging by setting TestHooksEnabled property to 1 at the registry key path: $vAppraiserPath"
        if ((Get-ItemProperty -Path $vAppraiserPath -Name TestHooksEnabled -ErrorAction SilentlyContinue) -eq $null)
        {
	    Try
            {
		New-ItemProperty -Path $vAppraiserPath -Name TestHooksEnabled -PropertyType DWord -Value 1 | Out-Null
	    }
	    Catch
            {
		Log "SetAppraiserVerboseMode failed to write the TestHooksEnabled property at registry key $vAppraiserPath. This is not fatal, script will continue." "Warning" $null "SetAppraiserVerboseMode" $_.Exception.HResult $_.Exception.Message
                return
	    }
        }
        else
        {
	    Log "Appraiser TestHooksEnabled property is already set"
        }

        Log "Passed: SetAppraiserVerboseMode"
    }
    Catch
    {
	Log "SetAppraiserVerboseMode failed with unexpected exception. This is not fatal, script will continue." "Warning" $null "SetAppraiserVerboseMode" $_.Exception.HResult $_.Exception.Message
    }
}

function DisableAppraiserVerboseMode
{
    Log "Start: DisableAppraiserVerboseMode"
    Try
    {
        $vAppraiserPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser"
        if ((Get-ItemProperty -Path $vAppraiserPath -Name VerboseMode -ErrorAction SilentlyContinue) -ne $null)
        {
	    Try
            {
		Remove-ItemProperty -Path $vAppraiserPath -Name VerboseMode
	    }
	    Catch
            {
		Log "DisableAppraiserVerboseMode failed deleting VerboseMode property at registry key path: $vAppraiserPath. This is not fatal, script will continue." "Warning" $null "DisableAppraiserVerboseMode" $_.Exception.HResult $_.Exception.Message
	    }
        }
        else
        {
	    Log "Appraiser VerboseMode key already deleted"
        }

        Log "Passed: DisableAppraiserVerboseMode"
    }
    Catch
    {
	Log "DisableAppraiserVerboseMode failed with unexpected exception. This is not fatal, script will continue." "Warning" $null "DisableAppraiserVerboseMode" $_.Exception.HResult $_.Exception.Message
    }
}

function SetRequestAllAppraiserVersions
{
    Log "Start: SetRequestAllAppraiserVersions"
    Try
    {
        $propertyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        $propertyGPOPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if(Test-Path -Path $propertyPath)
        {
            if ((Get-ItemProperty -Path $propertyPath -Name RequestAllAppraiserVersions -ErrorAction SilentlyContinue) -eq $null)
            {
	        Try
                {
		    New-ItemProperty -Path $propertyPath -Name RequestAllAppraiserVersions -PropertyType DWord -Value 1 | Out-Null
	        }
	        Catch
                {
		    Log "SetRequestAllAppraiserVersions failed setting RequestAllAppraiserVersions property at registry key path: $propertyPath" "Error" "20" "SetRequestAllAppraiserVersions" $_.Exception.HResult $_.Exception.Message
                    return
                }
            }
            else
            {
                Try
                {
		    Set-ItemProperty -Path $propertyPath -Name RequestAllAppraiserVersions -Value 1
	        }
	        Catch
                {
		    Log "SetRequestAllAppraiserVersions failed setting RequestAllAppraiserVersions property at registry key path: $propertyPath" "Error" "20" "SetRequestAllAppraiserVersions" $_.Exception.HResult $_.Exception.Message
                    return
	        }
            }
        }

        if(Test-Path -Path $propertyGPOPath)
        {
            if ((Get-ItemProperty -Path $propertyGPOPath -Name RequestAllAppraiserVersions -ErrorAction SilentlyContinue) -eq $null)
            {
	        Try
                {
		    New-ItemProperty -Path $propertyGPOPath -Name RequestAllAppraiserVersions -PropertyType DWord -Value 1 | Out-Null
	        }
	        Catch
                {
		    Log "SetRequestAllAppraiserVersions failed setting RequestAllAppraiserVersions property at registry key path: $propertyGPOPath" "Error" "20" "SetRequestAllAppraiserVersions" $_.Exception.HResult $_.Exception.Message
                    return
	        }
            }
            else
            {
                Try
                {
		    Set-ItemProperty -Path $propertyPath -Name RequestAllAppraiserVersions -Value 1
	        }
	        Catch
                {
		    Log "SetRequestAllAppraiserVersions failed setting RequestAllAppraiserVersions property at registry key path: $propertyGPOPath" "Error" "20" "SetRequestAllAppraiserVersions" $_.Exception.HResult $_.Exception.Message
                    return
	        }
            }
        }

        Log "Passed: SetRequestAllAppraiserVersions"
    }
    Catch
    {
	Log "SetRequestAllAppraiserVersions failed with unexpected exception." "Error" "21" "SetRequestAllAppraiserVersions" $_.Exception.HResult $_.Exception.Message
    }
}

function RunAppraiser
{
    Try
    {
	Log "Start: RunAppraiser"
        Log "Attempting to run inventory...This may take a few minutes to complete, please do not cancel the script."

        do
        {
            CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun ent | out-null
            $appraiserLastExitCode = $LASTEXITCODE
            $appraiserLastExitCodeHex = "{0:X}" -f $appraiserLastExitCode

            if($appraiserLastExitCode -eq 0x80070021)
            {
                Log "RunAppraiser needs to run CompatTelRunner.exe, but it is already running. Waiting for 60 seconds before retry."
                Start-Sleep -Seconds 60
            }
            else
            {
                break
            }

            $NoOfAppraiserRetries = $NoOfAppraiserRetries - 1

        }While($NoOfAppraiserRetries -gt 0)

	if ($appraiserLastExitCode -ne 0x0)
        {
            if ($appraiserLastExitCode -lt 0x0)
            {
		Log "RunAppraiser failed. CompatTelRunner.exe exited with last error code: 0x$appraiserLastExitCodeHex."  "Error" "33" "RunAppraiser" "0x$appraiserLastExitCodeHex" "CompatTelRunner.exe returned with an error code."
            }
            else
            {
                Log "RunAppraiser succeeded with a return code: 0x$appraiserLastExitCodeHex."
            }
	    }
        else
        {
            Log "Passed: RunAppraiser"
	}
    }
    Catch
    {
        Log "RunAppraiser failed with unexpected exception." "Error" "22" "RunAppraiser" $_.Exception.HResult $_.Exception.Message
    }
}

function RunCensus
{
    Log "Start: RunCensus"
    Try
    {
        $censusRunRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Census"

        if($(Test-Path $censusRunRegKey) -eq $false)
        {
	    New-Item -Path $censusRunRegKey -ItemType Key | Out-Null
        }

        # Turn Census FullSync mode on
        Log "Setting property: FullSync to value 1 at registry key path $censusRunRegKey to turn on Census FullSync mode"
        if ((Get-ItemProperty -Path $censusRunRegKey -Name FullSync -ErrorAction SilentlyContinue) -eq $null)
        {
	    New-ItemProperty -Path $censusRunRegKey -Name FullSync -PropertyType DWord -Value 1 | Out-Null
        }
        else
        {
            Set-ItemProperty -Path $censusRunRegKey -Name FullSync  -Value 1
        }


        # Run Census and validate the run
        # Census invocation commands are different for Windows 10 and Downlevel
        [int] $runCounterBefore = (Get-ItemProperty -Path $censusRunRegKey).RunCounter

        if($runCounterBefore -eq $null)
        {
            New-ItemProperty -Path $censusRunRegKey -Name RunCounter -PropertyType DWord -Value 0 | Out-Null
        }

        if(($global:operatingSystemName.ToLower().Contains("windows 10")) -or ($global:operatingSystemName.ToLower().Contains("windows 11")))
        {
            $censusExe = "$global:windir\system32\devicecensus.exe"
            if(Test-Path -Path $censusExe)
            {
                Log "Running $censusExe"
                & $censusExe | Out-Null
            }
            else
            {
                Log "$censusExe path not found" "Error" "52" "RunCensus"
                return
            }
        }
        else
        {
            CompatTelRunner.exe -m:generaltel.dll -f:DoCensusRun | Out-Null
        }

        [int] $runCounterAfter = (Get-ItemProperty -Path $censusRunRegKey).RunCounter
        $returnCode = (Get-ItemProperty -Path $censusRunRegKey).ReturnCode
        $startTime = Get-Date (Get-ItemProperty -Path $censusRunRegKey).StartTime
        $endTime = Get-Date (Get-ItemProperty -Path $censusRunRegKey).EndTime

        if($returnCode -eq 0)
        {
            if($runCounterAfter -gt $runCounterBefore -and $endTime -gt $startTime)
            {
                Log "Passed: RunCensus"
            }
            else
            {
                Log "Census did not run correctly. Registray data at $censusRunRegKey are: RunCounter Before trying to run Census:$runCounterBefore, RunCounter after trying to run Census:$runCounterAfter, ReturnCode:$returnCode, UTC StartTime:$startTime, UTC EndTime:$endTime" "Warning" $null "RunCensus"
            }
        }
        else
        {
            Log "Census returned a non zero ReturnCode:$returnCode" "Warning" $null "RunCensus"
        }

        # Turn Census FullSync mode off
        Log "Resetting property: FullSync to value 0 at registry key path $censusRunRegKey to turn off Census FullSync mode"
        Set-ItemProperty -Path $censusRunRegKey -Name FullSync  -Value 0

    }
    Catch
    {
        Log "RunCensus failed with unexpected exception" "Error" "51" "RunCensus" $_.Exception.HResult $_.Exception.Message
    }
}

function Log($logMessage, $logLevel, $errorCode, $operation, $exceptionHresult, $exceptionMessage)
{
    $global:logDate = Get-Date -Format s
    $global:utcDate = ((Get-Date).ToUniversalTime()).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $logMessageForAppInsights = $logMessage

    if(($logLevel -eq $null) -or ($logLevel -eq [string]::Empty))
    {
        $logLevel = "Info"
    }

    if($logLevel -eq "Error")
    {
        # check and update the errorCode (the script will exit with the first errorCode)
        if(($errorCode -ne $null) -and ($errorCode -ne [string]::Empty))
        {
            if(($global:errorCode -eq $null) -or ($global:errorCode -eq [string]::Empty))
            {
                $global:errorCode = $errorCode
            }

            $logMessage = "ErrorCode " + $errorCode + " : " + $logMessage
        }

        if($exceptionHresult -ne $null)
        {
             $logMessage = $logMessage + " HResult: " + $exceptionHresult
        }

        if($exceptionMessage -ne $null)
        {
            $logMessage = $logMessage + " ExceptionMessage: " + $exceptionMessage
        }

        $global:errorCount++
    }
    elseif($logLevel -eq "Exception")
    {
        if($exceptionHresult -ne $null)
        {
             $logMessage = $logMessage + " HResult: " + $exceptionHresult
        }

        if($exceptionMessage -ne $null)
        {
            $logMessage = $logMessage + " ExceptionMessage: " + $exceptionMessage
        }
    }
    elseif($logLevel -eq "Warning")
    {
        if($exceptionHresult -ne $null)
        {
             $logMessage = $logMessage + " HResult: " + $exceptionHresult
        }

        if($exceptionMessage -ne $null)
        {
            $logMessage = $logMessage + " ExceptionMessage: " + $exceptionMessage
        }
    }

    if ($LogMode -eq 0)
    {
        Try
        {
            WriteLogToConsole $logLevel $logMessage
        }
        Catch
        {
            # Error when logging to console
            $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
            $message = "Error when logging to consloe."
            Write-Error "$message`n$exceptionDetails"
            SendEventToAppInsights "logging" $message "Failure" $global:utcDate "2" $_.Exception.HResult $_.Exception.Message
            [System.Environment]::Exit(2)
        }
    }
    elseif ($LogMode -eq 1)
    {
        Try
        {
            WriteLogToConsole $logLevel $logMessage
            Add-Content $global:logFile "$global:logDate : $logLevel : $logMessage"
        }
        Catch
        {
            # Error when logging to console and file
            $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
            $message = "Error when logging to consloe and file."
            Write-Error "$message`n$exceptionDetails"
            SendEventToAppInsights "logging" $message "Failure" $global:utcDate "3" $_.Exception.HResult $_.Exception.Message
            [System.Environment]::Exit(3)
        }
    }
    elseif ($LogMode -eq 2)
    {
        Try
        {
            Add-Content $global:logFile "$global:logDate : $logLevel : $logMessage"
        }
        Catch
        {
            # Error when logging to file
            $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
            $message = "Error when logging to file."
            Write-Error "$message`n$exceptionDetails"
            SendEventToAppInsights "logging" $message "Failure" $global:utcDate "4" $_.Exception.HResult $_.Exception.Message
            [System.Environment]::Exit(4)
        }
    }
    else
    {
        Try
        {
            WriteLogToConsole $logLevel $logMessage
            Add-Content $global:logFile "$global:logDate : $logLevel : $logMessage"
        }
        Catch
        {
            # Error when logging to console and file
            $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
            $message = "Error when logging to consloe and file."
            Write-Error "$message`n$exceptionDetails"
            SendEventToAppInsights "logging" $message "Failure" $global:utcDate "5" $_.Exception.HResult $_.Exception.Message
            [System.Environment]::Exit(5)
        }
    }
}

function WriteLogToConsole($logLevel, $logMessage)
{
    switch ($logLevel)
    {
        "Error"   
            {    
                Write-Error "$global:logDate : $logMessage"; Break
            }
        "Exception"    
            {    
                Write-Error "$global:logDate : $logMessage"; Break
            }
        "Warning"    
            {    
                Write-Warning "$global:logDate : $logMessage"; Break
            }
        default     
            {    
                Write-Host "$global:logDate : $logMessage"; Break
            }
    }
}

# Calling the main function
&$main
