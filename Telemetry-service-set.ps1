$serviceName = "DiagTrack"

try {
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    $startupType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'").StartMode

    if ($startupType -ne "Auto") {
        Set-Service -Name $serviceName -StartupType Automatic
        Write-Output "Service '$serviceName' startup type changed to Automatic."
    } else {
        Write-Output "Service '$serviceName' is already set to Automatic."
    }

    if ($service.Status -ne "Running") {
        Start-Service -Name $serviceName
        Write-Output "Service '$serviceName' started."
    } else {
        Write-Output "Service '$serviceName' is already running."
    }

} catch {
    Write-Output "Service '$serviceName' not found or error occurred: $_"
}
