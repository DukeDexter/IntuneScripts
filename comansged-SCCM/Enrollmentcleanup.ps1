#Scheduled task portion

$task = Get-ScheduledTask -TaskName "Schedule #3 created by enrollment client"
#save off the enrollment id for later use
$enrollmentId = $task.TaskPath.Split('\')[4]
$enrollmentTasks = Get-ScheduledTask -TaskPath $task.TaskPath

#delete the tasks

foreach($scheduledTask in $enrollmentTasks)
{
Write-Host "Deleting " $scheduledTask.TaskName
Unregister-ScheduledTask -TaskName $scheduledTask.TaskName -Confirm:$false
}
#Registry portion
$regKeys = New-Object System.Collections.Generic.List[System.String]
$regKeys.Add("HKLM:\SOFTWARE\Microsoft\Enrollments\" + $enrollmentId)
$regKeys.Add("HKLM:\SOFTWARE\Microsoft\Enrollments\Status\" + $enrollmentId)
$regKeys.Add("HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\" + $enrollmentId)
$regKeys.Add("HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\" + $enrollmentId)
$regKeys.Add("HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\" + $enrollmentId)
$regKeys.Add("HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\" + $enrollmentId)
$regKeys.Add("HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\" + $enrollmentId)
$regKeys.Add("HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\" + $enrollmentId)
foreach($regKey in $regKeys)
{
Write-Host "Deleting " $regKey
Remove-Item -Path $regKey -Recurse
}

#remove the cert

Set-Location Cert:\LocalMachine\My
$certs = Get-ChildItem
foreach($cert in $certs)
{
if($cert.Issuer.Contains("Microsoft Intune") -and $cert.Issuer.Contains("MDM Device CA"))
{
Write-Host "Deleting " $cert.Issuer
$thumbprint = $cert.Thumbprint
Get-ChildItem Cert:\LocalMachine\My\$thumbprint | Remove-Item
}
}
