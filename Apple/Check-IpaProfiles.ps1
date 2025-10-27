<#
Run using command: 

./Check-IpaProfiles.ps1 -IpaPath "C:\Path\MyApp.ipa" `
    -TeamsWebhookUrl "https://outlook.office.com/webhook/..." `
    -AlertEmail "ios-alerts@yourcompany.com" `
    -DaysThreshold 30

Use Windows Task Scheduler or Azure Automation for daily/weekly runs.

This scripts Extracts IPA → Finds all .mobileprovision files.
Parses Name, AppID, ExpirationDate.
Compares expiry against threshold.
Sends alerts via:
Email (SMTP server required).
Teams (Incoming Webhook).

#>


param(
    [Parameter(Mandatory=$true)]
    [string]$IpaPath,

    [Parameter(Mandatory=$true)]
    [string]$TeamsWebhookUrl,

    [Parameter(Mandatory=$true)]
    [string]$AlertEmail,

    [int]$DaysThreshold = 30
)

# Create temp folder
$TempDir = Join-Path $env:TEMP ("IPA_" + [System.Guid]::NewGuid().ToString())
Expand-Archive -Path $IpaPath -DestinationPath $TempDir

Write-Host "Checking provisioning profiles in $IpaPath..."
$Profiles = Get-ChildItem -Path $TempDir -Recurse -Filter "*.mobileprovision"

$Alerts = @()

foreach ($Profile in $Profiles) {
    $Content = Get-Content $Profile.FullName
    $Name = ($Content | Select-String -Pattern "<key>Name</key>" -Context 0,1).Context.PostContext -replace "<string>|</string>", ""
    $AppID = ($Content | Select-String -Pattern "<key>application-identifier</key>" -Context 0,1).Context.PostContext -replace "<string>|</string>", ""
    $Expiry = ($Content | Select-String -Pattern "<key>ExpirationDate</key>" -Context 0,1).Context.PostContext -replace "<date>|</date>", ""

    $ExpiryDate = [datetime]$Expiry
    $DaysLeft = ($ExpiryDate - (Get-Date)).Days

    Write-Host ("Profile: {0} | AppID: {1} | Expiry: {2} | Days Left: {3}" -f $Name,$AppID,$ExpiryDate,$DaysLeft)

    if ($DaysLeft -lt $DaysThreshold) {
        $Alerts += @{
            Name = $Name
            AppID = $AppID
            Expiry = $ExpiryDate.ToString("yyyy-MM-dd")
            DaysLeft = $DaysLeft
        }
    }
}

# Cleanup
Remove-Item -Recurse -Force $TempDir

# Send Alerts if any
if ($Alerts.Count -gt 0) {
    $AlertText = "Provisioning Profiles expiring soon:`n" + ($Alerts | ForEach-Object { "$($_.Name) ($($_.AppID)) expires on $($_.Expiry) [$($_.DaysLeft) days left]" }) -join "`n"

    # Email Alert
    Send-MailMessage -To $AlertEmail -From "alerts@yourdomain.com" -Subject "IPA Provisioning Profile Expiry Alert" -Body $AlertText -SmtpServer "smtp.yourdomain.com"

    # Teams Alert
    $TeamsPayload = @{
        text = $AlertText
    } | ConvertTo-Json
    Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post -Body $TeamsPayload -ContentType 'application/json'

    Write-Host "Alerts sent via Email and Teams."
} else {
    Write-Host "No profiles expiring within $DaysThreshold days."
}
``
