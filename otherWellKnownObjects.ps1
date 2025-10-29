# Verify otherWellKnownObjects has a non-deleted MSA container

# Define the Distinguished Name (DN) of the domain's Naming Context (NC)
$domainNC = (Get-ADRootDSE).defaultNamingContext

# Search for the "otherWellKnownObjects" attribute on the NC head
$ncHead = Get-ADObject -Filter 'objectClass -eq "domainDNS"' -SearchBase $domainNC -Properties otherWellKnownObjects

# Check if "CN=Managed Service Accounts" exists in the otherWellKnownObjects attribute
if ($ncHead.otherWellKnownObjects -match "CN=Managed Service Accounts") {
    Write-Host "'CN=Managed Service Accounts' exists in otherWellKnownObjects."

    # Extract and print the full element for "CN=Managed Service Accounts"
    $msaElement = $ncHead.otherWellKnownObjects | Where-Object { $_ -match "CN=Managed Service Accounts" }
    Write-Host "Full element for 'CN=Managed Service Accounts':"
    Write-Host $msaElement
    Write-Host
    $isDelete = $true

    foreach ($item in $msaElement){
        if ($item -notlike "*CN=Deleted Objects*") {
            $isDelete = $false
        }
    }

    Write-Host "Does AD think CN=Managed Service Accounts is deleted: " $isDelete

} else {
    Write-Host "'CN=Managed Service Accounts' is missing from otherWellKnownObjects."
} 
