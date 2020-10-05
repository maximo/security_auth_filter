# Create new trusted application and application end point 
Write-Host
Write-Host "Security Authorization Filter: configuration of a trusted application pool, trusted application and application endpoint."
Write-Host
$ApplicationId= "urn:application:securityfilter"
$ApplicationFqdn= Read-Host "Specify the application FQDN (i.e. authorizationfilter.contoso.com)"
$ApplicationComputerFQDN = Read-Host "Specify FQDN of the Security Authorization Filter"
$RegistrarFQDN = Read-Host "Specify FQDN of Skype for Business pool"
$PortNo = 6666

New-CsTrustedApplicationPool -identity $ApplicationFqdn -Registrar $RegistrarFQDN -ComputerFqdn $ApplicationComputerFqdn

#Enable the topology
Enable-CSTopology

# Create Trusted Application
New-CSTrustedApplication –ApplicationId $ApplicationId -TrustedApplicationPoolFqdn $ApplicationFqdn -Port $PortNo

#Enable the topology
Enable-CSTopology

$ApplicationSipAddress= Read-Host "Specify the application endpoint SIP address (i.e. authorizationfilter@contoso.com)"
$DisplayName= Read-Host "Specify the application endpoint display name (i.e. Security Authorization Filter)"

New-CSTrustedApplicationEndpoint –ApplicationId $ApplicationId -TrustedApplicationPoolFqdn $ApplicationFqdn -SipAddress $ApplicationSipAddress -DisplayName 

$DisplayName
Write-Host
$ApplicationEndPoint=get-CSTrustedApplicationEndpoint $ApplicationSipAddress

Write-Host
Write-Host "Application endpoint created: "   $ApplicationEndPoint.DisplayName
Write-Host