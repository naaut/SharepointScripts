Param (

[string]$domain

)

$nDomain = $env:USERDOMAIN
Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
New-SPWebApplication -Name "frontend.$domain" -ApplicationPool "SharePoint - frontend.$domain" -AuthenticationMethod "NTLM" -ApplicationPoolAccount "$nDomain\sp-webapp" -Port 80 -URL "http://frontend.$domain" -DataBaseName FrontEnd_Content_DB -HostHeader "frontend.$domain"
$template = Get-SPWebTemplate "STS#0"
New-SPSite -Url "http://frontend.test.com/" -OwnerAlias "$nDomain\User" -SecondaryOwnerAlias "$nDomain\sp-installer" -Template $template