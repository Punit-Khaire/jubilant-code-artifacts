Param(
    [string]$solrVersion = "7.2.1",
    [string]$installFolder = "E:\InstallationDestination",
	[string]$solrZip = "E:\InstallationSource\solr-7.2.1.zip",
	[string]$nssmZip = "E:\InstallationSource\nssm-2.24.zip",
    [string]$SolrWinInstance = "Solr-721-WinInstance",	
    [string]$solrPort = "8983",
    [string]$solrHost = "my.solr721instance.com",
    [bool]$solrSSL = $TRUE,
    [string]$nssmVersion = "2.24",
	[string]$keystoreSecret = "secret",
	[string]$KeystoreFile = 'solr-ssl721.keystore.jks',
	[switch]$Clobber
)

$Global:ProgressPreference = "SilentlyContinue"

$solrRoot = "$installFolder\$SolrWinInstance"
$SolrChildZip = "solr-$solrVersion"

$downloadFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("..\assets") 
if (!(Test-Path $downloadFolder)){
	New-Item -ItemType Directory -Path $downloadFolder
}
$elevated = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
if(!($elevated))
{
    throw "In order to install services, please run this script elevated."
}

$JavaMinVersionRequired = "8.0.1510"

$ErrorActionPreference = 'Stop'

# Ensure Java environment variable
try {
	$keytool = (Get-Command 'keytool.exe').Source
} catch {
	$keytool = Get-JavaKeytool -JavaMinVersionRequired $JavaMinVersionRequired
}

if(Test-Path -Path $installFolder)
    {
        Write-Host "Extracting $solrZip to $solrRoot..."
        Expand-Archive $solrZip -DestinationPath $solrRoot
						
		Get-ChildItem -Path "$solrRoot\$SolrChildZip" -Recurse | Move-Item -Destination "$solrRoot"
		Remove-Item -Path "$solrRoot\$SolrChildZip" -force
		
		Write-Host "Extracting $nssmZip to $solrRoot..."
        Expand-Archive $nssmZip -DestinationPath $solrRoot
    }

### PARAM VALIDATION
if($keystoreSecret -ne 'secret') {
	Write-Error 'The keystore password must be "secret", because Solr apparently ignores the parameter'
}

if((Test-Path $KeystoreFile)) {
	if($Clobber) {
		Write-Host "Removing $KeystoreFile..."
		Remove-Item $KeystoreFile
	} else {
		$KeystorePath = Resolve-Path $KeystoreFile
		Write-Error "Keystore file $KeystorePath already existed. To regenerate it, pass -Clobber."
	}
}

$P12Path = [IO.Path]::ChangeExtension($KeystoreFile, 'p12')
if((Test-Path $P12Path)) {
	if($Clobber) {
		Write-Host "Removing $P12Path..."
		Remove-Item $P12Path
	} else {
		$P12Path = Resolve-Path $P12Path
		Write-Error "Keystore file $P12Path already existed. To regenerate it, pass -Clobber."
	}
}

### DOING STUFF

Write-Host ''
Write-Host 'Generating JKS keystore...'
& $keytool -genkeypair -alias solr-ssl -keyalg RSA -keysize 2048 -keypass $keystoreSecret -storepass $keystoreSecret -validity 9999 -keystore $KeystoreFile -ext SAN=DNS:$solrHost,IP:127.0.0.1 -dname "CN=$solrHost, OU=MyOU, O=MyCompany, L=Pune, ST=Maharashtra, C=India"

Write-Host ''
Write-Host 'Generating .p12 to import to Windows...'
& $keytool -importkeystore -srckeystore $KeystoreFile -destkeystore $P12Path -srcstoretype jks -deststoretype pkcs12 -srcstorepass $keystoreSecret -deststorepass $keystoreSecret

Write-Host ''
Write-Host 'Trusting generated SSL certificate...'
$secureStringKeystorePassword = ConvertTo-SecureString -String $keystoreSecret -Force -AsPlainText
$root = Import-PfxCertificate -FilePath $P12Path -Password $secureStringKeystorePassword -CertStoreLocation Cert:\LocalMachine\Root
Write-Host 'SSL certificate is now locally trusted. (added as root CA)'


$KeystorePath = Resolve-Path $KeystoreFile
Copy-Item $KeystorePath -Destination "$solrRoot\server\etc\$KeystoreFile" -Force
 # Update solr cfg to use keystore & right host name
 if(Test-Path -Path "$solrRoot\bin\solr.in.cmd.old")
 {
		 Write-Host "Resetting solr.in.cmd" -ForegroundColor Green
		 Remove-Item "$solrRoot\bin\solr.in.cmd"
		 Rename-Item -Path "$solrRoot\bin\solr.in.cmd.old" -NewName "$solrRoot\bin\solr.in.cmd"   
 }

	 Write-Host "Rewriting solr config"

	 $cfg = Get-Content "$solrRoot\bin\solr.in.cmd"
	 Rename-Item "$solrRoot\bin\solr.in.cmd" "$solrRoot\bin\solr.in.cmd.old"
	 $certStorePath = "etc/$KeystoreFile"
	 $newCfg = $cfg | ForEach-Object { $_ -replace "REM set SOLR_SSL_KEY_STORE=etc/solr-ssl.keystore.jks", "set SOLR_SSL_KEY_STORE=$certStorePath" }
	 $newCfg = $newCfg | ForEach-Object { $_ -replace "REM set SOLR_SSL_KEY_STORE_PASSWORD=secret", "set SOLR_SSL_KEY_STORE_PASSWORD=$keystoreSecret" }
	 $newCfg = $newCfg | ForEach-Object { $_ -replace "REM set SOLR_SSL_TRUST_STORE=etc/solr-ssl.keystore.jks", "set SOLR_SSL_TRUST_STORE=$certStorePath" }
	 $newCfg = $newCfg | ForEach-Object { $_ -replace "REM set SOLR_SSL_TRUST_STORE_PASSWORD=secret", "set SOLR_SSL_TRUST_STORE_PASSWORD=$keystoreSecret" }
	 $newCfg = $newCfg | ForEach-Object { $_ -replace "REM set SOLR_HOST=192.168.1.1", "set SOLR_HOST=$solrHost" }
	 $newCfg | Set-Content "$solrRoot\bin\solr.in.cmd"

# install the service & runs
$svc = Get-Service "$SolrWinInstance" -ErrorAction SilentlyContinue
if(!($svc))
{
    Write-Host "Installing Solr service"
    &"$solrRoot\nssm-$nssmVersion\win64\nssm.exe" install "$SolrWinInstance" "$solrRoot\bin\solr.cmd" "-f" "-p $solrPort"
    $svc = Get-Service "$SolrWinInstance" -ErrorAction SilentlyContinue
}

if($svc.Status -ne "Running")
{
	Write-Host "Starting Solr service..."
	Start-Service "$SolrWinInstance"
}
elseif ($svc.Status -eq "Running")
{
	Write-Host "Restarting Solr service..."
	Restart-Service "$SolrWinInstance"
}

        
Start-Sleep -s 5

# finally prove it's all working
$protocol = "http"
if($solrSSL)
{
    $protocol = "https"
}

Invoke-Expression "start $($protocol)://$($solrHost):$solrPort/solr/#/"

# Resetting Progress Bar back to default
$Global:ProgressPreference = "Continue"

Write-Host ''
Write-Host 'Done!' -ForegroundColor Green