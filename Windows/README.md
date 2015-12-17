# Bulk Rightlink 10 Enablement for Windows
This script will take unmanaged instances and turn them into RightScale servers.

##Prerequisites
- Powershell 3.0 or higher installed on all instances
- WinRM enabled on all instances
- The domain credentials used must be a member of the Administrators group on all instances 
- https://rightlink.rightscale.com must be accessible from the instances
- Import the [RightLink 10.2.1 Windows Base ServerTemplate](https://my.rightscale.com/library/server_templates/RightLink-10-2-1-Windows-Base/lineage/55964)

##Warning
This command automates the enablement of your infrastructure into the RightScale platform.
It's highly recommended that you read and understand the following documentation prior running this script.
- RL10 documentation
http://docs.rightscale.com/rl/getting_started.html
- ServerTemplate documentation
http://support.rightscale.com/12-Guides/Dashboard_Users_Guide/Design/ServerTemplates/Concepts/About_ServerTemplates/index.html

##Usage

###Parameters
```
    -TargetServers        Comma-separated list of hostnames or IP addresses to Rightlink enable.
    -Credential           PSCredential to establish PSRemoting Session with Target Servers
    -RefreshToken         RightScale API refresh token from the dash Settings>API Credentials (required)
    -DeploymentName       Name of the pre-existing deployment into which to put the server
    -DeploymentHref       HREF of the deployment to put the server. alternate to the name of the deployment (ex. /api/deployments/123456789)
    -ServerTemplateName   Name of the ServerTemplate to associate with this instance
    -ServerTemplateHref   Alternate to ServerTemplateName. HREF of the ServerTemplate to associate with this instance (ex. /api/server_templates/123456789)
    -ServerName           Name to call the server. Default is current Instance name or $DEFAULT_SERVER_NAME
    -Inputs               Server inputs in the form of NAME=key:value, separate multiple inputs with commas
    -CloudType            Cloud type the instance is in. Supported values are amazon, azure, cloud_stack, google, open_stack_v2, rackspace_next_gen, soft_layer, vscale
    -InstanceHref         RightScale API instance HREF (disables self-detection) (ex. /api/clouds/1/instances/123456ABCDEF)
    -ApiServer            Hostname for the RightScale API, Default: $DEFAULT_SERVER
    -Proxy                Have RightLink use HTTP proxy. Will also install RightLink through proxy
    -NoProxy              A list of hosts to not proxy. List is inherited by scripts/recipes as an environment variable
    -Username             RightLink Service User Name (default: RightLink)
    -Password             RightLink Service User Password (default: Randomly generated password)
    -Help                 Display help
```  
  
###Required Inputs
```
	-RefreshToken
	-TargetServers
	-Credential
	-ServerTemplateName or -ServerTemplateHref
	-DeploymentName or -DeploymentHref
    -CloudType or -InstanceHref
```  


###Notes
-	Be careful using "-ServerName" parameter when using bulk enablement script, as it will result in multiple servers being renamed to the same value.
-	When specifiying a ServerTemplate (via Name or Href), be mindful of the required inputs.  If the ServerTemplate has required inputs, those inputs will need to be set via the "-Inputs" parameter.  This is why the RightLink 10.2.1 Windows Base ServerTemplate is recommended.
-	Do not confuse "-Credential" with the "-Username" & "-Password" parameters.  The "-Credential" parameter is required and is expecting a PSCredential, used to remotely connect to each target server via WinRM.  The "-Username" & "-Password" parameters specify the local service account to run the Righlink Service.


##Example Enablement

####Set Target Servers Inline
```
$URL = 'https://raw.githubusercontent.com/rs-services/bulk-rightlink10-enablement/master/Windows/rightlink.bulk.enable.ps1'
$WC = New-Object System.Net.WebClient
$wc.DownloadFile($URL,"C:\Temp\rightlink.bulk.enable.ps1")
cd C:\Temp

.\rightlink.bulk.enable.ps1 -TargetServers "server1,server2,10.3.1.89" -Credential contoso\administrator -RefreshToken "bfae...7695" -DeploymentName "RL-Testing" -ServerTemplatename "RightLink 10.2.1 Windows Base v1" -CloudType "amazon"
```

####Set Target Servers via AD query
-	requires the ActiveDirectory PowerShell module to be installed on the server running the Enablement script
```
$URL = 'https://raw.githubusercontent.com/rs-services/bulk-rightlink10-enablement/master/Windows/rightlink.bulk.enable.ps1'
$WC = New-Object System.Net.WebClient
$wc.DownloadFile($URL,"C:\Temp\rightlink.bulk.enable.ps1")
cd C:\Temp

$servers = get-adcomputer -Filter * -SearchBase "OU=Servers,DC=contoso,DC=com"

.\rightlink.bulk.enable.ps1 -TargetServers $servers.DNSHostName -Credential contoso\administrator -RefreshToken "bfae...7695" -DeploymentName "DF-Testing" -ServerTemplatename "RightLink 10.2.1 Windows Base v1" -CloudType "amazon"
```

####Set Target Servers from Text File
Example file called servers.txt

```
SERVER1
10.33.1.200
SERVER3.DOMAIN.COM
SERVER7
```

```
$URL = 'https://raw.githubusercontent.com/rs-services/bulk-rightlink10-enablement/master/Windows/rightlink.bulk.enable.ps1'
$WC = New-Object System.Net.WebClient
$wc.DownloadFile($URL,"C:\Temp\rightlink.bulk.enable.ps1")
cd C:\Temp

.\rightlink.bulk.enable.ps1 -TargetServers (get-content .\servers.txt) -Credential contoso\administrator -RefreshToken "bfae...7695" -DeploymentName "DF-Testing" -ServerTemplatename "RightLink 10.2.1 Windows Base v1" -CloudType "amazon"
```

####Credential Parameter
The Credential paramter can be set in two ways.
1)	Set a PSCredential in a variable and then pass the variable as the value for the Credential parameter:
```
$admin = get-credential contoso\administrator

\rightlink.bulk.enable.ps1 -TargetServers "server1,server2 -Credential $admin ...
```
2)	Set the value of the Credential parameter to a username, as seen in examples above.

Either method will result in a prompt asking for the password for the specified account:
![Alt text](/../master/Windows/cred_prompt.png?raw=true "Credential Prompt Example")