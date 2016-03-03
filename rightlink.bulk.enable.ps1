# This script, when run on a running unmanaged (raw) instance, will install and run RightScale's
# RightLink agent to turn it into a "RightScale Server". Turning it into a RightScale Server
# allows management via the RightScale platform.
#
# It does this in 4 steps:
#  (1) locate the RightScale ServerTemplate and Deployment to use
#  (2) locate a unique identifier about this instance (such as instance ID)
#  (3) associate that ServerTemplate and Deployment with the instance by making a wrap_instance API
#      calls to RightScale's API service
#  (4) install RightLink
#
# This script is deliberately written in Powershell to be easy to customize
# and modify. For example, to supply custom inputs to servertemplates or hardcode in alternate
# defaults. This script is designed to be "idempotent", meaning you can rerun it multiple
# times with no ill effect.

# If a Username/Password to a local or domain user is supplied, this install script
# will attempt to run RightLink as that user. If no Username/Password is supplied,
# a local Administrator called "RightLink" with a randomly generated password will be created
# for RightLink to run under.
Param(
  $targetServers,
  [Parameter(Mandatory=$true)]
  [System.Management.Automation.CredentialAttribute()]
  $Credential,
  [alias('k')]
  [string]$refreshToken,
  [alias('d')]
  [string]$deploymentName,
  [alias('e')]
  [string]$deploymentHref,
  [alias('t')]
  [string]$serverTemplateName,
  [alias('r')]
  [string]$serverTemplateHref,
  [alias('n')]
  [string]$serverName,
  [alias('p')]
  [string]$inputs,
  [alias('c')]
  [string]$cloudType,
  [alias('i')]
  [string]$instanceHref,
  [alias('a')]
  [string]$apiServer,
  [alias('x')]
  [string]$proxy,
  [alias('y')]
  [string]$noProxy,
  [alias('u')]
  [string]$Username,
  [alias('w')]
  [string]$Password,
  [alias('h')]
  [switch]$help
)

function GetHelp
{
  Write-Host "This script will take unmanaged instances and turn them into RightScale servers."
  Write-Host "Parameters:"
  Write-Host "  -TargetServers        Comma-separated list of hostnames or IP addresses to RL-enable."
  Write-Host "  -Credential           PSCredential to establish PSRemoting Session with Target Servers"
  Write-Host "  -RefreshToken         RightScale API refresh token from the dash Settings>API Credentials (required)"
  Write-Host "  -DeploymentName       Name of the pre-existing deployment into which to put the server"
  Write-Host "  -DeploymentHref       HREF of the deployment to put the server. alternate to the name of the deployment (ex. /api/deployments/123456789)"
  Write-Host "  -ServerTemplateName   Name of the ServerTemplate to associate with this instance"
  Write-Host "  -ServerTemplateHref   Alternate to ServerTemplateName. HREF of the ServerTemplate to associate with this instance (ex. /api/server_templates/123456789)"
  Write-Host "  -ServerName           Name to call the server. Default is current Instance name or $DEFAULT_SERVER_NAME"
  Write-Host "  -Inputs               Server inputs in the form of NAME=key:value, separate multiple inputs with commas"
  Write-Host "  -CloudType            Cloud type the instance is in. Supported values are amazon, azure, cloud_stack, google, open_stack_v2, rackspace_next_gen, soft_layer, vscale"
  Write-Host "  -InstanceHref         RightScale API instance HREF (disables self-detection) (ex. /api/clouds/1/instances/123456ABCDEF)"
  Write-Host "  -ApiServer            Hostname for the RightScale API, Default: $DEFAULT_SERVER"
  Write-Host "  -Proxy                Have RightLink use HTTP proxy. Will also install RightLink through proxy"
  Write-Host "  -NoProxy              A list of hosts to not proxy. List is inherited by scripts/recipes as an environment variable"
  Write-Host "  -Username             RightLink Service User Name (default: RightLink)"
  Write-Host "  -Password             RightLink Service User Password (default: Randomly generated password)"
  Write-Host "  -Help                 Display help"
  Write-Host ""
  Write-Host "Required Inputs: -RefreshToken"
  Write-Host "                 -TargetServers"
  Write-Host "                 -Credential"
  Write-Host "                 -ServerTemplateName or -ServerTemplateHref"
  Write-Host "                 -DeploymentName or -DeploymentHref"
  Write-Host "                 -CloudType or -InstanceHref"
  Write-Host ""
}

[System.Management.Automation.ScriptBlock]$ScriptBlock = {
  if ($Debug) {
    $DebugPreference = "Continue"
  }

  function SessionIsElevated
  {
    [System.Security.Principal.WindowsPrincipal]$currentPrincipal = `
      New-Object System.Security.Principal.WindowsPrincipal(
        [System.Security.Principal.WindowsIdentity]::GetCurrent());

    [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = `
      [System.Security.Principal.WindowsBuiltInRole]::Administrator;

    return $currentPrincipal.IsInRole($administratorsRole)
  }

  function Expand-Zipfile($zipFile, $targetDir, $basePath = $Null)
  {
    if (! $basePath) { $basePath =  (Get-ChildItem $zipFile | Select-Object -Property FullName).FullName }
    $shell = New-Object -com Shell.Application
    $zip = $shell.NameSpace($zipFile)

    if (!(Test-Path -Path $targetDir)) {
      New-Item -Path $targetDir -Type directory
    }
    foreach($item in $zip.items())
    {
      $newPath = $item.path -replace [RegEx]::Escape($basePath), $targetDir
      if ($item.Type -eq "File Folder") {
        New-Item -Path $newPath -Type directory
        Expand-Zipfile $item.Path $targetDir $basePath
      } else {
        $newDir = [io.path]::GetDirectoryName($newPath)
        $shell.Namespace($newDir).CopyHere($item)
      }
    }
  }

  function Get-LegacyRLProgram
  {
  <#
  .SYNOPSIS
    Detect installation of RightScale RightLink
  .OUTPUTS
    Response object or $Null if not installed.
  #>
    $RegLoc = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall
    $Programs = $RegLoc | foreach {Get-ItemProperty $_.PsPath}

    Foreach ($prog in $Programs | Sort-Object DisplayName)
    {
      if ($prog.Displayname -eq "RightScale RightLink")
      {
        return $prog
      }
    }
    return $Null
  }

  function XenStoreReader
  {
    param(
      [Parameter(Mandatory=$True,Position=0)][string]$command,
      [Parameter(Mandatory=$True,Position=1)][string]$value
    )

    $sessionName = "XenStoreReader"

    $session = Get-WmiObject -Namespace root\wmi -Query "select * from CitrixXenStoreSession where Id='$sessionName'"
    if (!($session)) {
      $base = Get-WmiObject -Namespace root\wmi -Class CitrixXenStoreBase
      $base.AddSession($sessionName) | Out-Null
      $session = Get-WmiObject -Namespace root\wmi -Query "select * from CitrixXenStoreSession where Id='$sessionName'"
    }

    switch -regex ($command)
    {
      "^read$" {
        $res = $session.GetValue($value)
        if ($res) {
          return $res.value
        } else {
          throw "Could not find value $value"
        }
      }
      "^(ls|dir)$" {
        $res = $session.GetChildren($value)
        if ($res) {
          return $res.children.ChildNodes -replace "$value/", ""
        } else {
          throw "Could not find dir $value"
        }
      }
      default {
        throw "Unrecognized command $command. Only 'read' and 'dir' are currently supported."
      }
    }
  }

  function Test-Credential([string]$domain, [string]$username, [string]$password) {
    $LogonUserDefinition = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LogonUser(
string lpszUsername,
string lpszDomain,
string lpszPassword,
int dwLogonType,
int dwLogonProvider,
out IntPtr phToken
);
'@
    $Advapi32 = Add-Type -MemberDefinition $LogonUserDefinition -Name 'Advapi32' -Namespace 'Win32' -PassThru
    $LOGON32_LOGON_NETWORK = 3
    $LOGON32_PROVIDER_DEFAULT = 0

    $token = New-Object -TypeName IntPtr
    $Advapi32::LogonUser($username, $domain, $password, $LOGON32_LOGON_NETWORK, $LOGON32_PROVIDER_DEFAULT, [ref]$token)
  }

  function LogWrite([string]$logString, [boolean]$noNewlineFlag = $False)
  {
    if ($noNewlineFlag -eq $True) {
      [System.IO.File]::AppendAllText($INSTALL_LOG_FILE, $logString, [System.Text.Encoding]::UTF8)
      Write-Host -NoNewline $logString
    } else {
      Add-Content $INSTALL_LOG_FILE "$logString`n"
      Write-Host $logString
    }
  }

  function LogError([string]$logString)
  {
    Add-Content $INSTALL_LOG_FILE "`n$logString`n"
    throw $logString
  }

  ###############################################
  # Begin Main
  ###############################################

  $RIGHTLINK_DIR         = "$env:ProgramFiles\RightScale\RightLink"
  $LOG_DIR               = "$RIGHTLINK_DIR\Logs"
  $INSTALL_LOG_FILE      = "$LOG_DIR\install.log"
  $RSC                   = "$RIGHTLINK_DIR\rsc.exe"
  $RIGHTLINK_ZIP_URL     = "https://rightlink.rightscale.com/rll/10.3.0/rightlink.zip"
  $DEFAULT_SERVER        = "my.rightscale.com"
  $DEFAULT_SERVER_NAME   = "RightLink Enabled #$pid"
  $DEFAULT_INSTANCE_TYPE = "auto"

  # If RightLink directory doesn't exist then create it
  New-Item -Path $RIGHTLINK_DIR -Type Directory -Force | Out-Null
  New-Item -Path $LOG_DIR -Type Directory -Force | Out-Null

  # If log file doesn't exist then create it and the directory
  if (!(Test-Path -Path $INSTALL_LOG_FILE)) {
    New-Item -Path $INSTALL_LOG_FILE -Type File -Force | Out-Null
  }

  $currentTime = Get-Date
  LogWrite "$currentTime Starting Enablement"

  if (($legacyRLProg = Get-LegacyRLProgram))
  {
    LogError "ERROR: Prior RightLink $($legacyRLProg.DisplayVersion) found.`r`n" +
             "Enabling this instance will install RightLink 10, our latest agent.`r`n" +
             "RightLink 6 or any previous version must be uninstalled before proceeding.`r`n" +
             "Please visit https://support.rightscale.com/12-Guides/RightLink_6/Uninstall_RightLink for uninstall instructions."
  }

  if ($help) {
    GetHelp
    exit 0
  }

  if (!(SessionIsElevated)) {
    LogError "ERROR: This must be run in an elevated command prompt."
  }

  if (!$refreshToken) {
    GetHelp
    LogError "ERROR: -RefreshToken missing."
  }

  if ((!$serverTemplateName) -and (!$serverTemplateHref)) {
    GetHelp
    LogError "ERROR: -ServerTemplateName and -ServerTemplateHref missing. At least one must be present."
  }

  if ((!$instanceHref) -and (!$cloudType) -and (!$cloudName)) {
    GetHelp
    LogError "ERROR: -CloudType and -InstanceHref and -CloudName missing. At least one must be present."
  }

  if (!$apiServer) {
    if ($DEFAULT_SERVER) {
      $apiServer = $DEFAULT_SERVER
      LogWrite "Using API Host $DEFAULT_SERVER"
    } else {
      GetHelp
      LogError "ERROR: -ApiServer missing."
    }
  }
  if ((!$deploymentName) -and (!$deploymentHref)) {
    GetHelp
    LogError "ERROR: -DeploymentName and -DeploymentHref missing. At least one must be present."
  }

  if ($Username -ne "") {
    $Domain = ""
    $CheckUsername = $Username
    $parts = $Username.Split('\', 2)
    if ($parts.Length -eq 2) {
      $Domain = $parts[0]
      $CheckUsername = $parts[1]
    }
    if ( (Test-Credential $Domain $CheckUsername $Password) -eq $false ) {
      Write-Host "Please provide a valid Username and Password"
      exit 1
    }
  }

  # Pull in the JSON deserializer to parse openstack metadata below
  [reflection.assembly]::LoadWithPartialName("System.Web.Extensions") | Out-Null

  # ===== Download and expand RightLink

  $RIGHTLINK_INST_DIR = "$env:TEMP\RightLinkInstaller"

  if (Test-Path -Path $RIGHTLINK_INST_DIR) {
    Remove-Item $RIGHTLINK_INST_DIR -Force -Recurse
  }
  New-Item -Path $RIGHTLINK_INST_DIR -Force -Type Directory | Out-Null

  $wc = New-Object System.Net.WebClient
  $proxyAddr = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
  if ($proxy) {
    LogWrite "Using proxy $proxy"
    $parts = $proxy -replace "http://","" -replace "https://","" -split "@"
    $webproxy = New-Object System.Net.WebProxy
    if ($parts.Length -gt 1) {
      $userparts = $parts[0] -split ":"
      $user = $userparts[0]
      $passwd = $userparts[1]
      $creds = New-Object System.Net.NetworkCredential($user, $passwd)
      $webproxy.Credentials = $creds
      $webProxy.Address = "http://" + $parts[1]
    } else {
      $webProxy.Address = "http://" + $parts[0]
    }

    $wc.Proxy = $webproxy
    $env:http_proxy = $proxy # for rsc
    $env:no_proxy = $noProxy # for rsc
  } elseif ($proxyAddr) {
    # should be cautious about proxies authenticated using BASIC authentication in windows
    # https://support.microsoft.com/en-us/kb/2778122
    # http://blogs.msdn.com/b/ieinternals/archive/2012/08/03/manual-proxy-authentication-requiring-basic-or-digest-breaks-many-applications.aspx
    # So we basically only support unauthenticated proxies in this case
    LogWrite "Using system proxy $proxyAddr"
    $webproxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $webproxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    $wc = New-Object System.Net.WebClient
    $wc.Proxy = $webproxy
    $wc.UseDefaultCredentials = $true
    $env:http_proxy = $proxyAddr # for rsc
    $env:no_proxy = $noProxy # for rsc
  }

  $wc.DownloadFile($RIGHTLINK_ZIP_URL, "$RIGHTLINK_INST_DIR\rightlink.zip")
  Expand-Zipfile "$RIGHTLINK_INST_DIR\rightlink.zip" "$RIGHTLINK_INST_DIR" | Out-Null

  # If RightLink directory doesn't exist then create it
  New-Item -Path $RIGHTLINK_DIR -Type Directory -Force | Out-Null

  # ===== Install RSC command line tool
  Copy-Item -Force "$RIGHTLINK_INST_DIR\RightLink\rsc.exe" "$RSC"

  # ===== Retrieve cloud metadata and identify the instance in RightScale

  # Ideally we identify the instance by it's cloud id, known as resource_uid in RS, but sometimes
  # the cloud doesn't expose that to the instance, so we have to revert to something else, such
  # as the instance's public IP.
  $resourceLabel = "resource_uid"

  # Query API based on supplied Instance HREF to ensure that the instance running the enable script
  # is the same as the instance referenced in the Instance HREF
  if ($instanceHref) {
    LogWrite "Finding instance $instanceHref ... " $True
    $json = & $RSC --key $refreshToken --host $apiServer cm15 show $instanceHref
    $resourceUid = (Write-Output $json | & $RSC --x1 '.resource_uid' json 2> $null)
    $privateIpAddress = (Write-Output $json | & $RSC --x1 '.private_ip_addresses string' json 2> $null)
    $publicIpAddress = (Write-Output $json | & $RSC --x1 '.public_ip_addresses string' json 2> $null)
    if ($resourceUid) {
      LogWrite "Instance found with id: $resourceUid"
    } else {
      LogError "ERROR: Failed to retrieve resourceUid. Use -CloudType instead of -InstanceHref for self-detection."
    }
    $cloudHref = (Write-Output $json | & $RSC --x1 ':has(.rel:val(\"cloud\")).href' json 2> $null)
    if (!$cloudHref) {
      LogWrite "ERROR: Failed to retrieve cloudHref. Use -CloudType instead of -InstanceHref for self-detection."
    }

    LogWrite "Finding cloud type for $resourceUid ... " $True
    $existingCloudType = (& $RSC --key $refreshToken --host $apiServer --x1 '.cloud_type' cm15 show $cloudHref 2> $null)
    if ($existingCloudType) {
      if ($cloudType -and $cloudType -ne $existingCloudType) {
        LogError "ERROR: -CloudType input does not match instance cloudType ($cloudType != $existingCloudType)"
      } else {
        $cloudType = $existingCloudType
        LogWrite "cloud found with type: $cloudType"
      }
    } elseif (!$cloudType) {
      "ERROR: Failed to retrieve cloud type. Use -CloudType instead of -InstanceHref for self-detection."
    }
  }

  # Identify the cloud HREF from the cloud name if it is provided.
  if ($cloudName) {
    LogWrite "Finding cloud $cloudName ... " $True
    $json = & $RSC --key $refreshToken --host $apiServer cm15 index clouds "filter[]=name==$cloudName"
    $cloudHref = (Write-Output $json | & $RSC --x1 ':has(.rel:val(\"self\")).href' json 2> $null)
    if (!$cloudHref) {
      LogError "ERROR: Failed to find cloud. Use -CloudType instead of -CloudName for self-detection."
    }
    $cloudType = (Write-Output $json | & $RSC --x1 '.cloud_type' json)
    LogWrite "cloudHref = $cloudHref"
  }

  # Identify instanceId through the metadata to either determine the instance HREF or to compare
  # against the resource_uid of the user supplied instance HREF
  if ($cloudType) {
    if ($cloudType -eq 'amazon') {
      LogWrite "Retrieving EC2 metadata ... " $True
      $wc = New-Object System.Net.WebClient
      $instanceId = $wc.DownloadString("http://169.254.169.254/latest/meta-data/instance-id")
      if ($instanceId -notmatch "i-") {
        LogError "ERROR: Could not query instance-id from metadata service."
      }
    } elseif ($cloudType -eq 'azure') {
      LogWrite "Retrieving Azure metadata ... " $True
      $instanceId = hostname
    } elseif ($cloudType -eq 'cloud_stack') {
      LogWrite "Retrieving Cloudstack metadata ... " $True
      $dhcp = ipconfig /all | find /i "DHCP Server"
      $dhcp -match ": (.*)"
      $ip = $matches[1]
      $wc = New-Object System.Net.WebClient
      $instanceId = $wc.DownloadString("http://$ip/latest/meta-data/instance-id")
    } elseif ($cloudType -eq 'google') {
      LogWrite "Retrieving Google metadata ... " $True
      $wc = New-Object System.Net.WebClient
      $wc.Headers.add('Metadata-Flavor','Google')
      $hostname = $wc.DownloadString("http://metadata.google.internal/computeMetadata/v1/instance/hostname")
      $hostname -match "[^.]+"
      $hostname = $matches[0]
      $project = $wc.DownloadString("http://metadata.google.internal/computeMetadata/v1/project/project-id")
      $instanceId = "projects/$project/instances/$hostname"
    } elseif ($cloudType -eq 'open_stack_v2') {
      LogWrite "Retrieving Openstack metadata ... " $True
      $wc = New-Object System.Net.WebClient
      $metaData = $wc.DownloadString("http://169.254.169.254/openstack/latest/meta_data.json")
      $jsO = New-Object System.Web.Script.Serialization.JavaScriptSerializer
      $json = $jsO.DeserializeObject($metaData)
      $instanceId = $json.uuid
    } elseif ($cloudType -eq 'rackspace_next_gen') {
      LogWrite "Retrieving Rackspace metadata ... " $True
      $xenstoreClient = "$env:ProgramFiles\Citrix\XenTools\xenstore_client.exe"
      if (Test-Path -Path $xenstoreClient) {
        $instanceId = & $xenstoreClient read name
      } else {
        $instanceId = & XenStoreReader read name
      }
      $instanceId = $instanceId -replace "instance-", ""
      if ($instanceId.Length -lt 36) {
        LogError "ERROR: $instanceId doesn't appear to be a valid uuid."
      }
    } elseif ($cloudType -eq 'soft_layer') {
      LogWrite "Retrieving SoftLayer metadata ... " $True
      $wc = New-Object System.Net.WebClient
      $instanceId = $wc.DownloadString("https://api.service.softlayer.com/rest/v3.1/SoftLayer_Resource_Metadata/Id.txt")
      if ($instanceId -notmatch "^[0-9]+$") {
        LogError "ERROR: Could not query instance-id from metadata service."
      }
    } elseif ($cloudType -eq 'vscale') {
      LogWrite "Retrieving vScale metadata ... " $True
      $rpctool = "$env:ProgramFiles\VMware\VMware Tools\rpctool.exe"
      if (Test-Path -Path $rpctool) {
        $ovfEnv = (& $rpctool "info-get guestinfo.ovfEnv" 2> $null)
        $metadata = (& $rpctool "info-get guestinfo.metadata" 2> $null)
      }
      if (($ovfEnv -join "") -match 'vCenterId="(vm-[0-9]+)"') {
        $instanceId = $matches[1]
      } elseif ($metadata -match 'vs_instance_id=(vm-[0-9]+)') {
        $instanceId = $matches[1]
      }
      if (!$instanceId) {
        LogWrite "Unable to retrieve metadata using VMware Tools."
        LogWrite "Trying to match instance using IP address ... " $True
        $ip = Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.IPAddress.Length -gt 1}
        $instanceId = $ip.IPAddress[0]
        if ($instanceId -match "^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
          LogWrite "Warning: In certain RCA-V networking configurations (i.e. using multiple subnets), using private " `
            "IP as a unique identifier may cause problems.  Only use this method if you are sure you do not have any" `
            "overlapping IP space in any RCA-V clouds."
          $resourceLabel = "private_ip_address"
        } else {
          $resourceLabel = "public_ip_address"
        }
      }
    } elseif ($cloudType -eq 'uca') {
      # Find UCA cloud if needed
      if (!$cloudHref) {
        LogWrite "Locating UCA cloud ... " $True
        $cloudHref = & $RSC --key $refreshToken --host $apiServer --x1 'object:has(.rel:val(\"self\")).href' `
                     cm15 index clouds "filter[]=cloud_type==uca"
        if (!$cloudHref) {
          LogError "ERROR: Failed to find cloud."
        }
        LogWrite "cloudHref = $cloudHref"
      }
      LogWrite "Locating UCA datacenter ... " $True
      $datacenterHref = & $RSC --key $refreshToken --host $apiServer --x1 'object:has(.rel:val(\"self\")).href' `
                        cm15 index $cloudHref/datacenters
      if (!$datacenterHref) {
        LogError "ERROR: Failed to find datacenter."
      }
      LogWrite "datacenterHref = $datacenterHref"
      LogWrite "Locating UCA generic image ... " $True
      $imageHref = & $RSC --key $refreshToken --host $apiServer --x1 'object:has(.rel:val(\"self\")).href' `
                   cm15 index $cloudHref/images "filter[]=name==generic"
      if (!$imageHref) {
        LogError "ERROR: Failed to find generic image."
      }
      LogWrite "imageHref = $imageHref"
      if (!$instanceType) {
        $instanceType = $DEFAULT_INSTANCE_TYPE
      }
      LogWrite "Locating UCA instance type '$instanceType' ... " $True
      $instanceTypeHref = & $RSC --key $refreshToken --host $apiServer --x1 'object:has(.rel:val(\"self\")).href' `
                          cm15 index $cloudHref/instance_types "filter[]=resource_uid==$instanceType"
      if (!$instanceTypeHref) {
        LogError "ERROR: Failed to find instance type."
      }
      LogWrite "instanceTypeHref = $instanceTypeHref"

    } else {
      GetHelp
      LogError "Cloud $cloudType not currently supported."
    }

    if ($cloudType -ne 'uca') {
      if ($instanceId) {
        LogWrite "instanceId = $instanceId"
      } else {
        LogError "ERROR: Failed to find instanceId."
      }
    }

  } else {
    GetHelp
    LogError "ERROR: cloudType could not be determined."
  }

  # ===== Check instance metadata against the metadata of the instance HREF input

  # We don't have an instance yet in the UCA case, so there's nothing to check here
  if ($cloudType -ne "uca") {
    if ($instanceHref) {
      # Compare resource_uid of instance href against the current instance's metadata
      LogWrite "Comparing current instanceId against instanceHref instanceId ... " $True
      if ($resourceLabel -eq "private_ip_address") {
        if ($instanceId -ne $privateIpAddress) {
          LogError "ERROR: Instance privateIpAddress ($instanceId) does not match instanceHref privateIpAddress ($privateIpAddress)"
        }
      } elseif ($resourceLabel -eq "public_ip_address") {
        if ($instanceId -ne $publicIpAddress) {
          LogError "ERROR: Instance publicIpAddress ($instanceId) does not match instanceHref publicIpAddress ($publicIpAddress)"
        }
      } else {
        if ($instanceId -ne $resourceUid) {
          LogError "ERROR: Instance cloud metadata resourceUid ($instanceId) does not match instanceHref resourceUid ($resourceUid)"
        }
      }
      LogWrite "instanceIds match."
    } else {
      # ===== Enumerate the clouds of the type we're looking for if instance HREF was not supplied

      LogWrite "Enumerating clouds of type $cloudType ... " $True
      $cloudHrefs = @(& $RSC --key $refreshToken --host $apiServer --xm ':has(.rel:val(\"self\")).href' `
                    cm15 index /api/clouds "filter[]=cloud_type==$cloudType" | % { $_ -Replace '"', '' })
      $totalClouds = $cloudHrefs.Count
      if ($totalClouds -eq 0) {
        LogError "ERROR: No cloud type of $cloudType found in account."
      }
      LogWrite "Found $totalClouds clouds for cloud type $cloudType."

      # ===== Now locate the instance in one of the clouds

      # We try a bunch of times to locate this instance in the cloud, the reason is that it may
      # take a while for the platform to discover the instance if it just got launched.
      for($i = 1; $i -le 60; $i += 1) {
        # Iterate through all clouds of the type we're looking in
        foreach ($cloudHref in $cloudHrefs) {
          LogWrite "Finding instance $instanceId in $cloudHref ... " $True
          # Find our instance
          $instanceHref = (& $RSC --key $refreshToken --host $apiServer --x1 ':has(.rel:val(\"self\")).href' `
                          cm15 index "$cloudHref/instances" "filter[]=$resourceLabel==$instanceId" `
                          "filter[]=state<>terminated" "filter[]=state<>decommissioning" "filter[]=state<>terminating" `
                          "filter[]=state<>stopping" "filter[]=state<>provisioned" "filter[]=state<>failed" 2> $null)
          if ($instanceHref) {
            LogWrite "instanceHref = $instanceHref"
            break
          }
          LogWrite "none found."
        }
        if ($instanceHref) {
          break
        }
        if ($i -ne 60) {
          LogWrite "Attempt $i unsuccessful, sleeping 60 seconds and retrying ... "
          Start-Sleep 60
        }
      }
      if (!$instanceHref) {
        LogError "ERROR: Cannot find instance."
      }
    }
  }

  if (!$serverName) {
    $serverName = (& $RSC --key $refreshToken --host $apiServer --x1 ':root > .name' cm15 show $instanceHref 2> $null)
    if ($serverName) {
      LogWrite "Instance name used to set server name: $serverName"
    } else {
      if ($DEFAULT_SERVER_NAME) {
        $serverName = $DEFAULT_SERVER_NAME
        LogWrite "Default name used to set server name: $serverName"
      } else {
        GetHelp
        LogError "ERROR: -ServerName missing."
      }
    }
  }

  # ===== Find Server Template
  # We locate the desired ServerTemplate based on the command line argument. The ST is required
  # to create a server. It will provide boot scripts, operational scripts, decommissioning scripts,
  # alert definitions to the existing instance. An empty ST with an MCI to launch the surrogate
  # is the minimum required.

  if ($serverTemplateHref) {
    LogWrite "Finding ServerTemplate '$serverTemplateHref' ... " $True
    $serverTemplateHrefCheck = (& $RSC --key $refreshToken --host $apiServer --x1 ':has(.rel:val(\"self\")).href' `
                               cm15 show $serverTemplateHref 2> $null)
    if (!$serverTemplateHrefCheck) {
      LogError "ERROR: Could not find ServerTemplate with HREF $serverTemplateHref"
    }
  } else {
    LogWrite "Finding ServerTemplate '$serverTemplateName' ... " $True
    # check for multiple STs by checking for multiple lineages
    # if a single lineage is found, check for multiple revisions
    $json = & $RSC --key $refreshToken --host $apiServer --xj ":has(.name:val(\""$serverTemplateName\""))" `
            cm15 index "/api/server_templates" "filter[]=name==$serverTemplateName"
    if (!$json -or $json -eq "[]") {
      LogError "ERROR: Failed to find ServerTemplate. Please use -ServerTemplateHref."
    }
    $lineages = @(Write-Output $json | & $RSC --xm '.lineage' json | % { $_ -Replace '"', '' })
    foreach ($l in $lineages) {
      if (!$lineage) {
        $lineage = $l
      } elseif ($l -ne $lineage) {
        LogError "ERROR: Multiple ServerTemplates found. Please use -ServerTemplateHref."
      }
    }
    $revisions = @(Write-Output $json | & $RSC --xm '.revision' json | % { $_ -Replace '"', '' })
    $serverTemplateHrefs = @(Write-Output $json | & $RSC --xm ':has(.rel:val(\"self\")).href' json | % { $_ -Replace '"', '' })
    if ($revisions.Length -gt 1) {
      # print out all the revisions and their hrefs if more than one were found
      LogWrite ""
      foreach ($revision in $revisions) {
        $index = $revisions.IndexOf($revision)
        $href = $serverTemplateHrefs[$index]
        LogWrite "Revision $revision - HREF: $href"
      }
      LogError "ERROR: Multiple revisions found for $serverTemplateName. Please use -ServerTemplateHref for the desired revision."
    } elseif ($revisions.Length -eq 0) {
      LogError "ERROR: Failed to find revisions for $serverTemplateName. Please use -ServerTemplateHref."
    }
    $serverTemplateHref = (Write-Output $json | & $RSC --x1 ':has(.rel:val(\"self\")).href' json 2> $null)
  }
  LogWrite "serverTemplateHref = $serverTemplateHref"

  # ===== Find Deployment
  # We locate the desired deployment based on the command line argument. Alternatively, this
  # could be changed to create a deployment.

  if ($deploymentHref) {
    LogWrite "Finding Deployment '$deploymentHref' ... " $True
    $deploymentHrefCheck = (& $RSC --key $refreshToken --host $apiServer --x1 ':has(.rel:val(\"self\")).href' `
                           cm15 show $deploymentHref 2> $null)
    if (!$deploymentHrefCheck) {
      LogError "ERROR: Could not find Deployment with HREF $deploymentHref"
    }
  } else {
    LogWrite "Finding Deployment '$deploymentName' ... " $True
    $json = (& $RSC --key $refreshToken --host $apiServer --x1 ":has(.name:val(\""$deploymentName\""))" `
            cm15 index "/api/deployments" "filter[]=name==$deploymentName" 2> $null)
    if (!$json) {
      LogError "ERROR: Failed to find deployment. Please use -DeploymentHref."
    }
    $deploymentHref = (Write-Output $json | & $RSC --x1 ':has(.rel:val(\"self\")).href' json 2> $null)
  }
  LogWrite "deploymentHref = $deploymentHref"

  # ===== UCA case: we're "launching" the server

  if ($cloudType -eq "uca") {
    LogWrite "Creating UCA server ... " $True
    $serverHref = & $RSC --key $refreshToken --host $apiServer `
                  --xh 'location' cm15 create /api/servers `
                  "server[name]=$serverName" `
                  "server[deployment_href]=$deploymentHref" `
                  "server[instance][server_template_href]=$serverTemplateHref" `
                  "server[instance][cloud_href]=$cloudHref" `
                  "server[instance][datacenter_href]=$datacenterHref" `
                  "server[instance][image_href]=$imageHref" `
                  "server[instance][instance_type_href]=$instanceTypeHref" `
                  "server[instance][cloud_specific_attributes][num_cores]=2" `
                  "server[instance][cloud_specific_attributes][memory_mb]=2048" `
                  "server[instance][cloud_specific_attributes][disk_gb]=1024"
    if ($serverHref) {
      LogWrite "Created server: serverHref = $serverHref"
    } else {
      LogError "ERROR: Failed to create server."
    }

    LogWrite "Launching UCA server ... " $True
    # If launch command is sent too fast after creating it, it will return a 422 unprocessable entity
    # Try to launch 5 times before failing
    for($i = 1; $i -le 5; $i += 1) {
      $instanceHref = (& $RSC --key $refreshToken --host $apiServer --xh 'location' cm15 launch $serverHref 2> $null)
      if ($instanceHref) {
        break
      }
      Start-Sleep 1
    }
    if ($instanceHref) {
      LogWrite "instanceHref = $instanceHref"
    } else {
      & $RSC --key $refreshToken --host $apiServer cm15 destroy $serverHref
      LogError "ERROR: Failed to launch server."
    }
  } else {
  # ===== Non-UCA case: we need to enable (wrap) the instance

    # ===== Retrieve instance data
    # Make sure that the server is in a valid state to be enabled
    # Wait up to 45 minutes for the server to get into a valid state
    for($i = 1; $i -le 60; $i += 1) {
      LogWrite "Finding current instance ... " $True
      $json = & $RSC --key $refreshToken --host $apiServer cm15 show $instanceHref
      $state = (Write-Output $json | & $RSC --x1 '.state' json 2> $null)
      if ($state -ne "running" -and $state -ne "operational") {
        LogWrite "Instance found, but in the wrong state: $state."
        if ($i -ne 60) {
          LogWrite "Attempt $i unsuccessful, sleeping 60 seconds and retrying ... "
          Start-Sleep 60
        } else {
          LogError "ERROR: Instance failed to achieve running or operational state."
        }
      } else {
        LogWrite "Instance found and is in state: $state."
        break
      }
    }

    # ===== Existing enable check

    LogWrite "Checking to see if instance is already enabled ... " $True
    $serverHref = (Write-Output $json | & $RSC --x1 ':has(.rel:val(\"parent\")).href' json 2> $null)
    if ($serverHref) {
      LogWrite "serverHref = $serverHref"
    } else {
      LogWrite "Instance not enabled."

      # ===== Enable the instance
      # We turn the instance into a server using the wrap_instance API call. The server will have
      # this instance as current instance and an appropriate next-instance. We pass the ServerTemplate
      # href in the call and this will determine the operational scripts available as well as any
      # alerts.

      LogWrite "Enabling instance '$serverName' ... " $True
      $request = "& '$RSC' --key $refreshToken --host $apiServer --xh 'location' cm15 wrap_instance /api/servers" +
                 " 'server[name]=$serverName' 'server[instance][server_template_href]=$serverTemplateHref'" +
                 " 'server[deployment_href]=$deploymentHref' 'server[instance][href]=$instanceHref'"
      if ($inputs) {
        $inputs_array = $inputs -replace ',([^,=]+=)', 'REPLACE_TOKEN$1' -split 'REPLACE_TOKEN'
        foreach ($input in $inputs_array) {
          $values = $input -split "=", 2
          if ($values[0] -and $values[1]) {
            $inputName     = $values[0].trim()
            $inputKeyValue = $values[1].trim()
            $request += " 'server[instance][inputs][$inputName]=$inputKeyValue'"
          } else {
            LogError "ERROR: Malformed input: $values. Please use the format NAME=key:value."
          }
        }
      }
      $serverHref = Invoke-Expression $request
      if ($serverHref) {
        LogWrite "Created server: serverHref = $serverHref"
      } else {
        LogError "ERROR: Failed to create server."
      }
    }
  }

  # ===== Grab user-data from server
  # We grab the user-data which is required for RightLink to be able to connect with the RS platform.
  # The user-data is only part of the extended instance view

  LogWrite "Fetching user-data for instance $instanceHref ... " $True
  $userData = (& $RSC --key $refreshToken --host $apiServer --x1 '.user_data' cm15 show $instanceHref "view=extended" 2> $null)
  if ($userData) {
    LogWrite "user-data found.`n"
  } else {
    LogError "ERROR: Failed to retrieve user-data."
  }

  # ===== Save user-data in a file
  # We save the user-data in a file so it remains available if RightLink10 is restarted,
  # for example due to a reboot. Here we handle query-string user-data format, which we may have
  # to switch to mime depending on the MCIs we want to use and to support relaunching the
  # instance.

  $RS_DIR       = "$env:ProgramData\RightScale\RightLink"
  $RS_ID_FILE   = "$RS_DIR\rightscale-identity"

  if (!(Test-Path -Path $RS_DIR)) {
    New-Item -Path $RS_DIR -Type Directory -Force | Out-Null
  }

  # Theres two different formats (RL10 and RL6). Ensure unformity by translating
  # them both into RL10 format.
  $RS_VARS = ""
  $userData = $userData | foreach {$_ -split "&|`n"}
  foreach ($line in $userData) {
    LogWrite $line
    $line = $line -replace 'RS_rn_auth',     'client_secret'
    $line = $line -replace 'RS_rn_id',       'client_id'
    $line = $line -replace 'RS_server',      'api_hostname'
    $line = $line -replace 'RS_account',     'account'
    $line = $line -replace 'http_no_proxy',  'no_proxy'
    $line = $line -replace "(.*)='(.*)'", "`$1=`$2"
    if ($line -match "client_secret|client_id|api_hostname|account|http_proxy|no_proxy") {
      $RS_VARS = $RS_VARS + $line + "`n"
    }
  }

  # Workaround: we can't set the tag on instances and have the core recognize
  # it, so we write it ourselves into the identity file. We also set the tag on the server
  # Setting the server tags ensures we'll write proxy correctly in the event of a
  # stop/start, and is informative otherwise.
  if ($env:http_proxy -and $env:http_proxy -ne "") {
    $RS_VARS = $RS_VARS + "http_proxy=$env:http_proxy`n"
    $resp = & $RSC --key $refreshToken --host $apiServer cm15 multi_add /api/tags/multi_add resource_hrefs[]=$serverHref resource_hrefs[]=$instanceHref tags[]=rs_agent:http_proxy=$env:http_proxy
    $status=$?
    if (!($status)) {
      LogError "ERROR: Failed to tag server with rs_agent:http_proxy=$env:http_proxy, exit code: $status`nResponse '$resp'"
    }
    LogWrite "Added rs_agent:http_proxy tag to server"
  }

  if ($env:no_proxy -and $env:no_proxy -ne "") {
    $RS_VARS = $RS_VARS + "no_proxy=$env:no_proxy`n"
    $resp = & $RSC --key $refreshToken --host $apiServer cm15 multi_add /api/tags/multi_add resource_hrefs[]=$serverHref resource_hrefs[]=$instanceHref tags[]=rs_agent:http_no_proxy=$env:no_proxy
    $status=$?
    if (!($status)) {
      LogError "ERROR: Failed to tag server with rs_agent:http_no_proxy=$env:no_proxy, exit code: $status`nResponse '$resp'"
    }
    LogWrite "Added rs_agent:http_no_proxy tag to server"
  }

  LogWrite "`nWriting RightLink enrollment info to $RS_ID_FILE"
  Set-Content $RS_ID_FILE $RS_VARS

  # ===== Install RightLink
  if ($Username -eq "") {
    & "$RIGHTLINK_INST_DIR\RightLink\install.ps1" -Start
  } else {
    & "$RIGHTLINK_INST_DIR\RightLink\install.ps1" -Start -Username ${Username} -Password ${Password}
  }

  $currentTime = Get-Date
  LogWrite "$currentTime Enablement complete."

} #end ScriptBlock

if ($targetServers.GetType().Name -eq "Object[]") { $ServersArr = $targetServers }
elseif ($targetServers.GetType().Name -eq "String") {
    $ServersArr = $targetServers.Split(",")
}
else {
    write-host "Invalid TargetServers parameter set"
}


$allsessions = Get-PSSession
if ($AllSessions) { $AllSessions | foreach { Remove-PSSession -Session $_ } }

Foreach ($targetServer in $ServersArr) {
    $session = $null
    New-PSSession -ComputerName $targetServer -Credential $Credential
    $Session = Get-PSSession -ComputerName $targetServer -Credential $Credential
    Invoke-Command -Session $session -ScriptBlock {
        Set-ExecutionPolicy Bypass -Scope Process
        $refreshToken = $Using:refreshToken
        $deploymentName = $Using:deploymentName
        $deploymentHref = $Using:deploymentHref
        $serverTemplateName = $Using:serverTemplateName
        $serverTemplateHref = $Using:serverTemplateHref
        $serverName = $Using:serverName
        $inputs = $Using:inputs
        $cloudType = $Using:cloudType
        $instanceHref = $Using:instanceHref
        $apiServer = $Using:apiServer
        $proxy = $Using:proxy
        $noProxy = $Using:noProxy
        $Username = $Using:Username
        $Password = $Using:Password
        Invoke-Expression -Command $Using:ScriptBlock
    }
    Remove-PSSession -Session $session

}
