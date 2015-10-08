# Bulk Rightlink 10 Enablement
Install RightLink 10 on a group of servers. Uses ssh keys or password to access servers.

##Options
```
Usage:
  -u The user used to SSH into the server
  -p The password used when SSH authenticates with a password
  -k The ssh private key to use when SSH authenticates with keys
  -f The file listing the hostnames or ips to bulk enable
  -d The deployment where enabled servers will the grouped within RightScale
  -n The name given to the server within RightScale
  -m Pass this flag to enable RightScale managed logins
  -s The server template href to associate the enaled server (e.g. /api/server_templates/355861004)
  -t The rightscale API refresh token (Settings>API Credentials)
  -a api_hostname the hostname for the RightScale API (us-3.rightscale.com / us-4.rightscale.com)
  -c cloud (e.g. amazon, azure, cloud_stack, google, open_stack_v2, rackspace_next_gen, soft_layer, vscale)
  -D disable rightlink requires (-t refresh api token, -u username, -f file with ips/hostnames)"
  -h show help information (documentation can be found here: https://github.com/rs-services/bulk-rightlink10-enablement)
```
##Warning
This command automates the enablement of your infrastructure into the RightScale platform.
It's highly recommended that you read and understand the following documentation prior running this script.
- RL10 documentation
http://docs.rightscale.com/rl/getting_started.html
- ServerTemplate documentation
http://support.rightscale.com/12-Guides/Dashboard_Users_Guide/Design/ServerTemplates/Concepts/About_ServerTemplates/index.html

##Prerequisites

1. Import the base RL10 Bulk ST
[RightLink 10 Bulk ServerTemplate](https://us-4.rightscale.com/library/server_templates/RightLink-10-2-1-Bulk-Linux-Ba/lineage/56111)



##Download and use
```
wget https://raw.githubusercontent.com/rs-services/bulk-rightlink10-enablement/master/rl_bulk_enable.sh
chmod +x rl_enable.sh
./rl_bulk_enable.sh -h
```

###Requirements

-    Deployment Name **(-d)**

  The name of the deployment where you'd like the serves to be placed.

-   Server Template Href **(-s)**

  The href of the ServerTemplate you would like associated with this server.

  -   API hostname **(-a)**

    This token can be found by login into the cloud management dashboard at (http://my.rightscale.com) Click on Settings then API Credentials

-   Refresh Token **(-t)**

  This token can be found by login into the cloud management dashboard at (http://my.rightscale.com) Click on Settings then API Credentials

-   Cloud **(-c)**

  The cloud we should reference for this server (e.g. amazon, azure, cloud_stack, google, open_stack_v2,
                rackspace_next_gen, soft_layer, vscale )

-   Authentication
   options
    - ssh key **(-k)**
    - password **(-p)**
    - no key or pass (managed on your computer via ssh-agent)

-   List of servers
    - You will need to provide the script a file with the list of servers to rightlink enable.

    example file called server.txt

```
10.10.12.1
10.10.14.3
database.domain.com
192.168.8.8
backend.domain.com
```

##Example Enablement
``` shell
./rl_bulk_enable.sh -u ec2-user -k ~/edwin-aws.pem -f servers.txt -d 'AWS Backend Workload Deployment' -s '/api/server_templates/362953003' -t '7bPLUbLfGaQFcSkywVfLpRMt7bPLUbLfGaQFcSkywVfLpRMt' -c 'amazon' -a 'us-3.rightscale.com'
```
**Output**

![Alt text](/../master/output.png?raw=true "Optional Title")


##Example Disablement
``` shell
./rl_bulk_enable.sh -u ec2-user -k ~/stash/edwin-aws.pem -D -t '7bPLUbLfGaQFcSkywVfLpRMt7bPLUbLfGaQFcSkywVfLpRMt' -f servers.txt -a 'us-3.rightscale.com'
```

##Logging
All logging information is stored in the rightscale_rl10 directory on the computer from where the script is being executed.
We will keep logs of failed attempts in the following format.
``` 1.2.3.4--failed-rl.log ```

We will also create a file with the ips/hostname of the failed instances so that you easily re-run the script using the new list of host as the server file.

```failed_enablement_process.2015-07-13_15-44-56.txt ```

```./rl_bulk_enable.sh -u ec2-user -k ~/edwin-aws.pem -f rightscale_r10/failed_enablement_process.2015-07-13_15-44-56.txt -d 'AWS Backend Workload Deployment' -s '/api/server_templates/362953003' -t '7bPLUbLfGaQFcSkywVfLpRMt7bPLUbLfGaQFcSkywVfLpRMt' -c 'amazon' ```


**Note:**
On clouds that support stop/start, instances only currently support starting the instance from either the RightScale Dashboard or through the API.
