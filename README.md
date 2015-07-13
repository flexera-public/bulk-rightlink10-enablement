# Bulk Rightlink 10 Enablement
Install RightLink 10 on a group of servers. Uses ssh keys or password to access servers.

##Options
```
Usage:
  -u user to access servers
  -p password to use when authenticating with a password
  -k ssh private key to use when authenticating with keys
  -f file with hostnames or ips
  -d deployment where servers will the grouped
  -n server name prefix
  -m enable managed logins
  -s server template name to associate the enaled server
  -t rightscale API refresh token (Settings>API Credentials)
  -c cloud (e.g. amazon, azure, cloud_stack, google, open_stack_v2,
                rackspace_next_gen, soft_layer, vscale )
  -h show help information
```


##Download and use
```
wget https://raw.githubusercontent.com/rs-services/bulk-rightlink10-enablement/master/rl_bulk_enable.sh
chmod +x rl_enable.sh
./rl_enable.sh -h
```

###Requirements

-    Deployment Name **(-d)**

  The name of the deployment where you'd like the serves to be placed.

-   Server Template Name **(-s)**

  The name of the ServerTemplate you would like associated with this server.

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

##Example
``` shell
./rl_bulk_enable.sh -u ec2-user -k ~/edwin-aws.pem -f servers.txt -d 'AWS Backend Workload Deployment' -s 'RightLink 10.1.3 Linux Base' -t '7bPLUbLfGaQFcSkywVfLpRMt7bPLUbLfGaQFcSkywVfLpRMt' -c 'amazon' 
```

##Logging 
All logging information is stored in the rightscale_rl10 directory on the computer from where the script is being executed.
We will keep logs of failed attempts in the following format.
``` 1.2.3.4--failed-rl.log ```

We will also create a file with the ips/hostname of the failed instances so that you easily re-run the script using the new list of host as the server file.

```failed_enablement_process.2015-07-13_15-44-56.txt ```

```./rl_bulk_enable.sh -u ec2-user -k ~/edwin-aws.pem -f rightscale_r10/failed_enablement_process.2015-07-13_15-44-56.txt -d 'AWS Backend Workload Deployment' -s 'RightLink 10.1.3 Linux Base' -t '7bPLUbLfGaQFcSkywVfLpRMt7bPLUbLfGaQFcSkywVfLpRMt' -c 'amazon' ```




