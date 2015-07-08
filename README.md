# Bulk Rightlink 10 Enablement
Install RightLink 10 on a group of servers. Uses ssh keys or password to access servers.

##Options
```
Usage:
-  -u user to access servers
-  -p password to use when authenticating with a password
-  -k ssh private key to use when authenticating with keys
-  -f file with hostnames or ips
-  -d deployment where servers will the grouped
-  -n server name prefix
-  -m enable managed logins
-  -s server template name to associate the enaled server
-  -t rightscale API refresh token (Settings>API Credentials)
-  -c cloud (e.g. amazon, azure, cloud_stack, google, open_stack_v2,
-                rackspace_next_gen, soft_layer, vscale )
-  -h show help information
```


##Download and use
```
wget https://raw.githubusercontent.com/rs-services/bulk-rightlink10-enablement/master/rl_enable.sh
chmod +x rl_enable.sh
./rl_enable.sh -h
```

###Requirements

-    Deployment Name
  
  The name of the deployment where you'd like the serves to be placed.

-   Server Template Name

  The name of the ServerTemplate you would like associated with this server.

-   Refresh Token

  This token can be found by login into the cloud management dashboard at (http://my.rightscale.com) Click on Settings then API Credentials
-   Cloud

  The cloud we should reference for this server (e.g. amazon, azure, cloud_stack, google, open_stack_v2,
                rackspace_next_gen, soft_layer, vscale )
-   Authentication
   options
    - ssh key
    - password
    - no key or pass (managed on your computer via keyagent)

-   List of servers


You will need to provide the script a file with the list of servers to rightlink enable.

servers.txt
```
10.10.12.1
10.10.14.3
database.domain.com
192.168.8.8
backend.domain.com
```




##Example 


