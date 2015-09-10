#!/bin/bash
#Script documentation can me found here
#https://github.com/rs-services/bulk-rightlink10-enablement
#Script to be used to enable running servers.
#It will execute the rightscale.enable.sh or rightscript.disable.sh script
#https://rightlink.rightscale.com/rll/10.1.4/rightlink.enable.sh
#on all listed servers.


#local working directory
RL10_WORKING_DIR='rightscale_rl10'


#use sshpass for passing the password ssh when not using a key
#MAC OSX brew install https://git.io/sshpass.rb
#CENTOS/RHELyum -y install sshpass
#UBUNTU apt-get -y install sshpass

#uses pssh for parrallel ssh sessions
 #after testing on 20 instances , not a significant need.
#MAC OSX brew install pssh
#CENTOS/RHEL yum -y install pssh
#UBUNTU/DEBIAN apt-get -y install pssh

function show_help
{
     echo ""
     echo "Usage: "
     echo "  -u The user used to SSH into the server"
     echo "  -p The password used when SSH authenticates with a password"
     echo "  -k The ssh private key to use when SSH authenticates with keys"
     echo "  -f The file listing the hostnames or ips to bulk enable"
     echo "  -d The deployment where enabled servers will the grouped within RightScale"
     echo "  -n The name given to the server within RightScale"
     echo "  -m Pass this flag to enable RightScale managed logins"
     echo "  -s The server template href to associate the enaled server (e.g. /api/server_templates/355861004)"
     echo "  -t The rightscale API refresh token (Settings>API Credentials)"
     echo "  -a the hostname for the RightScale API (i.e. us-4.rightscale.com)"
     echo "  -c cloud (e.g. amazon, azure, cloud_stack, google, open_stack_v2,
                rackspace_next_gen, soft_layer, vscale )"
     echo "  -D disable rightlink requires (-t refresh api token, -u username, -f file with ips/hostnames)"
     echo "  -h show help information (documentation can be found here: https://github.com/rs-services/bulk-rightlink10-enablement)"
     echo ""
}


while getopts ":u:p:k:f:d:n:ms:t:a:c:hD" opt; do
  case $opt in
    # User to ssh as
    u)
    export RS_SSH_USER=$OPTARG
    ;;
    # Password
    p)
    export SSHPASS=$OPTARG
    ;;
    #ssh key file
    k)
    export SSH_KEY_FILE=$OPTARG
    ;;
    # file with host information
    f)
    export RS_HOSTS_FILE=$OPTARG
    ;;
    #deployment name
    d)
    export RS_DEPLOYMENT=$OPTARG
    ;;
    #server name
    n)
    export RS_SERVER_NAME=$OPTARG
    ;;
    #enabled managed login
    m)
    export RS_MANAGED_LOGIN='-l'
    ;;
    #Server template name to use on enabled vms
    s)
    export RS_SERVER_TEMPLATE_HREF=$OPTARG
    ;;
    #rightscale api refresh token
    t)
    export RS_API_TOKEN=$OPTARG
    ;;
    #rightscale api endpoint
    a)
    export RS_API_ENDPOINT=$OPTARG
    ;;
    #cloud type
    c)
    export RS_CLOUD=$OPTARG
    ;;
    #disable rightlink
    D)
    export DISABLE=true
    ;;
    # help
    h)
    show_help;exit 0;
    ;;
    # Invalid option
    \?) echo "invalid option -$OPTARG"; show_help;exit 1;;
  esac
done

#Create a working directory for the script and storing logs for each host (rightscale_rl10_script)
if [ ! -d "$RL10_WORKING_DIR" ]; then
  mkdir $RL10_WORKING_DIR
fi

#Generate SSH command options
#1 ssh -u -p #user and password
#2 ssh -u -k #user and private key
#3 ssh -u  #only user

if [[ -z "$RS_SSH_USER" ]]; then
  echo "ERROR: -u user missing." >&2
  show_help >&2
  exit 1
fi

if [[ -z "$RS_API_ENDPOINT" ]]; then
  echo "ERROR: -a api endpoint missing." >&2
  show_help >&2
  exit 1
fi

#randomize name to RightLink Enable #random (to be fixed in later release)
#disable RL opton for group of servers.


#check for server name option
if [ -z "$RS_SERVER_NAME" ]; then
  RS_SERVER_NAME="RightLink Enabled"
fi


#build ssh command
if [ ! -z "$SSHPASS" ]; then
  SSH_CMD="sshpass -e ssh -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 $RS_SSH_USER"
elif [ ! -z "$SSH_KEY_FILE" ]; then
  SSH_CMD="ssh -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $SSH_KEY_FILE $RS_SSH_USER"
else
  SSH_CMD="ssh -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 $RS_SSH_USER"
fi

#prompt for confirmation of bulk action.
NUM_SERVERS=`wc -l < $RS_HOSTS_FILE`

# Prompt user for confirmation
if [[ "$DISABLE" == 'true' ]];then
    echo ""
    echo "Number of Servers to be disabled: $NUM_SERVERS"
    echo ""
    read -r -p "Do you want to proceed? [y/N] " response </dev/tty

    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo "Continuing with disablement"
    else
    echo "Aborted disablement process"
    exit 1
    fi
else
    # Prompt user for confirmation
    echo ""
    echo "Number of Servers to be enabled: $NUM_SERVERS"
    echo "ServerTemplate to be associated with server: $RS_SERVER_TEMPLATE_HREF"
    echo ""
    read -r -p "Do you want to proceed? [y/N] " response </dev/tty

    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
      echo "Continuing with enablement"
    else
      echo "Aborted enablement process"
      exit 1
    fi
fi


for server in `cat $RS_HOSTS_FILE` ; do

    # ?( {

    if [[ "$DISABLE" == 'true' ]];then
      {
      (
          echo "Output from $server:" ; $SSH_CMD@$server " \

          #check if the file already exists, previous attempts
          [[ -f 'rightlink.disable.sh' ]] && rm 'rightlink.disable.sh'

          curl https://rightlink.rightscale.com/rll/10.1.4/rightlink.disable.sh > rightlink.disable.sh && chmod +x rightlink.disable.sh && \

          #Disable server -s is not needed it will used data that's on the server. (-f auto confirm the disablment prompt)
          sudo ./rightlink.disable.sh -k  "\'$RS_API_TOKEN\'" -f
          ";
          ) 2> "$RL10_WORKING_DIR/$server-rl.log" | sed -e "s/^/$server:/" >> "$RL10_WORKING_DIR/$server-rl.log" &
      }
    else
    {
    (
          echo "Output from $server:" ; $SSH_CMD@$server " \

          #check if the file already exists, previous attempts
          [[ -f 'rightlink.enable.sh' ]] && rm 'rightlink.enable.sh'

          curl https://rightlink.rightscale.com/rll/10.1.4/rightlink.enable.sh > rightlink.enable.sh && chmod +x rightlink.enable.sh && \

          #RS_MANAGED_LOGIN is set to "-l" if the -m flag is used.
          sudo ./rightlink.enable.sh $RS_MANAGED_LOGIN -a "\'$RS_API_ENDPOINT\'" -n "\'$RS_SERVER_NAME $RANDOM\'" -k  "\'$RS_API_TOKEN\'" -r "\'$RS_SERVER_TEMPLATE_HREF\'"  -c "\'$RS_CLOUD\'"  -d "\'$RS_DEPLOYMENT\'"
          ";
          ) 2> "$RL10_WORKING_DIR/$server-rl.log" | sed -e "s/^/$server:/" >> "$RL10_WORKING_DIR/$server-rl.log" &

    }
    fi

    #fix logging issue here.
    #| \
    #sed -e "s/^/$server:/" >> "$RL10_WORKING_DIR/$server-rl.log"

    #})

 done
 wait

#Report Status of each server
RED='\033[0;31m' # Red
GREEN='\033[0;32m' # Green
NC='\033[0m' # No Color
TIMESTAMP=`date +"%Y-%m-%d_%H-%M-%S"`

 for server in `cat $RS_HOSTS_FILE` ; do

          if [[ "$DISABLE" == 'true' ]];then
            DETECTION_STRING='Disablement'
          else
            DETECTION_STRING='Enablement'
          fi

  #  grep "Enablement complete." $RL10_WORKING_DIR/$server-rl.log
     if grep -Fq "$DETECTION_STRING complete." "$RL10_WORKING_DIR/$server-rl.log"; then
       printf "$server: Rightlink $DETECTION_STRING ${GREEN} [OK] ${NC}\n";
     else
       printf "$server: Rightlink $DETECTION_STRING ${RED} [FAILED] ${NC}\n";
       HAS_FAILED='true'
       echo $server >> "$RL10_WORKING_DIR/failed_$DETECTION_STRING.$TIMESTAMP.txt"
       mv "$RL10_WORKING_DIR/$server-rl.log" "$RL10_WORKING_DIR/$server-failed-rl.log"
     fi

     #clean up logs for another run.
     rm -rf $RL10_WORKING_DIR/$server-rl.log

done

if [ "$HAS_FAILED" == 'true' ]; then

echo "#####################################################################################################"
echo "A list of failed server can be found here $RL10_WORKING_DIR/failed_$DETECTION_STRING.$TIMESTAMP.txt"
echo "A log file for each failed server is included in $RL10_WORKING_DIR"
echo "#####################################################################################################"
echo "#####################################################################################################"
echo " "
fi
