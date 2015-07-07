#!/bin/bash
#Script to be used to enable running servers.
#Requirements :
#    -
#
#
#
#

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
     echo "  -u user to access servers"
     echo "  -p password to use when authenticating with a password"
     echo "  -k ssh private key to use when authenticating with keys"
     echo "  -f file with hostnames or ips"
     echo "  -d deployment where servers will the grouped"
     echo "  -n server name prefix"
     echo "  -m enable managed logins"
     echo "  -s server template name to associate the enaled server"
     echo "  -t rightscale API refresh token (Settings>API Credentials)"
     echo "  -c cloud (e.g. amazon, azure, cloud_stack, google, open_stack_v2,
                rackspace_next_gen, soft_layer, vscale )"
     echo "  -h show help information"
     echo ""
}

#
# function check_connectivity($server)
# {
#
# }
#


while getopts ":u:p:k:f:d:n:m:s:t:c:h" opt; do
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
    export RS_MANAGED_LOGIN=true
    ;;
    #Server template name to use on enabled vms
    s)
    export RS_SERVER_TEMPLATE_NAME=$OPTARG
    ;;
    #rightscale api refresh token
    t)
    export RS_API_TOKEN=$OPTARG
    ;;
    #cloud type
    c)
    export RS_CLOUD=$OPTARG
    ;;
    # help
    h)
    show_help
    ;;
    # Invalid option
    \?) echo "invalid option -$OPTARG"; show_help;exit 1;;
  esac
done

#Create a working directory for the script and storing logs for each host (rightscale_rl10_script)
if [ ! -d "$RL10_WORKING_DIR" ]; then
  mkdir $RL10_WORKING_DIR
else
  echo "Working directory $RL10_WORKING_DIR exists . . . continue"
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

#build ssh command
if [ ! -z "$SSHPASS" ]; then
  SSH_CMD="sshpass -e ssh -tt -o StrictHostKeyChecking=no $RS_SSH_USER"
elif [ ! -z "$SSH_KEY_FILE" ]; then
  SSH_CMD="ssh -tt -o StrictHostKeyChecking=no -i $SSH_KEY_FILE $RS_SSH_USER"
else
  SSH_CMD="ssh -tt -o StrictHostKeyChecking=no $RS_SSH_USER"
fi

#for debugging - (REMOVE ME)
echo $SSH_CMD


#generate naming prefix if not provided with the -n option.
# if [ -z "$RS_SERVER_NAME" ];then
#   RS_SERVER_NAME=

#Process each individual server
#TODO use pssh for paralle ssh sessions




for server in `cat $RS_HOSTS_FILE` ; do



    ( { echo "output from $server" ; $SSH_CMD@$server " \

    #check if the file already exists, previous attempts
    [[ -f 'rightlink.enable.sh' ]] && rm 'rightlink.enable.sh'

    #get the latest enable script
    #add logic if curl -h doesn't return 0, try wget.
    curl https://rightlink.rightscale.com/rll/10.1.3/rightlink.enable.sh > rightlink.enable.sh && chmod +x rightlink.enable.sh && \

    #wget https://rightlink.rightscale.com/rll/10.1.3/rightlink.enable.sh && chmod +x rightlink.enable.sh  \

    #run the enable script
    #echo  "RightLink10: Enabled on \r"

    sudo ./rightlink.enable.sh -l -k  "\'$RS_API_TOKEN\'" -t "\'$RS_SERVER_TEMPLATE_NAME\'"  -c "\'$RS_CLOUD\'"  -d "\'$RS_DEPLOYMENT\'"
    echo 'success' " ; } | \
    #sed -e "s/^/$server:/" >> "$RL10_WORKING_DIR/$server-rl.log"
    sed -e "s/^/RightLink10:/"
    ) &

 done
 wait
