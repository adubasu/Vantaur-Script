#!/bin/bash

TMP_FOLDER=$(mktemp -d)
CONFIG_FILE="Vantaur.conf"
VANTAUR_DAEMON="/usr/local/bin/vantaurd"
VANTAUR_REPO="https://github.com/vantaur/vantaur"
DEFAULTVANTAURPORT=11453
DEFAULTVANTAURUSER="vantaur"
NODEIP=$(curl -s4 icanhazip.com)


RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


function compile_error() {
if [ "$?" -gt "0" ];
 then
  echo -e "${RED}Failed to compile $@. Please investigate.${NC}"
  exit 1
fi
}


function checks() {
if [[ $(lsb_release -d) != *16.04* ]]; then
  echo -e "${RED}You are not running Ubuntu 16.04. Installation is cancelled.${NC}"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}$0 must be run as root.${NC}"
   exit 1
fi

if [ -n "$(pidof $VANTAUR_DAEMON)" ] || [ -e "$VANTAUR_DAEMOM" ] ; then
  echo -e "${GREEN}\c"
  read -e -p "Vantaur is already installed. Do you want to add another MN? [Y/N]" NEW_VANTAUR
  echo -e "{NC}"
  clear
else
  NEW_VANTAUR="new"
fi
}

function prepare_system() {

echo -e "Prepare the system to install Vantaur master node."
apt-get update >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get update > /dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y -qq upgrade >/dev/null 2>&1
apt install -y software-properties-common >/dev/null 2>&1
echo -e "${GREEN}Adding bitcoin PPA repository"
apt-add-repository -y ppa:bitcoin/bitcoin >/dev/null 2>&1
echo -e "Installing required packages, it may take some time to finish.${NC}"
apt-get update >/dev/null 2>&1
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" make software-properties-common \
build-essential libtool autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev libboost-program-options-dev \
libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git wget pwgen curl libdb4.8-dev bsdmainutils libdb4.8++-dev \
libminiupnpc-dev libgmp3-dev >/dev/null 2>&1
clear
if [ "$?" -gt "0" ];
  then
    echo -e "${RED}Not all required packages were installed properly. Try to install them manually by running the following commands:${NC}\n"
    echo "apt-get update"
    echo "apt -y install software-properties-common"
    echo "apt-add-repository -y ppa:bitcoin/bitcoin"
    echo "apt-get update"
    echo "apt install -y make build-essential libtool software-properties-common autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev \
libboost-program-options-dev libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git pwgen curl libdb4.8-dev \
bsdmainutils libdb4.8++-dev libminiupnpc-dev libgmp3-dev"
 exit 1
fi

clear
echo -e "Checking if swap space is needed."
PHYMEM=$(free -g|awk '/^Mem:/{print $2}')
SWAP=$(free -g|awk '/^Swap:/{print $2}')
if [ "$PHYMEM" -lt "2" ] && [ -n "$SWAP" ]
  then
    echo -e "${GREEN}Server is running with less than 2G of RAM without SWAP, creating 2G swap file.${NC}"
    SWAPFILE=$(mktemp)
    dd if=/dev/zero of=$SWAPFILE bs=1024 count=2M
    chmod 600 $SWAPFILE
    mkswap $SWAPFILE
    swapon -a $SWAPFILE
else
  echo -e "${GREEN}Server running with at least 2G of RAM, no swap needed.${NC}"
fi
clear
}

function compile_vantaur() {
  echo -e "Clone git repo and compile it. This may take some time. Press a key to continue."
  read -n 1 -s -r -p ""

  cd $TMP_FOLDER
  git clone https://github.com/bitcoin-core/secp256k1
  cd secp256k1
  chmod +x ./autogen.sh
  ./autogen.sh
  ./configure
  make
  ./tests
  sudo make install 
  clear 

  cd $TMP_FOLDER
  git clone $VANTAUR_REPO
  cd vantaur/src
  make -f makefile.unix 
  compile_error Vantaur
  cp -a Vantaurd /usr/local/bin
  cd ~
  rm -rf $TMP_FOLDER
  clear
}

function enable_firewall() {
  FWSTATUS=$(ufw status 2>/dev/null|awk '/^Status:/{print $NF}')
  if [ "$FWSTATUS" = "active" ]; then
    echo -e "Setting up firewall to allow ingress on port ${GREEN}$VANTAURPORT${NC}"
    ufw allow $VANTAURPORT/tcp comment "Vantaur MN port" >/dev/null
  fi
}

function systemd_vantaur() {
  cat << EOF > /etc/systemd/system/$VANTAURUSER.service
[Unit]
Description=Vantaur service
After=network.target

[Service]
ExecStart=$VANTAUR_DAEMON -conf=$VANTAURFOLDER/$CONFIG_FILE -datadir=$VANTAURFOLDER
ExecStop=$VANTAUR_DAEMON -conf=$VANTAURFOLDER/$CONFIG_FILE -datadir=$VANTAURFOLDER stop
Restart=on-abord
User=$VANTAURUSER
Group=$VANTAURUSER

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  sleep 3
  systemctl start $VANTAURUSER.service
  systemctl enable $VANTAURUSER.service

  if [[ -z "$(ps axo user:15,cmd:100 | egrep ^$VANTAURUSER | grep $VANTAUR_DAEMON)" ]]; then
    echo -e "${RED}Vantaurd is not running${NC}, please investigate. You should start by running the following commands as root:"
    echo -e "${GREEN}systemctl start $VANTAURUSER.service"
    echo -e "systemctl status $VANTAURUSER.service"
    echo -e "less /var/log/syslog${NC}"
    exit 1
  fi
}

function ask_port() {
read -p "VANTAUR Port: " -i $DEFAULTVANTAURPORT -e VANTAURPORT
: ${VANTAURPORT:=$DEFAULTVANTAURPORT}
}

function ask_user() {
  read -p "VANTAUR user: " -i $DEFAULTVANTAURUSER -e VANTAURUSER
  : ${VANTAURUSER:=$DEFAULTVANTAURUSER}

  if [ -z "$(getent passwd $VANTAURUSER)" ]; then
    USERPASS=$(pwgen -s 12 1)
    useradd -m $VANTAURUSER
    echo "$VANTAURUSER:$USERPASS" | chpasswd

    VANTAURHOME=$(sudo -H -u $VANTAURUSER bash -c 'echo $HOME')
    DEFAULTVANTAURFOLDER="$VANTAURHOME/.VANTAUR"
    read -p "Configuration folder: " -i $DEFAULTVANTAURFOLDER -e VANTAURFOLDER
    : ${VANTAURFOLDER:=$DEFAULTVANTAURFOLDER}
    mkdir -p $VANTAURFOLDER
    chown -R $VANTAURUSER: $VANTAURFOLDER >/dev/null
  else
    clear
    echo -e "${RED}User exits. Please enter another username: ${NC}"
    ask_user
  fi
}

function check_port() {
  declare -a PORTS
  PORTS=($(netstat -tnlp | awk '/LISTEN/ {print $4}' | awk -F":" '{print $NF}' | sort | uniq | tr '\r\n'  ' '))
  ask_port

  while [[ ${PORTS[@]} =~ $VANTAURPORT ]] || [[ ${PORTS[@]} =~ $[VANTAURPORT+1] ]]; do
    clear
    echo -e "${RED}Port in use, please choose another port:${NF}"
    ask_port
  done
}

function create_config() {
  RPCUSER=$(pwgen -s 8 1)
  RPCPASSWORD=$(pwgen -s 15 1)
  cat << EOF > $VANTAURFOLDER/$CONFIG_FILE
rpcuser=$RPCUSER
rpcpassword=$RPCPASSWORD
rpcallowip=127.0.0.1
rpcport=$[VANTAURPORT+1]
listen=1
server=1
daemon=1
port=$VANTAURPORT
EOF
}

function create_key() {
  echo -e "Enter your ${RED}Masternode Private Key${NC}. Leave it blank to generate a new ${RED}Masternode Private Key${NC} for you:"
  read -e VANTAURKEY
  if [[ -z "$VANTAURKEY" ]]; then
  sudo -u $VANTAURUSER $VANTAUR_DAEMON -conf=$VANTAURFOLDER/$CONFIG_FILE -datadir=$VANTAURFOLDER
  sleep 5
  if [ -z "$(ps axo user:15,cmd:100 | egrep ^$VANTAURUSER | grep $VANTAUR_DAEMON)" ]; then
   echo -e "${RED}Vantaurd server couldn't start. Check /var/log/syslog for errors.{$NC}"
   exit 1
  fi
  VANTAURKEY=$(sudo -u $VANTAURUSER $VANTAUR_DAEMON -conf=$VANTAURFOLDER/$CONFIG_FILE -datadir=$VANTAURFOLDER masternode genkey)
  sudo -u $VANTAURUSER $VANTAUR_DAEMON -conf=$VANTAURFOLDER/$CONFIG_FILE -datadir=$VANTAURFOLDER stop
fi
}

function update_config() {
  sed -i 's/daemon=1/daemon=0/' $VANTAURFOLDER/$CONFIG_FILE
  cat << EOF >> $VANTAURFOLDER/$CONFIG_FILE
maxconnections=256
masternode=1
masternodeaddr=$NODEIP:$VANTAURPORT
masternodeprivkey=$VANTAURKEY
EOF
  chown -R $VANTAURUSER: $VANTAURFOLDER >/dev/null
}

function important_information() {
 echo
 echo -e "================================================================================================================================"
 echo -e "VANTAUR Masternode is up and running as user ${GREEN}$VANTAURUSER${NC} and it is listening on port ${GREEN}$VANTAURPORT${NC}."
 echo -e "${GREEN}$VANTAURUSER${NC} password is ${RED}$USERPASS${NC}"
 echo -e "Configuration file is: ${RED}$VANTAURFOLDER/$CONFIG_FILE${NC}"
 echo -e "Start: ${RED}systemctl start $VANTAURUSER.service${NC}"
 echo -e "Stop: ${RED}systemctl stop $VANTAURUSER.service${NC}"
 echo -e "VPS_IP:PORT ${RED}$NODEIP:$VANTAURPORT${NC}"
 echo -e "MASTERNODE PRIVATEKEY is: ${RED}$VANTAURKEY${NC}"
 echo -e "Please check VANTAUR is running with the following command: ${GREEN}systemctl status $VANTAURUSER.service${NC}"
 echo -e "================================================================================================================================"
}

function setup_node() {
  ask_user
  check_port
  create_config
  create_key
  update_config
  enable_firewall
  systemd_vantaur
  important_information
}


##### Main #####
clear

checks
if [[ ("$NEW_VANTAUR" == "y" || "$NEW_VANTAUR" == "Y") ]]; then
  setup_node
  exit 0
elif [[ "$NEW_VANTAUR" == "new" ]]; then
  prepare_system
  compile_vantaur
  setup_node
else
  echo -e "${GREEN}Vantaurd already running.${NC}"
  exit 0
fi

