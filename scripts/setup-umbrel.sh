#!/bin/bash
# This script setup the environment needed for VPN usage on lightning network nodes
# Use with care
#
# Usage: sudo bash setup-umbrel.sh

#VERSION NUMBER
#Update if your make a significant change
##########UPDATE IF YOU MAKE A NEW RELEASE#############
major=0
minor=0
patch=26

# Helper
function valid_ipv4() {
    local ip=$1
    local stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 &&
            ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# check if sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (with sudo)"
    exit 1
fi

# intro
echo -e "
###############################
         Tunnel⚡️Sats
         Umbrel Setup Script
         Version:
         v$major.$minor.$patch
###############################"
echo

# Check which implementation the user wants to tunnel
lnImplementation=""

while true; do
    read -p "Which lightning implementation do you want to tunnel? Supported are LND and CLN for now ⚡️: " answer

    case $answer in
    lnd | LND*)
        echo "> Setting up Tunnel⚡️Sats for LND on port 9735 "
        echo
        lnImplementation="lnd"
        break
        ;;

    cln | CLN*)
        echo "> Setting up Tunnel⚡️Sats for CLN on port 9735 "
        echo
        lnImplementation="cln"
        break
        ;;

    *) echo "Enter LND or CLN, please." ;;
    esac
done

# check for downloaded tunnelsatsv2.conf, exit if not available
# get current directory
directory=$(dirname -- "$(readlink -fn -- "$0")")
echo "Looking for WireGuard config file..."
if [ ! -f "$directory"/tunnelsatsv2.conf ] || [ $(grep -c "Endpoint" "$directory"/tunnelsatsv2.conf) -eq 0 ]; then
    echo "> ERR: tunnelsatsv2.conf not found or missing Endpoint."
    echo "> Please place it in this script's location and check original tunnelsatsv2.conf for \"Endpoint\" entry"
    echo
    exit 1
else
    echo "> tunnelsatsv2.conf found, proceeding."
    echo
fi

# check requirements and update repos
echo "Checking and installing requirements..."
echo "Updating the package repositories..."
apt update >/dev/null
echo

sleep 2

# check / install nftables
echo "Checking nftables installation..."
checknft=$(nft -v 2>/dev/null | grep -c "nftables")
if [ $checknft -eq 0 ]; then
    echo "Installing nftables..."
    if apt install -y nftables >/dev/null; then
        echo "> nftables installed"
        echo
    else
        echo "> failed to install nftables"
        echo
        exit 1
    fi
else
    echo "> nftables found"
    echo
fi

sleep 2

# check / install wireguard
echo "Checking wireguard installation..."
checkwg=$(wg -v 2>/dev/null | grep -c "wireguard-tools")
if [ $checkwg -eq 0 ]; then
    echo "Installing wireguard..."

    if apt install -y wireguard >/dev/null; then
        echo "> wireguard installed"
        echo
    else
        echo "> failed to install wireguard"
        echo
        exit 1
    fi

else
    echo "> wireguard found"
    echo
fi

sleep 2

# add resolvconf package to docker systems for DNS resolving
echo "Checking resolvconf installation..."
checkResolv=$(resolvconf 2>/dev/null | grep -c "^Usage")
if [ $checkResolv -eq 0 ]; then
    echo "Installing resolvconf..."
    if apt install -y resolvconf >/dev/null; then
        echo "> resolvconf installed"
        echo
    else
        echo "> failed to install resolvconf"
        echo
        exit 1
    fi
else
    echo "> resolvconf found"
    echo
fi

sleep 2

# Create Docker Tunnelsat Network which stays persistent over restarts
echo "Creating TunnelSats Docker Network..."
checkdockernetwork=$(docker network ls 2>/dev/null | grep -c "docker-tunnelsats")
# the subnet needs a bigger subnetmask (25) than the normal umbrel_mainet subnetmask of 24
# otherwise the network will not be chosen as the gateway for outside connection
dockersubnet="10.9.9.0/25"

if [ $checkdockernetwork -eq 0 ]; then
    docker network create "docker-tunnelsats" --subnet $dockersubnet -o "com.docker.network.driver.mtu"="1420" &>/dev/null
    if [ $? -eq 0 ]; then
        echo "> docker-tunnelsats created successfully"
        echo
    else
        echo "> failed to create docker-tunnelsats network"
        echo
        exit 1
    fi
else
    echo "> docker-tunnelsats already created"
    echo
fi

# Clean Routing Tables from prior failed wg-quick starts
delrule1=$(ip rule | grep -c "from all lookup main suppress_prefixlength 0")
delrule2=$(ip rule | grep -c "from $dockersubnet lookup 51820")
for i in $(seq 1 $delrule1); do
    ip rule del from all table main suppress_prefixlength 0
done

for i in $(seq 1 $delrule2); do
    ip rule del from $dockersubnet table 51820
done

# Flush any rules which are still present from failed interface starts
ip route flush table 51820 &>/dev/null

sleep 2

# edit tunnelsats.conf, add PostUp/Down rules
# and copy to destination folder
echo "Copy wireguard conf file to /etc/wireguard and apply network rules..."

ruleset="\n
[Interface]\n
DNS = 8.8.8.8\n
FwMark = 0x3333\n
Table = off\n
\n
PostUp = ip rule add from \$(docker network inspect \"docker-tunnelsats\" | grep Subnet | awk '{print \$2}' | sed 's/[\",]//g') table 51820\n
PostUp = ip rule add from all table main suppress_prefixlength 0\n
PostUp = ip rule add from all fwmark 0x1111 table main \n
PostUp = ip route add blackhole default metric 3 table 51820\n
PostUp = ip route add default dev %i metric 2 table 51820\n
PostUp = ip route add  10.9.0.0/24 dev %i  proto kernel scope link; ping -c1 10.9.0.1\n
\n
PostUp = sysctl -w net.ipv4.conf.all.rp_filter=0\n
PostUp = sysctl -w net.ipv6.conf.all.disable_ipv6=1\n
PostUp = sysctl -w net.ipv6.conf.default.disable_ipv6=1\n
\n
PostDown = ip rule del from \$(docker network inspect \"docker-tunnelsats\" | grep Subnet | awk '{print \$2}' | sed 's/[\",]//g') table 51820\n
PostDown = ip rule del from all table  main suppress_prefixlength 0\n
PostDown = ip rule del from all fwmark 0x1111 table main \n
PostDown = ip route flush table 51820\n
PostDown = sysctl -w net.ipv4.conf.all.rp_filter=1\n
"

directory=$(dirname -- "$(readlink -fn -- "$0")")
if [ -f "$directory"/tunnelsatsv2.conf ]; then
    cp "$directory"/tunnelsatsv2.conf /etc/wireguard/
    if [ -f /etc/wireguard/tunnelsatsv2.conf ]; then
        echo "> tunnelsatsv2.conf copied to /etc/wireguard/"
    else
        echo "> ERR: tunnelsatsv2.conf not found in /etc/wireguard/. Please check for errors."
        echo
    fi

    echo -e $ruleset 2>/dev/null >>/etc/wireguard/tunnelsatsv2.conf

    # check
    check=$(grep -c "FwMark" /etc/wireguard/tunnelsatsv2.conf)
    if [ $check -gt 0 ]; then
        echo "> network rules applied"
        echo
    else
        echo "> ERR: network rules not applied"
        echo
    fi
fi

sleep 2

# Creating Killswitch to prevent any leakage
echo "Applying KillSwitch to Docker setup..."
# Get main interface
mainif=$(ip route | grep default | cut -d' ' -f5)
localsubnet="$(hostname -I | awk '{print $1}' | cut -d"." -f1-3)".0/24

# Get docker umbrel lnd/cln ip address
dockerlndip=$(grep LND_IP "$HOME"/umbrel/.env 2>/dev/null | cut -d= -f2)
dockerlndip=${dockerlndip:-"10.21.21.9"}

if [ -d "$HOME"/umbrel/app-data/core-lightning ]; then
    dockerclnip=$(grep APP_CORE_LIGHTNING_DAEMON_IP "$HOME"/umbrel/app-data/core-lightning/exports.sh | cut -d "\"" -f2)
else
    dockerclnip=""
fi

result=""
dockertunnelsatsip="10.9.9.9"
if [ -z "$dockerclnip" ]; then
    result="$dockerlndip"
else
    result="${dockerlndip}, ${dockerclnip}"
fi

if [ -n "$mainif" ]; then

    if [ -f /etc/nftables.conf ] && [ ! -f /etc/nftablespriortunnelsats.backup ]; then
        echo "> Info: tunnelsats replaces the whole /etc/nftables.conf, backup was saved to /etc/nftablespriortunnelsats.backup"
        mv /etc/nftables.conf /etc/nftablespriortunnelsats.backup
    fi

    # Flush table if exist to avoid redundant rules
    if nft list table ip tunnelsatsv2 &>/dev/null; then
        nft flush table ip tunnelsatsv2
    fi

    echo "#!/sbin/nft -f
table ip tunnelsatsv2 {
  set killswitch_tunnelsats {
    type ipv4_addr
    elements = { ${dockertunnelsatsip}, ${result} }
  }
  #block traffic from lighting containers
  chain forward {
    type filter hook forward priority filter -1; policy accept;
    oifname ${mainif} ip daddr != ${localsubnet} ip saddr @killswitch_tunnelsats  meta mark != 0x00001111 counter  drop
  }
  #restrict traffic from the tunnelsats network other than the lightning traffic
  chain input {
    type filter hook input priority filter - 1; policy accept;
    iifname tunnelsatsv2  ct state established,related counter accept
    iifname tunnelsatsv2   tcp dport != 9735 counter drop 
    iifname tunnelsatsv2   udp dport != 9735 counter drop 
  }

  #Allow Access via tailscale/zerotier
  	chain prerouting { 
		type filter hook prerouting priority dstnat - 10; policy accept;
		ip saddr ${dockertunnelsatsip} tcp sport { 8080, 10009 } fib daddr type != local meta mark set 0x00001111 counter
	}
}" >/etc/nftables.conf

    # check application
    check=$(grep -c "tunnelsatsv2" /etc/nftables.conf)
    if [ $check -ne 0 ]; then
        echo "> KillSwitch applied"
        echo
    else
        echo "> ERR: KillSwitch not applied. Please check /etc/nftables.conf"
        echo
        exit 1
    fi

else
    echo "> ERR: not able to get default routing interface.  Please check for errors."
    echo
    exit 1
fi

## create and enable nftables service
echo "Initializing nftables..."
systemctl daemon-reload >/dev/null
if systemctl enable nftables >/dev/null && systemctl start nftables >/dev/null; then

    if [ ! -d /etc/systemd/system/umbrel-startup.service.d ]; then
        mkdir /etc/systemd/system/umbrel-startup.service.d >/dev/null
    fi

    echo "[Unit]
Description=Forcing wg-quick to start after umbrel startup scripts
# Make sure kill switch is in place before starting umbrel containers
Requires=nftables.service
After=nftables.service
" >/etc/systemd/system/umbrel-startup.service.d/tunnelsats_killswitch.conf

    # Start nftables service
    systemctl daemon-reload >/dev/null
    systemctl reload nftables >/dev/null
    if [ $? -eq 0 ]; then
        echo "> nftables systemd service started"
    else
        echo "> ERR: nftables service could not be started. Please check for errors."
        echo
        # We exit here to prevent potential ip leakage
        exit 1
    fi

else
    echo "> ERR: nftables service could not be enabled. Please check for errors."
    echo
    exit 1
fi

# Check if kill switch is in place
checkKillSwitch=$(nft list chain ip tunnelsatsv2 forward | grep -c "oifname")
if [ $checkKillSwitch -eq 0 ]; then
    echo "> ERR: Killswitch failed to activate. Please check for errors."
    echo
    exit 1
else
    echo "> Killswitch successfully activated"
    echo
fi

sleep 2

# Add Monitor which connects the docker-tunnelsats network to the lightning container
# create file
echo "Creating tunnelsats-docker-network.sh file in /etc/wireguard/..."
echo "#!/bin/sh
set -e
lightningcontainer=\$(docker ps --format 'table {{.Image}} {{.Names}} {{.Ports}}' | grep 0.0.0.0:9735 | awk '{print \$2}')
checkdockernetwork=\$(docker network ls  2> /dev/null | grep -c \"docker-tunnelsats\")
if [ \$checkdockernetwork -ne 0 ] && [ ! -z \$lightningcontainer ]; then
  if ! docker inspect \$lightningcontainer | grep -c \"tunnelsats\" > /dev/null; then
  docker network connect --ip 10.9.9.9 docker-tunnelsats \$lightningcontainer  > /dev/null
  fi
fi" >/etc/wireguard/tunnelsats-docker-network.sh

if [ -f /etc/wireguard/tunnelsats-docker-network.sh ]; then
    echo "> /etc/wireguard/tunnelsats-docker-network.sh created"
    chmod +x /etc/wireguard/tunnelsats-docker-network.sh
else
    echo "> ERR: /etc/wireguard/tunnelsats-docker-network.sh was not created. Please check for errors."
    exit 1
fi

# run it once
if [ -f /etc/wireguard/tunnelsats-docker-network.sh ]; then
    echo "> tunnelsats-docker-network.sh created, executing..."
    # run
    bash /etc/wireguard/tunnelsats-docker-network.sh
    echo "> tunnelsats-docker-network.sh successfully executed"
    echo
else
    echo "> ERR: tunnelsats-docker-network.sh execution failed"
    echo
    exit 1
fi

# enable systemd service
# create systemd file
echo "Creating tunnelsats-docker-network.sh systemd service..."
if [ ! -f /etc/systemd/system/tunnelsats-docker-network.sh ]; then
    echo "[Unit]
Description=Adding Lightning Container to the tunnel
StartLimitInterval=200
StartLimitBurst=5
[Service]
Type=oneshot
ExecStart=/bin/bash /etc/wireguard/tunnelsats-docker-network.sh
[Install]
WantedBy=multi-user.target
" >/etc/systemd/system/tunnelsats-docker-network.service

    echo "[Unit]
Description=5min timer for tunnelsats-docker-network.service
[Timer]
OnBootSec=60
OnUnitActiveSec=60
Persistent=true
[Install]
WantedBy=timers.target
" >/etc/systemd/system/tunnelsats-docker-network.timer

    if [ -f /etc/systemd/system/tunnelsats-docker-network.service ]; then
        echo "> tunnelsats-docker-network.service created"
    else
        echo "> ERR: tunnelsats-docker-network.service not created. Please check for errors."
        echo
        exit 1
    fi

    if [ -f /etc/systemd/system/tunnelsats-docker-network.timer ]; then
        echo "> tunnelsats-docker-network.timer created"
    else
        echo "> ERR: tunnelsats-docker-network.timer not created. Please check for errors."
        echo
        exit 1
    fi

fi

# enable and start tunnelsats-docker-network.service
if [ -f /etc/systemd/system/tunnelsats-docker-network.service ]; then
    systemctl daemon-reload >/dev/null
    if systemctl enable tunnelsats-docker-network.service >/dev/null &&
        systemctl start tunnelsats-docker-network.service >/dev/null; then
        echo "> tunnelsats-docker-network.service: systemd service enabled and started"
    else
        echo "> ERR: tunnelsats-docker-network.service could not be enabled or started. Please check for errors."
        echo
        exit 1
    fi
    # Docker: enable timer
    if [ -f /etc/systemd/system/tunnelsats-docker-network.timer ]; then
        if systemctl enable tunnelsats-docker-network.timer >/dev/null &&
            systemctl start tunnelsats-docker-network.timer >/dev/null; then
            echo "> tunnelsats-docker-network.timer: systemd timer enabled and started"
            echo
        else
            echo "> ERR: tunnelsats-docker-network.timer: systemd timer could not be enabled or started. Please check for errors."
            echo
            exit 1
        fi
    fi

else
    echo "> ERR: tunnelsats-docker-network.service was not created. Please check for errors."
    echo
    exit 1
fi

sleep 2

## create and enable wireguard service
echo "Initializing the service..."
systemctl daemon-reload >/dev/null
if systemctl enable wg-quick@tunnelsatsv2 >/dev/null; then

    if [ -f /etc/systemd/system/umbrel-startup.service ]; then
        if [ ! -d /etc/systemd/system/wg-quick@tunnelsatsv2.service.d ]; then
            mkdir /etc/systemd/system/wg-quick@tunnelsatsv2.service.d >/dev/null
        fi
        echo "[Unit]
Description=Forcing wg-quick to start after umbrel startup scripts
# Make sure to start vpn after umbrel start up to have lnd containers available
Requires=umbrel-startup.service
After=umbrel-startup.service
" >/etc/systemd/system/wg-quick@tunnelsatsv2.service.d/tunnelsatsv2.conf
    fi

    systemctl daemon-reload >/dev/null
    systemctl restart wg-quick@tunnelsatsv2 >/dev/null
    if [ $? -eq 0 ]; then
        echo "> wireguard systemd service enabled and started"
        echo
    else
        echo "> ERR: wireguard service could not be started. Please check for errors."
        echo
        exit 1
    fi

else
    echo "> ERR: wireguard service could not be enabled. Please check for errors."
    echo
    exit 1
fi

sleep 2

# Check if tunnel works
echo "Verifying tunnel ..."
if docker pull curlimages/curl >/dev/null; then
    ipHome=$(curl --silent https://api.ipify.org)
    ipVPN=$(docker run -ti --rm --net=docker-tunnelsats curlimages/curl https://api.ipify.org 2>/dev/null)
    if [ "$ipHome" != "$ipVPN" ] && valid_ipv4 $ipHome && valid_ipv4 $ipVPN; then
        echo "> Tunnel is active ✅
      Your ISP external IP: ${ipHome} 
      Your TunnelSats external IP: ${ipVPN}"
        echo
    else
        echo "> ERR: TunnelSats VPN interface not successfully activated, please check debug logs"
        echo
        exit 1
    fi
else
    echo "> Tunnel verification failed. curlimages/curl not available for your system "
    echo
    exit 1
fi

# Instructions
vpnExternalDNS=$(grep "Endpoint" /etc/wireguard/tunnelsatsv2.conf | awk '{ print $3 }' | cut -d ":" -f1)
vpnExternalPort=$(grep "#VPNPort" /etc/wireguard/tunnelsatsv2.conf | awk '{ print $3 }')

echo "______________________________________________________________________

These are your personal VPN credentials for your lightning configuration."
echo

# echo "INFO: Tunnel⚡️Sats only support one lightning process on a single node.
# Meaning that running lnd and cln simultaneously via the tunnel will not work.
# Only the process which listens on 9735 will be reachable via the tunnel";echo

if [ "$lnImplementation" == "lnd" ]; then

    echo "LND:

Before editing, please create a backup of your current LND config file.
Then edit and add or modify the following lines. Please note that
settings could already be part of your configuration file 
and duplicated lines could lead to errors.

#########################################
[Application Options]
externalhosts=${vpnExternalDNS}:${vpnExternalPort}
[Tor]
tor.streamisolation=false
tor.skip-proxy-for-clearnet-targets=true
#########################################"
    echo

fi

if [ "$lnImplementation" == "cln" ]; then

    echo "CLN:

Before editing, please create a backup of your current CLN config file.
Then edit and add or modify the following lines. Please note that
settings could already be part of your configuration file
and duplicated lines could lead to errors.

###############################################################################
Umbrel 0.5+:
create CLN config file 'config':
  $ nano ${HOME}/umbrel/app-data/core-lightning/data/lightningd/bitcoin/config 
insert:
  bind-addr=10.9.9.9:9735
  announce-addr=${vpnExternalDNS}:${vpnExternalPort}
  always-use-proxy=false

edit 'export.sh':
  $ nano ${HOME}/umbrel/app-data/core-lightning/export.sh
change assigned port of APP_CORE_LIGHTNING_DAEMON_PORT from 9736 to 9735:
  export APP_CORE_LIGHTNING_DAEMON_PORT=\"9735\"

###############################################################################

Native CLN installation (config file):
  # Tor
  addr=statictor:127.0.0.1:9051/torport=9735
  proxy=127.0.0.1:9050
  always-use-proxy=false

  # VPN
  bind-addr=0.0.0.0:9735
  announce-addr=${vpnExternalDNS}:${vpnExternalPort}
  always-use-proxy=false
###############################################################################"
    echo

fi

echo "Please save these infos in a file or write them down for later use.

A more detailed guide is available at: https://blckbx.github.io/tunnelsats/
Afterwards please restart LND / CLN for changes to take effect.
VPN setup completed!

Welcome to Tunnel⚡Sats.
Feel free to join the Amboss Community here: https://amboss.space/community/29db5f25-24bb-407e-b752-be69f9431071"
echo

echo "Restart ${lnImplementation} on Umbrel afterwards via the command:
  sudo ~/umbrel/scripts/stop
  sudo ~/umbrel/scripts/start"
echo

# the end
exit 0
