#!/bin/bash
# This script setup the environment needed for VPN usage on lightning network nodes
# Use with care
#
# Usage: sudo bash setup-raspibolt.sh

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
#################################
         Tunnel⚡️Sats
         RaspiBolt Setup Script
         Version:
         v$major.$minor.$patch
#################################"
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

echo "Looking for systemd service..."
if [ "$lnImplementation" == "lnd" ] && [ ! -f /etc/systemd/system/lnd.service ]; then
    echo "> /etc/systemd/system/lnd.service not found. Setup aborted."
    echo
    exit 1
elif [ "$lnImplementation" == "cln" ] && [ ! -f /etc/systemd/system/lightningd.service ]; then
    echo "> /etc/systemd/system/lightningd.service not found. Setup aborted."
    echo
    exit 1
else
    echo "> systemd service found, proceeding..."
    echo
fi

# check requirements and update repos
echo "Checking and installing requirements..."
echo "Updating the package repositories..."
apt update >/dev/null
echo

# check cgroup-tools only necessary when lightning runs as systemd service
echo "Checking cgroup-tools..."
checkcgroup=$(cgcreate -h 2>/dev/null | grep -c "Usage")
if [ $checkcgroup -eq 0 ]; then
    echo "Installing cgroup-tools..."
    if apt install -y cgroup-tools >/dev/null; then
        echo "> cgroup-tools installed"
        echo
    else
        echo "> failed to install cgroup-tools"
        echo
        exit 1
    fi
else
    echo "> cgroup-tools found"
    echo
fi

sleep 2

# check nftables
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

# check wireguard
echo "Checking wireguard installation..."
checkwg=$(wg -v 2>/dev/null | grep -c "wireguard-tools")
if [ $checkwg -eq 0 ]; then
    echo "Installing wireguard..."

    if apt install -y wireguard >/dev/null; then
        echo "> wireguard installed"
        echo
    else
        # try Debian 10 Buster workaround / myNode
        codename=$(lsb_release -c 2>/dev/null | awk '{print $2}')
        if [ "$codename" == "buster" ]; then
            if apt install -y -t buster-backports wireguard >/dev/null; then
                echo "> wireguard installed"
                echo
            else
                echo "> failed to install wireguard"
                echo
                exit 1
            fi
        fi
    fi
else
    echo "> wireguard found"
    echo
fi

sleep 2

# Delete Rules for non-docker setup
# Clean Routing Tables from prior failed wg-quick starts
delrule1=$(ip rule | grep -c "from all lookup main suppress_prefixlength 0")
delrule2=$(ip rule | grep -c "from all fwmark 0xdeadbeef lookup 51820")
for i in $(seq 1 $delrule1); do
    ip rule del from all table main suppress_prefixlength 0
done

for i in $(seq 1 $delrule2); do
    ip rule del from all fwmark 0xdeadbeef table 51820
done

# Flush any rules which are still present from failed interface starts
ip route flush table 51820 &>/dev/null

sleep 2

# edit tunnelsats.conf, add PostUp/Down rules
# and copy to destination folder
echo "Copy wireguard conf file to /etc/wireguard and apply network rules..."

ruleset="\n
[Interface]\n
FwMark = 0x3333\n
Table = off\n
\n
PostUp = ip rule add from all fwmark 0xdeadbeef table 51820;ip rule add from all table main suppress_prefixlength 0\n
PostUp = ip route add default dev %i table 51820;\n
PostUp = ip route add  10.9.0.0/24 dev %i  proto kernel scope link; ping -c1 10.9.0.1\n
PostUp = sysctl -w net.ipv4.conf.all.rp_filter=0\n
PostUp = sysctl -w net.ipv6.conf.all.disable_ipv6=1\n
PostUp = sysctl -w net.ipv6.conf.default.disable_ipv6=1\n
\n
PostUp = nft add table ip %i\n
PostUp = nft add chain ip %i prerouting '{type filter hook prerouting priority mangle -1; policy accept;}'; nft add rule ip %i prerouting meta mark set ct mark\n
PostUp = nft add chain ip %i mangle '{type route hook output priority mangle -1; policy accept;}'; nft add rule ip %i mangle tcp sport != { 8080, 10009 } meta mark != 0x3333 meta cgroup 1118498 meta mark set 0xdeadbeef\n
PostUp = nft add chain ip %i nat'{type nat hook postrouting priority srcnat -1; policy accept;}'; nft insert rule ip %i nat fib daddr type != local oif != %i ct mark 0xdeadbeef drop;nft add rule ip %i nat oif != \"lo\" ct mark 0xdeadbeef masquerade\n
PostUp = nft add chain ip %i postroutingmangle'{type filter hook postrouting priority mangle -1; policy accept;}'; nft add rule ip %i postroutingmangle meta mark 0xdeadbeef ct mark set meta mark\n
PostUp = nft add chain ip %i input'{type filter hook input priority filter -1; policy accept;}'; nft add rule ip %i input iifname %i  ct state established,related counter accept; nft add rule ip %i input iifname %i tcp dport != 9735 counter drop; nft add rule ip %i input iifname %i udp dport != 9735 counter drop\n

\n
PostDown = nft delete table ip %i\n
PostDown = ip rule del from all table  main suppress_prefixlength 0; ip rule del from all fwmark 0xdeadbeef table 51820\n
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

# setup for cgroup
# create file
echo "Creating cgroup tunnelsats-create-cgroup.sh file in /etc/wireguard/..."
echo "#!/bin/sh
set -e
dir_netcls=\"/sys/fs/cgroup/net_cls\"
splitted_processes=\"/sys/fs/cgroup/net_cls/splitted_processes\"
modprobe cls_cgroup
if [ ! -d \"\$dir_netcls\" ]; then
  mkdir \$dir_netcls
  mount -t cgroup -o net_cls none \$dir_netcls
  echo \"> Successfully added cgroup net_cls subsystem\"
fi
if [ ! -d \"\$splitted_processes\" ]; then
  mkdir /sys/fs/cgroup/net_cls/splitted_processes
  echo 1118498  > /sys/fs/cgroup/net_cls/splitted_processes/net_cls.classid
  chmod 666  /sys/fs/cgroup/net_cls/splitted_processes/tasks
  echo \"> Successfully added Mark for net_cls subsystem\"
else
  echo \"> Mark for net_cls subsystem already present\"
fi
" >/etc/wireguard/tunnelsats-create-cgroup.sh

chmod +x /etc/wireguard/tunnelsats-create-cgroup.sh

if [ -f /etc/wireguard/tunnelsats-create-cgroup.sh ]; then
    echo "> /etc/wireguard/tunnelsats-create-cgroup.sh created."
    echo
else
    echo "> ERR: /etc/wireguard/tunnelsats-create-cgroup.sh was not created. Please check for errors."
    exit 1
fi

# run it once
if [ -f /etc/wireguard/tunnelsats-create-cgroup.sh ]; then
    echo "> tunnelsats-create-cgroup.sh created, executing..."
    # run
    if bash /etc/wireguard/tunnelsats-create-cgroup.sh; then
        echo "> Created tunnelsats cgroup successfully"
        echo
    else
        echo "> ERR: tunnelsats-create-cgroup.sh execution failed. Please check for errors."
        echo
        exit 1
    fi
fi

# enable systemd service
# create systemd file
echo "Creating cgroup systemd service..."
echo "[Unit]
Description=Creating cgroup for Splitting lightning traffic
StartLimitInterval=200
StartLimitBurst=5
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash /etc/wireguard/tunnelsats-create-cgroup.sh
[Install]
WantedBy=multi-user.target
" >/etc/systemd/system/tunnelsats-create-cgroup.service

# enable and start tunnelsats-create-cgroup.service
if [ -f /etc/systemd/system/tunnelsats-create-cgroup.service ]; then
    systemctl daemon-reload >/dev/null
    if systemctl enable tunnelsats-create-cgroup.service >/dev/null &&
        systemctl start tunnelsats-create-cgroup.service >/dev/null; then
        echo "> tunnelsats-create-cgroup.service: systemd service enabled and started"
        echo
    else
        echo "> ERR: tunnelsats-create-cgroup.service could not be enabled or started. Please check for errors."
        echo
    fi
else
    echo "> ERR: tunnelsats-create-cgroup.service was not created. Please check for errors."
    echo
    exit 1
fi

# Adding tunnelsats-create-cgroup requirement to lnd/cln
if [ "$lnImplementation" == "lnd" ]; then
    if [ ! -d /etc/systemd/system/lnd.service.d ]; then
        mkdir /etc/systemd/system/lnd.service.d >/dev/null
    fi
    echo "#Don't edit this file its generated by tunnelsats scripts
[Unit]
Description=lnd needs cgroup before it can start
Requires=tunnelsats-create-cgroup.service
After=tunnelsats-create-cgroup.service
Requires=wg-quick@tunnelsatsv2.service
After=wg-quick@tunnelsatsv2.service
" >/etc/systemd/system/lnd.service.d/tunnelsats-cgroup.conf

    systemctl daemon-reload >/dev/null

elif [ "$lnImplementation" == "cln" ]; then

    if [ ! -d /etc/systemd/system/lightningd.service.d ]; then
        mkdir /etc/systemd/system/lightningd.service.d >/dev/null
    fi
    echo "#Don't edit this file! It was generated by tunnelsats scripts
[Unit]
Description=lightningd needs cgroup before it can start
Requires=tunnelsats-create-cgroup.service
After=tunnelsats-create-cgroup.service
Requires=wg-quick@tunnelsatsv2.service
After=wg-quick@tunnelsatsv2.service
" >/etc/systemd/system/lightningd.service.d/tunnelsats-cgroup.conf

    systemctl daemon-reload >/dev/null

fi

# Create lightning splitting.service
# create file
echo "Creating tunnelsats-splitting-processes.sh file in /etc/wireguard/..."
echo "#!/bin/sh
# add Lightning pid(s) to cgroup
pgrep -x lnd | xargs -I % sh -c 'echo % >> /sys/fs/cgroup/net_cls/splitted_processes/tasks' &> /dev/null
pgrep -x lightningd | xargs -I % sh -c 'echo % >> /sys/fs/cgroup/net_cls/splitted_processes/tasks' &> /dev/null
count=\$(cat /sys/fs/cgroup/net_cls/splitted_processes/tasks | wc -l)
if [ \$count -eq 0 ];then
  echo \"> no available lightning processes available for tunneling\"
else
  echo \"> \${count} Process(es) successfully excluded\"
fi
" >/etc/wireguard/tunnelsats-splitting-processes.sh

if [ -f /etc/wireguard/tunnelsats-splitting-processes.sh ]; then
    echo "> /etc/wireguard/tunnelsats-splitting-processes.sh created"
    chmod +x /etc/wireguard/tunnelsats-splitting-processes.sh
else
    echo "> ERR: /etc/wireguard/tunnelsats-splitting-processes.sh was not created. Please check for errors."
    exit 1
fi

# run it once
if [ -f /etc/wireguard/tunnelsats-splitting-processes.sh ]; then
    echo "> tunnelsats-splitting-processes.sh created, executing..."
    bash /etc/wireguard/tunnelsats-splitting-processes.sh
    echo "> tunnelsats-splitting-processes.sh successfully executed"
    echo
else
    echo "> ERR: tunnelsats-splitting-processes.sh execution failed"
    echo
    exit 1
fi

# enable systemd service
# create systemd file
echo "Creating tunnelsats-splitting-processes systemd service..."
if [ ! -f /etc/systemd/system/tunnelsats-splitting-processes.sh ]; then

    echo "[Unit]
Description=Adding Lightning Process to the tunnel
[Service]
Type=oneshot
ExecStart=/bin/bash /etc/wireguard/tunnelsats-splitting-processes.sh
[Install]
WantedBy=multi-user.target
" >/etc/systemd/system/tunnelsats-splitting-processes.service

    echo "[Unit]
Description=1min timer for tunnelsats-splitting-processes.service
[Timer]
OnBootSec=10
OnUnitActiveSec=10
Persistent=true
[Install]
WantedBy=timers.target
" >/etc/systemd/system/tunnelsats-splitting-processes.timer

    if [ -f /etc/systemd/system/tunnelsats-splitting-processes.service ]; then
        echo "> tunnelsats-splitting-processes.service created"
    else
        echo "> ERR: tunnelsats-splitting-processes.service not created. Please check for errors."
        echo
        exit 1
    fi

    if [ -f /etc/systemd/system/tunnelsats-splitting-processes.timer ]; then
        echo "> tunnelsats-splitting-processes.timer created"
    else
        echo "> ERR: tunnelsats-splitting-processes.timer not created. Please check for errors."
        echo
        exit 1
    fi
fi

# enable and start tunnelsats-splitting-processes.service
if [ -f /etc/systemd/system/tunnelsats-splitting-processes.service ]; then
    systemctl daemon-reload >/dev/null
    if systemctl enable tunnelsats-splitting-processes.service >/dev/null &&
        systemctl start tunnelsats-splitting-processes.service >/dev/null; then
        echo "> tunnelsats-splitting-processes.service: systemd service enabled and started"
    else
        echo "> ERR: tunnelsats-splitting-processes.service could not be enabled or started. Please check for errors."
        echo
        exit 1
    fi
    # enable timer
    if [ -f /etc/systemd/system/tunnelsats-splitting-processes.timer ]; then
        if systemctl enable tunnelsats-splitting-processes.timer >/dev/null &&
            systemctl start tunnelsats-splitting-processes.timer >/dev/null; then
            echo "> tunnelsats-splitting-processes.timer: systemd timer enabled and started"
            echo
        else
            echo "> ERR: tunnelsats-splitting-processes.timer: systemd timer could not be enabled or started. Please check for errors."
            echo
            exit 1
        fi
    fi
else
    echo "> ERR: tunnelsats-splitting-processes.service was not created. Please check for errors."
    echo
    exit 1
fi

sleep 2

# Start lightning implementation in cggroup
# changing respective .service file
if [ "$lnImplementation" == "lnd" ]; then

    if [ ! -f /etc/systemd/system/lnd.service.bak ]; then
        cp /etc/systemd/system/lnd.service /etc/systemd/system/lnd.service.bak
    fi

    # Check if lnd.service already has cgexec command included
    check=$(grep -c "cgexec" /etc/systemd/system/lnd.service)
    if [ $check -eq 0 ]; then

        if sed -i 's/ExecStart=/ExecStart=\/usr\/bin\/cgexec -g net_cls:splitted_processes /g' /etc/systemd/system/lnd.service; then
            echo "> lnd.service updated now starts in cgroup tunnelsats"
            echo
            echo "> backup saved under /etc/systemd/system/lnd.service.bak"
            echo
            systemctl daemon-reload >/dev/null
        else
            echo "> ERR: not able to change /etc/systemd/system/lnd.service. Please check for errors."
            echo
        fi

    else
        echo "> /etc/systemd/system/lnd.service already  starts in cgroup tunnelsats"
        echo
    fi

elif [ "$lnImplementation" == "cln" ]; then

    if [ ! -f /etc/systemd/system/lightningd.service.bak ]; then
        cp /etc/systemd/system/lightningd.service /etc/systemd/system/lightningd.service.bak
    fi

    # Check if lightningd.service already has cgexec command included
    check=$(grep -c "cgexec" /etc/systemd/system/lightningd.service)
    if [ $check -eq 0 ]; then
        if sed -i 's/ExecStart=/ExecStart=\/usr\/bin\/cgexec -g net_cls:splitted_processes /g' /etc/systemd/system/lightningd.service; then
            echo "> lightningd.service updated now starts in cgroup tunnelsats"
            echo
            echo "> backup saved under /etc/systemd/system/lightningd.service.bak"
            echo
            systemctl daemon-reload >/dev/null
        else
            echo "> ERR: not able to change /etc/systemd/system/lightningd.service. Please check for errors."
            echo
        fi
    else
        echo "> /etc/systemd/system/lightningd.service already starts in cgroup tunnelsats"
        echo
    fi

fi

sleep 2

# create and enable wireguard service
echo "Initializing the service..."
systemctl daemon-reload >/dev/null
if systemctl enable wg-quick@tunnelsatsv2 >/dev/null; then

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

#Check if tunnel works
echo "Verifying tunnel ..."
ipHome=$(curl --silent https://api.ipify.org)
ipVPN=$(cgexec -g net_cls:splitted_processes curl --silent https://api.ipify.org)
if [ "$ipHome" != "$ipVPN" ] && valid_ipv4 $ipHome && valid_ipv4 $ipVPN; then
    echo "> Tunnel is  active ✅
    Your ISP external IP: ${ipHome}
    Your TunnelSats external IP: ${ipVPN}"
    echo
else
    echo "> ERR: TunnelSats VPN Interface not successfully activated, check debug logs"
    echo
    exit 1
fi

sleep 2

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
and duplicate entries could lead to errors.

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
and duplicate entries could lead to errors.

###################################################
CLN (config file):
  # Tor
  addr=statictor:127.0.0.1:9051/torport=9735
  proxy=127.0.0.1:9050
  always-use-proxy=false

  # VPN
  bind-addr=0.0.0.0:9735
  announce-addr=${vpnExternalDNS}:${vpnExternalPort}
####################################################"
    echo

fi

echo "Please save these infos in a file or write them down for later use.

A more detailed guide is available at: https://blckbx.github.io/tunnelsats/
Afterwards please restart LND / CLN for changes to take effect.
VPN setup completed!

Welcome to Tunnel⚡Sats.
Feel free to join the Amboss Community here: https://amboss.space/community/29db5f25-24bb-407e-b752-be69f9431071"
echo

if [ "${lnImplementation}" == "cln" ]; then
    serviceName="lightningd"
else
    serviceName="lnd"
fi
echo "Restart ${lnImplementation} afterwards via command:
    sudo systemctl restart ${serviceName}.service"
echo

# the end
exit 0
