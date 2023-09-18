#!/bin/bash
set -eoE pipefail
trap 'rc=$?; if [ $rc != '0' ]; then echo "Error at line ${LINENO} (exit: $rc)"; fi; exit $rc' ERR
trap 'rc=$?;if [ $rc != "0" ]; then echo "Error $rc "; fi; exit $rc' EXIT
if [ "${DEBUG,,}" = "true" ]; then set -x; fi
_log() { echo "$1"; }
__dirname=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
#Note: Do not use this character anywhere, specifically in SSID or passwords
SPECIAL=╏
cmds=()
config() { local IFS=$SPECIAL ; cmds+=( "$*" ); }

#########################################################################################################
# Begin configuration
#
# Create your own config. Call any of the function below, except for the helper functions that 
# start with _. 
# 
#########################################################################################################

if [ -f "$__dirname/wg-config" ]; then
    _log "Loading config from $__dirname/wg-config"
    source "$__dirname/wg-config"
elif [ -f "$CONFIG" ]; then
    _log "Loading config from $CONFIG"
    source "$CONFIG"
else 
    _log "Could not find config file $__dirname"
    exit 1
fi

#########################################################################################################
# Probably don't need to change anything below, but knock yourself out!
#########################################################################################################

CHAINS="mangle:PREROUTING mangle:POSTROUTING mangle:FORWARD nat:POSTROUTING filter:INPUT filter:FORWARD"
PREFIX=WG_PORTALS_

# Create the iptables chains
_create_chains() {
	for entry in ${CHAINS}; do
		table=$(echo "${entry}" | cut -d':' -f1)
		chain=$(echo "${entry}" | cut -d':' -f2)
		iptables -w -t "${table}" -N "${PREFIX}${chain}" >/dev/null 2>&1 || true
		_add_rule "${table}" "${chain} -j ${PREFIX}${chain}" noprefix
	done
}

# Delete the iptables chains
_delete_chains() {
	for entry in ${CHAINS}; do
		table=$(echo "${entry}" | cut -d':' -f1)
		chain=$(echo "${entry}" | cut -d':' -f2)
		iptables -w -t "${table}" -D "${chain}" -j "${PREFIX}${chain}" >/dev/null 2>&1 || true
		iptables -w -t "${table}" -F "${PREFIX}${chain}" >/dev/null 2>&1 || true
		iptables -w -t "${table}" -X "${PREFIX}${chain}" >/dev/null 2>&1 || true
	done
}

# Retrieves the ip associated with the interface
_dev_addr() {
    local dev=$1
    ip a show dev "$dev" 2>/dev/null | sed -En s/".*inet ([^ \/]+)(\/[0-9]+)? .*"/"\1"/p
}

# Adds a rule to given table if it doesn't already exist
_add_rule() {
    local table=$1
    local rule=$2
    if [ "$3" = "noprefix" ]; then
		prefix=""
	else
		prefix=${PREFIX}
	fi
    # shellcheck disable=SC2086
    iptables -w -t "$table" -C $prefix$rule >/dev/null 2>&1 || iptables -w -t "$table" -A $prefix$rule
}

# Deletes a rule from the given table 
_delete_rule() {
    local table=$1
    local rule=$2
    if [ "$3" = "noprefix" ]; then
		prefix=""
	else
		prefix=${PREFIX}
	fi
    # shellcheck disable=SC2086
    iptables -w -t "$table" -D $prefix$rule >/dev/null || true
}

# Starts or stops routing/NAT-ing traffic from source_dev to target_dev.
#
# 1. Tags all source_dev packgets using mark (must be number) 
# 2. Add new routing table with same number as mark
# 3. Direct all marked source packets to new routing table 
# Note: exempt packets that are meant for the source gateway itself
redir() {
    local action=$1
    local source_dev=$2
    local target_dev=$3
    local mark=$4
    local source_dev_ip=
    
    source_dev_ip=$(_dev_addr "$source_dev")
    if [ "$action" = "up" ]; then
        _log "Creating redirection of $source_dev to $target_dev using fwmark $mark and routing table $mark"
        # This trick is performed by wg-quick to prevent the need for changing     
        # sysctl -q net.ipv4.conf.default.rp_filter=2
        # see https://github.com/tailscale/tailscale/issues/3310#issuecomment-1271412885
        # Note: this isn't working for me right now....
        # https://manpages.debian.org/bookworm/iptables/iptables-extensions.8.en.html#rpfilter
        # https://serverfault.com/questions/932205/advanced-routing-with-firewall-marks-and-rp-filter
        # _add_rule mangle "POSTROUTING ! -s $source_dev_ip -o $target_dev -m mark --mark 0x$mark -p udp -j CONNMARK --save-mark"
        # _add_rule mangle "PREROUTING -p udp -j CONNMARK --restore-mark"
        _add_rule mangle "PREROUTING -i $source_dev ! -d $source_dev_ip -j MARK --set-xmark 0x$mark"
        _add_rule nat "POSTROUTING ! -s $source_dev_ip -o $target_dev -m mark --mark 0x$mark -j MASQUERADE"

        target_gateway_route=$(ip route show 0.0.0.0/0 dev "$target_dev" | sed -En "s/.*default ((via [^ ]+ )?(dev [^ ]+)?).*/\1dev $target_dev/p" | tail -n1)
        if [ -z "$target_gateway_route" ]; then
            target_dev_ip=$(_dev_addr "$target_dev")
            # no default gateway on the device, fallback to the device ip
            target_gateway_route="via $target_dev_ip dev $target_dev"
        fi

         # shellcheck disable=SC2086
        ip route replace default $target_gateway_route table "$mark"
        ip rule add fwmark "0x$mark" lookup "$mark" pref "$mark"
    fi
    if [ "$action" = "down" ]; then
        _log "Deleting redirection of $source_dev to $target_dev using fwmark $mark and routing table $mark"
        ip rule del pref "$mark"
        ip route flush table "$mark"
        _delete_rule nat "POSTROUTING ! -s $source_dev_ip -o $target_dev -m mark --mark 0x$mark -j MASQUERADE"
        _delete_rule mangle "PREROUTING -i $source_dev ! -d $source_dev_ip -j MARK --set-xmark 0x$mark"
        # _delete_rule mangle "POSTROUTING ! -s $source_dev_ip -o $target_dev -m mark --mark 0x$mark -p udp -j CONNMARK --save-mark"
        # _delete_rule mangle "PREROUTING -p udp -j CONNMARK --restore-mark"
    fi
    if [ "$action" = "show" ]; then
       _log "Redirection table of $source_dev to $target_dev using fwmark $mark and routing table $mark"
       _log "+ip route show table $mark"
       ip route show table "$mark"
    fi
}

# Remove destination networks from redirection. 
exempt_dest() { 
    local action=$1
    local dest=$2
    local mark=$3
    if [ "$action" = "up" ]; then
        _log "Creating exemption for destination network $dest from fwmark $mark and routing table $mark"
        _add_rule mangle "PREROUTING -d ${dest} -m mark --mark 0x$mark -j MARK --set-xmark 0x0"
    fi
    if [ "$action" = "down" ]; then
        _log "Deleting exemption for destination network $dest from fwmark $mark and routing table $mark"
        _delete_rule mangle "PREROUTING -d ${dest} -m mark --mark 0x$mark -j MARK --set-xmark 0x0"
    fi
    if [ "$action" = "show" ]; then
        _log "Excemption: for destination network $dest from fwmark $mark and routing table $mark"
    fi
}

# Creates a hostapd configuration (Wifi Access Point)
_conf_hostapd() {
    local dev=$1
    local ssid=$2
    local password=$3
    cat <<EOF
interface=$dev
ssid=$ssid
country_code=US
country3=0x49
hw_mode=g
channel=6
ieee80211n=1
ieee80211d=1
wpa=2
wpa_passphrase=$password
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wmm_enabled=1
logger_syslog=-1
logger_syslog_level=2
ctrl_interface=/var/run/wg-portals/hostapd-$dev
EOF
}

# Starts or stops Wifi Interface (for sharing).
# 
# 1. Configures and brings up Wifi interface
# 2. Starts/stops the DNS/DHCP server (dnsmasq)
# 3. Starts/stops the radio for Access Point
wifi_dev() {
    local action=$1
    local dev=$2
    local ip=$3
    local dns=$4
    local ssid=$5
    local password=$6

    local pid="/var/run/wg-portals/hostapd-$dev.pid"
    if [ "$action" = "up" ]; then
        dhcp_dev "$action" "$dev" "$ip" "$dns"
        _log "Creating WIFI hotspot [$ssid]"
        hostapd <(_conf_hostapd "$dev" "$ssid" "$password") -B -P "$pid" -f "/var/log/wg-portals/hostapd-$dev.log"
        _log "WIFI hotspot [$ssid] ready"
    fi
    if [ "$action" = "down" ]; then
        if [ -f "$pid" ]; then
            _log "Stopping WIFI hotspot [$ssid]"
            kill "$(cat "$pid")" || true
            rm -f "$pid"
            dhcp_dev "$action" "$dev" "$ip"
            _log "WIFI hotspot [$ssid] stopped"
        else    
            _log "Already stopped WIFI hotspot [$ssid]"
        fi
    fi
    if [ "$action" = "wait" ]; then
        if [ -f "$pid" ]; then
            tail --pid="$(cat "$pid")" -f /dev/null || true
        fi
    fi
    if [ "$action" = "show" ]; then
        _log "WIFI hotspot [$ssid] using $2 with ip $ip, using dns server $dns"
        dhcp_dev "$action" "$dev" "$ip" "$dns"
        hostapd_cli -p "/var/run/wg-portals/hostapd-$dev" status
    fi
}

# Starts/stops Wireguard VPN interface (for sharing).
wireguard_dev() {
    local action=$1
    local dev=$2
    local private_key=$3
    local ip=$4
    local port=$5

    if [ "$action" = "up" ]; then
        _log "Starting wireguard on interface $dev using $ip and listening on $port"

        ip link add "$dev" type wireguard
        ip address add "$ip/24" dev "$dev"
        # see https://github.com/tailscale/tailscale/blob/v1.44.0/net/tstun/mtu.go#L15
        ip link set mtu 1280 up dev "$dev"

        wg set "$dev" private-key <(echo "$private_key")
        wg set "$dev" listen-port "$port"

        # Probably not needed, but just in case
        _add_rule filter "FORWARD -i $dev -j ACCEPT"
        _add_rule filter "FORWARD -o $dev -j ACCEPT"
        _add_rule filter "INPUT -p udp -m udp --dport $port -j ACCEPT"
        # note, mss = mtu - 20 (tcp) - 20 (ip)
        _add_rule mangle "FORWARD -i $dev -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240"
        _add_rule mangle "FORWARD -o $dev -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240"
    fi
    if [ "$action" = "down" ]; then
        _log "Stopping wireguard on interface $dev using $ip and listening on $port"

        _delete_rule mangle "FORWARD -o $dev -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240"
        _delete_rule mangle "FORWARD -i $dev -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240"
        _delete_rule filter "INPUT -p udp -m udp --dport $port -j ACCEPT"
        _delete_rule filter "FORWARD -o $dev -j ACCEPT"
        _delete_rule filter "FORWARD -i $dev -j ACCEPT"
        ip link delete "$dev"
    fi
    if [ "$action" = "show" ]; then
        wg show "$dev"
    fi
    if [ "$action" = "wait" ]; then
        while true; do
            if ip link show "$dev" &> /dev/null && ip link show "$dev"  | grep -q "<.*UP.*>" ; then
                sleep 1 || true
            else
                break
            fi
        done
    fi
}

# Adds a exit peer to the Wireguard VPN network. Note, there can only be one
# exit node per wireguard interface. 
wireguard_add_exitnode() {
    wireguard_add_peer "$1" "$2" "$3" "$4" "0.0.0.0/0" "$5"
}
# Adds a peer to the Wireguard VPN network, be sure not to specify overlapping
# ip addresses or ranges. 
wireguard_add_peer() {
    local action=$1
    local dev=$2
    local peer_public_key=$3
    local preshared_key=$4
    local allowed_ips=$5
    local endpoint=$6
    if [ "$action" = "up" ]; then
        wg set "$dev" peer "$peer_public_key" allowed-ips "$allowed_ips"
        if [ -n "$endpoint" ]; then
            wg set "$dev" peer "$peer_public_key" endpoint "$endpoint" || true
        fi
        if [ -n "$preshared_key" ]; then
            wg set "$dev" peer "$peer_public_key" preshared-key <(echo "$preshared_key")
        fi
        wg set "$dev" peer "$peer_public_key" persistent-keepalive 5
    fi
}

# Creates a dnsmasq configuration that caches an upstream DNS and provides DHCP. 
_conf_dnsmasq() {
    local dev=$1
    local ip=$2
    local dns=$3
    local IFS=. 
    read -r i1 i2 i3 i4 <<< "$ip"
    local IFS=$'\n\t'
    local range_start=$i1.$i2.$i3.$(("$i4"+1))
    local range_end=$i1.$i2.$i3.200
    cat <<EOF
interface="$dev"
bind-interfaces
except-interface=lo
domain-needed
bogus-priv
server=$dns
no-hosts
dhcp-range=$range_start,$range_end,12h
log-facility=/var/log/wg-portals/dnsmasq-$dev.log
EOF
}

# Starts or stop the DNS/DHCP server (dnsmasq)
serve_dhcp() {
    local action=$1
    local dev=$2
    local ip=$3
    local dns=$4

    local pid="/var/run/wg-portals/dnsmasq-$dev.pid"
    local log="/var/log/wg-portals/dnsmasq-$dev.log"
    if [ "$action" = "up" ]; then
        _log "Starting dnsmasq for $dev on $ip using $dns"
        mkdir -p "$(dirname "$pid")"
        mkdir -p "$(dirname "$log")"
        dnsmasq -C <(_conf_dnsmasq "$dev" "$ip" "$dns") --pid-file="$pid"
    fi
    if [ "$action" = "down" ]; then
        if [ -f "$pid" ]; then
            _log "Stopping dnsmasq for $dev on $ip using $dns"
            kill "$(cat "$pid")" || true
            rm -f "$pid"
        else 
            _log "Already stopped dnsmasq for $dev on $ip using $dns"
        fi
    fi
    if [ "$action" = "wait" ]; then
        if [ -f "$pid" ]; then
            wait "$(cat "$pid")" 
        fi
    fi
    if [ "$action" = "config" ]; then
        if [ -f "$log" ]; then
            _log "Dnsmasq for $dev on $ip using $dns"
            tail -n 25 "$log"
        fi
    fi
    
}

# Starts/stops a regular ethernet interface (for sharing). 
dhcp_dev() {
    local action=$1
    local dev=$2
    local ip=$3
    local dns=$4

    if [ "$action" = "up" ]; then
        _log "Bringing up $dev"
        ip a add "$ip/24" dev "$dev"
        serve_dhcp "$action" "$dev" "$ip" "$dns"
        ip link set "$dev" up
    fi
    if [ "$action" = "down" ]; then
        _log "Bringing down $dev"
        ip link set "$dev" down
        serve_dhcp "$action" "$dev" 
        ip a del "$ip/24" dev "$dev"
    fi
    if [ "$action" = "config" ]; then
        _log "Using interface $dev"
        serve_dhcp "$action" "$dev" "$ip" "$dns"
    fi
}

# Starts/stops dyndns server for cloudflare
cloudflare_dyndns() {
    local action=$1
    local apitoken=$2
    local hostname=$3
    local zone=$4

    local pid="/var/run/wg-portals/inadyn-cloudflare.pid"
    if [ "$action" = "up" ]; then
        _log "Starting cloudflare dyndns"
        inadyn -f <(_cloudflare_inadyn "$apitoken" "$hostname" "$zone") -P "$pid"
    fi
    if [ "$action" = "down" ]; then
        if [ -f "$pid" ]; then
            _log "Stopping cloudflare dyndns"
            kill "$(cat "$pid")" || true
            rm -f "$pid"
        else 
            _log "Already stopped cloudflare dyndns"
        fi
    fi
    if [ "$action" = "wait" ]; then
        if [ -f "$pid" ]; then
            wait "$(cat "$pid")" 
        fi
    fi
}


# Creates a dnsmasq configuration that caches an upstream DNS and provides DHCP. 
_cloudflare_inadyn() {
    local apitoken=$1
    local hostname=$2
    local zone=$3

    cat <<EOF
period=3600
# www.cloudflare.com 
provider cloudflare.com { 
    username = $zone
    # Create a unique custom api token with the following permissions: Zone.Zone - Read, Zone.DNS - Edit. 
    password = $apitoken
    hostname = $hostname.$zone
    # optional, value of 1 is 'automatic'. 
    ttl = 1 
    # optional. 
    proxied = false 
}
EOF
}

loose_rp_filter() {
    sysctl -q net.ipv4.conf.all.rp_filter=2
}

_eval_cmd() {
    local IFS=$SPECIAL
    read -r -a cmd_array <<< "$2"
    local IFS=$' \n\t'
    "${cmd_array[0]}" "$1" "${cmd_array[@]:1}" 
}

_eval_config() { for cmd in "${cmds[@]}"; do _eval_cmd "$1" "$cmd"; done }

_prereq() {
    # Required prerequisite sysctls
    sysctl -q net.ipv4.conf.all.src_valid_mark=1
    sysctl -q net.ipv4.ip_forward=1
    _create_chains
}

# Brings up the configuration
_config_up() {
    _prereq
    _eval_config "up"
}

_config_show() {
    _log "+ip rule show"
    ip rule show
    _eval_config "show"
}

# Brings down the configuration
_config_down() {
    set +eoE pipefail
    for (( idx=${#cmds[@]}-1 ; idx>=0 ; idx-- )); 
        do _eval_cmd down "${cmds[idx]}"; 
    done
    _delete_chains
}
_trap_exit() {
    _log "Interrupted - killing background tasks"
    _config_down
}

_conf_systemd_service() {
cat <<EOF
[Unit]
Description=wg-portals - wireguard portals
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
Environment=CONFIG=$__dirname/wg-config
ExecStart=$__dirname/wg-portals.sh daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

_install_systemd() {
    service=$(_conf_systemd_service)
    _log "Creating /etc/systemd/system/wg-portals.service"
    printf "%s\n" "$service" > /etc/systemd/system/wg-portals.service
    _log "systemctl enable wg-portals"
    systemctl enable wg-portals
    _log "systemctl start wg-portals"
    systemctl start wg-portals
}

_conf_openrc_service() {
cat <<EOF
#!/sbin/openrc-run
name=\$RC_SVCNAME
command=$__dirname/wg-portals.sh
command_args="daemon"
pidfile=/run/\${RC_SVCNAME}.pid
command_background=true

depend() {
        use dns
        need net
        after net-online
}

EOF
}

_conf_gen_exit_pair() {

    while :; do
        read -rep 'Enter number of mesh nodes: (2-25)? ' number
        [[ $number =~ ^[[:digit:]]+$ ]] || continue
        (( ( (number=(10#$number)) <= 25 ) && number >= 0 )) || continue
        break
    done

    node_names=({A..Z})
    read -r -p "Do you want to name the nodes? [y/N]? " answer
    if [ "$answer" != "${answer#[Yy]}" ]; then
        while :; do
            read -p "Enter $number names, seperated by spaces: " -a node_names
            len=${#node_names[@]}
            if [ ! $len = $number ]; then 
                echo "Need $number elements, got $len"
                continue
            fi
            break
        done
    fi

    hostname=example.com
    read -r -p "Hostname $hostname: Change? [y/N]? " answer
    if [ "$answer" != "${answer#[Yy]}" ]; then
        while :; do
            read -p "Enter hostname: " hostname
            if [ -n "$hostname" ]; then
                break;
            fi
        done
    fi

    port=65501
    read -r -p "Starting port $port: Change? [y/N]? " answer
    if [ "$answer" != "${answer#[Yy]}" ]; then
        while :; do
            read -rep 'Enter port number: (1-65535)? ' port
            [[ $port =~ ^[[:digit:]]+$ ]] || continue
            (( ( (port=(10#$port)) <= 65535 ) && port >= 0 )) || continue
            break
        done
    fi

    net=20
    read -r -p "Subnet 10.0.NET.x where NET=$net: Change? [y/N]? " answer
    if [ "$answer" != "${answer#[Yy]}" ]; then
        while :; do
            read -rep 'Enter starting NET: (1-255)? ' net
            [[ $net =~ ^[[:digit:]]+$ ]] || continue
            (( ( (net=(10#$net)) <= 255 ) && net >= 0 )) || continue
            break
        done
    fi

    declare -A keys
    declare -A shared

    for ((i=0; i < number; i++)); do
        source_node=${node_names[$i]}
        for ((j=0; j < number; j++)); do
            if [ $j = $i ]; then continue; fi
            dest_node=${node_names[$j]}
            private=$(wg genkey)
            public=$(echo "$private" | wg pubkey)
            psk=$(wg genpsk)
            keys[${source_node}_${dest_node}]="$private $public $port"
            port=$((port+1))
            if [ -n "${shared[${source_node}_${dest_node}]}" ]; then
                shared[${dest_node}_${source_node}]=${shared[${source_node}_${dest_node}]}
            elif [ -n "${subnets[${dest_node}_${source_node}]}" ]; then
                shared[${source_node}_${dest_node}]=${shared[${dest_node}_${source_node}]}
            else
                sharedval="$psk $net 1"
                shared[${source_node}_${dest_node}]=$sharedval;
                shared[${dest_node}_${source_node}]=$sharedval;
                net=$((net+1))
            fi
        done
    done

    # debug
    # for i in "${!shared[@]}"
    # do
    # echo "${i}=${shared[$i]}"
    # done

    output="\n\n"
    ip=20
    for ((i=0; i < number; i++)); do
        source_node=${node_names[$i]}
        output="${output}### wg-config snippet for machine named $source_node\n"
        table=100
        for ((j=0; j < number; j++)); do
            if [ $j = $i ]; then continue; fi
            dest_node=${node_names[$j]}

            sval=${shared[${source_node}_${dest_node}]}
            read -r psk net router <<< "$sval"

            source_to_dest=${keys[${source_node}_${dest_node}]}
            dest_to_source=${keys[${dest_node}_${source_node}]}

            read -r source_private source_public source_port <<< "$source_to_dest"
            read -r dest_private dest_public dest_port <<< "$dest_to_source"

            # increment router and write back
            sharedval="$psk $net $((router+1))"
            shared[${source_node}_${dest_node}]=$sharedval;
            shared[${dest_node}_${source_node}]=$sharedval;

            source_ip=10.1.$net.$router

            dest_dev=to_$dest_node
            output="${output}# dedicated interface for traffic between $source_node and $dest_node\n"
            #output="${output}# fyi public key is $source_public\n"
            output="${output}config wireguard_dev $dest_dev $source_private $source_ip $source_port\n"
            #output="${output}# fyi private key is $dest_private\n"
            output="${output}config wireguard_add_exitnode $dest_dev $dest_public $psk $dest_node.$hostname:$dest_port\n"
            output="${output}# make $dest_dev traffic leave via eth0\n"
            output="${output}config redir $dest_dev eth0 $table\n"
            output="${output}\n"
            table=$((table+=1))
        done    
        output="${output}\n"
        output="${output}\n"
    done
    echo -e "$output"
}

_install_openrc() {
    service=$(_conf_openrc_service)
    _log "Creating /etc/init.d/wg-portals"
    printf "%s\n" "$service" > /etc/init.d/wg-portals
    chmod +x /etc/init.d/wg-portals
    _log "rc-update add wg-portals default"
    rc-update add wg-portals default
    _log "rc-service wg-portals start"
    rc-service wg-portals start
}

if [ "$1" = "up" ]; then 
    _config_up
    echo "Success"
elif [ "$1" = "daemon" ]; then 
    _config_up
    echo "Success"
    trap '_trap_exit' SIGTERM SIGINT
    _eval_config "wait"
elif [ "$1" = "down" ]; then 
    _config_down
    echo "Success"
elif [ "$1" = "install-systemd" ]; then 
    _install_systemd
elif [ "$1" = "install-openrc" ]; then 
    _install_openrc
elif [ "$1" = "watch-tables" ]; then
    watch --interval=0.5 "echo ==MANGLE== ; iptables -nvL -t mangle; echo ==NAT== ; iptables -nvL -t nat; echo ==FILTER== ; iptables -nvL -t filter"
elif [ "$1" = "flush-tables" ]; then
    printf "WARNING: Are you sure you want to delete all iptables rules? [y/N]?"
    read -r answer
    if [ "$answer" != "${answer#[Yy]}" ]; then
        iptables --flush -t mangle 
        iptables --flush -t nat
        iptables --flush -t filter
        iptables --flush -t raw
    fi
elif [ "$1" = "show-config" ]; then
    _config_show
elif [ "$1" = "gen-exit-pair" ]; then
    _conf_gen_exit_pair
else 
    echo "Missing command. Try: up, down, daemon, watch-tables, flush-tables, show-config"
fi

