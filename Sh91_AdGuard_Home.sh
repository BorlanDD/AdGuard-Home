#!/bin/sh
#copyright by hiboy
source /etc/storage/script/init.sh
AdGuardHome_enable=`nvram get app_84`
[ -z $AdGuardHome_enable ] && AdGuardHome_enable=0 && nvram set app_84=0
AdGuardHome_2_server=`nvram get app_85`
if [ "$AdGuardHome_enable" != "0" ] ; then
#nvramshow=`nvram showall | grep '=' | grep AdGuardHome | awk '{print gensub(/'"'"'/,"'"'"'\"'"'"'\"'"'"'","g",$0);}'| awk '{print gensub(/=/,"='\''",1,$0)"'\'';";}'` && eval $nvramshow

AdGuardHome_renum=`nvram get AdGuardHome_renum`
cmd_log_enable=`nvram get cmd_log_enable`
cmd_name="AdGuardHome"
cmd_log=""
if [ "$cmd_log_enable" = "1" ] || [ "$AdGuardHome_renum" -gt "0" ] ; then
	cmd_log="$cmd_log2"
fi

fi

if [ ! -z "$(echo $scriptfilepath | grep -v "/tmp/script/" | grep AdGuard_Home)" ]  && [ ! -s /tmp/script/_app17 ]; then
	mkdir -p /tmp/script
	{ echo '#!/bin/sh' ; echo $scriptfilepath '"$@"' '&' ; } > /tmp/script/_app17
	chmod 777 /tmp/script/_app17
fi

AdGuardHome_restart () {

relock="/var/lock/AdGuardHome_restart.lock"
if [ "$1" = "o" ] ; then
	nvram set AdGuardHome_renum="0"
	[ -f $relock ] && rm -f $relock
	return 0
fi
if [ "$1" = "x" ] ; then
	if [ -f $relock ] ; then
		logger -t "【AdGuardHome】" "Multiple attempts to start failed, wait for 【"`cat $relock`" minutes】 to automatically restart"
		exit 0
	fi
	AdGuardHome_renum=${AdGuardHome_renum:-"0"}
	AdGuardHome_renum=`expr $AdGuardHome_renum + 1`
	nvram set AdGuardHome_renum="$AdGuardHome_renum"
	if [ "$AdGuardHome_renum" -gt "2" ] ; then
		I=19
		echo $I > $relock
		logger -t "【AdGuardHome】" "Multiple attempts to start failed, wait for 【"`cat $relock`" minutes】 to automatically restart"
		while [ $I -gt 0 ]; do
			I=$(($I - 1))
			echo $I > $relock
			sleep 60
			[ "$(nvram get AdGuardHome_renum)" = "0" ] && exit 0
			[ $I -lt 0 ] && break
		done
		nvram set AdGuardHome_renum="0"
	fi
	[ -f $relock ] && rm -f $relock
fi
nvram set AdGuardHome_status=0
eval "$scriptfilepath &"
exit 0
}

AdGuardHome_get_status () {

A_restart=`nvram get AdGuardHome_status`
B_restart="$AdGuardHome_enable$AdGuardHome_2_server"
[ "$(nvram get app_86)" = "1" ] && B_restart="$B_restart""$(cat /etc/storage/app_19.sh | grep -v '^#' | grep -v "^$")"
B_restart=`echo -n "$B_restart" | md5sum | sed s/[[:space:]]//g | sed s/-//g`
if [ "$A_restart" != "$B_restart" ] ; then
	nvram set AdGuardHome_status=$B_restart
	needed_restart=1
else
	needed_restart=0
fi
}

AdGuardHome_check () {
AdGuardHome_get_status
if [ "$AdGuardHome_enable" != "1" ] && [ "$needed_restart" = "1" ] ; then
	[ ! -z "$(ps -w | grep "AdGuardHome" | grep -v grep )" ] && logger -t "【AdGuardHome】" "Stop AdGuardHome" && AdGuardHome_close
	{ kill_ps "$scriptname" exit0; exit 0; }
fi
if [ "$AdGuardHome_enable" = "1" ] ; then
	if [ "$needed_restart" = "1" ] ; then
		AdGuardHome_close
		AdGuardHome_start
	else
		[ -z "$AdGuardHome_2_server" ] && [ -z "$(ps -w | grep "AdGuardHome" | grep -v grep )" ] && AdGuardHome_restart
		if [ "$(grep "server=127.0.0.1#5353"  /etc/storage/dnsmasq/dnsmasq.conf | wc -l)" = 0 ] ; then
			sleep 10 
			if [ "$(grep "server=127.0.0.1#5353"  /etc/storage/dnsmasq/dnsmasq.conf | wc -l)" = 0 ] ; then
				logger -t "【AdGuardHome】" "Detection: Cannot find dnsmasq forwarding rule server = 127.0.0.1#5353, automatically try to restart"
				AdGuardHome_restart
			fi
		fi
	fi
fi
}

AdGuardHome_keep () {
logger -t "【AdGuardHome】" "Daemon start"
if [ -s /tmp/script/_opt_script_check ]; then
sed -Ei '/【AdGuardHome】|^$/d' /tmp/script/_opt_script_check
cat >> "/tmp/script/_opt_script_check" <<-OSC
	[ -z "\`pidof AdGuardHome\`" ] || [ ! -s "/opt/AdGuardHome/AdGuardHome" ] && nvram set AdGuardHome_status=00 && logger -t "【AdGuardHome】" "Restart" && eval "$scriptfilepath &" && sed -Ei '/【AdGuardHome】|^$/d' /tmp/script/_opt_script_check # 【AdGuardHome】
OSC
#return
fi
while true; do
	if [ "$(grep "server=127.0.0.1#5353"  /etc/storage/dnsmasq/dnsmasq.conf | wc -l)" = 0 ] ; then
		sleep 10
		if [ "$(grep "server=127.0.0.1#5353"  /etc/storage/dnsmasq/dnsmasq.conf | wc -l)" = 0 ] ; then
			logger -t "【AdGuardHome】" "Detection: Cannot find dnsmasq forwarding rule server = 127.0.0.1#5353, automatically try to restart"
			AdGuardHome_restart
		fi
	fi
sleep 61
done
}

AdGuardHome_close () {
port=$(grep "#server=127.0.0.1#8053"  /etc/storage/dnsmasq/dnsmasq.conf | wc -l)
sed -Ei '/server=127.0.0.1#5353/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -Ei '/AdGuardHome/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -Ei 's/^#dns-forward-max/dns-forward-max/g' /etc/storage/dnsmasq/dnsmasq.conf
if [ "$port" != 0 ] ; then
	sed -Ei '/server=127.0.0.1#8053/d' /etc/storage/dnsmasq/dnsmasq.conf
	echo 'server=127.0.0.1#8053' >> /etc/storage/dnsmasq/dnsmasq.conf
	logger -t "【AdGuardHome】" "Dnsmasq forwarding rule detected, restore server = 127.0.0.1#8053"
fi
restart_dhcpd
sed -Ei '/【AdGuardHome】|^$/d' /tmp/script/_opt_script_check
killall AdGuardHome
killall -9 AdGuardHome
kill_ps "/tmp/script/_app17"
kill_ps "_AdGuard_Home.sh"
kill_ps "$scriptname"
}

AdGuardHome_start () {
check_webui_yes
port=$(grep "server=127.0.0.1#8053"  /etc/storage/dnsmasq/dnsmasq.conf | wc -l)
if [ ! -z "$AdGuardHome_2_server" ] ; then
	logger -t "【AdGuardHome】" "Use an external AdGuardHome server： $AdGuardHome_2_server"
	logger -t "【AdGuardHome】" "It is recommended that the upstream DNS of the external AdGuardHome server is pollution-free"
	AdGuardHome_server="server=$(echo $AdGuardHome_2_server | sed 's@:\|：@#@g')"
else
	SVC_PATH="/opt/AdGuardHome/AdGuardHome"
	if [ ! -s "$SVC_PATH" ] ; then
		logger -t "【AdGuardHome】" "$SVC_PATH not found, install opt"
		/tmp/script/_mountopt start
		initopt
	fi
	mkdir -p "/opt/AdGuardHome"
	if [ ! -s "$SVC_PATH" ] && [ -d "/opt/AdGuardHome" ] ; then
		logger -t "【AdGuardHome】" "$SVC_PATH not found, install AdGuardHome program"
		tag="$( wget -T 5 -t 3 --no-check-certificate --max-redirect=0  https://github.com/AdguardTeam/AdGuardHome/releases/latest  2>&1 | grep releases/tag | awk -F '/' '{print $NF}' | awk -F ' ' '{print $1}' )"
		[ -z "$tag" ] && tag="$( wget -T 5 -t 3 --no-check-certificate --quiet --output-document=-  https://github.com/AdguardTeam/AdGuardHome/releases/latest  2>&1 | grep '<a href="/AdguardTeam/AdGuardHome/tree/'  |head -n1 | awk -F '/' '{print $NF}' | awk -F '"' '{print $1}' )"
		if [ ! -z "$tag" ] ; then
			logger -t "【AdGuardHome】" "Automatically download the latest version $tag"
			wgetcurl.sh "/opt/AdGuardHome/AdGuardHome.tar.gz" "https://github.com/AdguardTeam/AdGuardHome/releases/download/$tag/AdGuardHome_linux_mipsle.tar.gz"
			tar -xzvf /opt/AdGuardHome/AdGuardHome.tar.gz -C /opt
			rm -f /opt/AdGuardHome/AdGuardHome.tar.gz /opt/AdGuardHome/LICENSE.txt /opt/AdGuardHome/README.md
		fi
		if [ ! -s "$SVC_PATH" ] && [ -d "/opt/AdGuardHome" ] ; then
			logger -t "【AdGuardHome】" "Get latest version failed!"
			logger -t "【AdGuardHome】" "Start download $hiboyfile2/AdGuardHome"
			wgetcurl.sh "/opt/AdGuardHome/AdGuardHome" "$hiboyfile/AdGuardHome" "$hiboyfile2/AdGuardHome"
		fi
	fi
	chmod 777 "$SVC_PATH"
	AdGuardHome_v=$($SVC_PATH -c /etc/storage/app_19.sh -w /opt/AdGuardHome --check-config --verbose 2>&1 | grep version | sed -n '1p' | awk -F 'version' '{print $2;}'| awk -F ',' '{print $1;}')
	nvram set AdGuardHome_v="$AdGuardHome_v"
	[ -z "$AdGuardHome_v" ] && rm -rf $SVC_PATH
	if [ ! -s "$SVC_PATH" ] ; then
		logger -t "【AdGuardHome】" "$SVC_PATH was not found，you need to install $SVC_PATH manually"
		logger -t "【AdGuardHome】" "Failed to start, automatically try to restart after 10 seconds" && sleep 10 && AdGuardHome_restart x
	fi
	logger -t "【AdGuardHome】" "Enable native AdGuardHome service"
	AdGuardHome_server='server=127.0.0.1#5353'
	# Generate a configuration file
	if [ "$port" != 0 ] ; then
		logger -t "【AdGuardHome】" "Modify the upstream DNS of the local AdGuardHome server: 127.0.0.1:8053"
		set_dns "127.0.0.1:8053"
		set_dns "1.1.1.1" "del"
	else
		set_dns "127.0.0.1:8053" "del"
	fi
	logger -t "【AdGuardHome】" "Run /opt/AdGuardHome/AdGuardHome"
	eval "/opt/AdGuardHome/AdGuardHome -c /etc/storage/app_19.sh -w /opt/AdGuardHome $cmd_log" &
	sleep 3
	[ ! -z "$(ps -w | grep "AdGuardHome" | grep -v grep )" ] && logger -t "【AdGuardHome】" "Started successfully" && AdGuardHome_restart o
	[ -z "$(ps -w | grep "AdGuardHome" | grep -v grep )" ] && logger -t "【AdGuardHome】" "Failed to start, pay attention to check whether AdGuardHome has been downloaded completely, and automatically try to restart after 10 seconds" && sleep 10 && AdGuardHome_restart x
	nvram set app_86=0
	AdGuardHome_get_status
	eval "$scriptfilepath keep &"
fi
if [ "$port" != 0 ] ; then
	logger -t "【AdGuardHome】" "Dnsmasq forwarding rule detected, delete server=127.0.0.1#8053"
	sed -Ei '/server=/d' /etc/storage/dnsmasq/dnsmasq.conf
	echo '#server=127.0.0.1#8053' >> /etc/storage/dnsmasq/dnsmasq.conf
fi
logger -t "【AdGuardHome】" "Add dnsmasq forwarding rules for AdGuardHome server=127.0.0.1#5353"
sed -Ei '/AdGuardHome/d' /etc/storage/dnsmasq/dnsmasq.conf
echo "$AdGuardHome_server #AdGuardHome" >> /etc/storage/dnsmasq/dnsmasq.conf
echo "no-resolv #AdGuardHome" >> /etc/storage/dnsmasq/dnsmasq.conf
sed -Ei 's/^dns-forward-max/#dns-forward-max/g' /etc/storage/dnsmasq/dnsmasq.conf
echo "dns-forward-max=1000 #AdGuardHome" >> /etc/storage/dnsmasq/dnsmasq.conf
restart_dhcpd
exit 0
}

set_dns () {
add_dns="$1"
del_dns="$2"
get_dns="$(awk '/upstream_dns:/,/tls:/'  /etc/storage/app_19.sh)"
tmp_dns=""
if [ "$del_dns" != "del" ] ; then
	if [ -z "$(echo "$get_dns" | grep "  - $add_dns")" ] ; then
		logger -t "【AdGuardHome】" "Add upstream DNS server: $add_dns"
		tmp_dns="$(echo "$get_dns" | sed '/upstream_dns:/a\  - '"$add_dns")"
		get_dns="$tmp_dns"
	fi
else
	if [ ! -z "$(echo "$get_dns" | grep "  - $add_dns")" ] ; then
		logger -t "【AdGuardHome】" "Remove upstream DNS server: $add_dns"
		tmp_dns="$(echo "$get_dns" | sed /"$add_dns"/d)"
		get_dns="$tmp_dns"
	fi
fi
if [ -z "$(echo "$get_dns" | grep "  - ")" ] ; then
	tmp_dns="$(echo "$get_dns" | sed '/upstream_dns:/a\  - 1.1.1.1')"
fi
if [ ! -z "$tmp_dns" ] ; then
tmp_dns2="$(echo "$tmp_dns" | sed -e ":a;N;s/\n/\\\n/g;ta")"
sed -i ':a;$!{N;ba};s@  upstream_dns.*\ntls:@'"$tmp_dns2"'@' /etc/storage/app_19.sh
fi
}

initopt () {
optPath=`grep ' /opt ' /proc/mounts | grep tmpfs`
[ ! -z "$optPath" ] && return
if [ ! -z "$(echo $scriptfilepath | grep -v "/opt/etc/init")" ] && [ -s "/opt/etc/init.d/rc.func" ] ; then
	{ echo '#!/bin/sh' ; echo $scriptfilepath '"$@"' '&' ; } > /opt/etc/init.d/$scriptname && chmod 777  /opt/etc/init.d/$scriptname
fi

}

initconfig () {

app_19="/etc/storage/app_19.sh"
if [ ! -f "$app_19" ] || [ ! -s "$app_19" ] ; then
	cat > "$app_19" <<-\EEE
bind_host: 0.0.0.0
bind_port: 3000
auth_name: admin
auth_pass: admin
language: zh-cn
rlimit_nofile: 0
dns:
  bind_host: 0.0.0.0
  port: 5353
  protection_enabled: true
  filtering_enabled: true
  blocking_mode: nxdomain
  blocked_response_ttl: 10
  querylog_enabled: true
  ratelimit: 20
  ratelimit_whitelist: []
  refuse_any: true
  bootstrap_dns:
  - 1.1.1.1
  all_servers: true
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts: []
  parental_sensitivity: 0
  parental_enabled: false
  safesearch_enabled: false
  safebrowsing_enabled: false
  resolveraddress: ""
  upstream_dns:
  - 1.1.1.1
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  certificate_chain: ""
  private_key: ""
filters:
- enabled: true
  url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
  name: AdGuard Simplified Domain Names filter
  id: 1
- enabled: true
  url: https://adaway.org/hosts.txt
  name: AdAway
  id: 2
- enabled: true
  url: https://hosts-file.net/ad_servers.txt
  name: hpHosts - Ad and Tracking servers only
  id: 3
- enabled: true
  url: https://www.malwaredomainlist.com/hostslist/hosts.txt
  name: MalwareDomainList.com Hosts List
  id: 4
user_rules: []
dhcp:
  enabled: false
  interface_name: ""
  gateway_ip: ""
  subnet_mask: ""
  range_start: ""
  range_end: ""
  lease_duration: 86400
  icmp_timeout_msec: 1000
clients: []
log_file: ""
verbose: false
schema_version: 3

EEE
	chmod 755 "$app_19"
fi

}

initconfig

update_init () {
source /etc/storage/script/init.sh
[ "$init_ver" -lt 0 ] && init_ver="0" || { [ "$init_ver" -gt 0 ] || init_ver="0" ; }
init_s_ver=2
if [ "$init_s_ver" -gt "$init_ver" ] ; then
	logger -t "【update_init】" "Update /etc/storage/script/init.sh"
	wgetcurl.sh /tmp/init_tmp.sh  "$hiboyscript/script/init.sh" "$hiboyscript2/script/init.sh"
	[ -s /tmp/init_tmp.sh ] && cp -f /tmp/init_tmp.sh /etc/storage/script/init.sh
	chmod 755 /etc/storage/script/init.sh
	source /etc/storage/script/init.sh
fi
}

update_app () {
update_init
mkdir -p /opt/app/AdGuardHome
if [ "$1" = "del" ] ; then
	rm -rf /opt/app/AdGuardHome/Advanced_Extensions_AdGuardHome.asp /opt/AdGuardHome/AdGuardHome
fi

initconfig

# Loader configuration page
if [ ! -f "/opt/app/AdGuardHome/Advanced_Extensions_AdGuardHome.asp" ] || [ ! -s "/opt/app/AdGuardHome/Advanced_Extensions_AdGuardHome.asp" ] ; then
	wgetcurl.sh /opt/app/AdGuardHome/Advanced_Extensions_AdGuardHome.asp "$hiboyfile/Advanced_Extensions_AdGuardHomeasp" "$hiboyfile2/Advanced_Extensions_AdGuardHomeasp"
fi
umount /www/Advanced_Extensions_app17.asp
mount --bind /opt/app/AdGuardHome/Advanced_Extensions_AdGuardHome.asp /www/Advanced_Extensions_app17.asp
# Updater startup script

[ "$1" = "del" ] && /etc/storage/www_sh/AdGuardHome del &
}

case $ACTION in
start)
	AdGuardHome_close
	AdGuardHome_check
	;;
check)
	AdGuardHome_check
	;;
stop)
	AdGuardHome_close
	;;
updateapp17)
	AdGuardHome_restart o
	[ "$AdGuardHome_enable" = "1" ] && nvram set AdGuardHome_status="updateAdGuardHome" && logger -t "【AdGuardHome】" "Restart" && AdGuardHome_restart
	[ "$AdGuardHome_enable" != "1" ] && nvram set AdGuardHome_v="" && logger -t "【AdGuardHome】" "Update" && update_app del
	;;
update_app)
	update_app
	;;
keep)
	#AdGuardHome_check
	AdGuardHome_keep
	;;
*)
	AdGuardHome_check
	;;
esac

