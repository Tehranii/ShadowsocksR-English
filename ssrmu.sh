#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+/Debian 6+/Ubuntu 14.04+
#	Description: Install the ShadowsocksR mudbjson server
#	Version: 1.0.26
#	Author: Toyo
#	Blog: https://doub.io/ss-jc60/
#=================================================

sh_ver="1.0.26"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
ssr_folder="/usr/local/shadowsocksr"
config_file="${ssr_folder}/config.json"
config_user_file="${ssr_folder}/user-config.json"
config_user_api_file="${ssr_folder}/userapiconfig.py"
config_user_mudb_file="${ssr_folder}/mudb.json"
ssr_log_file="${ssr_folder}/ssserver.log"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
LotServer_file="/appex/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh"
jq_file="${ssr_folder}/jq"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[Information]${Font_color_suffix}"
Error="${Red_font_prefix}[Mistake]${Font_color_suffix}"
Tip="${Green_font_prefix}[Notice]${Font_color_suffix}"
Separator_1="——————————————————————————————"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} The current account is not ROOT (or does not have ROOT authority), and the operation cannot continue. Please use ${Green_background_prefix} sudo su ${Font_color_suffix} to obtain temporary ROOT authority (After execution, you will be prompted to enter the password of the current account)." && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
check_crontab(){
	[[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error} The dependency Crontab is missing, please try to install CentOS manually: yum install crond -y , Debian/Ubuntu: apt-get install cron - y!" && exit 1
}
SSR_installation_status(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR folder not found, please check!" && exit 1
}
Server_Speeder_installation_status(){
	[[ ! -e ${Server_Speeder_file} ]] && echo -e "${Error} Server Speeder is not installed, please check!" && exit 1
}
LotServer_installation_status(){
	[[ ! -e ${LotServer_file} ]] && echo -e "${Error} LotServer is not installed, please check!" && exit 1
}
BBR_installation_status(){
	if [[ ! -e ${BBR_file} ]]; then
		echo -e "${Error} BBR script not found, start downloading..."
		cd "${file}"
		if ! wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/bbr.sh; then
			echo -e "${Error} BBR script download failed!" && exit 1
		else
			echo -e "${Info} BBR script download complete!"
			chmod +x bbr.sh
		fi
	fi
}
# Set firewall rules
Add_iptables(){
	if [[ ! -z "${ssr_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	fi
}
Del_iptables(){
	if [[ ! -z "${port}" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	fi
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
# read configuration information
Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User_info(){
	Get_user_port=$1
	user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
	match_info=$(echo "${user_info_get}"|grep -w "### user ")
	if [[ -z "${match_info}" ]]; then
		echo -e "${Error} failed to obtain user information ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	fi
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${protocol_param} ]] && protocol_param="0(unlimited)"
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#transfer_enable=$(echo "${user_info_get}"|grep -w "transfer_enable :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}'|awk -F "ytes" '{print $1}'|sed 's/KB/ KB/;s/MB/ MB/;s/GB/ GB/;s/TB/ TB/;s/PB/ PB/')
	#u=$(echo "${user_info_get}"|grep -w "u :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#d=$(echo "${user_info_get}"|grep -w "d :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	forbidden_port=$(echo "${user_info_get}"|grep -w "forbidden_port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${forbidden_port} ]] && forbidden_port="unlimited"
	speed_limit_per_con=$(echo "${user_info_get}"|grep -w "speed_limit_per_con :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	speed_limit_per_user=$(echo "${user_info_get}"|grep -w "speed_limit_per_user :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	Get_User_transfer "${port}"
}
Get_User_transfer(){
	transfer_port=$1
	#echo "transfer_port=${transfer_port}"
	all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
	#echo "all_port=${all_port}"
	port_num=$(echo "${all_port}"|grep -nw "${transfer_port}"|awk -F ":" '{print $1}')
	#echo "port_num=${port_num}"
	port_num_1=$(echo $((${port_num}-1)))
	#echo "port_num_1=${port_num_1}"
	transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
	#echo "transfer_enable_1=${transfer_enable_1}"
	u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
	#echo "u_1=${u_1}"
	d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
	#echo "d_1=${d_1}"
	transfer_enable_Used_2_1=$(echo $((${u_1}+${d_1})))
	#echo "transfer_enable_Used_2_1=${transfer_enable_Used_2_1}"
	transfer_enable_Used_1=$(echo $((${transfer_enable_1}-${transfer_enable_Used_2_1})))
	#echo "transfer_enable_Used_1=${transfer_enable_Used_1}"
	
	if [[ ${transfer_enable_1} -lt 1024 ]]; then
		transfer_enable="${transfer_enable_1} B"
	elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
		transfer_enable="${transfer_enable} KB"
	elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
		transfer_enable="${transfer_enable} MB"
	elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
		transfer_enable="${transfer_enable} GB"
	elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
		transfer_enable="${transfer_enable} TB"
	fi
	#echo "transfer_enable=${transfer_enable}"
	if [[ ${u_1} -lt 1024 ]]; then
		u="${u_1} B"
	elif [[ ${u_1} -lt 1048576 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
		u="${u} KB"
	elif [[ ${u_1} -lt 1073741824 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
		u="${u} MB"
	elif [[ ${u_1} -lt 1099511627776 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
		u="${u} GB"
	elif [[ ${u_1} -lt 1125899906842624 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
		u="${u} TB"
	fi
	#echo "u=${u}"
	if [[ ${d_1} -lt 1024 ]]; then
		d="${d_1} B"
	elif [[ ${d_1} -lt 1048576 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
		d="${d} KB"
	elif [[ ${d_1} -lt 1073741824 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
		d="${d} MB"
	elif [[ ${d_1} -lt 1099511627776 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
		d="${d} GB"
	elif [[ ${d_1} -lt 1125899906842624 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
		d="${d} TB"
	fi
	#echo "d=${d}"
	if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
		transfer_enable_Used="${transfer_enable_Used_1} B"
	elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
		transfer_enable_Used="${transfer_enable_Used} KB"
	elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
		transfer_enable_Used="${transfer_enable_Used} MB"
	elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
		transfer_enable_Used="${transfer_enable_Used} GB"
	elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
		transfer_enable_Used="${transfer_enable_Used} TB"
	fi
	#echo "transfer_enable_Used=${transfer_enable_Used}"
	if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
		transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
	elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} KB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} MB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} GB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} TB"
	fi
	#echo "transfer_enable_Used_2=${transfer_enable_Used_2}"
}
Get_User_transfer_all(){
	if [[ ${transfer_enable_Used_233} -lt 1024 ]]; then
		transfer_enable_Used_233_2="${transfer_enable_Used_233} B"
	elif [[ ${transfer_enable_Used_233} -lt 1048576 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1024'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} KB"
	elif [[ ${transfer_enable_Used_233} -lt 1073741824 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1048576'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} MB"
	elif [[ ${transfer_enable_Used_233} -lt 1099511627776 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1073741824'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} GB"
	elif [[ ${transfer_enable_Used_233} -lt 1125899906842624 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1099511627776'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} TB"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="http://doub.pw/qr/qr.php?text=${SSurl}"
	ss_link=" SS link: ${Green_font_prefix}${SSurl}${Font_color_suffix} \n SS QR code: ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
}
ssr_link_qr(){
	SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
	SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
	SSRPWDbase64=$(urlsafe_base64 "${password}")
	SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}")
	SSRurl="ssr://${SSRbase64}"
	SSRQRcode="http://doub.pw/qr/qr.php?text=${SSRurl}"
	ssr_link=" SSR link: ${Red_font_prefix}${SSRurl}${Font_color_suffix} \n SSR QR code: ${Red_font_prefix}${SSRQRcode}${Font_color_suffix} \n "
}
ss_ssr_determine(){
	protocol_suffix=`echo ${protocol} | awk -F "_" '{print $NF}'`
	obfs_suffix=`echo ${obfs} | awk -F "_" '{print $NF}'`
	if [[ ${protocol} = "origin" ]]; then
		if [[ ${obfs} = "plain" ]]; then
			ss_link_qr
			ssr_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				ss_link=""
			else
				ss_link_qr
			fi
		fi
	else
		if [[ ${protocol_suffix} != "compatible" ]]; then
			ss_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				if [[ ${obfs_suffix} = "plain" ]]; then
					ss_link_qr
				else
					ss_link=""
				fi
			else
				ss_link_qr
			fi
		fi
	fi
	ssr_link_qr
}
# Display configuration information
View_User(){
	SSR_installation_status
	List_port_user
	while true
	do
		echo -e "Please enter the user port to view account information"
		read -e -p "(default: cancel):" View_user_port
		[[ -z "${View_user_port}" ]] && echo -e "Cancelled..." && exit 1
		View_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${View_user_port}"',')
		if [[ ! -z ${View_user} ]]; then
			Get_User_info "${View_user_port}"
			View_User_info
			break
		else
			echo -e "${Error} Please enter the correct port!"
		fi
	done
}
View_User_info(){
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	ss_ssr_determine
	clear && echo "===================================================" && echo
	echo -e "Configuration information of user [${user_name}]:" && echo
	echo -e " I  P\t    : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " Port\t    : ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " Password\t    : ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " Encryption\t    : ${Green_font_prefix}${method}${Font_color_suffix}"
	echo -e " protocol\t    : ${Red_font_prefix}${protocol}${Font_color_suffix}"
	echo -e " To confuse\t    : ${Red_font_prefix}${obfs}${Font_color_suffix}"
	echo -e "Device limit: ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
	echo -e "Single thread speed limit: ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
	echo -e "Total user speed limit: ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
	echo -e "Forbidden port: ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"
	echo
	echo -e "Used traffic: Upload: ${Green_font_prefix}${u}${Font_color_suffix} + Download: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix} "
	echo -e "Remaining traffic: ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
	echo -e "Total flow of users: ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
	echo -e "${ss_link}"
	echo -e "${ssr_link}"
	echo -e " ${Green_font_prefix} type: ${Font_color_suffix}
 In the browser, open the QR code link, and you can see the QR code picture.
 [ _compatible ] behind the protocol and confusion refers to compatibility with the original protocol/obfuscation. "
	echo && echo "==================================================="
}
# Set configuration information
Set_config_user(){
	echo "Please enter the user name of the user to be set (do not repeat, it is used to distinguish, does not support Chinese, spaces, and will report an error!)"
	read -e -p "(default: doubi):" ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="doubi"
	ssr_user=$(echo "${ssr_user}"|sed 's/ //g')
	echo && echo ${Separator_1} && echo -e " Type : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_port(){
	while true
	do
	echo -e "Please enter the user port to be set (do not repeat, for distinction)"
	read -e -p "(default: 2333):" ssr_port
	[[ -z "$ssr_port" ]] && ssr_port="2333"
	echo $((${ssr_port}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e " Enter : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Please enter the correct number (1-65535)"
		fi
	else
		echo -e "${Error} Please enter the correct number (1-65535)"
	fi
	done
}
Set_config_password(){
	echo "Please enter the user password to be set"
	read -e -p "(default: doub.io):" ssr_password
	[[ -z "${ssr_password}" ]] && ssr_password="doub.io"
	echo && echo ${Separator_1} && echo -e " Default : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_method(){
	echo -e "Please select the user encryption method to be set
	
 ${Green_font_prefix} 1.${Font_color_suffix} none
 ${Tip} If you use the auth_chain_* series of protocols, it is recommended to select none for the encryption method (this series of protocols comes with RC4 encryption), and the confusion is free
 
 ${Green_font_prefix} 2.${Font_color_suffix} rc4
 ${Green_font_prefix} 3.${Font_color_suffix} rc4-md5
 ${Green_font_prefix} 4.${Font_color_suffix} rc4-md5-6
 
 ${Green_font_prefix} 5.${Font_color_suffix} aes-128-ctr
 ${Green_font_prefix} 6.${Font_color_suffix} aes-192-ctr
 ${Green_font_prefix} 7.${Font_color_suffix} aes-256-ctr
 
 ${Green_font_prefix} 8.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-192-cfb
 ${Green_font_prefix}10.${Font_color_suffix} aes-256-cfb
 
 ${Green_font_prefix}11.${Font_color_suffix} aes-128-cfb8
 ${Green_font_prefix}12.${Font_color_suffix} aes-192-cfb8
 ${Green_font_prefix}13.${Font_color_suffix} aes-256-cfb8
 
 ${Green_font_prefix}14.${Font_color_suffix} salsa20
 ${Green_font_prefix}15.${Font_color_suffix} chacha20
 ${Green_font_prefix}16.${Font_color_suffix} chacha20-ietf
 ${Tip} salsa20/chacha20-* series of encryption methods require additional installation of libsodium, otherwise ShadowsocksR will not be able to start!" && echo
	read -e -p "(default: 5. aes-128-ctr):" ssr_method
	[[ -z "${ssr_method}" ]] && ssr_method="5"
	if [[ ${ssr_method} == "1" ]]; then
		ssr_method="none"
	elif [[ ${ssr_method} == "2" ]]; then
		ssr_method="rc4"
	elif [[ ${ssr_method} == "3" ]]; then
		ssr_method="rc4-md5"
	elif [[ ${ssr_method} == "4" ]]; then
		ssr_method="rc4-md5-6"
	elif [[ ${ssr_method} == "5" ]]; then
		ssr_method="aes-128-ctr"
	elif [[ ${ssr_method} == "6" ]]; then
		ssr_method="aes-192-ctr"
	elif [[ ${ssr_method} == "7" ]]; then
		ssr_method="aes-256-ctr"
	elif [[ ${ssr_method} == "8" ]]; then
		ssr_method="aes-128-cfb"
	elif [[ ${ssr_method} == "9" ]]; then
		ssr_method="aes-192-cfb"
	elif [[ ${ssr_method} == "10" ]]; then
		ssr_method="aes-256-cfb"
	elif [[ ${ssr_method} == "11" ]]; then
		ssr_method="aes-128-cfb8"
	elif [[ ${ssr_method} == "12" ]]; then
		ssr_method="aes-192-cfb8"
	elif [[ ${ssr_method} == "13" ]]; then
		ssr_method="aes-256-cfb8"
	elif [[ ${ssr_method} == "14" ]]; then
		ssr_method="salsa20"
	elif [[ ${ssr_method} == "15" ]]; then
		ssr_method="chacha20"
	elif [[ ${ssr_method} == "16" ]]; then
		ssr_method="chacha20-ietf"
	else
		ssr_method="aes-128-ctr"
	fi
	echo && echo ${Separator_1} && echo -e " Enter : ${Green_font_prefix}${ssr_method}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_protocol(){
	echo -e "Please select the user agreement plug-in to be set
	
 ${Green_font_prefix}1.${Font_color_suffix} origin
 ${Green_font_prefix}2.${Font_color_suffix} auth_sha1_v4
 ${Green_font_prefix}3.${Font_color_suffix} auth_aes128_md5
 ${Green_font_prefix}4.${Font_color_suffix} auth_aes128_sha1
 ${Green_font_prefix}5.${Font_color_suffix} auth_chain_a
 ${Green_font_prefix}6.${Font_color_suffix} auth_chain_b
 ${Tip} If you use the auth_chain_* series of protocols, it is recommended to select none for the encryption method (this series of protocols comes with RC4 encryption), and the confusion is free" && echo
	read -e -p "(Default: 3. auth_aes128_md5):" ssr_protocol
	[[ -z "${ssr_protocol}" ]] && ssr_protocol="3"
	if [[ ${ssr_protocol} == "1" ]]; then
		ssr_protocol="origin"
	elif [[ ${ssr_protocol} == "2" ]]; then
		ssr_protocol="auth_sha1_v4"
	elif [[ ${ssr_protocol} == "3" ]]; then
		ssr_protocol="auth_aes128_md5"
	elif [[ ${ssr_protocol} == "4" ]]; then
		ssr_protocol="auth_aes128_sha1"
	elif [[ ${ssr_protocol} == "5" ]]; then
		ssr_protocol="auth_chain_a"
	elif [[ ${ssr_protocol} == "6" ]]; then
		ssr_protocol="auth_chain_b"
	else
		ssr_protocol="auth_aes128_md5"
	fi
	echo && echo ${Separator_1} && echo -e " Enter : ${Green_font_prefix}${ssr_protocol}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_protocol} != "origin" ]]; then
		if [[ ${ssr_protocol} == "auth_sha1_v4" ]]; then
			read -e -p "Do you want to set the protocol plugin to be compatible with the original version (_compatible)? [Y/n]" ssr_protocol_yn
			[[ -z "${ssr_protocol_yn}" ]] && ssr_protocol_yn="y"
			[[ $ssr_protocol_yn == [Yy] ]] && ssr_protocol=${ssr_protocol}"_compatible"
			echo
		fi
	fi
}
Set_config_obfs(){
	echo -e "Please select the user obfuscation plugin to set
	
 ${Green_font_prefix}1.${Font_color_suffix} plain
 ${Green_font_prefix}2.${Font_color_suffix} http_simple
 ${Green_font_prefix}3.${Font_color_suffix} http_post
 ${Green_font_prefix}4.${Font_color_suffix} random_head
 ${Green_font_prefix}5.${Font_color_suffix} tls1.2_ticket_auth
 ${Tip} If you use ShadowsocksR to proxy the game, it is recommended to choose obfuscation compatible with the original version or plain obfuscation, and then the client chooses plain, otherwise it will increase the delay!
 In addition, if you choose tls1.2_ticket_auth, then the client can choose tls1.2_ticket_fastauth, which can pretend without adding delay!
 If you are building in popular areas such as Japan and the United States, then choosing plain may be less likely to be blocked!" && echo
	read -e -p "(default: 1. plain):" ssr_obfs
	[[ -z "${ssr_obfs}" ]] && ssr_obfs="1"
	if [[ ${ssr_obfs} == "1" ]]; then
		ssr_obfs="plain"
	elif [[ ${ssr_obfs} == "2" ]]; then
		ssr_obfs="http_simple"
	elif [[ ${ssr_obfs} == "3" ]]; then
		ssr_obfs="http_post"
	elif [[ ${ssr_obfs} == "4" ]]; then
		ssr_obfs="random_head"
	elif [[ ${ssr_obfs} == "5" ]]; then
		ssr_obfs="tls1.2_ticket_auth"
	else
		ssr_obfs="plain"
	fi
	echo && echo ${Separator_1} && echo -e " Type : ${Green_font_prefix}${ssr_obfs}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_obfs} != "plain" ]]; then
			read -e -p "Do you want to set the obfuscation plugin to be compatible with the original version (_compatible)? [Y/n]" ssr_obfs_yn
			[[ -z "${ssr_obfs_yn}" ]] && ssr_obfs_yn="y"
			[[ $ssr_obfs_yn == [Yy] ]] && ssr_obfs=${ssr_obfs}"_compatible"
			echo
	fi
}
Set_config_protocol_param(){
	while true
	do
	echo -e "Please enter the number of devices that the user wants to limit (${Green_font_prefix} auth_* series protocol is not compatible with the original version to be valid ${Font_color_suffix})"
	echo -e "${Tip} device limit: the number of clients that can be connected to each port at the same time (multi-port mode, each port is calculated independently), at least 2 are recommended."
	read -e -p "(default: unlimited):" ssr_protocol_param
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && echo && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
			echo && echo ${Separator_1} && echo -e " Environment : ${Green_font_prefix}${ssr_protocol_param}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Please enter the correct number (1-9999)"
		fi
	else
		echo -e "${Error} Please enter the correct number (1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	echo -e "Please enter the upper limit of the user's single thread speed limit to be set (unit: KB/S)"
	echo -e "${Tip} single-thread speed limit: the upper limit of the speed limit of each port single thread, multi-thread is invalid."
	read -e -p "(default: unlimited):" ssr_speed_limit_per_con
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && echo && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e " Environment : ${Green_font_prefix}${ssr_speed_limit_per_con}KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Please enter the correct number (1-131072)"
		fi
	else
		echo -e "${Error} Please enter the correct number (1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	echo -e "Please enter the upper limit of the user's total speed limit to be set (unit: KB/S)"
	echo -e "${Tip} total port speed limit: the upper limit of the total speed limit for each port, and the overall speed limit for a single port."
	read -e -p "(default: unlimited):" ssr_speed_limit_per_user
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && echo && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e " Default type : ${Green_font_prefix}${ssr_speed_limit_per_user} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Please enter the correct number (1-131072)"
		fi
	else
		echo -e "${Error} Please enter the correct number (1-131072)"
	fi
	done
}
Set_config_transfer(){
	while true
	do
	echo
	echo -e "Please enter the upper limit of the total traffic available to the user to be set (unit: GB, 1-838868 GB)"
	read -e -p "(default: unlimited):" ssr_transfer
	[[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && echo && break
	echo $((${ssr_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
			echo && echo ${Separator_1} && echo -e " Default : ${Green_font_prefix}${ssr_transfer} GB${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Please enter the correct number (1-838868)"
		fi
	else
		echo -e "${Error} Please enter the correct number (1-838868)"
	fi
	done
}
Set_config_forbid(){
	echo "Please enter the port that the user is prohibited from accessing"
	echo -e "${Tip} Prohibited ports: For example, if access to port 25 is not allowed, users will not be able to access mail port 25 through the SSR proxy. If 80,443 is prohibited, users will not be able to access http/https websites normally.
Block a single port Format: 25
Block multiple ports Format: 23,465
Banned port segment format: 233-266
Block multiple format ports: 25,465,233-666 (without the colon:)"
	read -e -p "(default is empty and does not prohibit access to any port):" ssr_forbid
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
	echo && echo ${Separator_1} && echo -e " Default setting : ${Green_font_prefix}${ssr_forbidden}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_enable(){
	user_total=$(echo $((${user_total}-1)))
	for((integer = 0; integer <= ${user_total}; integer++))
	do
		echo -e "integer=${integer}"
		port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
		echo -e "port_jq=${port_jq}"
		if [[ "${ssr_port}" == "${port_jq}" ]]; then
			enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
			echo -e "enable=${enable}"
			[[ "${enable}" == "null" ]] && echo -e "${Error} Failed to get the disabled status of the current port [${ssr_port}]!" && exit 1
			ssr_port_num=$(cat "${config_user_mudb_file}"|grep -n '"port": '${ssr_port}','|awk -F ":" '{print $1}')
			echo -e "ssr_port_num=${ssr_port_num}"
			[[ "${ssr_port_num}" == "null" ]] && echo -e "${Error} Failed to get the line number of the current port [${ssr_port}]!" && exit 1
			ssr_enable_num=$(echo $((${ssr_port_num}-5)))
			echo -e "ssr_enable_num=${ssr_enable_num}"
			break
		fi
	done
	if [[ "${enable}" == "1" ]]; then
		echo -e "The account status of port [${ssr_port}] is: ${Green_font_prefix} enables ${Font_color_suffix}, whether to switch to ${Red_font_prefix} to disable ${Font_color_suffix} ?[Y/n]"
		read -e -p "(default: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn="y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="0"
		else
			echo "Cancel..." && exit 0
		fi
	elif [[ "${enable}" == "0" ]]; then
		echo -e "The account status of port [${ssr_port}] is: ${Green_font_prefix} disables ${Font_color_suffix}, whether to switch to ${Red_font_prefix} and enable ${Font_color_suffix} ?[Y/n]"
		read -e -p "(default: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn = "y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="1"
		else
			echo "Cancel..." && exit 0
		fi
	else
		echo -e "${Error} The disabled status of the current port is abnormal [${enable}] !" && exit 1
	fi
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} Failed to obtain the currently configured server IP or domain name!" && exit 1
		else
			echo -e "${Info} currently configured server IP or domain name: ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
		fi
	fi
	echo "Please enter the server IP or domain name to be displayed in the user configuration (when the server has multiple IPs, you can specify the IP or domain name displayed in the user configuration)"
	read -e -p "(Automatically detect external network IP by default):" ssr_server_pub_addr
	if [[ -z "${ssr_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} Failed to automatically detect external network IP, please manually enter server IP or domain name" ssr_server_pub_addr
			if [[ -z "$ssr_server_pub_addr" ]]; then
				echo -e "${Error} cannot be empty!"
			else
				break
			fi
			done
		else
			ssr_server_pub_addr="${ip}"
		fi
	fi
	echo && echo ${Separator_1} && echo -e " IP address : ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_all(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	else
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	fi
}
# Modify configuration information
Modify_config_password(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -k "${ssr_password}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} user password modification failed ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} user password changed successfully ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Note: It may take about ten seconds to apply the latest configuration)"
	fi
}
Modify_config_method(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -m "${ssr_method}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} user encryption method modification failed ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} user encryption method modified successfully ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Note: It may take about ten seconds to apply the latest configuration)"
	fi
}
Modify_config_protocol(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -O "${ssr_protocol}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} user protocol modification failed ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} user agreement modified successfully ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Note: It may take about ten seconds to apply the latest configuration)"
	fi
}
Modify_config_obfs(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -o "${ssr_obfs}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} user confusion modification failed ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} user confusion modified successfully ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Note: It may take about ten seconds to apply the latest configuration)"
	fi
}
Modify_config_protocol_param(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -G "${ssr_protocol_param}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} User protocol parameter (device limit) modification failed ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} user conference parameters (device limit) modified successfully ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Note: It may take about ten seconds to apply the latest configuration)"
	fi
}
Modify_config_speed_limit_per_con(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -s "${ssr_speed_limit_per_con}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} user single-thread rate limit modification failed ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "The ${Info} user's single-thread speed limit has been modified successfully ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Note: It may take about ten seconds to apply the latest configuration)"
	fi
}
Modify_config_speed_limit_per_user(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -S "${ssr_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Failed to modify the total speed limit of the user port ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "The total speed limit of ${Info} user port has been modified successfully ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Note: It may take about ten seconds to apply the latest configuration)"
	fi
}
Modify_config_connect_verbose_info(){
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"',/g' ${config_user_file}
}
Modify_config_transfer(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -t "${ssr_transfer}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} user total traffic modification failed ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "The total traffic of ${Info} users has been modified successfully ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Note: It may take about ten seconds to apply the latest configuration)"
	fi
}
Modify_config_forbid(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -f "${ssr_forbid}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} user is prohibited from accessing port modification failed ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "The ${Info} user is prohibited from accessing the port and modified successfully ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Note: It may take about ten seconds to apply the latest configuration)"
	fi
}
Modify_config_enable(){
	sed -i "${ssr_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ssr_enable})"',/' ${config_user_mudb_file}
}
Modify_user_api_server_pub_addr(){
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
}
Modify_config_all(){
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
	Modify_config_transfer
	Modify_config_forbid
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} does not have Python installed, starting to install..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Cents_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip crond net-tools
	else
		yum install -y vim unzip crond
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip cron net-tools
	else
		apt-get install -y vim unzip cron
	fi
}
# Download ShadowsocksR
Download_SSR(){
	cd "/usr/local"
	wget -N --no-check-certificate "https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip"
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY=true git clone -b manyuser https://github.com/ToyoDAdoubiBackup/shadowsocksr.git
	#[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR server download failed!" && exit 1
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} ShadowsocksR server compressed package download failed!" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} ShadowsocksR server decompression failed!" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} ShadowsocksR server rename failed!" && rm -rf manyuser.zip && rm -rf "/usr/local/ shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	cd "shadowsocksr"
	cp "${ssr_folder}/config.json" "${config_user_file}"
	cp "${ssr_folder}/mysql.json" "${ssr_folder}/usermysql.json"
	cp "${ssr_folder}/apiconfig.py" "${config_user_api_file}"
	[[ ! -e ${config_user_api_file} ]] && echo -e "${Error} ShadowsocksR server apiconfig.py copy failed!" && exit 1
	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
	server_pub_addr="127.0.0.1"
	Modify_user_api_server_pub_addr
	#sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '${ip}'/" ${config_user_api_file}
	sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
	echo -e "${Info} ShadowsocksR server download complete!"
}
Service_SSR(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR service management script download failed!" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		chkconfig --add ssrmu
		chkconfig ssrmu on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR service management script download failed!" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		update-rc.d -f ssrmu defaults
	fi
	echo -e "${Info} ShadowsocksR service management script download complete!"
}
# Install JQ parser
JQ_install(){
	if [[ ! -e ${jq_file} ]]; then
		cd "${ssr_folder}"
		if [[ ${bit} = "x86_64" ]]; then
			mv "jq-linux64" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
		else
			mv "jq-linux32" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
		fi
		[[ ! -e ${jq_file} ]] && echo -e "${Error} JQ parser rename failed, please check!" && exit 1
		chmod +x ${jq_file}
		echo -e "${Info} JQ parser installation is complete, continue..."
	else
		echo -e "${Info} JQ parser installed, continue..."
	fi
}
# install dependencies
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Cents_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} depends on unzip (unzip the compressed package) and the installation failed. It is probably a problem with the package source. Please check!" && exit 1
	Check_python
	#echo "nameserver 8.8.8.8" > /etc/resolv.conf
	#echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	if [[ ${release} == "centos" ]]; then
		/etc/init.d/crond restart
	else
		/etc/init.d/cron restart
	fi
}
Install_SSR(){
	check_root
	[[ -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR folder already exists, please check (if the installation fails or there is an old version, please uninstall first)!" && exit 1
	echo -e "${Info} start setting up ShadowsocksR account configuration..."
	Set_user_api_server_pub_addr
	Set_config_all
	echo -e "${Info} starts installing/configuring ShadowsocksR dependencies..."
	Installation_dependency
	echo -e "${Info} start downloading/installing ShadowsocksR files..."
	Download_SSR
	echo -e "${Info} start downloading/installing ShadowsocksR service script (init)..."
	Service_SSR
	echo -e "${Info} start downloading/installing JSNO parser JQ..."
	JQ_install
	echo -e "${Info} starting to add initial user..."
	Add_port_user "install"
	echo -e "${Info} start setting up iptables firewall..."
	Set_iptables
	echo -e "${Info} start adding iptables firewall rules..."
	Add_iptables
	echo -e "${Info} start saving iptables firewall rules..."
	Save_iptables
	echo -e "${Info} All steps are installed, start the ShadowsocksR server..."
	Start_SSR
	Get_User_info "${ssr_port}"
	View_User_info
}
Update_SSR(){
	SSR_installation_status
	echo -e "This function is temporarily disabled because the update of the ShadowsocksR server is temporarily suspended."
	#cd ${ssr_folder}
	#git pull
	#Restart_SSR
}
Uninstall_SSR(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR is not installed, please check!" && exit 1
	echo "Are you sure you want to uninstall ShadowsocksR? [y/N]" && echo
	read -e -p "(default: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		user_info=$(python mujson_mgr.py -l)
		user_total=$(echo "${user_info}"|wc -l)
		if [[ ! -z ${user_info} ]]; then
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
				del_iptables
			done
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ssrmu.sh") ]]; then
			crontab_monitor_ssr_cron_stop
			Clear_transfer_all_cron_stop
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
		echo && echo "ShadowsocksR uninstall complete!" && echo
	else
		echo && echo "Uninstall canceled..." && echo
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} started fetching latest version of libsodium..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "The latest version of ${Info} libsodium is ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix} !"
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} libsodium is already installed, do you want to overwrite (update)? [y/N]"
		read -e -p "(default: n):" yn
		[[ -z ${in} ]] && in="n"
		if [[ ${in} == [Nn] ]]; then
			echo "Cancelled..." && exit 1
		fi
	else
		echo -e "${Info} libsodium is not installed, starting to install..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} install dependencies..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} Download..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} decompression..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} compile and install..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} install dependencies..."
		apt-get install -y build-essential
		echo -e "${Info} Download..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} decompression..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} compile and install..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} libsodium installation failed!" && exit 1
	echo && echo -e "${Info} libsodium installed successfully!" && echo
}
# show connection info
debian_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} No user found, please check!" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep ":${user_port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"username: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix}\t port: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Total number of linked IPs: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t current linkIP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Total number of users: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Total link IP: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
centos_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} No user found, please check!" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep ":${user_port} "|grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"username: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix}\t port: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Total number of linked IPs: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t current linkIP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Total number of users: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Total link IP: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
View_user_connection_info(){
	SSR_installation_status
	echo && echo -e "Please select the format to display:
 ${Green_font_prefix}1.${Font_color_suffix} display IP format
 ${Green_font_prefix}2.${Font_color_suffix} display IP+IP attribution format " && echo
	read -e -p "(Default: 1):" ssr_connection_info
	[[ -z "${ssr_connection_info}" ]] && ssr_connection_info="1"
	if [[ ${ssr_connection_info} == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ ${ssr_connection_info} == "2" ]]; then
		echo -e "${Tip} detects the IP attribution (ipip.net), if there are many IPs, it may take a long time..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} Please enter the correct number (1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
get_IP_address(){
	#echo "user_IP_1=${user_IP_1}"
	if [[ ! -z ${user_IP_1} ]]; then
	#echo "user_IP_total=${user_IP_total}"
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=`echo "${user_IP_1}" |sed -n "$integer_1"p`
			#echo "IP=${IP}"
			IP_address=`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g'`
			#echo "IP_address=${IP_address}"
			user_IP="${user_IP}\n${IP}(${IP_address})"
			#echo "user_IP=${user_IP}"
			sleep 1s
		done
	fi
}
# Modify user configuration
Modify_port(){
	List_port_user
	while true
	do
		echo -e "Please enter the user port to be modified"
		read -e -p "(default: cancel):" ssr_port
		[[ -z "${ssr_port}" ]] && echo -e "Cancelled..." && exit 1
		Modify_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${ssr_port}"',')
		if [[ ! -z ${Modify_user} ]]; then
			break
		else
			echo -e "${Error} Please enter the correct port!"
		fi
	done
}
Modify_Config(){
	SSR_installation_status
	echo && echo -e "What are you going to do?
 ${Green_font_prefix}1.${Font_color_suffix} Add user configuration
 ${Green_font_prefix}2.${Font_color_suffix} delete user configuration
———— Modify user configuration ————
 ${Green_font_prefix}3. ${Font_color_suffix} modify user password
 ${Green_font_prefix}4.${Font_color_suffix} Modify the encryption method
 ${Green_font_prefix}5.${Font_color_suffix} modify protocol plugin
 ${Green_font_prefix}6.${Font_color_suffix} Modify the obfuscation plugin
 ${Green_font_prefix}7.${Font_color_suffix} modify the device limit
 ${Green_font_prefix}8.${Font_color_suffix} modify single thread speed limit
 ${Green_font_prefix}9.${Font_color_suffix} Modify the user's total speed limit
 ${Green_font_prefix}10.${Font_color_suffix} Modify the total traffic of users
 ${Green_font_prefix}11.${Font_color_suffix} modify user disabled port
 ${Green_font_prefix}12.${Font_color_suffix} Modify all configurations
----- other-----
 ${Green_font_prefix}13.${Font_color_suffix} Modify the IP or domain name displayed in the user configuration
 
 ${Tip} The username and port of the user cannot be modified, if you need to modify it, please use the manual modification function of the script!" && echo
	read -e -p "(default: cancel):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "Cancelled..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Add_port_user
	elif [[ ${ssr_modify} == "2" ]]; then
		Del_port_user
	elif [[ ${ssr_modify} == "3" ]]; then
		Modify_port
		Set_config_password
		Modify_config_password
	elif [[ ${ssr_modify} == "4" ]]; then
		Modify_port
		Set_config_method
		Modify_config_method
	elif [[ ${ssr_modify} == "5" ]]; then
		Modify_port
		Set_config_protocol
		Modify_config_protocol
	elif [[ ${ssr_modify} == "6" ]]; then
		Modify_port
		Set_config_obfs
		Modify_config_obfs
	elif [[ ${ssr_modify} == "7" ]]; then
		Modify_port
		Set_config_protocol_param
		Modify_config_protocol_param
	elif [[ ${ssr_modify} == "8" ]]; then
		Modify_port
		Set_config_speed_limit_per_con
		Modify_config_speed_limit_per_con
	elif [[ ${ssr_modify} == "9" ]]; then
		Modify_port
		Set_config_speed_limit_per_user
		Modify_config_speed_limit_per_user
	elif [[ ${ssr_modify} == "10" ]]; then
		Modify_port
		Set_config_transfer
		Modify_config_transfer
	elif [[ ${ssr_modify} == "11" ]]; then
		Modify_port
		Set_config_forbid
		Modify_config_forbid
	elif [[ ${ssr_modify} == "12" ]]; then
		Modify_port
		Set_config_all "Modify"
		Modify_config_all
	elif [[ ${ssr_modify} == "13" ]]; then
		Set_user_api_server_pub_addr "Modify"
		Modify_user_api_server_pub_addr
	else
		echo -e "${Error} Please enter the correct number (1-13)" && exit 1
	fi
}
List_port_user(){
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} No user found, please check!" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		Get_User_transfer "${user_port}"
		transfer_enable_Used_233=$(echo $((${transfer_enable_Used_233}+${transfer_enable_Used_2_1})))
		user_list_all=${user_list_all}"username: ${Green_font_prefix} "${user_username}"${Font_color_suffix}\t port: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Traffic usage (used + remaining = total): ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix} + ${Green_font_prefix}${transfer_enable_Used}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable}${Font_color_suffix}\n"
	done
	Get_User_transfer_all
	echo && echo -e "=== Total users ${Green_background_prefix} "${user_total}" ${Font_color_suffix}"
	echo -e ${user_list_all}
	echo -e "=== The sum of traffic used by all current users: ${Green_background_prefix} ${transfer_enable_Used_233_2} ${Font_color_suffix}\n"
}
Add_port_user(){
	lalal=$1
	if [[ "$lalal" == "install" ]]; then
		match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
	else
		while true
		do
			Set_config_all
			match_port=$(python mujson_mgr.py -l|grep -w "port ${ssr_port}$")
			[[ ! -z "${match_port}" ]] && echo -e "${Error} The port [${ssr_port}] already exists, please do not add it again!" && exit 1
			match_username=$(python mujson_mgr.py -l|grep -w "user \[${ssr_user}]")
			[[ ! -z "${match_username}" ]] && echo -e "${Error} The username [${ssr_user}] already exists, please do not add it again!" && exit 1
			match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
			if [[ -z "${match_add}" ]]; then
				echo -e "${Error} failed to add user ${Green_font_prefix}[username: ${ssr_user}, port: ${ssr_port}]${Font_color_suffix}"
				break
			else
				Add_iptables
				Save_iptables
				echo -e "${Info} user successfully added ${Green_font_prefix}[username: ${ssr_user}, port: ${ssr_port}]${Font_color_suffix}"
				echo
				read -e -p "Continue to add user configuration? [Y/n]:" addyn
				[[ -z ${addyn} ]] && addyn="y"
				if [[ ${addyn} == [Nn] ]]; then
					Get_User_info "${ssr_port}"
					View_User_info
					break
				else
					echo -e "${Info} continue to add user configuration..."
				fi
			fi
		done
	fi
}
Del_port_user(){
	List_port_user
	while true
	do
		echo -e "Please enter the user port to be deleted"
		read -e -p "(default: cancel):" del_user_port
		[[ -z "${del_user_port}" ]] && echo -e "Cancelled..." && exit 1
		del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
		if [[ ! -z ${del_user} ]]; then
			port=${del_user_port}
			match_del=$(python mujson_mgr.py -d -p "${del_user_port}"|grep -w "delete user ")
			if [[ -z "${match_del}" ]]; then
				echo -e "${Error} failed to delete user ${Green_font_prefix}[port: ${del_user_port}]${Font_color_suffix}"
			else
				del_iptables
				Save_iptables
				echo -e "${Info} user deleted successfully ${Green_font_prefix}[port: ${del_user_port}]${Font_color_suffix}"
			fi
			break
		else
			echo -e "${Error} Please enter the correct port!"
		fi
	done
}
Manually_Modify_Config(){
	SSR_installation_status
	vi ${config_user_mudb_file}
	echo "Do you want to restart ShadowsocksR now? [Y/n]" && echo
	read -e -p "(default: y):" yn
	[[ -z ${in} ]] && in="y"
	if [[ ${in} == [Yy] ]]; then
		Restart_SSR
	fi
}
Clear_transfer(){
	SSR_installation_status
	echo && echo -e "What are you going to do?
 ${Green_font_prefix}1.${Font_color_suffix} Clear the data used by a single user
 ${Green_font_prefix}2.${Font_color_suffix} clears all traffic used by users (irretrievable)
 ${Green_font_prefix}3. ${Font_color_suffix} Start timing and clear all user traffic
 ${Green_font_prefix}4.${Font_color_suffix} Stop timing and clear all user traffic
 ${Green_font_prefix}5.${Font_color_suffix} Modify timing and clear all user traffic" && echo
	read -e -p "(default: cancel):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "Cancelled..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Clear_transfer_one
	elif [[ ${ssr_modify} == "2" ]]; then
		echo "Are you sure you want to clear the traffic used by all users? [y/N]" && echo
		read -e -p "(default: n):" yn
		[[ -z ${in} ]] && in="n"
		if [[ ${in} == [Yy] ]]; then
			Clear_transfer_all
		else
			echo "Cancel..."
		fi
	elif [[ ${ssr_modify} == "3" ]]; then
		check_crontab
		Set_crontab
		Clear_transfer_all_cron_start
	elif [[ ${ssr_modify} == "4" ]]; then
		check_crontab
		Clear_transfer_all_cron_stop
	elif [[ ${ssr_modify} == "5" ]]; then
		check_crontab
		Clear_transfer_all_cron_modify
	else
		echo -e "${Error} Please enter the correct number (1-5)" && exit 1
	fi
}
Clear_transfer_one(){
	List_port_user
	while true
	do
		echo -e "Please enter the user port to clear the used traffic"
		read -e -p "(default: cancel):" Clear_transfer_user_port
		[[ -z "${Clear_transfer_user_port}" ]] && echo -e "Cancelled..." && exit 1
		Clear_transfer_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${Clear_transfer_user_port}"',')
		if [[ ! -z ${Clear_transfer_user} ]]; then
			match_clear=$(python mujson_mgr.py -c -p "${Clear_transfer_user_port}"|grep -w "clear user ")
			if [[ -z "${match_clear}" ]]; then
				echo -e "${Error} failed to clear the traffic used by the user ${Green_font_prefix}[port: ${Clear_transfer_user_port}]${Font_color_suffix}"
			else
				echo -e "${Info} user has successfully cleared the traffic used ${Green_font_prefix}[port: ${Clear_transfer_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} Please enter the correct port!"
		fi
	done
}
Clear_transfer_all(){
	cd "${ssr_folder}"
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} No user found, please check!" && exit 1
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		match_clear=$(python mujson_mgr.py -c -p "${user_port}"|grep -w "clear user ")
		if [[ -z "${match_clear}" ]]; then
			echo -e "${Error} Failed to reset user traffic to zero ${Green_font_prefix}[port: ${user_port}]${Font_color_suffix}"
		else
			echo -e "${Info} user has successfully cleared the traffic used by ${Green_font_prefix}[port: ${user_port}]${Font_color_suffix}"
		fi
	done
	echo -e "${Info} all user traffic cleared!"
}
Clear_transfer_all_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} /bin/bash $file/ssrmu.sh clearall" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Failed to clear all user traffic at regular intervals!" && exit 1
	else
		echo -e "${Info} scheduled all user traffic cleared and started successfully!"
	fi
}
Clear_transfer_all_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Failed to clear and stop all user traffic at regular intervals!" && exit 1
	else
		echo -e "${Info} scheduled all user traffic cleared and stopped successfully!"
	fi
}
Clear_transfer_all_cron_modify(){
	Set_crontab
	Clear_transfer_all_cron_stop
	Clear_transfer_all_cron_start
}
Set_crontab(){
		echo -e "Please enter the time interval for traffic clearing
 === Format description ===
 * * * * * corresponds to minutes, hours, days, months, and weeks
 ${Green_font_prefix} 0 2 1 * * ${Font_color_suffix} means clearing the used traffic at 2:00 on the 1st of each month
 ${Green_font_prefix} 0 2 15 * * ${Font_color_suffix} means clearing the used traffic at 2:00 on the 15th of each month
 ${Green_font_prefix} 0 2 */7 * * ${Font_color_suffix} means clearing the used traffic at 2:00 every 7 days
 ${Green_font_prefix} 0 2 * * 0 ${Font_color_suffix} means every Sunday (7) clear the used flow
 ${Green_font_prefix} 0 2 * * 3 ${Font_color_suffix} represents every Wednesday (3) to clear the used traffic" && echo
	read -e -p "(Default: 0 2 1 * * 2:00 on the 1st of every month):" Crontab_time
	[[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
}
Start_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR is running!" && exit 1
	/etc/init.d/ssrmu start
}
Stop_SSR(){
	SSR_installation_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR is not running!" && exit 1
	/etc/init.d/ssrmu stop
}
Restart_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ssrmu stop
	/etc/init.d/ssrmu start
}
View_Log(){
	SSR_installation_status
	[[ ! -e ${ssr_log_file} ]] && echo -e "${Error} ShadowsocksR log file does not exist!" && exit 1
	echo && echo -e "${Tip} press ${Red_font_prefix}Ctrl+C${Font_color_suffix} to stop viewing the log" && echo -e "If you need to view the complete log content, please use ${Red_font_prefix}cat ${ssr_log_file}$ {Font_color_suffix} command." && echo
	tail -f ${ssr_log_file}
}
# sharp speed
Configure_Server_Speeder(){
	echo && echo -e "What are you going to do?
 ${Green_font_prefix}1.${Font_color_suffix} install sharp speed
 ${Green_font_prefix}2.${Font_color_suffix} Uninstall Sharp Speed
————————
 ${Green_font_prefix}3. ${Font_color_suffix} start sharp speed
 ${Green_font_prefix}4.${Font_color_suffix} stop sharp speed
 ${Green_font_prefix}5.${Font_color_suffix} restart sharp speed
 ${Green_font_prefix}6.${Font_color_suffix} View sharp speed status
 
 Note: Rushspeed and LotServer cannot be installed/started at the same time! " && echo
	read -e -p "(default: cancel):" server_speeder_num
	[[ -z "${server_speeder_num}" ]] && echo "Cancelled..." && exit 1
	if [[ ${server_speeder_num} == "1" ]]; then
		Install_ServerSpeeder
	elif [[ ${server_speeder_num} == "2" ]]; then
		Server_Speeder_installation_status
		Uninstall_ServerSpeeder
	elif [[ ${server_speeder_num} == "3" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} start
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "4" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} stop
	elif [[ ${server_speeder_num} == "5" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} restart
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "6" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} status
	else
		echo -e "${Error} Please enter the correct number (1-6)" && exit 1
	fi
}
Install_ServerSpeeder(){
	[[ -e ${Server_Speeder_file} ]] && echo -e "${Error} Server Speeder has been installed!" && exit 1
	#Borrow 91yun.rog's happy version of sharp speed
	wget --no-check-certificate -qO /tmp/serverspeeder.sh https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder.sh
	[[ ! -e "/tmp/serverspeeder.sh" ]] && echo -e "${Error} Failed to download the sharp speed installation script!" && exit 1
	bash /tmp/serverspeeder.sh
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "serverspeeder" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		rm -rf /tmp/serverspeeder.sh
		rm -rf /tmp/91yunserverspeeder
		rm -rf /tmp/91yunserverspeeder.tar.gz
		echo -e "${Info} Server Speeder installed!" && exit 1
	else
		echo -e "${Error} Server Speeder failed to install!" && exit 1
	fi
}
Uninstall_ServerSpeeder(){
	echo "Are you sure you want to uninstall Server Speeder? [y/N]" && echo
	read -e -p "(default: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "Enter..." && exit
	if [[ ${unyn} == [Yy] ]]; then
		chattr -i /serverspeeder/etc/apx*
		/serverspeeder/bin/serverSpeeder.sh uninstall -f
		echo && echo "Server Speeder uninstallation complete!" && echo
	fi
}
# LotServer
Configure_LotServer(){
	echo && echo -e "What are you going to do?
 ${Green_font_prefix}1.${Font_color_suffix} Enable LotServer
 ${Green_font_prefix}2.${Font_color_suffix} uninstall LotServer
————————
 ${Green_font_prefix}3.${Font_color_suffix} Local LotServer
 ${Green_font_prefix}4.${Font_color_suffix} Enable LotServer
 ${Green_font_prefix}5.${Font_color_suffix} reboot LotServer
 ${Green_font_prefix}6. ${Font_color_suffix} View LotServer status
 
 Note: Rushspeed and LotServer cannot be installed/started at the same time! " && echo
	read -e -p "(default: cancel):" lotserver_num
	[[ -z "${lotserver_num}" ]] && echo "Cancelled..." && exit 1
	if [[ ${lotserver_num} == "1" ]]; then
		Install_LotServer
	elif [[ ${lotserver_num} == "2" ]]; then
		LotServer_installation_status
		Uninstall_LotServer
	elif [[ ${lotserver_num} == "3" ]]; then
		LotServer_installation_status
		${LotServer_file} start
		${LotServer_file} status
	elif [[ ${lotserver_num} == "4" ]]; then
		LotServer_installation_status
		${LotServer_file} stop
	elif [[ ${lotserver_num} == "5" ]]; then
		LotServer_installation_status
		${LotServer_file} restart
		${LotServer_file} status
	elif [[ ${lotserver_num} == "6" ]]; then
		LotServer_installation_status
		${LotServer_file} status
	else
		echo -e "${Error} Please enter the correct number (1-6)" && exit 1
	fi
}
Install_LotServer(){
	[[ -e ${LotServer_file} ]] && echo -e "${Error} LotServer is already installed!" && exit 1
	#Github: https://github.com/0oVicero0/serverSpeeder_Install
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	[[ ! -e "/tmp/appex.sh" ]] && echo -e "${Error} LotServer installation script download failed!" && exit 1
	bash /tmp/appex.sh 'install'
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "appex" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		echo -e "${Info} LotServer installed!" && exit 1
	else
		echo -e "${Error} LotServer installation failed!" && exit 1
	fi
}
Uninstall_LotServer(){
	echo "Are you sure you want to uninstall LotServer? [y/N]" && echo
	read -e -p "(default: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "Enter..." && exit
	if [[ ${unyn} == [Yy] ]]; then
		wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh" && bash /tmp/appex.sh 'uninstall'
		echo && echo "LotServer uninstall complete!" && echo
	fi
}
# BBR
Configure_BBR(){
	echo && echo -e "What are you going to do?
	
 ${Green_font_prefix}1.${Font_color_suffix} Enable BBR
————————
 ${Green_font_prefix}2.${Font_color_suffix} Enter BBR
 ${Green_font_prefix}3.${Font_color_suffix} New BBR
 ${Green_font_prefix}4.${Font_color_suffix} View BBR status" && echo
echo -e "${Green_font_prefix} [Note before installation] ${Font_color_suffix}
1. Install and enable BBR, you need to replace the kernel, there are risks such as replacement failure (cannot boot after restarting)
2. This script only supports Debian/Ubuntu system to change the kernel, OpenVZ and Docker do not support changing the kernel
3. Debian will prompt [Whether to stop uninstalling the kernel] during the kernel replacement process, please select ${Green_font_prefix} NO ${Font_color_suffix}" && echo
	read -e -p "(default: cancel):" bbr_num
	[[ -z "${bbr_num}" ]] && echo "Cancelled..." && exit 1
	if [[ ${bbr_num} == "1" ]]; then
		Install_BBR
	elif [[ ${bbr_num} == "2" ]]; then
		Start_BBR
	elif [[ ${bbr_num} == "3" ]]; then
		Stop_BBR
	elif [[ ${bbr_num} == "4" ]]; then
		Status_BBR
	else
		echo -e "${Error} Please enter the correct number (1-4)" && exit 1
	fi
}
Install_BBR(){
	[[ ${release} = "centos" ]] && echo -e "${Error} This script does not support CentOS system installation BBR!" && exit 1
	BBR_installation_status
	bash "${BBR_file}"
}
Start_BBR(){
	BBR_installation_status
	bash "${BBR_file}" start
}
Stop_BBR(){
	BBR_installation_status
	bash "${BBR_file}" stop
}
Status_BBR(){
	BBR_installation_status
	bash "${BBR_file}" status
}
# Other functions
Other_functions(){
	echo && echo -e "What are you going to do?
	
  ${Green_font_prefix}1.${Font_color_suffix} Note BBR
  ${Green_font_prefix}2.${Font_color_suffix} Placement ServerSpeeder
  ${Green_font_prefix}3. ${Font_color_suffix} Configure LotServer (Ruisu parent company)
  ${Tip} Ruisu/LotServer/BBR does not support OpenVZ!
  ${Tip} Rushspeed and LotServer cannot coexist!
————————————
  ${Green_font_prefix}4.${Font_color_suffix} one-click ban BT/PT/SPAM (iptables)
  ${Green_font_prefix}5.${Font_color_suffix} Unblock BT/PT/SPAM (iptables) with one click
————————————
  ${Green_font_prefix}6. ${Font_color_suffix} switch ShadowsocksR log output mode
  —— Note: SSR only outputs error logs by default, and this item can be switched to output detailed access logs.
  ${Green_font_prefix}7.${Font_color_suffix} Monitor the running status of ShadowsocksR server
  —— Description: This function is suitable for the SSR server to end the process frequently. After starting this function, it will detect once every minute. When the process does not exist, the SSR server will be automatically started. " && echo
	read -e -p "(default: cancel):" other_num
	[[ -z "${other_num}" ]] && echo "Cancelled..." && exit 1
	if [[ ${other_num} == "1" ]]; then
		Configure_BBR
	elif [[ ${other_num} == "2" ]]; then
		Configure_Server_Speeder
	elif [[ ${other_num} == "3" ]]; then
		Configure_LotServer
	elif [[ ${other_num} == "4" ]]; then
		BanBTPTSPAM
	elif [[ ${other_num} == "5" ]]; then
		UnBanBTPTSPAM
	elif [[ ${other_num} == "6" ]]; then
		Set_config_connect_verbose_info
	elif [[ ${other_num} == "7" ]]; then
		Set_crontab_monitor_ssr
	else
		echo -e "${Error} Please enter the correct number [1-7]" && exit 1
	fi
}
# Ban BT PT SPAM
BanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh banall
	rm -rf ban_iptables.sh
}
# Unblock BT PT SPAM
UnBanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh unbanall
	rm -rf ban_iptables.sh
}
Set_config_connect_verbose_info(){
	SSR_installation_status
	[[ ! -e ${jq_file} ]] && echo -e "${Error} JQ parser does not exist, please check!" && exit 1
	connect_verbose_info=`${jq_file} '.connect_verbose_info' ${config_user_file}`
	if [[ ${connect_verbose_info} = "0" ]]; then
		echo && echo -e "Current log mode: ${Green_font_prefix} simple mode (only output error log) ${Font_color_suffix}" && echo
		echo -e "Are you sure you want to switch to ${Green_font_prefix} verbose mode (output detailed connection log + error log) ${Font_color_suffix}? [y/N]"
		read -e -p "(default: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="1"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "Cancelled..." && echo
		fi
	else
		echo && echo -e "Current log mode: ${Green_font_prefix} detailed mode (output detailed connection log + error log) ${Font_color_suffix}" && echo
		echo -e "Are you sure you want to switch to ${Green_font_prefix} simple mode (only error log output) ${Font_color_suffix}? [y/N]"
		read -e -p "(default: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="0"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "Cancelled..." && echo
		fi
	fi
}
Set_crontab_monitor_ssr(){
	SSR_installation_status
	crontab_monitor_ssr_status=$(crontab -l|grep "ssrmu.sh monitor")
	if [[ -z "${crontab_monitor_ssr_status}" ]]; then
		echo && echo -e "Current monitoring mode: $ {Green_font_prefix} is not enabled ${Font_color_suffix}" && echo
		echo -e "Are you sure you want to enable ${Green_font_prefix}ShadowsocksR server running status monitoring ${Font_color_suffix} function? (When the process is closed, the SSR server will be automatically started)[Y/n]"
		read -e -p "(default: y):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="y"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_start
		else
			echo && echo "Cancelled..." && echo
		fi
	else
		echo && echo -e "Current monitoring mode: ${Green_font_prefix} is enabled ${Font_color_suffix}" && echo
		echo -e "Are you sure you want to disable the function of ${Font_color_suffix} running status monitoring for the ${Green_font_prefix}ShadowsocksR server? (When the process is closed, the SSR server will be started automatically)[y/N]"
		read -e -p "(default: n):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="n"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_stop
		else
			echo && echo "Cancelled..." && echo
		fi
	fi
}
crontab_monitor_ssr(){
	SSR_installation_status
	check_pid
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Detected that the ShadowsocksR server is not running, and started to start... " | tee -a ${ssr_log_file}
		/etc/init.d/ssrmu start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR server failed to start..." | tee -a ${ssr_log_file} && exit 1
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR server started successfully..." | tee -a ${ssr_log_file} && exit 1
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR server process is running normally..." exit 0
	fi
}
crontab_monitor_ssr_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file/ssrmu.sh monitor" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} ShadowsocksR server running status monitoring function failed to start!" && exit 1
	else
		echo -e "${Info} ShadowsocksR server running status monitoring function started successfully!"
	fi
}
crontab_monitor_ssr_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} ShadowsocksR server running status monitoring function failed to stop!" && exit 1
	else
		echo -e "${Info} ShadowsocksR server running status monitoring function stopped successfully!"
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssrmu.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} cannot link to Github!" && exit 0
	if [[ -e "/etc/init.d/ssrmu" ]]; then
		rm -rf /etc/init.d/ssrmu
		Service_SSR
	fi
	cd "${file}"
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssrmu.sh" && chmod +x ssrmu.sh
	echo -e "The script has been updated to the latest version [ ${sh_new_ver} ]! (Note: Because the update method directly overwrites the currently running script, some errors may be prompted below, just ignore it)" && exit 0
}
# show menu status
menu_status(){
	if [[ -e ${ssr_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e "Current status: ${Green_font_prefix} installed ${Font_color_suffix} and ${Green_font_prefix} started ${Font_color_suffix}"
		else
			echo -e "Current status: ${Green_font_prefix} is installed ${Font_color_suffix} but ${Red_font_prefix} is not enabled ${Font_color_suffix}"
		fi
		cd "${ssr_folder}"
	else
		echo -e "Current status: ${Red_font_prefix} is not installed ${Font_color_suffix}"
	fi
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} This script does not support the current system ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
	echo -e " ShadowsocksR MuJSON one-click management script ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  ---- Toyo | doub.io/ss-jc60 ----

  ${Green_font_prefix}1.${Font_color_suffix} Install ShadowsocksR
  ${Green_font_prefix}2.${Font_color_suffix} Update ShadowsocksR
  ${Green_font_prefix}3.${Font_color_suffix} uninstall ShadowsocksR
  ${Green_font_prefix}4.${Font_color_suffix} Install libsodium(chacha20)
--------------
  ${Green_font_prefix}5.${Font_color_suffix} View account information
  ${Green_font_prefix}6.${Font_color_suffix} Show connection information
  ${Green_font_prefix}7.${Font_color_suffix} set user configuration
  ${Green_font_prefix}8.${Font_color_suffix} manually modify the configuration
  ${Green_font_prefix}9.${Font_color_suffix} configure traffic clearing
--------------
 ${Green_font_prefix}10.${Font_color_suffix} Start ShadowsocksR
 ${Green_font_prefix}11.${Font_color_suffix} Stop ShadowsocksR
 ${Green_font_prefix}12.${Font_color_suffix} Restart ShadowsocksR
 ${Green_font_prefix}13.${Font_color_suffix} View ShadowsocksR logs
--------------
 ${Green_font_prefix}14.${Font_color_suffix} Other functions
 ${Green_font_prefix}15.${Font_color_suffix} Upgrade script
 "
	menu_status
	echo && read -e -p "Please enter the number [1-15]:" num
case "$num" in
	1)
	Install_SSR
	;;
	2)
	Update_SSR
	;;
	3)
	Uninstall_SSR
	;;
	4)
	Install_Libsodium
	;;
	5)
	View_User
	;;
	6)
	View_user_connection_info
	;;
	7)
	Modify_Config
	;;
	8)
	Manually_Modify_Config
	;;
	9)
	Clear_transfer
	;;
	10)
	Start_SSR
	;;
	11)
	Stop_SSR
	;;
	12)
	Restart_SSR
	;;
	13)
	View_Log
	;;
	14)
	Other_functions
	;;
	15)
	Update_Shell
	;;
	*)
	echo -e "${Error} Please enter the correct number [1-15]"
	;;
esac
fi
