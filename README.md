نصب شادوساکس آر انگلیسی

# ShadowsocksR-English   Telegram: https://t.me/iCNii

install ShadowsocksR English @iCNii

wget -N --no-check-certificate https://raw.githubusercontent.com/Tehranii/ShadowsocksR-English/main/ssrmu.sh && chmod +x ssrmu.sh && ./ssrmu.sh


نصب بی بی آر افزایش سرعت سرور و کاهش تاخیر 
install BBR

$ nano /etc/sysctl.conf

net.ipv4.ip_forward=1

net.core.default_qdisc=fq

net.ipv4.tcp_congestion_control=bbr

تست نصب بی بی ار

$ sysctl --system

ران کردن اسکریپت موقع ریبوت کردن و کرش کردن سرور
$ sudo nano /etc/rc.local

#! /bin/bash
path/to/ssrmu.sh
exit 0

$ sudo chmod +x /etc/rc.local


