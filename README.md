# ShadowsocksR-English

install ShadowsocksR English

wget -N --no-check-certificate https://github.com/Tehranii/ShadowsocksR-English/blob/main/ssrmu.sh && chmod +x ssrmu.sh && ./ssrmu.sh

install BBR

$ nano /etc/sysctl.conf

net.ipv4.ip_forward=1

net.core.default_qdisc=fq

net.ipv4.tcp_congestion_control=bbr

$ sysctl --system
