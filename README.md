

# ShadowsocksR-English   Telegram: https://t.me/iCNii ✌✌ 
نصب شادوساکس آر انگلیسی

install ShadowsocksR English @iCNii


<pre>wget -N --no-check-certificate https://raw.githubusercontent.com/Tehranii/ShadowsocksR-English/main/ssrmu.sh && chmod +x ssrmu.sh && ./ssrmu.sh <span class="pl-k"></span></pre>

<p><img alt="" src="https://raw.githubusercontent.com/Tehranii/ShadowsocksR-English/main/shadowsocksR.png" /></p>

نصب بی بی آر افزایش سرعت سرور و کاهش تاخیر 
install BBR
<pre>
$ nano /etc/sysctl.conf

net.ipv4.ip_forward=1

net.core.default_qdisc=fq

net.ipv4.tcp_congestion_control=bbr
<span class="pl-k"></span></pre>
تست نصب بی بی ار

<pre>$ sysctl --system<span class="pl-k"></span></pre>

ران کردن اسکریپت موقع ریبوت کردن و کرش کردن سرور
<pre>
$ sudo nano /etc/rc.local
#! /bin/bash
path/to/ssrmu.sh
exit 0
$ sudo chmod +x /etc/rc.local
<span class="pl-k"></span></pre>

نصب با زدن دستور زیر و عدد 1

<pre>./ssrmu.sh<span class="pl-k"></span></pre>
