

# ShadowsocksR-English   Telegram: https://t.me/iCNii ✌✌ 
نصب شادوساکس آر انگلیسی

install ShadowsocksR English @iCNii


<pre>wget -N --no-check-certificate https://raw.githubusercontent.com/Tehranii/ShadowsocksR-English/main/ssrmu.sh && chmod +x ssrmu.sh && ./ssrmu.sh <span class="pl-k"></span></pre>

<p><img alt="" src="https://raw.githubusercontent.com/Tehranii/ShadowsocksR-English/main/shadowsocksR.png" /></p>

نصب بی بی آر افزایش سرعت سرور و کاهش تاخیر 
install BBR

<pre class="notranslate"><code>
$ nano /etc/sysctl.conf
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
</code></pre>

تست نصب بی بی ار

<pre class="notranslate"><code>$ sysctl --system</code></pre>

ران کردن اسکریپت موقع ریبوت کردن و کرش کردن سرور
<pre class="notranslate"><code>
$ sudo nano /etc/rc.local
#! /bin/bash
path/to/ssrmu.sh
exit 0
$ sudo chmod +x /etc/rc.local
</code></pre>

نصب با زدن دستور زیر و عدد 1

<pre class="notranslate"><code>./ssrmu.sh</code></pre>
