

# ShadowsocksR-English   Telegram: https://t.me/iCNii ✌✌ 
نصب شادوساکس آر انگلیسی

install ShadowsocksR English @iCNii

آپدیت و آپگرید سرور
<pre class="notranslate"><code>sudo -- sh -c 'apt-get update; apt-get upgrade -y; apt-get full-upgrade -y; apt-get autoremove -y; apt-get autoclean -y' </code></pre>

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

لینک دانلود برنامه
Download Link


<a href="/ShadowsocksR-Live/ssrWin/releases/download/0.8.6/ssr-win-x64.zip" rel="nofollow" data-turbo="false" data-view-component="true" class="Truncate">
    <span data-view-component="true" class="Truncate-text text-bold">ssr-win-x64.zip</span>
    <span data-view-component="true" class="Truncate-text"></span>
</a>
<div>
<a href="/ShadowsocksR-Live/ssrWin/releases/download/0.8.6/ssr-win-x86.zip" rel="nofollow" data-turbo="false" data-view-component="true" class="Truncate">
    <span data-view-component="true" class="Truncate-text text-bold">ssr-win-x86.zip</span>
    <span data-view-component="true" class="Truncate-text"></span>
</a>
<div>
<a href="/HMBSbige/ShadowsocksR-Android/releases/download/3.8.2/shadowsocksr-android-3.8.2.apk" rel="nofollow" data-turbo="false" data-view-component="true" class="Truncate">
    <span data-view-component="true" class="Truncate-text text-bold">shadowsocksr-android.apk</span>
    <span data-view-component="true" class="Truncate-text"></span>
</a>
