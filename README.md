

# ShadowsocksR-English   Telegram: https://t.me/iCNii ✌ 
<h2 dir="auto">نصب اسکریپت شادوساکس آر انگلیسی</h2>

<h2 dir="auto">install scripts ShadowsocksR English @iCNii</h2>

<h2 dir="auto">دستور آپدیت و آپگرید سرور</h2>
<pre class="notranslate"><code>sudo -- sh -c 'apt-get update; apt-get upgrade -y; apt-get full-upgrade -y; apt-get autoremove -y; apt-get autoclean -y' </code></pre>
<h2 dir="auto">دستور نصب اسکریپت شادوساکس آر</h2>
<pre>wget -N --no-check-certificate https://raw.githubusercontent.com/Tehranii/ShadowsocksR-English/main/ssrmu.sh && chmod +x ssrmu.sh && ./ssrmu.sh <span class="pl-k"></span></pre>

<p><img alt="" src="https://raw.githubusercontent.com/Tehranii/github/main/shadowsocksR.png?token=GHSAT0AAAAAAB7XAM7NT4MEOARSZSDERITMZAHUUAA" /></p>

<h2 dir="auto">نصب بی بی آر افزایش سرعت سرور و کاهش تاخیر</h2> 
install BBR

<pre class="notranslate"><code>
$ nano /etc/sysctl.conf
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
</code></pre>

<h2 dir="auto">تست نصب بی بی ار</h2>

<pre class="notranslate"><code>$ sysctl --system</code></pre>

<h2 dir="auto">ران کردن اسکریپت موقع ریبوت کردن و کرش کردن سرور</h2>
<pre class="notranslate"><code>
$ sudo nano /etc/rc.local
#! /bin/bash
path/to/ssrmu.sh
exit 0
$ sudo chmod +x /etc/rc.local
</code></pre>

<h2 dir="auto">نصب با زدن دستور زیر و عدد 1</h2>

<pre class="notranslate"><code>./ssrmu.sh</code></pre>

<h2 dir="auto">لینک دانلود برنامه
Download Link
</h2>

<pre class="notranslate"><code>
<a href="https://github.com//ShadowsocksR-Live/ssrWin/releases/download/0.8.6/ssr-win-x64.zip" rel="nofollow" data-turbo="false" data-view-component="true" class="Truncate">
    <span data-view-component="true" class="Truncate-text text-bold">ssr-win-x64.zip</span>
<a href="https://github.com//ShadowsocksR-Live/ssrWin/releases/download/0.8.6/ssr-win-x86.zip" rel="nofollow" data-turbo="false" data-view-component="true" class="Truncate">
    <span data-view-component="true" class="Truncate-text text-bold">ssr-win-x86.zip</span>
<a href="https://github.com/HMBSbige/ShadowsocksR-Android/releases/download/3.8.2/shadowsocksr-android-3.8.2.apk" rel="nofollow" data-turbo="false" data-view-component="true" class="Truncate">
    <span data-view-component="true" class="Truncate-text text-bold">ssr-android.apk</span>
<a href="https://apps.apple.com/us/app/potatso/id1239860606" rel="nofollow" data-turbo="false" data-view-component="true" class="Truncate">
    <span data-view-component="true" class="Truncate-text text-bold">ssr-iphone.ios</span>
</a>
</code></pre>
