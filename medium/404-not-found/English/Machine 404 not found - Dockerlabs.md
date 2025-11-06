![Screenshot](/medium/404-not-found/images/machine.png)

Difficulty: **medium**

Made by: **dise0**

# Steps to pwn 🥽

* 👁️‍🗨️ [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---


Once the machine is up, I make sure the machine is really active.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/404-not-found]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.178 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.131 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.131 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2048ms
rtt min/avg/max/mdev = 0.131/0.146/0.178/0.022 ms

```

---

# Reconnaissance

Okay now, im going to make a nmap scan to see what ports are open.

 ```
 ┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/404-not-found]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-01 19:43 -05
Initiating ARP Ping Scan at 19:43
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 19:43, 0.14s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 19:43
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 19:43, 2.80s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2025-11-01 19:43:06 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.24 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
 ```

I see here 2 ports open, the port 22 (ssh) and the port 80 (http), Im going to make another nmap scan to know more in detail about these ports.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/404-not-found]
└─$ nmap -p22,80 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-01 19:46 -05
Nmap scan report for hidden.lab (172.17.0.2)
Host is up (0.000086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 59:4e:10:e2:31:bf:13:43:c9:69:9e:4f:3f:a2:95:a6 (ECDSA)
|_  256 fb:dc:ca:6e:f5:d6:5a:41:25:2b:b2:21:f1:71:16:6c (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://404-not-found.hl/
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.96 seconds
```

We see in the port 80 that it redirects to http://404-not-found.hl, then im going to edit the file **/etc/hosts**. We are going to make sure the content of the file will have this:

```
172.17.0.2      404-not-found.hl
```

Once done this, I want to scan what technologies use this website.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/404-not-found]
└─$ whatweb http://404-not-found.hl
http://404-not-found.hl/ [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[404-Not-Found CTF]
```

It seems this website use apache, and nothing more interesting, I am going to see what is on the browser.

---

# Enumeration

![Screenshot](/medium/404-not-found/images/image1.png)
We see this on the website so im going to see more on detail what's inside of this.

First of all, I do some enumeration on the website, but we see nothing interesting, only the button that it says **Participate Now!** then I click on it, and we this:

![Screenshot](/medium/404-not-found/images/image2.png)

We see here a **secret key**, it seems that is encoded in base64, im going to decode it to see what is inside.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/404-not-found]
└─$ echo "UXVlIGhhY2VzPywgbWlyYSBlbiBsYSBVUkwu" | base64 -d
Que haces?, mira en la URL. 
```

Translated it says **"What are you doing? Look in the URL"** basically this a some kind of hint. But nothing more, anything else in the content of the website is useless.

Im going to do some **fuzzing**, to see some possibly subdomains that are on the website.

![Screenshot](/medium/404-not-found/images/image3.png)

We see a result of **"info"** this a good sign, we make sure this is on the file of **/etc/hosts** 

```
172.17.0.2      404-not-found.hl info.404-not-found.hl
```

Once saved this, we go again to the browser to see again the website.

![Screenshot](/medium/404-not-found/images/image4.png)

---

# Exploitation

We see a login page here. I try to do some sql injections, but it seems it doesn't work, so I see the content of the website and we can see this at the end of the content:

```
<!-- I believe this login works with LDAP -->
```

This a hint, it seems this page is vulnerable to LDAP injections, so im going to try it with this on the username field:

* )(username= * ))(|(password= *

And in the password field you can type anything.

The injection was successful, we can see this now:

![Screenshot](/medium/404-not-found/images/image5.png)

We see an admin panel here, and also we got some credentials that is:

* User = 404-page
* Password = not-found-page-secret

We can try it this credentials through ssh, the login is successful.

![Screenshot](/medium/404-not-found/images/image6.png)

Once inside I do **"sudo -l"**  command, and we can see this:

```
404-page@e222738f4121:~$ sudo -l
Matching Defaults entries for 404-page on e222738f4121:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User 404-page may run the following commands on e222738f4121:
    (200-ok : 200-ok) /home/404-page/calculator.py
```

We can see this python file, but it has nothing interesting on it, we don't have permissions to read, write, or to execute.

```
404-page@e222738f4121:~$ ls -l
total 4
-rwx--x--x 1 200-ok 200-ok 784 Aug 19  2024 calculator.py
```

After looking a long time, I try to search on the **/var/www/** directory where is the content of the website.

Once here, we can see this:

```
404-page@e222738f4121:/var/www$ ls
404-not-found  html  info  nota.txt
```


We see here a file called **"nota.txt"** translated is: **"note.txt"** so im going to take a look what is inside.

```
404-page@e222738f4121:/var/www$ cat nota.txt 

In the calculator I don't know what the symbol is used for "!" followed by something else, only 200-ok knows.
```

Another hint, for now this not help to much.

---

# Privilege Escalation

Im going to take a look what it's on inside of the login page. The content is on the **/info/** directory.

```
404-page@e222738f4121:/var/www/info$ ls
admin_panel_very_secret_impossibol.html  fail.html  index.html  login.php
```

We can see a php file, it seems that is the login. Let's going to take a look.

```
404-page@e222738f4121:/var/www/info$ cat login.php 
<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Vulnerable to LDAP injection (simulación)
    $ldap_query = "(&(uid=$username)(password=$password))";

    // Simulación de una autenticación LDAP correcta
    if ($username == "admin" && $password == "supersecurepassword") {
        header("Location: admin_panel_very_secret_impossibol.html");
        exit();
    } 
    // Simulación de bypass LDAP exitoso
    else if (strpos($ldap_query, "(&") !== false && strpos($ldap_query, ")(|") !== false) {
        header("Location: admin_panel_very_secret_impossibol.html");
        exit();
    } 
    // Credenciales incorrectas
    else {
        header("Location: fail.html");
        exit();
    }
} else {
    echo "<h2>Acceso no permitido.</h2>";
}
?>

```

We can see a password in this file.

* supersecurepassword

I can try this password to the user **200-ok** and the password works on this user.

```
404-page@e222738f4121:/var/www/info$ su 200-ok
Password:
200-ok@e222738f4121:/var/www/info$
```

Then we can go to the home directory of the user 200-ok, and we can see this:

```
200-ok@e222738f4121:~$ ls
boss.txt  user.txt
```

We can see the user flag, but another interesting file, let's take a look.

```
200-ok@e222738f4121:~$ cat boss.txt 

What is rooteable
```

Somehow, I try **rooteable** on the password of the user root, and it works lol.

![Screenshot](/medium/404-not-found/images/image7.png)

We got the flag of root. ***...Pwned!...***
