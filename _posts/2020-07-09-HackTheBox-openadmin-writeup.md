---
title: HackTheBox - Openadmin write up
date: 2020-07-09 22:19:00 +0100
categories: [TryHackMe]
tags: [HackTheBox, Ona, OpenNetAdmin]
render_with_liquid: false
---

![insert the box picture](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/pic.jpg)


recently, hackthebox started an event called `take it easy`, where it made a bunch of retired easy machine accessible to everyone, so here's my write up for the first box I've rooted in the event

# Reconnaissance

I first added the machine in my hosts file as `openadmin.htb` then ran a regular nmap scan to get the open ports

```bash
$ sudo nmap openadmin.htb -v -oN ports
# Nmap 7.91 scan initiated Fri Jul  9 02:07:40 2021 as: nmap -v -oN ports openadmin.htb
Increasing send delay for 10.10.10.171 from 0 to 5 due to 42 out of 140 dropped probes since last increase.
Increasing send delay for 10.10.10.171 from 5 to 10 due to 213 out of 709 dropped probes since last increase.
Nmap scan report for openadmin.htb (10.10.10.171)
Host is up (0.099s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
# Nmap done at Fri Jul  9 02:08:00 2021 -- 1 IP address (1 host up) scanned in 20.27 seconds
```

then a detailed scan against the 2 found services

```bash
$ nmap -v -sC -sV -p 80,22 -oN detailed_scan openadmin.htb
# Nmap 7.91 scan initiated Fri Jul  9 02:11:41 2021 as: nmap -v -sC -sV -p 80,22 -oN detailed_scan openadmin.htb
Nmap scan report for openadmin.htb (10.10.10.171)
Host is up (0.100s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul  9 02:11:54 2021 -- 1 IP address (1 host up) scanned in 13.16 seconds
```

# http enumeration

![default appache page](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/default_index.png)

the box was serving a default apache index with no `robots.txt` whatsoever, so I've run some bruteforces to find hidden files/directories and I end up with the following results

```bash
[18:31:22] 301 -  314B  - /music  ->  http://openadmin.htb/music/

[18:44:12] 200 -    4KB - /ona/login.php
[18:44:13] 200 -  127B  - /ona/logout.php
[18:44:15] 200 -   24KB - /ona/index.php
[18:45:57] 200 -    2B  - /ona/shell.php

[18:31:28] 301 -  316B  - /artwork  ->  http://openadmin.htb/artwork/
[18:53:42] 200 -    9KB - /artwork/contact.html
[18:53:46] 200 -   11KB - /artwork/about.html
[18:53:48] 200 -  931B  - /artwork/main.html
[18:53:49] 200 -   11KB - /artwork/blog.html
[18:53:52] 200 -   11KB - /artwork/services.html
[18:53:53] 200 -  410B  - /artwork/readme.txt

[19:00:10] 301 -  315B  - /sierra  ->  http://openadmin.htb/sierra/
[19:05:49] 200 -   42KB - /sierra/index.html
[19:05:51] 200 -   15KB - /sierra/contact.html
[19:06:07] 200 -   20KB - /sierra/blog.html
[19:06:08] 200 -   20KB - /sierra/about-us.html
[19:06:26] 200 -   22KB - /sierra/service.html
[19:06:31] 200 -   13KB - /sierra/portfolio.html
[19:07:46] 200 -    0B  - /sierra/contact_process.php
````

when you browse to `/music/login.php` you get directed to `/ona` which had the following page

![insert ona.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/ona.png)

this page disclose a bunch of info, first the domain `openadmin.htb` which we've already guessed, a mysql service running on localhost with the user `ona_sys`, and that we're running on version v18.1.1  <b>which is not the latest version</b>, and a download link which revealed that the website us running an IP address management system called OpenNetAdmin

![the IP address management system](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/openNetAdmin.png)

luckily for us this version had a vulnerability that led to remote code excution

![openNetAdmin remote code excution](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/rce.png)

now I just used the exploit in [this repo](https://github.com/amriunix/ona-rce) to get a reverse shell

![getting a reverse shell](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/rev_shell.png)

# www-data

after getting in on the box I found some creds in `/opt/ona/www/local/config/database_settings.inc.php`

![database password](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/db_creds.png)

I've also found 2 users on the box, and the database password turned out to be re-used as jimmy's

![other users](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/users.png)

# jimmy

I've logged in trough ssh to get a nicer shell, then found an internal http server running on port 52846, hosted on `/var/www/internal/`

![internal http server](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/internal.png)

basically `index.php` checks if the password is `jimmy` the the sha512 hash is equal to the hash shown in the picture, which is sha512 for the word "Revealed"

![internal appache index.php](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/internal_index.png)

if this checks out it redirects the user to `main.php` which shows joanna's private ssh key

![internal appache main.php](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/internal_main.png)

I just called `main.php` directly with curl and got the key

![joanna ssh private key](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/joanna_ssh_key.png)

I cracked the ssh key with john and rockyou.txt, and logged in

![cracking joanna ssh keys](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/cracked_joanna_key.png)

# joanna

once I'm was in, I found that I can edit a file with sudo privileges

![sudo -l](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/sudo_l.png)

I always have a custom `/etc/passwd` entry generated with `mkpasswd -m sha-512 PASSWORD -s SALT` for situations like this, all I have to do is to put it in there

I just pressed CTRL-L to load the content of `/etc/passwd`, put my entry as the user jeff and gave it a uid of 0, so I can have the same privileges as the root user, the file the file looked like this in the end

![making a custom /etc/passwd entry](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/custom_passwd_entry.png)

then I just overwrote /etc/passwd with the new cotent and logged in as jeff :)

![logging in as jeff](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/htb/open_admin/ma_nama_jeff.png)



