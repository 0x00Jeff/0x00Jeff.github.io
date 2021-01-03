---
layout: post
title: tryhackme wonderland write up
---


![wonderland](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/wonder/wonderland.jpeg)

### about the machine
this is a medium rated machine from wonderland series, which happens to be the first series I try to get root on

### Reconnaissance

first thing I did is adding the box's ip to my hosts file
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


### http service enumeation

we have a static page without any usefull information, or so I thought, because as it will turn out later, it has the first flag
![index_page](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/wonder/index_page.png)

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

![r_directory](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/wonder/r_directory.png)

the name 'r' seemed a bit strange to me since it was a one-letter directory, so to make the bruteforce process quicker I made a wordlist that contains only single letters and used it to bruteforce other directories under `ctf.thm` and subdirectories under `ctf.thm/r/` and it worked

```bash
$ for i in {a..z}; do echo $i >> word; done
$ for i in {A..Z}; do echo $i >> word; done
$ gobuster dir -u http://10.10.114.141/r/ -w word
/a (Status: 301)
```
at this point I knew there was a `ctf.thm/r/a/b/b/i/t` path, and with each letter I got a static pages telling me I was on the right path with no additional info, except for the last page which had a picture hinting there is something hidden in there

![hidden creds](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/wonder/something_hidden.png)

examining the source code showed what appeared to be the ssh credentiels for the user `alice`

![ssh creds](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/master/assets/thm/wonder/creds.png)

### I'm in
