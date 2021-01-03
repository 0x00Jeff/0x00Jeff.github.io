---
layout: post
title: tryhackme wonderland write up
---


![picture](https://miro.medium.com/max/700/1*b5daOFm9rHuSrIzmwvSP7w.jpeg)

### about the machine
this is a mediumm rated machine from wonderland series, which happens to be the first series I try to get root on

### Reconnaissance

first thing I did is adding the box's ip to my hosts file
```
echo "10.10.114.141 ctf.thm" | sudo tee -a /etc/hosts
```

using nmap shows 2 running services on the machine, http and ssh. usally when I find an authentication service running on these types of CTFs I usualy run nmap with bruteforce nse scripts in the background to get the root password, or as soon as I get a potentiel user, sometimes it works

running a full ports scan with nmap doesn't give any interesting results

```
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

### http service enumeation

we have a static page without any usefull information, or so I thought, because as it will turn out later, it has the first flag

the next thing I did was running a directory-bruteforce which revealed the following 3 directories
# insert gobuster picturew
/img didn't had anything useful for us

/poem had the following poem written on it, as useful as /img was

and the /r directory had a quote on it that encouraged me to keep searching for subdirectories
# insert /r picture on the browser

the name 'r' seemed a bit strange to me since it was a one-letter directory, so to make the bruteforce process quicker I made a wordlist that contains only single letters and digits and used it to bruteforce other directories under `ctf.thm` and subdirectories under `ctf.thm/r/` and it worked

# insert r/a/ picture on the browser
at this point I knew there was a r/a/b/b/i/t path, and with each letter I got a static pages telling me I was on the right path
# insert all r/a/b/b/i/t/

till I got the last page, which had a picture of a girl (alice) trying to unlock a hidden door, checking the source code the that last page, I found what appeared to be the ssh credentiels for the user alice on the box

### I'm in
