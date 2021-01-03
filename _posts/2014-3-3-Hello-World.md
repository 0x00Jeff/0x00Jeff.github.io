---
layout: post
title: tryhackme wonderland write up
---
# insert picture

### about the machine
this is a mediumm rated machine from wonderland series, which happens to be the first series I try to get root on

### Reconnaissance

first thing I did is adding the box's ip to my hosts file
# insert hosts pictures

using nmap shows 2 running services on the machine, http and ssh. usally when I find an authentication service running on these types of CTFs I usualy run nmap with bruteforce nse scripts in the background to get the root password, or as soon as I get a potentiel user, sometimes it works

running a full ports scan with nmap doesn't give any interesting results

# insert nmap picture

### http service enumeation

we have a static page withtout any usefull information, or so I thought, because as it will turn out later, it has the first flag

the next thing I did was running a directory-bruteforce which yields reveals the following 3 directories
# insert gobuster picture
/img didn't had anything useful for us

/poem had the following poem written on it, as useful as /img was

and the /r directory had a quote on it that encouraged me to keep searching for subdirectories
# insert /r picture on the browser

the name 'r' seemed a bit strange to me since it was a one-letter directory, so to make the bruteforce process quicker I made a wordlist that contains only single letters in the range \[a-z\]-\[A-Z\], and tested it against the index page and against the r/ directory, and it worked 

# insert r/a/ picture on the browser
at this point I knew there was a r/a/b/b/i/t path, and with each letter I got a static pages telling me I was on the right path
# insert all r/a/b/b/i/t/

till I got the last page, which had a picture of a girl (alice) trying to unlock a hidden door, checking the source code the that last page, I found what appeared to be the ssh credentiels for the user alice on the box

### I'm in
