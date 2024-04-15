---
title: HackTheBox - Codify write up
date: 2023-11-28 22:19:00 +0100
categories: [HackTheBox]
tags: [HackTheBox, Node.js, vm2, sqlite]
render_with_liquid: false
---

# Codify

# recon

I ran a simple `nmap` scan to find out port 22, 80 and 3000 are running on the machine

```jsx
$ nmap 10.10.11.239
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-28 13:40 +01
Nmap scan report for 10.10.11.239
Host is up (0.25s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 3.44 seconds
```

upon sending a request to port 80 and examining the response headers, we can see that the `vhost` of this machine is `codify.htb`

```jsx
$ curl -v 10.10.11.239
*   Trying 10.10.11.239:80...
* Connected to 10.10.11.239 (10.10.11.239) port 80
> GET / HTTP/1.1
> Host: 10.10.11.239
> User-Agent: curl/8.3.0
> Accept: */*
> 
< HTTP/1.1 301 Moved Permanently
< Date: Tue, 28 Nov 2023 12:38:37 GMT
< Server: Apache/2.4.52 (Ubuntu)
< Location: http://codify.htb/
< Content-Length: 304
< Content-Type: text/html; charset=iso-8859-1
< 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://codify.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at 10.10.11.239 Port 80</address>
</body></html>
* Connection #0 to host 10.10.11.239 left intact
```

I added that to `/etc/hosts` and ran `nmap` again to get more a more detailed scan about the open ports

```jsx
$ nmap -v -oN ports -v 10.10.11.219
# Nmap 7.94 scan initiated Sat Jul  8 20:01:58 2023 as: nmap -v -oN ports -v 10.10.11.219
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up, received echo-reply ttl 63 (0.12s latency).
Scanned at 2023-07-08 20:01:58 +01 for 2s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Jul  8 20:02:00 2023 -- 1 IP address (1 host up) scanned in 2.03 seconds
```

then ran a full scan on them to have an idea of what I’m dealing with

```bash
$ nmap -sC -sV -A codify.htb -p 22,80,3000 -oN detailed_scan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-28 13:44 +01
Nmap scan report for codify.htb (10.10.11.239)
Host is up (0.13s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Codify
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   122.83 ms 10.10.14.1
2   123.48 ms codify.htb (10.10.11.239)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.43 seconds
```

