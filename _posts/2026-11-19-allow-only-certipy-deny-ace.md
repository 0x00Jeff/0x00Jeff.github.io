---
title: "Allow-Only: how a Deny ACE turns into a false positive in certipy"
categories: [Notes, ADCS]
tags: [research, ADCS, certipy, ACE, DACL, Deny]
render_with_liquid: false
---

## intro

same series as before: exploring AD/ADCS edge cases while breaking and fixing public tooling along the way. the [last certipy post](https://0x00jeff.github.io/posts/noisy-but-blind-certipy-ca-enumeration/) was about the CA-side registry read going blind. this one stays inside certipy's `find` command but moves to a different surface: how it reads the **ACLs** it leans on to decide **ESC4**, **ESC7** and **ESC13**.

the bug is simple: **certipy ignores `Deny` ACEs.** windows treats an explicit Deny as beating an Allow, but certipy only reads the Allow side, so it can flag an account that is actually locked out. the same parsing feeds ESC4, ESC7 and ESC13, so the one blind spot shows up in all three, and you can trip it by accident, no attacker needed, through ordinary nested group grants.

(there was a second parser bug i found alongside this one. it looked like a footnote at first, then turned into something a lot more interesting: a quirk in how ACEs get written and read back that lets you leave a `WriteDacl` backdoor LDAP scanners never report, so i'm saving it for its own future post.)

these are the kind of quiet parser mistakes that make you trust a clean scan a little less, which is exactly what this series is about.

## background: how certipy decides these

a certificate template is an AD object living under `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,...`. who can modify it is controlled by its `nTSecurityDescriptor`, and the part that matters is the `DACL`, an ordered list of `ACE`s. every ACE names a SID, says allow or deny, and carries a set of rights.

ESC4 is the case where a low-priv principal can tamper with a template and flip it into something like ESC1. so certipy walks the DACL and, for the account it's running as plus every group that account belongs to, checks whether they hold a dangerous right over the template. the exact same shape backs **ESC13** (the ACL on an issuance-policy OID object) and **ESC7** (the `Manage CA` / `Manage Certificates` rights on the CA's own security descriptor). different objects, same idea: parse a security descriptor into a per-SID rights map, then check that map for dangerous rights.

two details from the ESC4 path make it concrete. certipy doesn't only look at your own SID, it collects every SID you effectively are:

```python
# certipy/commands/find.py
user_sids = self.connection.get_user_sids(self.target.username, self.sid, self.dn)
...
for sid, rights in security.aces.items():
    if sid not in user_sids:   # is this ACE about me, or a group i'm in?
        continue
```

and the rights it counts as dangerous for ESC4:

```python
# certipy/commands/find.py
dangerous_rights = [
    CertificateRights.GENERIC_ALL,
    CertificateRights.WRITE_OWNER,
    CertificateRights.WRITE_DACL,
    CertificateRights.GENERIC_WRITE,
]
```

the rights map those checks read is built one layer below, in the parser that turns a raw DACL into the per-SID `rights` map. for templates and OIDs that's `ActiveDirectorySecurity._parse_aces()` in `certipy/lib/security.py`; the CA keeps its own copy, `CASecurity._parse_aces()`, over the descriptor it pulls from the CA by RPC. the bug lives in that layer, and both parsers have it.

## the bug: deny aces are ignored

the template/OID parser loop, trimmed down:

```python
# certipy/lib/security.py
def _parse_aces(self) -> None:
    aces = self.sd["Dacl"]["Data"]

    # TODO: Handle DENIED ACEs

    for ace in aces:
        ...
        if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
            ...
        elif ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and ...:
            ...
```

the loop only handles `ACCESS_ALLOWED_ACE` and `ACCESS_ALLOWED_OBJECT_ACE`. that `# TODO: Handle DENIED ACEs` was left for someone to come back and handle `ACCESS_DENIED_ACE` and `ACCESS_DENIED_OBJECT_ACE`, but it never happened. deny ACEs are skipped, in both parsers.

windows resolves this the opposite way: an explicit Deny beats an Allow. so a right windows has explicitly revoked still reads as granted.

### repro: esc7 in two lines

the cheapest way to see it needs no staging script at all, because certipy already ships the tool that writes CA ACEs. `certipy ca` takes `-ace-type deny`, so you can poison its own ESC7 view against itself in two lines: grant `Manage CA` to a throwaway user, then deny the same right back.

```bash
certipy ca -ca 'mylab-CA-SERVER-CA' -add-manager denytest -ace-type allow -u administrator@mylab.local -p "$PASSWORD" -target CA-SERVER.mylab.local
certipy ca -ca 'mylab-CA-SERVER-CA' -add-manager denytest -ace-type deny  -u administrator@mylab.local -p "$PASSWORD" -target CA-SERVER.mylab.local
```

net access denied, so `denytest` cannot touch the CA. now scan as `denytest`, not as an admin (an admin holds real rights everywhere and that noise buries the one you're testing):

```bash
certipy find -u denytest@mylab.local -p 'Passw0rd!' -dc-ip 192.168.69.69 -stdout
```

and the CA lights up:

```text
    CA Name                 : mylab-CA-SERVER-CA
    ...
    [!] Vulnerabilities
      ESC7                  : User has dangerous permissions.
```

certipy says `denytest` has `Manage CA`; windows says nothing. (`-add-officer` instead of `-add-manager` plants `Manage Certificates`, the other half of ESC7.)

### does this happen for real?

it does, and groups are the reason. certipy folds in every group you belong to, so the Allow and the Deny don't need your name on them at all. the common shape is "everyone in Helpdesk can manage this, except one contractor":

- Allow the right to `Helpdesk`
- Deny the right to `contractor`

when `contractor` runs certipy, both ACEs apply, one through the group and one direct. certipy reads the Allow, ignores the Deny, and flags an account that is specifically locked out. in a real forest with years of stacked, nested group grants, that is easy to end up with and impossible to eyeball.

### bonus: esc4 and esc13 too

ESC7 came from the CA parser. the template and OID parser (`ActiveDirectorySecurity`, with the `IssuancePolicySecurity` wrapper) has the same skip, so the same bug lands two more findings. i planted the pair for denytest on a template and on an issuance-policy OID, scanned as denytest, and both flagged:

| check | object | parser | right planted |
|---|---|---|---|
| ESC7  | CA security descriptor | `CASecurity`              | `ManageCA`, `ManageCertificates` |
| ESC4  | certificate template   | `ActiveDirectorySecurity` | `WriteDacl` |
| ESC13 | issuance-policy OID     | `IssuancePolicySecurity`  | `WriteDacl` |

the only difference is where the ACEs go. the full ESC4 staging script (clone a template, stack the two ACEs) is in the `<details>` below.

<details markdown="1">
<summary>full ESC4 staging script (PowerShell, run on a DC)</summary>

```powershell
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# 1. throwaway low-priv user
$pw = ConvertTo-SecureString 'Passw0rd!' -AsPlainText -Force
New-ADUser -Name denytest -SamAccountName denytest -AccountPassword $pw -Enabled $true
$usid = (Get-ADUser denytest).SID

# 2. clone the built-in "User" template into a new "DenyTest" template
$cont  = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
$tplDN = "CN=DenyTest,$cont"
$want  = @('flags','revision','pKIDefaultKeySpec','pKIKeyUsage','pKIMaxIssuingDepth',
          'pKICriticalExtensions','pKIExpirationPeriod','pKIOverlapPeriod','pKIExtendedKeyUsage',
          'pKIDefaultCSPs','msPKI-RA-Signature','msPKI-Enrollment-Flag','msPKI-Private-Key-Flag',
          'msPKI-Certificate-Name-Flag','msPKI-Minimal-Key-Size','msPKI-Template-Schema-Version',
          'msPKI-Template-Minor-Revision')
$src   = Get-ADObject -Identity "CN=User,$cont" -Properties $want
$attrs = @{}
foreach ($p in $want) { if ($null -ne $src.$p) { $attrs[$p] = $src.$p } }
$attrs['displayName']             = 'DenyTest'
$attrs['msPKI-Cert-Template-OID'] = '1.3.6.1.4.1.311.21.8.1.1.1.1.1.1.99999.1'
New-ADObject -Name DenyTest -Type pKICertificateTemplate -Path $cont -OtherAttributes $attrs

# 3. put BOTH an Allow and a Deny WriteDacl for denytest on the template
$obj = [ADSI]"LDAP://$tplDN"
$obj.ObjectSecurity.AddAccessRule(
  (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($usid,'WriteDacl','Allow')))
$obj.ObjectSecurity.AddAccessRule(
  (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($usid,'WriteDacl','Deny')))
$obj.CommitChanges()

# 4. show how windows actually stored them (deny first)
([ADSI]"LDAP://$tplDN").ObjectSecurity.GetAccessRules(
    $true, $false, [System.Security.Principal.SecurityIdentifier]) |
  Where-Object { $_.IdentityReference -eq $usid } |
  ForEach-Object { "{0} {1}" -f $_.AccessControlType, $_.ActiveDirectoryRights }
```

</details>

## the fix

i taught both parsers to keep a per-SID `denied_rights` mask instead of dropping `Deny`, and net it against the allowed rights. then in `find` i added a small `_denied_rights_union` helper that gathers the denies across every SID you hold, and each ESC check subtracts that before testing for dangerous rights, so a `Deny` on you beats an `Allow` handed to one of your groups.

i have not opened a PR upstream yet. the repo has been quiet for a while, so i am holding it and will send it later. until then the change sits on my fork if you want it now: [the commit](https://github.com/0x00Jeff/Certipy/commit/c110c2d5c16b61567348309dbaed72f831f67168), and a ready-to-apply [patch file](https://github.com/0x00Jeff/Certipy/commit/c110c2d5c16b61567348309dbaed72f831f67168.patch) you can drop straight into a checkout:

```bash
curl -sL https://github.com/0x00Jeff/Certipy/commit/c110c2d5c16b61567348309dbaed72f831f67168.patch | git apply
```

## wrap

certipy reads the Allow side of a DACL and skips the Deny, so a right windows has explicitly taken away still reads as granted. the same parsing sits behind ESC4, ESC7 and ESC13, so one habit misfires in three places, and nested group grants let you hit it with nothing planted at all.

same shape as the registry post: a scan that reads as authoritative while being wrong in one specific, repeatable way. the other parser bug i hit along the way, the object-ACE drop that turns into a backdoor LDAP scanners miss, is its own writeup, coming next.
