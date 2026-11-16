---
title: "Noisy but Blind: One Missing Registry Value Breaks Certipy's CA Enumeration"
categories: [Notes, ADCS]
tags: [research, ADCS]
render_with_liquid: false
---

## intro

some context: i've been building a multi-forest AD lab and going deep on AD/ADCS security, reproducing every vuln i can find in every flavor documented online. along the way i keep hitting edge cases where the tooling breaks or quietly mishandles something. the [first one was an impacket bug](https://0x00jeff.github.io/posts/impacket-3-parts-spn-exception/), this one's in certipy. i actually hit this one right after the impacket bug, but life got busy and i only got around to finishing the write-up now.

the short version: a sysadmin deletes one registry value on an ADCS CA server, and certipy still connects to the CA, still starts the Remote Registry service, still makes all the noise of a "loud" scan, then silently throws the whole CA configuration away. the vulns that were there a second ago (ESC6, ESC7, ESC11) just vanish.

the twist: that value is the exact one you touch to remediate ESC16. so fixing one misconfiguration can quietly blind the scanner to three others, and the operator never opts into it. they pay for a loud scan and get the coverage of a quiet one.

and it's not a lab curiosity or a fresh regression. the unguarded read has shipped in every certipy release since `v5.0.0` (introduced in commit `21e0b2d`, May 2025, the rewrite that first added ESC16 support), it's still live on `main` today, and i hit it on the current `certipy-ad 5.1.0` from PyPI.

this is a light dive into certipy's source and how it pulls CA config over `RRP`, not an ESC tutorial, there are better write-ups for that.

## certipy's two scanning modes

the punchline is a tradeoff between certipy's two scan modes, so here they are.

- **full mode** (default): certipy queries `LDAP` on the DC for templates and CA objects, then reaches the CA host over `RRP` (Remote Registry Protocol) to read settings that only live in the CA's local registry (`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`) and never get published to AD: user-specified SANs (ESC6), `RPC` encryption enforcement (ESC11), stripped extensions (ESC16), the CA's security descriptor (ESC7). if Remote Registry isn't running, certipy starts it. loud, but it's the only way to catch the CA-side vulns, and those are usually a very quick win if they exist

- **dc-only mode** (`certipy find -dc-only`): skips the CA, talks only to the DC. quiet, but blind to every CA-side vuln. you pick it on purpose, for opsec or when the CA isn't reachable.

the mental model:

| mode | talks to CA? | noise | sees CA-side vulns (ESC6/7/11/16...) |
|---|---|---|---|
| full (default) | yes, over `RRP` | loud | yes |
| `-dc-only` | no | quiet | no |

the vulns that come from this registry read, and so the only ones this bug can hide, are **ESC6, ESC7, ESC11, ESC16**. everything else (ESC1-5, ESC8, ESC9, ESC13, ESC17, ...) comes from `LDAP` or web-enrollment probing and is unaffected.

this post is about a third row that shouldn't exist: **loud, and yet blind to the CA-side vulns.** full-mode noise with dc-only mode coverage

## the finding

I've configured my lab CA to be vulnerable to ESC6, ESC7, ESC8, ESC11 and ESC16, a normal scan catches them all. the healthy baseline:

```bash
$ certipy find -u ESC7_attacker@mylab.local -p $PASSWORD -dc-ip 192.168.69.69 -target CA-SERVER -stdout -hide-admins
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 43 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 19 enabled certificate templates
[*] Retrieving CA configuration for 'mylab-CA-SERVER-CA' via RRP
[*] Successfully retrieved CA configuration for 'mylab-CA-SERVER-CA'
...
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    ...
    [!] Vulnerabilities
      ESC6                              : Enrollee can specify SAN.
      ESC7                              : User has dangerous permissions.
      ESC8                              : Web Enrollment is enabled over HTTP and HTTPS, and Channel Binding is disabled.
      ESC11                             : Encryption is not enforced for ICPR (RPC) requests.
      ESC16                             : Security Extension is disabled.
```

note these two lines, they matter later:

```
[*] Retrieving CA configuration for 'mylab-CA-SERVER-CA' via RRP
[*] Successfully retrieved CA configuration for 'mylab-CA-SERVER-CA'
```

ESC16 exists when `DisableExtensionList` holds the OID `1.3.6.1.4.1.311.25.2` (`szOID_NTDS_CA_SECURITY_EXT`). there are two ways to remediate it that look identical but aren't:

1. **remove the OID, leave the list in place but empty.** the value still exists, it just holds zero entries.
2. **delete the list value entirely.** the value is gone.

a `REG_MULTI_SZ` with zero entries is still a value, so certipy reads it fine and gets an empty list. delete it outright and there's nothing to read. that difference is the whole bug.

so let's trigger it. i take remediation path 2 on the CA (delete the value outright), then run the exact same scan as the baseline above:

```bash
# delete the list
nxc smb CA-SERVER -u administrator -p $LAPS_PASSWORD --local-auth \
  -X 'certutil -delreg policy\DisableExtensionList; Restart-Service CertSvc -Force' --no-output

# scan again
$ certipy find -u ESC7_attacker@mylab.local -p $PASSWORD -dc-ip 192.168.69.69 -target CA-SERVER -stdout -hide-admins
...
[*] Retrieving CA configuration for 'mylab-CA-SERVER-CA' via RRP
[!] Failed to get CA configuration for 'mylab-CA-SERVER-CA' via RRP: RRP SessionError: code: 0x2 - ERROR_FILE_NOT_FOUND - The system cannot find the file specified.
[!] Use -debug to print a stacktrace
[!] Could not retrieve configuration for 'mylab-CA-SERVER-CA'
...
    User Specified SAN                  : Unknown
    Request Disposition                 : Unknown
    Enforce Encryption for Requests     : Unknown
    Active Policy                       : Unknown
    Disabled Extensions                 : Unknown
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP and HTTPS, and Channel Binding is disabled.
```

here's the subtle part. **ESC16 is supposed to be gone**, deleting `DisableExtensionList` *is* its remediation, so certipy is right to drop it. the problem is **ESC6, ESC7, and ESC11 went dark with it.** those are unrelated to what you just fixed, still fully present on the CA, and now invisible. every CA-config field reads `Unknown` and only ESC8 survives (it comes from web enrollment, not the registry read). and certipy still connected and still started Remote Registry before failing, so you made all the noise for nothing.

the same run with `-debug` points straight at the culprit:

```python
Traceback (most recent call last):
  File ".../certipy/commands/ca.py", line 731, in get_config
    result = self.get_config_rrp()
  File ".../certipy/commands/ca.py", line 646, in get_config_rrp
    _, disable_extension_list = rrp.hBaseRegQueryValue(
        self.rrp_dce, policy_key["phkResult"], "DisableExtensionList"
    )
  File ".../impacket/dcerpc/v5/rrp.py", line 908, in hBaseRegQueryValue
    resp = dce.request(request)
```

## root cause

### get_config returns None on any exception

when you run `find`, certipy calls `get_config` to connect and pull the CA config:

```python
def get_config(self) -> Optional["CAConfiguration"]:
    try:
        logging.info(f"Retrieving CA configuration for {self.ca!r} via RRP")
        result = self.get_config_rrp()
        logging.info(f"Successfully retrieved CA configuration for {self.ca!r}")
        return result
    except Exception as e:
        logging.warning(f"Failed to get CA configuration for {self.ca!r} via RRP: {e}")
        handle_error(True)
        logging.warning(f"Could not retrieve configuration for {self.ca!r}")
        return None
```

one try/except around the whole thing: any exception inside `get_config_rrp` returns `None`, no partial config. that's the load-bearing part.

### get_config_rrp reads a handful of registry values

`get_config_rrp` opens the machine hive over `RRP` and reads a set of values, all under `SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` (omitted below). `{ca}` is the CA name, `{active}` is the active policy module's name, itself read from the `Active` value (usually `CertificateAuthority_MicrosoftDefault.Policy`):

| key path | value | meaning |
|---|---|---|
| `{ca}\PolicyModules` | `Active` | active policy module name |
| `{ca}\PolicyModules\{active}` | `EditFlags` | request behavior (SAN flag lives here) |
| `{ca}\PolicyModules\{active}` | `RequestDisposition` | issue vs pending |
| `{ca}\PolicyModules\{active}` | `DisableExtensionList` | disabled extensions (ESC16) |
| `{ca}` | `InterfaceFlags` | interface behavior (RPC encryption, ESC11) |
| `{ca}` | `Security` | security descriptor (ESC7) |
| `{ca}` | `EnrollmentAgentRights` | enrollment-agent restrictions |

### the code already treats some values as optional

`EnrollmentAgentRights` is already treated as optional, wrapped in its own try/except so its absence is harmless:

```python
enrollment_agent_restrictions = None
try:
    _, ea_rights_bytes = rrp.hBaseRegQueryValue(
        self.rrp_dce, configuration_key["phkResult"], "EnrollmentAgentRights"
    )
    if isinstance(ea_rights_bytes, bytes) and ea_rights_bytes:
        enrollment_agent_restrictions = _parse_enrollment_agent_rights(ea_rights_bytes)
except Exception:
    pass
```

but `DisableExtensionList` gets no such guard:

```python
# Retrieve disabled extensions
_, disable_extension_list = rrp.hBaseRegQueryValue(
    self.rrp_dce, policy_key["phkResult"], "DisableExtensionList"
)
```

when it's absent, `hBaseRegQueryValue` raises `ERROR_FILE_NOT_FOUND`, which nothing catches, so it hits `get_config`'s one try/except and the whole config returns `None`. present-but-empty reads fine, absent nukes everything. the guard they wrote for `EnrollmentAgentRights` is exactly what's missing here.

## blast radius

`get_config_rrp` builds a `CAConfiguration` object and returns it:

```python
return CAConfiguration(
    active_policy, edit_flags, disable_extension_list,
    request_disposition, interface_flags,
    security_descriptor, enrollment_agent_restrictions,
)
```

when `get_config` returns `None`, every check that needs that object falls through to its default. in `find.py`, `_get_ca_config_and_web_enrollment` seeds everything to `"Unknown"`/`None`, and the branch that would overwrite them sits behind `if ca_configuration is not None:`, now never taken:

| config field | default when None | check that goes dark |
|---|---|---|
| `edit_flags` (SAN bit) | `user_specified_san = "Unknown"` | **ESC6** needs `== "Enabled"` |
| `security` (descriptor) | `security = None` | **ESC7** returns early on `security is None` |
| `interface_flags` (enc bit) | `enforce_encrypt_icertrequest = "Unknown"` | **ESC11** needs `== "Disabled"` |

the three checks in `get_ca_vulnerabilities`, none of which can fire now:

```python
# ESC6
if ca.get("user_specified_san") == "Enabled" and will_issue and user_can_enroll:
    vulnerabilities["ESC6"] = "Enrollee can specify SAN."

# ESC7  (ca_has_vulnerable_acl returns (False, []) when security is None)
has_vulnerable_acl, vulnerable_acl_sids = self.ca_has_vulnerable_acl(ca)

# ESC11
if ca.get("enforce_encrypt_icertrequest") == "Disabled" and will_issue:
    vulnerabilities["ESC11"] = "Encryption is not enforced for ICPR (RPC) requests."
```

one missing registry value, three dead checks.

## the thesis: dc-only blindness with full-mode noise

go back to the two-mode table. this bug adds the row that shouldn't be reachable:

| mode | talks to CA? | noise | sees CA-side vulns |
|---|---|---|---|
| full (default) | yes | loud | yes |
| `-dc-only` | no | quiet | no |
| full + deleted value | **yes** | **loud** | **no** |

certipy never drops into dc-only mode here, it does everything full mode does (resolves the CA, connects over `RRP`, starts Remote Registry), then discards the result. you get the coverage of dc-only and the footprint of full mode

the realistic path is accidental: an admin remediates ESC16 by deleting `DisableExtensionList` instead of emptying it, and from then on their scans quietly stop reporting ESC7 and ESC11. someone could also it deliberately to blind certipy, the misconfig is still there and still exploitable just now a certipy scan wouldn't show it, `certutil` shows it locally would still show it locally, that's one reason you have to rely on more than one tool, but you'd have to already have a shell inside for that

losing ESC11 isn't a big deal, `RPC` encryption is on by default. losing ESC7 is: a dangerous CA ACL (`DACL` abuse, or going after a principal with `ManageCA`/`ManageCertificates`) is a common, high-value path

## it's bigger than one value

`DisableExtensionList` isn't special, it's just the one a plausible remediation deletes. `Active`, `EditFlags`, `RequestDisposition`, `InterfaceFlags`, and `Security` are all read the same unguarded way, so any one of them missing zeroes out the whole config. i verified each in the lab: delete the value, run certipy, restore it.

| value deleted | deletable? | certipy result |
|---|---|---|
| `InterfaceFlags` | yes | `Failed to get CA configuration ... ERROR_FILE_NOT_FOUND` |
| `EditFlags` | yes | same |
| `RequestDisposition` | yes | same |
| `Active` | yes | same |
| `Security` | yes | same |

same result every time: the four CA-side vulns (ESC6, ESC7, ESC11, ESC16) vanish, everything else stays, all failing at that one `get_config` exception. `Security` has a nuance, certipy handles a missing descriptor gracefully (`ca_has_vulnerable_acl` returns `(False, [])` when `security is None`), but deleting the value never reaches that path: the *read* throws first and the whole object becomes `None`, so it takes ESC6, ESC11, and ESC16 down with ESC7.

### but would this happen in real life?

deleting a value and modifying one are different acts, and that's where `DisableExtensionList` stands apart. how admins actually touch each:

| value | how admins normally change it | realistic *delete* scenario? |
|---|---|---|
| `DisableExtensionList` | `certutil -delreg policy\DisableExtensionList` to undo ESC16 | **yes**, documented remediation |
| `EditFlags` | `-setreg policy\EditFlags -FLAG` clears a *bit* (ESC6 fix) | no, the value stays, only a bit is cleared |
| `InterfaceFlags` | `-setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST` (ESC11 fix) | no, flag toggled, value stays |
| `RequestDisposition` | rarely touched directly | no |
| `Security` | edited via the CA MMC ACL editor | no, Microsoft warns deleting/corrupting it can stop the CA |
| `Active` | set once at CA install (policy module name) | no, deleting breaks policy module loading |

so the bug is general at the code level, but the real-world exposure is basically all `DisableExtensionList`: it's the only one with a documented command that *removes the value outright*. the rest are modified in place, and deleting `Active` or `Security` breaks the CA itself (confirmed in the lab: deleting either took the CA offline until i restored it), so nobody does it on purpose and an attacker doing it is just sabotaging the CA, not hiding in it.

## an aside random finding while having fun: deleting RequestDisposition flips the CA to manager approval

to be clear, this part is not a certipy bug, it's a separate thing i hit while deleting the same values, and it's about the CA's own behavior. delete `RequestDisposition` and you get no error at all, but every request that used to auto-issue now sits pending, waiting for a manager to approve it:

```
[*] Request ID is 271
[!] Certificate request is pending approval
```

**why.** `RequestDisposition = 0x1` (`REQDISP_ISSUE`) is what tells an *enterprise* CA's policy module to issue immediately. delete it and the module falls back to its default: hold every request for approval, exactly how a *standalone* CA behaves. no error, just a silent policy change, enrollment still "works", it only queues.

**who can drain the queue?** approving a pending request needs "Issue and Manage Certificates", the CA-officer role, which is exactly the **ESC7** right. tested in my lab:

| identity | can approve? | how |
|---|---|---|
| `jeff` (Domain Admin) | **no** | `certipy ca -issue-request` -> "Access denied: Insufficient permissions to issue certificate" |
| `ESC7_attacker` (has ManageCertificates) | **yes** | `certipy ca -issue-request 271` -> "Successfully issued certificate request ID 271" |
| local `administrator` on the CA | yes | `certutil -resubmit 271` on the box |

`jeff` is a Domain Admin and still can't approve, which surprised me at first, but a domain admin isn't automatically a CA officer, that's a separate ACL (you could grant yourself the right, of course). once `ESC7_attacker` approved, `certipy req -retrieve 271` pulls the issued cert and you're done.

the loop is the fun part: deleting `RequestDisposition` blinds certipy to ESC7 *and* gates the CA behind approval, and the one role that can clear that backlog is the ESC7 right the blinding just hid. the person who can quietly keep the CA issuing is exactly the person you can no longer see.

## default state: a clean CA isn't affected

a fresh ADCS install ships with `DisableExtensionList` present, so the read succeeds and a clean CA scans fine out of the box. the bug only surfaces once the value is deleted outright, and the realistic way that happens is the ESC16 remediation (`certutil -delreg policy\DisableExtensionList`). so this isn't something that fires on every CA in the wild, it's scoped to CAs where someone has run that remediation (or deleted the value deliberately to blind the scanner).

## the patch

the fix mirrors the `EnrollmentAgentRights` precedent, but scoped tighter. instead of a broad `except` on each read, i added one small helper that catches *only* the not-found case and re-raises everything else:

```python
def _query_optional_value(self, hkey, value_name, default):
    try:
        _, value = rrp.hBaseRegQueryValue(self.rrp_dce, hkey, value_name)
        return value
    except rrp.DCERPCSessionError as e:
        if e.get_error_code() != system_errors.ERROR_FILE_NOT_FOUND:
            raise
        return default
```

the four values whose absence still leaves a working CA (`EditFlags`, `RequestDisposition`, `DisableExtensionList`, `InterfaceFlags`) now call it. `Active` and `Security` are left to fail on purpose: their absence means a genuinely broken CA (confirmed in the lab), and defaulting there would just hide a dead one.

the narrow catch is the point. an absent value is benign and defaults cleanly, but a read that fails for another reason (access denied, an `RPC` hiccup) still surfaces as a real failure instead of being silently turned into "nothing here", the exact blind spot this whole post is about.

with that in place the scan behaves again: config retrieved, ESC6/ESC7/ESC11 all back.

i've opened a [PR](https://github.com/ly4k/Certipy/pull/393) for this, but if you need it before it gets merged you can apply the [following patch](https://patch-diff.githubusercontent.com/raw/ly4k/Certipy/pull/393.patch) to your local certipy.

and honestly, the satisfying part isn't the vulns coming back, it's seeing these two lines again on a CA that used to fail:

```
[*] Retrieving CA configuration for 'mylab-CA-SERVER-CA' via RRP
[*] Successfully retrieved CA configuration for 'mylab-CA-SERVER-CA'
```

i'd been seeing the failure version on HTB boxes for a while without knowing why. fixing it felt like a blocked nose finally clearing.
