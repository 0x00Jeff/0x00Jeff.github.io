---
title:  TOKEN IMPERSONATION
date: 2024-03-19 13:48:00 +0000
categories: [Active-Directory]
tags: [blog]
render_with_liquid: false
---
 **TOKEN IMPERSONATION**

 Welcome to another blog concerning Active Directory Hacking! This time I chose to talk about **TOKEN IMPERSONATION**, so let's discover some hacking stuff!
 
**OVERVIEW**

When an attacker succeeds in compromising a machine within an Active Directory network and gains an interactive shell,they attempt to leverage this access to escalate privileges and navigate freely in the system files. One of the techniques they could use is TOKEN IMPERSONATION, which is a Windows post-exploitation technique that allows an attacker to steal the access token of a logged-on user on the system without knowing their credentials and impersonate them to perform operations with their privileges.

The figure below illustrates a TOKEN IMPERSONATION scenario:

![Desktop View](/media/token_imper.png)


**FUNDAMENTALS**

Before diving into the details of this attack, we must explain some necessary terms that we'll be using during the walkthrough

**1-ACCESS TOKENS** : 

An access token is an object that describes the security context of a process or thread. The information in a token includes the identity and privileges of the user account associated with the process or thread. When a user logs on, the system verifies the user's password by comparing it with information stored in a security database. If the password is authenticated, the system produces an access token. Every process executed on behalf of this user has a copy of this access token

  [Reference](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)

Here's an example of access token :


 ![Desktop View](/media/acces_token.png)

an it contains many information such as :

- The (SID) for the user's account
- SIDs for the groups of which the user is a member

- A logon SID that identifies the current logon session



**2-Local administrator TOKENS** :

When a local administrator logins, two access tokens are created: One with admin rights and other one with normal rights. By default, when this user executes a process the one with regular (non-administrator) rights is used. When this user tries to execute anything as administrator ("Run as Administrator" for example) the UAC will be used to ask for permission.

  [Reference](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/access-tokens)



**3-Token Types** :

There are two types of tokens related to the token impersonation technique  **Delegation and Impersonation**:

**Delegation tokens** are created when users interactively login into a system using their credentials. The interactive logins can be physical or remote as a Remote Desktop with RDP or VNC.

Delegation tokens are used for domain escalation because they contain authentication credentials; attackers can steal high-privileged tokens and use them to perform privileged operations without knowing their actual credentials.

**Impersonation tokens are** created when users non-interactively login into a system, like accessing a shared drive on the network. Users usually don’t get prompted for credentials when accessing the share; instead, they use their tokens for the access.

Impersonation tokens are usually generated after the delegation tokens. Non-interactive authentication uses established credentials from an interactive authentication.

 [Reference](https://medium.com/r3d-buck3t/domain-escalation-with-token-impersonation-bc577db55a0f)


**4-TOKENS DURATION** :

Tokens persist until a reboot. When a user logs off, their delegate token is reported as an impersonate token, but will still hold all of the rights of a delegate token.

(we will be doing a proof of concept of this )

 [Reference](https://www.offsec.com/metasploit-unleashed/fun-incognito/#:~:text=There%20are%20two%20types%20of,or%20a%20domain%20logon%20script)



 ![Desktop View](/media/too-much-information-maurice.gif)



Now let's put this theoretical information into practice


**ATTACK WALKTHROUGH**

At First we start a session in metasploit :

 ![Desktop View](/media/mfsconsole_impers.png)


Then we choose the module and set the necessary options :

![Desktop View](/media/module.png)
   
![Desktop View](/media/options.png)

![Desktop View](/media/payload.png)

And we specify the target :

![Desktop View](/media/targer.png)

Following that, we run the exploit ,then we got the shell.

![Desktop View](/media/got%20shell.png)

After gaining access, we proceed to the main part, which is Token impersonation. To carry out this step, we  use a tool called Incognito, offered by Metasploit.

![Desktop View](/media/spy-incognito.gif)

incognito is a stand-alone application that allowed you to impersonate user tokens when successfully compromising a system.

[More Information](https://www.offsec.com/metasploit-unleashed/fun-incognito/#:~:text=Incognito%20was%20originally%20a%20stand,via%20Luke%20Jennings%20original%20paper)

So,we load the incognito using this command :

![Desktop View](/media/incognito.png)

After loading incognito we list the existing tokens :

![Desktop View](/media/tokenslist.png)


As seen here, there are multiple delegation tokens. For instance, the 'MYDOMAIN\USER2' token signifies that USER2 has logged into this machine.

let's try login with the Administrator account into this machine :

![Desktop View](/media/adminlogin.png)


 Checking the tokens list again :

 ![Desktop View](/media/relisttokens.png)

As expected, the administrator account token has been created and added to the list of tokens. Let's try to impersonate it!

  ![Desktop View](/media/impersonate.png)
   ![Desktop View](/media/getuidadmin.png)


![Desktop View](/media/kangaroo-jack-jackie-legs.gif)


In the "Fundamentals" section, we stated that tokens persist until a reboot. Let's now conduct a proof of concept to verify this.

we reboot the compromised machine manually and we run the metasploit exploit again:

![Desktop View](/media/afterreboot.png)

As we can see, USER2 and Administrator tokens aren’t available, and this due to the fact that tokens persist until a reboot.


**MITIGATIONS**

**1-Privileged Account Management** : aimed at  limiting permissions so that users and user groups cannot create tokens

*Techniques Addressed by this Mitigation:*

- Remove users from the local administrator group on systems.
By requiring a password, even if an adversary can get terminal access, they must know the password to run anything in the sudoers file. Setting the timestamp_timeout to 0 will require the user to input their password every time sudo is executed.

- Access Token Manipulation by Limiting  permissions so that users and user groups cannot create tokens.

  [Reference](https://attack.mitre.org/mitigations/M1026/)





**2-Active Directory Tiering** :
Account tiering in Active Directory typically involves organizing users into different groups or organizational units (OUs) based on their roles, responsibilities, or levels of authority within the organization. This hierarchical structure helps in efficiently managing permissions and access control across the network.when the AD is tiered, you limit the exposure of sensitive credentials

[Reference1](https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/tier-model-for-partitioning-administrative-privileges)


An example of a Tiered Active Directory :

![Desktop View](/media/tierd.png)

[Reference2](https://files.truesec.com/hubfs/PDF/Service-Descriptions/Service-Overview-AD-Tiering-Implementation.pdf)




I hope you enjoy reading and come away with a deep understanding of this topic. Catch you in the next blog!







