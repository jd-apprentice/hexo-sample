---
title: Feedback - Vulnlab
date: 2024-06-05 02:06:42
tags: [vulnlab, Easy]
categories: vulnlab
keywords: 'Vulnlab, Easy, Linux'
description: This box was really creative, and involved a Kiosk breakout with the only port being 3389. When I initially started this, I was going into it relatively blind. The attack path is more so up to interpretation and really get's you thinking into understanding what you have access to and exploiting it.
cover: /images/vulnlab/feedback-vl/feedback_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

This is another machine from VulnLab, and it involves exploiting a Log4J vulnerability in a web service and use it to access internal resources to compromise a Linux machine. This specific machine seems to focus heavily on web services, which is a nice change of pace to the AD pen-testing that I'm used to.

# Enumeration

Let's start with our usual NMAP scan of the machine.

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-02 22:30 EDT
Nmap scan report for 10.10.75.95
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 13.28 seconds
```

It seems that there is a proxy on port `8080`, so we'll try to access that through our web browser. Remember to append the port number after the URL so you can access the website properly.

![](/images/vulnlab/feedback-vl/b.png)

We seem to be greeted with an Apache Tomcat website, to which we are within the root website of this server. there are three nodes towards the right (server status, manager app, and host manager), to which we do not have access to.

The title of the website indicates to us that the version of this specific Apache Tomcat application is version `9.0.56`.

Given that there isn't much for us to look at due to this being the documentation portion of the website, let's run a `gobuster` scan to see if there are any other webpages we can access.

```
└─$ gobuster dir -u http://10.10.75.95:8080 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
......
/feedback             (Status: 302) [Size: 0] [--> /feedback/]
```

You'll see that there is an odd directory called `feedback`, which I'm assuming should be the apart of the attack path given the name of the machine. The other directory results are relatively common, so we'll focus on this `feedback` directory that we've found.

![](/images/vulnlab/feedback-vl/c.png)

As you'll see this links us to a web panel that is asking for input feedback for the web service. You'll notice that the page is relatively bare aside from the two input panels that we have access to.

My first initial thought is to take a look at the request that gets sent from this feedback form through [Burpsuite](https://portswigger.net/burp/documentation/desktop/getting-started).

![](/images/vulnlab/feedback-vl/d.png)

The product of the request seems to be what I would've expected - you'll see two parameters for our name and the feedback that we wanted to give to the website. That being said, you'll notice an odd `JSESSIONID` parameter as our cookie parameter. I'm unfamiliar for this particular parameter, so we'll research into it with regards to `Tomcat 9.0.56`.

That brought me to an interesting vulnerability - Log4Shell.

# Exploiting Log4Shell

Also known as the Log4J vulnerability, [Log4Shell](https://www.ibm.com/topics/log4shell) is a remote code execution vulnerability in a few of the versions of the Apache Log4J 2 Java library. This is an open-source logging library created by Apache that records information and events within a program. This is particularly directed towards error messages and user inputs.

This isn't it's own service, but a snippet of code that Java applications can utilize at a broad scale. The issue at hand is a parameter that you can specify in most user input parsers that Log4J has to parse - specifically JNDI.

JNDI, otherwise known as the Java Naming and Directory Interface, is an API that Java uses to access resources hosted on outside servers. A command exists called JNDI lookup that tells the application to go to the link provided in the input and execute it as code or a script. The older versions of Log4J will generally run any code provided to them without any form of handling. The goal of Log4Shell is to have the website using Log4J to execute a reverse shell and generate a session for the attacker.

In our case, this application is vulnerable to Log4Shell within the input parameter on this webpage. You can find the POC for Log4Shell [here](https://github.com/kozmer/log4j-shell-poc), which will require you to download JDK 1.8.0_20 and place it within the same directory as the exploit. You can find the specific JDK version within [this](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html) download page on Oracle.

![](/images/vulnlab/feedback-vl/e.png)

As seen in the above, the POC will launch an LDAP and HTTP server for us to handle the exploit process. We'll need to make sure a netcat session is listening on port `9001` using `nc -lvnp 9001`. The Java application that the HTTP server is using will redirect the machine we are attacking to our reverse shell once the exploit is executed by the machine.

All that's required next is to send the one-liner payload to an input field that Log4J will parse. In our case, you can put it in the `name` parameter. Make sure to URL encode the one-liner so the Log4J can parse it properly based on the request.

![](/images/vulnlab/feedback-vl/f.png)

If we send the request in Repeater, we shouldn't receive any output in the Response area of Repeater, indicating that something has caused the application to pause. If we return to our terminal window, we should see the exploit downloaded and a reverse shell appear on our listener.

```
└─$ nc -lvnp 9001    
listening on [any] 9001 ...
connect to [10.8.0.173] from (UNKNOWN) [10.10.75.95] 55526
whoami
tomcat
```

# Host Reconnaissance

Now that we have access to a reverse shell, we'll need to enumerate the machine to find if there is anything on the machine that we exploit for privilege escalation.

Note that we do have a pretty bare-bones shell at the moment that does not have a TTY. You can use Python to spawn a valid TTY, though that's up to you.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
tomcat@ip-10-10-10-7:/$
```

I stood up a simple [Sliver](https://github.com/BishopFox/sliver) C2 server and ran an implant on the machine so I could receive an easier way to transfer files to and from the machine.

I did some research into this machine via the progress bar in the [Discord](https://discord.gg/vulnlab), and it seems that this machine only has a root flag. You can verify this by accessing the `/home` directory of the machine, which seems to only have the default `ubuntu` user.

```
tomcat@ip-10-10-10-7:/$ ls -la /home
ls -la /home
total 12
drwxr-xr-x  3 root   root   4096 Dec 11  2021 .
drwxr-xr-x 23 root   root   4096 Jun  3 02:24 ..
drwxr-xr-x  5 ubuntu ubuntu 4096 Dec 11  2021 ubuntu
```

There was an interesting file that I found in `/opt/tomcat/conf/tomcat-users.xml`, which seems to include information about the `tomcat` users on the machine.

```
  <user username="admin" password="[...snip...]" roles="manager-gui"/>
  <user username="robot" password="[...snip...]" roles="manager-script"/>
```

While these seem to be interesting credentials and would be helpful in a red-teaming environment, there isn't really anything we can use these for as we can't authenticate to the `Manager` panel in any fashion. That is what I had thought until I tried `su` to login as the root user on this machine. I used the same password that was within the above XML file, at it seemed to work properly.

```
tomcat@ip-10-10-10-7:~/conf$ su
Password: 
root@ip-10-10-10-7:/opt/tomcat/conf# cd /root
root@ip-10-10-10-7:~# ls
root.txt  snap
```

Since we have access to the root flag, we have successfully rooted this machine!

# Conclusion

Although this was a relatively short machine, it's sometimes common to see vulnerabilities in credential reusage such as what we did for this machine. It can even be as simple as reusing a password for any user. Nonetheless I did enjoy exploiting every part of this machine, and I believe that it is extremely user-friendly. Big thanks go out to xct for the development of this machine!

# Resources

https://www.ibm.com/topics/log4shell
https://www.youtube.com/watch?v=nF8tfsY74ws
https://www.dynatrace.com/news/blog/what-is-log4shell/
https://github.com/kozmer/log4j-shell-poc
https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html
https://github.com/BishopFox/sliver
https://discord.com/invite/vulnlab

