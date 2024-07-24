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

![alt text](https://cdn.discordapp.com/attachments/750764502181740564/1265465407075123270/image.png?ex=66a19c00&is=66a04a80&hm=785901b91835a790a2766e2c6fff1aa24fc43779c88677010cec52d92418e48b&)


Now that we have the username and password hash, we can crack the password using a tool like hashcat.

Copy the hash and save it to a file (named hashes.txt for example) on your default operating system (can do machine but default is faster) within the same folder the hashcat.exe is in.

Include any word list to compare the hash to in the same folder like rockyou.txt, a hashcat word list, or the SecList on github.

Then run hashcat on command prompt in administrator mode by using the command ‘hashcat.exe -m 5600 hashes.txt rockyou.txt -O’. 5600 is a type of hash for NTLM and the -O switch just optimizes the command.

This gets you the following from hashcat:

![alt text](https://cdn.discordapp.com/attachments/750764502181740564/1265465712277979166/image.png?ex=66a19c49&is=66a04ac9&hm=731dd02bfdf997d67878e943d72d87203eab122cf83e5f33572042ee6d3ff423&)

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
* 
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

![alt text](https://cdn.discordapp.com/attachments/750764502181740564/1265468434154786886/image.png?ex=66a19ed1&is=66a04d51&hm=cc14740edb8717f909a7eb782ddba85811f875b304842fccce5eb172ae1c5bae&)

Opening domain_users_by_group.html gives us the following:

![alt text](https://cdn.discordapp.com/attachments/750764502181740564/1265468721120677969/image.png?ex=66a19f16&is=66a04d96&hm=37231340f19c3ade459e39da89e016a6f9cf3fc92cae770b0e5a7e0a1546e1f7&)

Once the admin logs into the domain controller, it will create a new user and password:

![alt text](https://cdn.discordapp.com/attachments/750764502181740564/1265469288605552740/image.png?ex=66a19f9d&is=66a04e1d&hm=fd7da1561baf08ab429202c3a83e4c0da8cd8004ebada98ae6d4b09f52973fe5&)

Then you should see the new account in the domain controller:

![alt text](https://cdn.discordapp.com/attachments/750764502181740564/1265469321573040138/image.png?ex=66a19fa5&is=66a04e25&hm=63eec78cb1a9ebd41960989691b2f42e9a0beaf0b4622e32c1d5c78fa3ac2bf1&)

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

![alt text](https://cdn.discordapp.com/attachments/750764502181740564/1265477682561286224/image.png?ex=66a1a76e&is=66a055ee&hm=80b7f22dbec38247eb65df3a16aeb873dec3f09cb5728875d50144132d2a3e19&)

You can also see high value targets as well:

![alt text](https://cdn.discordapp.com/attachments/750764502181740564/1265482340981936262/image.png?ex=66a1abc5&is=66a05a45&hm=953143562d95d9d3594867ea9525628f9636b42fb36891fff62fc07f3b0ae8e4&)
