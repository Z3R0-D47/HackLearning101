# **Nmap Scripting Engine**
Nmap Scripting Engine (NSE) is a powerful component within Nmap that allows users to write and execute scripts to automate a variety of tasks during network reconnaissance and scanning. These scripts enable the extension of Nmap's functionality, providing a wide range of capabilities for vulnerability detection, service enumeration, and more.

## 1. Introduction to NSE
The Nmap Scripting Engine comprises a collection of scripts written in Lua programming language. These scripts are categorized into various categories, each serving a specific purpose. 

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
| NSE Category | Description                                                                                          | Example Usage                                 |
|--------------|------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| Auth         | Scripts focusing on authentication mechanisms to identify authentication-related vulnerabilities.    | `nmap --script auth <target>`                 |
| Broadcast    | Scripts dealing with broadcast-based services or protocols, used to discover responsive hosts.       | `nmap --script broadcast <target>`            |
| Brute        | Scripts performing brute-force attacks on services like FTP, SSH, or others to test weak credentials.| `nmap --script brute <target>`                |
| Default      | General-purpose scripts performing common tasks during scanning, covering a wide range of functions. | `nmap --script default <target>`              |
| Discovery    | Scripts dedicated to gathering information about hosts, services, and network configurations.        | `nmap --script discovery <target>`            |
| Dos          | Scripts testing service robustness against Denial of Service (DoS) attacks.                          | `nmap --script dos <target>`                  |
| Exploit      | Scripts attempting to exploit vulnerabilities in target services or systems.                         | `nmap --script exploit <target>`              |
| External     | Scripts interacting with external systems or databases for information gathering.                    | `nmap --script external <target>`             |
| Fuzzer       | Scripts sending malformed data to test vulnerabilities related to input handling or parsing.         | `nmap --script fuzzer <target>`               |
| Intrusive    | More aggressive scripts performing deeper and potentially disruptive scans on target systems.        | `nmap --script intrusive <target>`            |
| Malware      | Scripts looking for indicators of compromise or signs of malicious software presence in a network.   | `nmap --script malware <target>`              |
| Safe         | Non-disruptive scripts prioritizing safety during scanning, avoiding unintended impact on systems.   | `nmap --script safe <target>`                 |
| Version      | Scripts focusing on detecting service/software versions to aid in vulnerability assessment.          | `nmap --script version <target>`              |
| Vuln         | Scripts designed to detect and exploit known vulnerabilities in target systems or services.          | `nmap --script vuln <target>`                 |
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 2. Using NSE in Nmap Scans
To utilize NSE scripts during a scan, the -sC option can be used to enable default scripts, while specifying individual scripts can be done using -sC <script_name>. Here are some examples:

Running default scripts:

```bash
nmap -sC <target>
```

Running specific scripts:

```bash
nmap --script=<script_name> <target>
```
## 3. Common NSE Script Examples
- **HTTP Enumeration**<br>
The http-enum.nse script is used to enumerate directories and files on web servers.
```bash
nmap --script=http-enum <target>
```

- **SMB Vulnerability Detection**<br>
The smb-vuln-ms17-010.nse script identifies the MS17-010 vulnerability present in SMB services.
```bash
nmap --script=smb-vuln-ms17-010 <target>
```

- **DNS Zone Transfer**<br>
The dns-zone-transfer.nse script attempts a DNS zone transfer on a specified target.
```bash
nmap --script=dns-zone-transfer <target>
```
- **FTP Anonymous Access Check**<br>
The ftp-anon.nse scripts checks for anonymous FTP access on FTP servers.
```bash
nmap --script=ftp-anon <target>
```

- **SMTP Service Enumeration**<br>
The smtp-enum-users.nse scripts enumerates users through the SMTP service.
```bash
nmap --script=smtp-enum-users <target>
```

- **SSH Brute-force Detection**<br>
The ssh-brute.nse scripts performs brute-force password guessing against SSH servers.
```bash
nmap --script=ssh-brute <target>
```

- **HTTP Server Type and Version Detection**<br>
The http-server-header.nse scripts retrieves server type and version information from HTTP headers.
```bash
nmap --script=http-server-header <target>
```

## 4. Creating Custom NSE Scripts
One of the significant advantages of Nmap Scripting Engine (NSE) is the flexibility it offers to create custom scripts tailored to specific requirements. Leveraging Nmap's extensive Application Programming Interface (API) and the Lua scripting language, users have the capability to develop scripts catering to their unique needs in network reconnaissance and security assessments.

### Developing Custom NSE Scripts
Before create custom NSE Scripts, need to understand Lua and Nmap API first.Lua is the scripting language used for writing NSE scripts. Familiarize yourself with Lua basics and the Nmap scripting API for script development.

a. Understanding Lua Basics:

- Syntax and Structure: Learn Lua's syntax, data types, control structures, and functions.
- Lua Libraries: Understand Lua libraries and functions that facilitate tasks within NSE scripting.
  
b. Familiarizing with Nmap API:

- NSE Functions: Explore the Nmap scripting API, which provides access to various functions for network scanning, host discovery, service enumeration, and more.
- Script Categories: Understand script categories like `prerule`, `portrule`, `hostrule`, and `action`, defining script behavior on targets.


