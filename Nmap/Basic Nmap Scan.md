# **Nmap**
Nmap, recognized as Network Mapper, represents an open-source utility extensively employed for specialized network scanning aimed at reconnaissance and security applications. Its primary function revolves around uncovering devices, services, and prospective vulnerabilities residing within computer networks. Embraced widely within the realm of penetration testing, Nmap plays a pivotal role where reconnaissance stands as the initial step in ethical hacking practices, allowing detailed insights into network layouts and configurations.

<details>
<summary><strong>Set Up Your Environment (Skip this if already done)</strong></summary> 
Before using Nmap for network scanning and reconnaissance, ensure you have it installed on your system. You can install Nmap on various operating systems like Kali Linux, Parrot OS, Windows, or macOS. 
  
Here's how to get started:

- Installing Nmap on Linux:
For Debian-based Systems (e.g., Ubuntu, Kali Linux):
Use the following command in the terminal:
  
```bash
sudo apt-get update
sudo apt-get install nmap
```

- For Red Hat-based Systems (e.g., Fedora, CentOS):
Run the following command:
```
bash
sudo yum install nmap
```

- Installing Nmap on macOS:
Using Homebrew:
If you have Homebrew installed, you can install Nmap by running:

```bash
brew install nmap
```

- Installing Nmap on Windows:
Using Installer:
Download the Nmap installer from the official Nmap website and follow the installation instructions provided.

After installation, you can start using Nmap for network scanning and reconnaissance.
Remember, for Linux and macOS, you might need to use sudo or administrative privileges to install packages or software. Adjust the installation steps based on your system requirements.
</details>

## 1. Basic Scanning Techniques with Nmap 
-------------------------------------------------------------------------------------------------------------------------------------------------
| Scan Type                 | Description                                                                             | Example Usage           |
|---------------------------|-----------------------------------------------------------------------------------------|-------------------------|
| TCP SYN Scan              | Initiates a TCP SYN scan by sending SYN packets to identify open ports on the target.   | `nmap -sS <target>`     |
| TCP Connect Scan          | Performs a full TCP connection to each port to check for open ports and services.       | `nmap -sT <target>`     |
| UDP Scan                  | Conducts a UDP scan to discover open UDP ports on the target system.                    | `nmap -sU <target>`     |
| OS Detection              | Attempts to identify the target's operating system based on network characteristics.    | `nmap -O <target>`      |
| Service Version Detection | Detects service versions running on open ports                                          | `nmap -sV <target>`     |
| Ping Sweep (ICMP)         | Conducts a ping sweep to discover live hosts without performing a port scan.            | `nmap -sn <target>`     |
-------------------------------------------------------------------------------------------------------------------------------------------------

These commands allow for basic network scanning, identifying open ports, determining operating system details, and exploring service versions running on those ports. To display all available nmap command-line options, use `nmap -h` command. Adjust the `<target>` parameter with the IP address or hostname of the target network. For instance, to execute a TCP SYN Scan on the IP address `192.100.10.1`, use the following command: `nmap -sS 192.100.10.1`.

## 2. Nmap Command-Line Options
-------------------------------------------------------------------------------------------------
| Option | Description                                         | Example Usage                  |
|--------|-----------------------------------------------------|--------------------------------|
| `-A`   | Enable OS detection, version detection, script scan | `nmap -A <target>`             |
| `-O`   | Enable OS detection                                 | `nmap -O <target>`             |
| `-Pn`  | Treat all hosts as online (skip host discovery)     | `nmap -Pn <target>`            |
| `-sV`  | Scan open ports to determine service/version info   | `nmap -sV <target>`            |
| `-v`   | Increase verbosity level (show more details)        | `nmap -v <target>`             |
| `-vv`  | Increase verbosity level further                    | `nmap -vv <target>`            |
| `-sL`  | No Scan. List targets only                          | `nmap -sL <target>`            |
| `-sn`  | Disable port scanning. Host discovery only.         | `nmap -sn <target>`            |
| `-Pn`  | Disable host discovery. Port scan only.             | `nmap -Pn <target>`            |
-------------------------------------------------------------------------------------------------

This table provides a brief description of each option commonly used in Nmap. Adjusting these options can affect the scan behavior, and verbosity level, allowing for more control and detailed scans.These options can be combined to scans according to specific requirements, empowering users to execute comprehensive and detailed network reconnaissance. For instance, using `nmap -A -vv <target>` together combines OS detection, version detection, and increase the verbosity level to provide a comprehensive and detailed analysis.

## 3. Port Specification Commands
------------------------------------------------------------------------------------------------------------
| Port Specification    | Description                                      | Example Usage                 |
|-----------------------|--------------------------------------------------|-------------------------------|
| `-p 80`               | Scan a specific port                             | `nmap -p 80 <target>`         |
| `-p 443,80`           | Scan multiple ports                              | `nmap -p 443,80 <target>`     |
| `-p 1-200`            | Scan a range of ports                            | `nmap -p 1-200 <target>`      |
| `-p-`                 | Scan all 0-65535 ports                           | `nmap -p- <target>`           |
| `-p http,https`       | Scan port by service names                       | `nmap -p http,https <target>` |
------------------------------------------------------------------------------------------------------------

This table displays different ways to specify ports using Nmap commands, enabling users to define specific ports, port ranges, all ports, or services to scan during network exploration and reconnaissance. Adjust the <target> parameter with the IP address or hostname of the target network.

## 4. Scan Timing Templates
--------------------------------------------------------------------------------------------
| Option | Description                                        | Example Usage              |
|--------|----------------------------------------------------|----------------------------|
| `-T0`  | Set timing template to "Paranoid" (slowest)        | `nmap -T0 <target>`        |
| `-T1`  | Set timing template to "Sneaky"                    | `nmap -T1 <target>`        |
| `-T2`  | Set timing template to "Polite"                    | `nmap -T2 <target>`        |
| `-T3`  | Set timing template to "Normal" (default)          | `nmap -T3 <target>`        |
| `-T4`  | Set timing template to "Aggressive"                | `nmap -T4 <target>`        |
| `-T5`  | Set timing template to "Insane" (fastest)          | `nmap -T5 <target>`        |
--------------------------------------------------------------------------------------------

This table provides different timing options available in Nmap, allowing users to adjust the scan speed and intensity. These options range from slower, stealthier scans to faster, more aggressive ones, offering flexibility to scans based on the user's preference.

## 5. Output Format
--------------------------------------------------------------------------------------------------------------------------------
| Output Format           | Description                                              | Example Usage                           |
|-------------------------|----------------------------------------------------------|-----------------------------------------|
| Normal Output (-oN)     | Default human-readable format on the terminal.           | `nmap -oN scan_results.txt <target>`    |
| Grepable Output (-oG)   | Machine-parsable output suitable for scripting.          | `nmap -oG scan_results.gnmap <target>`  |
| XML Output (-oX)        | Results in XML format for importing or further analysis. | `nmap -oX scan_results.xml <target>`    |
--------------------------------------------------------------------------------------------------------------------------------

This table displays different output formats available in Nmap, providing users flexibility in how scan results are saved based on their requirements. Adjust the command by replacing <target> with the IP address or hostname of the target network.
