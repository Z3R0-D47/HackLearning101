# Nmap
Nmap, recognized as Network Mapper, represents an open-source utility extensively employed for specialized network scanning aimed at reconnaissance and security applications. Its primary function revolves around uncovering devices, services, and prospective vulnerabilities residing within computer networks. Embraced widely within the realm of penetration testing, Nmap plays a pivotal role where reconnaissance stands as the initial step in ethical hacking practices, allowing meticulous examination and understanding of network landscapes.

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
---------------------------------------------------------------------------------------------------------------------------------------------------------
| Scan Type                 | Command                    | Description                                                                                  |                   
|---------------------------|----------------------------|----------------------------------------------------------------------------------------------|
| TCP SYN Scan              | `nmap -sS <target>`        | Initiates a TCP SYN scan by sending SYN packets to identify open ports on the target         |
| TCP Connect Scan          | `nmap -sT <target>`        | Performs a full TCP connection to each port to check for open ports and services.            |                    
| UDP Scan                  | `nmap -sU <target>`        | Conducts a UDP scan to discover open UDP ports on the target system.                         |                    
| OS Detection              | `nmap -O <target>`         | Attempts to identify the target's operating system based on various network characteristics. |                     
| Service Version Detection | `nmap -sV <target>`        | Detects service versions running on open ports.                                              |                    
| Ping Sweep (ICMP)         | `nmap -sn <target>`        | Conducts a ping sweep to discover live hosts without performing a port scan.                 |                     
---------------------------------------------------------------------------------------------------------------------------------------------------------
These commands allow for basic network scanning, identifying open ports, determining operating system details, and exploring service versions running on those ports. Adjust the <target> parameter with the IP address or hostname of the target network.


