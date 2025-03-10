# PentaDock Maintenance Suite

**PentaDock Maintenance Suite** is an interactive Bash script designed for comprehensive system administration on Ubuntu. It includes functionalities for:

- Updating, cleaning, and maintaining Ubuntu  
- Installing Pentesting and Office tools  
- Connecting to a VPN as a client (change public IP)  
- Deploying Kali Linux containers with Docker  
- MAC Spoofing (changing MAC address)  
- Installing and using ClamAV antivirus  
- Deploying a Kali container with wireless interface forwarding  
- UNINSTALLING installed tools (Pentesting and Office)

> **Use at your own risk!**

## Features

- **System Maintenance:** Update, upgrade, and clean your Ubuntu system via APT, Snap, and Flatpak.
- **Pentesting Tools:** Installs well-known tools like `nmap`, `wireshark`, `metasploit`, etc.
- **Office Tools:** Installs LibreOffice, GIMP, VLC, Brave, Chrome, Thunderbird, etc.
- **Docker Management:** Deploy and manage Kali Linux containers (detached, interactive, wireless forwarding).
- **VPN Client Configuration:** Easily connect, disconnect, and check VPN status with `.ovpn` config files.
- **MAC Spoofing:** Randomly or manually change your MAC address and restore it afterward.
- **ClamAV Antivirus:** Install, update, and perform system scans.
- **All-in-One Automation:** Includes an option (`Run full automation process`) to execute common tasks in one go.
- **Logging:** Everything is logged to a file on your desktop for easy review.

## Requirements

- **Ubuntu** (20.04 or later recommended)
- **Bash** (the script is written for Bash)
- **Sudo privileges** (many commands require elevated privileges)
- **Optional**: Snap and Flatpak installed if you plan to install certain packages from those sources

## Installation

1. **Clone or Download the Repository**  
   - If you have Git installed:
     ```bash
     git clone https://github.com/yourusername/pentadock-maintenance-suite.git
     cd pentadock-maintenance-suite
     ```
   - Or download the script directly from the repo and place it in a local directory.

2. **Make the Script Executable**  
   ```bash
   chmod +x pentadock.sh
