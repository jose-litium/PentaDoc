#!/bin/bash
# Author and Script Information
AUTHOR="jose-litium"
GITHUB="https://github.com/jose-litium"
LINKEDIN="https://www.linkedin.com/in/josemmanueldiaz/"
DATE="2025-02-17"
VERSION="1.0"

# Determine desktop path (for Spanish or English environments)
if [ -d "$HOME/Escritorio" ]; then
  DESKTOP_DIR="$HOME/Escritorio"
elif [ -d "$HOME/Desktop" ]; then
  DESKTOP_DIR="$HOME/Desktop"
else
  DESKTOP_DIR="$HOME"
fi

# Log file on the desktop
LOG_FILE="$DESKTOP_DIR/pentadock_maintenance_$(date +'%Y%m%d_%H%M%S').log"

# Redirect all output to the log file (while still showing it on screen)
exec > >(tee -a "$LOG_FILE") 2>&1

##############################
# Presentation Functions     #
##############################

print_banner() {
 cat << "EOF"
 ___ ___ __  _ _____ __  __   __   ____  __
| _,\ __|  \| |_   _/  \| _\ /__\ / _/ |/ /
| v_/ _|| | ' | | || /\ | v | \/ | \_|   < 
|_| |___|_|\__| |_||_||_|__/ \__/ \__/_|\_\
         PentaDock Maintenance Suite v1.0
EOF
  echo ""
}

print_info() {
  echo "----------------------------------------------------------------"
  echo "  Author    : $AUTHOR"
  echo "  GitHub    : $GITHUB"
  echo "  LinkedIn  : $LINKEDIN"
  echo "  Date      : $DATE"
  echo ""
  echo "  Interactive script for:"
  echo "   - Updating, cleaning, and maintaining Ubuntu"
  echo "   - Installing Pentesting and Office tools"
  echo "   - Connecting to a VPN as a client (change public IP)"
  echo "   - Deploying Kali Linux containers with Docker"
  echo "   - MAC Spoofing (changing MAC address)"
  echo "   - Installing and using ClamAV antivirus"
  echo "   - Deploying a Kali container with wireless interface forwarding"
  echo "   - UNINSTALLING installed tools (Pentesting and Office)"
  echo ""
  echo "  USE AT YOUR OWN RISK!"
  echo "----------------------------------------------------------------"
  echo ""
}

print_signature() {
  echo "----------------------------------------------------------------"
  echo "  Script executed by $AUTHOR"
  echo "  Execution Date: $(date)"
  echo "  Log file: $LOG_FILE"
  echo "----------------------------------------------------------------"
}

print_separator() {
  echo "--------------------------------------------------------"
}

pause() {
  echo "Waiting 1 second to continue... (Ctrl + C to cancel)"
  sleep 1
}

##############################
# System Functions           #
##############################

disable_openvpn_server_config() {
  echo "→ Disabling any OpenVPN server configuration..."
  sudo systemctl stop openvpn@server &>/dev/null || true
  sudo systemctl disable openvpn@server &>/dev/null || true
  if [ -f /etc/openvpn/server.conf ]; then
    echo "→ Renaming /etc/openvpn/server.conf to avoid conflicts."
    sudo mv /etc/openvpn/server.conf /etc/openvpn/server.conf.bak
  fi
}

auto_find_ovpn() {
  local ovpn_files=()
  readarray -t ovpn_files < <(find /etc/openvpn "$HOME" -type f -name "*.ovpn" 2>/dev/null)
  if [ ${#ovpn_files[@]} -eq 0 ]; then
    return 1
  fi
  # Fixed syntax error here: added space before ]
  if [ ${#ovpn_files[@]} -eq 1 ]; then
    echo "${ovpn_files[0]}"
  else
    echo -e "\nFound the following .ovpn files:"
    for i in "${!ovpn_files[@]}"; do
      echo "$((i+1))) ${ovpn_files[i]}"
    done
    read -p "Select a file [1-${#ovpn_files[@]}]: " selection
    if [[ $selection -ge 1 && $selection -le ${#ovpn_files[@]} ]]; then
      echo "${ovpn_files[$((selection-1))]}"
    else
      return 1
    fi
  fi
}

check_vpn_status() {
  echo "→ Checking openvpn@client service status..."
  if systemctl is-active --quiet openvpn@client; then
    echo "✓ openvpn@client is ACTIVE."
    if ip a | grep -q "tun0"; then
      echo "→ 'tun0' interface detected. Your current public IP is:"
      curl -s ifconfig.me
      echo ""
    else
      echo "⚠ 'tun0' not detected. Please check logs."
    fi
  else
    echo "✗ openvpn@client is INACTIVE or failed."
  fi
}

update_system() {
  print_separator
  echo "→ Updating package list..."
  sudo apt update -y
  print_separator
  echo "→ Upgrading installed packages..."
  sudo apt upgrade -y && sudo apt full-upgrade -y
  print_separator
  echo "→ Cleaning obsolete packages and caches..."
  sudo apt autoremove -y && sudo apt autoclean -y && sudo apt clean -y
  if dpkg -l | grep '^rc' &>/dev/null; then
    echo "→ Removing residual configurations..."
    sudo apt purge $(dpkg -l | awk '/^rc/ {print $2}') -y || true
  fi
  echo "✓ System successfully updated."
}

update_snap_flatpak() {
  print_separator
  echo "→ Updating Snap packages..."
  sudo snap refresh || true
  print_separator
  echo "→ Updating Flatpak packages (if installed)..."
  if command -v flatpak &>/dev/null; then
    flatpak update -y || true
  else
    echo "Flatpak not installed; skipping..."
  fi
  echo "✓ Snap/Flatpak updated."
}

clean_system() {
  print_separator
  echo "→ Rotating logs with journalctl..."
  sudo journalctl --rotate
  echo "→ Cleaning old logs (keeping 100MB)..."
  sudo journalctl --vacuum-size=100M
  echo "→ Removing log files in /var/log..."
  sudo find /var/log -type f -exec rm -f {} \; || true
  print_separator
  echo "→ Cleaning caches and temporary files..."
  if command -v resolvectl &>/dev/null; then
    echo "→ Flushing DNS cache with resolvectl..."
    sudo resolvectl flush-caches || true
  elif command -v systemd-resolve &>/dev/null; then
    echo "→ Flushing DNS cache with systemd-resolve..."
    sudo systemd-resolve --flush-caches || true
  else
    echo "No DNS cleaning tool found."
  fi
  echo "→ Removing files in /tmp and /var/tmp..."
  sudo rm -rf /tmp/* || true
  sudo rm -rf /var/tmp/* || true
  if [ "$USER" != "root" ]; then
    echo "→ Removing thumbnail cache..."
    rm -rf ~/.cache/thumbnails/* || true
  fi
  echo "✓ System cleaned."
}

update_distribution() {
  print_separator
  echo "→ Checking for update-manager-core..."
  sudo apt install update-manager-core -y
  echo "→ Running do-release-upgrade in -d mode..."
  sudo do-release-upgrade -d || true
  echo "✓ Distribution update completed (or skipped)."
}

repair_packages() {
  print_separator
  echo "→ Repairing broken packages..."
  sudo dpkg --configure -a || true
  sudo apt --fix-broken install -y || true
  echo "✓ Broken packages repaired."
}

##############################
# Package Installation       #
##############################

install_pentest_tools() {
  print_separator
  echo "→ Installing Pentesting and network tools:"
  local pentest_packages=( "nmap" "wireshark" "metasploit-framework" "aircrack-ng" "john" "sqlmap" "burpsuite" "ettercap-graphical" "netcat-openbsd" "hashcat" "maltego" "hydra" "moxxi" "theharvester" "recon-ng" )

  if [ "$EUID" -eq 0 ]; then
    if [ -n "$SUDO_USER" ]; then
      USER_FOR_SNAP="$SUDO_USER"
    else
      USER_FOR_SNAP=$(logname 2>/dev/null)
    fi
    if [ -n "$USER_FOR_SNAP" ]; then
      SNAP_CMD="sudo -u $USER_FOR_SNAP snap"
    else
      SNAP_CMD="snap"
    fi
  else
    SNAP_CMD="snap"
  fi

  for pkg in "${pentest_packages[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
      echo "  - $pkg is already installed (via APT)."
      continue
    fi
    echo "→ Installing $pkg via APT..."
    if sudo apt install -y "$pkg"; then
      echo "  - $pkg installed successfully via APT."
    else
      echo "  - $pkg not found in APT repositories."
      if command -v snap &>/dev/null; then
        if $SNAP_CMD info "$pkg" &>/dev/null; then
          echo "→ Installing $pkg via snap..."
          if $SNAP_CMD install "$pkg"; then
            echo "  - $pkg installed successfully via snap."
          else
            echo "  - Failed to install $pkg via snap."
          fi
        else
          echo "  - Snap package \"$pkg\" not available. Manual installation might be required."
        fi
      else
        echo "  - snap is not installed. Please install snap or install $pkg manually."
      fi
    fi
  done
  echo "✓ Pentesting tools installation process completed."
}

install_office_tools() {
  print_separator
  echo "→ Installing Office and basic utilities:"
  # Office tools including additional browsers and email client.
  local office_packages=( "libreoffice" "gimp" "vlc" "git" "curl" "wget" "build-essential" "htop" "brave-browser" "google-chrome-stable" "thunderbird" )
  for pkg in "${office_packages[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
      echo "  - $pkg is already installed."
    else
      echo "→ Installing $pkg..."
      sudo apt install -y "$pkg"
    fi
  done
  echo "✓ Office tools installation completed."
}

##############################
# Uninstallation Function    #
##############################
# Note: This function removes only the packages listed.
# Essential packages such as Brave, Google Chrome, and Thunderbird are excluded.

uninstall_tools() {
  print_separator
  echo "→ Uninstalling Pentesting and Office tools (excluding essential applications)..."
  local pentest_packages=( "nmap" "wireshark" "metasploit-framework" "aircrack-ng" "john" "sqlmap" "burpsuite" "ettercap-graphical" "netcat-openbsd" "hashcat" "maltego" "hydra" "moxxi" "theharvester" "recon-ng" )
  # Only uninstall non-essential Office tools.
  local office_packages=( "libreoffice" "gimp" "vlc" "git" "curl" "wget" "build-essential" "htop" )

  echo "→ Uninstalling Pentesting tools..."
  for pkg in "${pentest_packages[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
      sudo apt remove -y "$pkg"
      echo "  - $pkg uninstalled."
    else
      echo "  - $pkg was not installed."
    fi
  done

  echo "→ Uninstalling Office tools (non-essential)..."
  for pkg in "${office_packages[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
      sudo apt remove -y "$pkg"
      echo "  - $pkg uninstalled."
    else
      echo "  - $pkg was not installed."
    fi
  done
  echo "✓ Uninstallation process completed."
}

check_reboot() {
  print_separator
  if [ -f /var/run/reboot-required ]; then
    echo "A restart is required to complete changes!"
    read -p "Restart now? (y/n): " reboot_resp
    if [[ $reboot_resp =~ ^[yY] ]]; then
      echo "→ Restarting system..."
      sudo reboot
    else
      echo "→ Restart skipped. Remember to restart later."
    fi
  else
    echo "No restart required at this time."
  fi
}

install_docker_if_needed() {
  print_separator
  echo "→ Checking Docker installation..."
  if ! command -v docker &>/dev/null; then
    read -p "Docker is not installed. Install Docker (docker.io)? (y/n): " install_docker
    if [[ $install_docker =~ ^[yY] ]]; then
      sudo apt update -y
      sudo apt install -y docker.io
      sudo systemctl enable docker
      sudo systemctl start docker
      echo "✓ Docker installed and enabled."
    else
      echo "Operation cancelled. Docker will not be installed."
      return 1
    fi
  else
    echo "Docker is already installed."
  fi

  if ! groups "$USER" | grep -q docker; then
    read -p "User '$USER' is not in the 'docker' group. Add now? (y/n): " add_to_group
    if [[ $add_to_group =~ ^[yY] ]]; then
      sudo usermod -aG docker "$USER"
      echo "→ User '$USER' added to 'docker' group. Please log out and back in."
    else
      echo "→ User not added; you will need to use Docker with sudo."
    fi
  fi

  if ! systemctl is-active --quiet docker; then
    echo "→ Docker service is not active. Starting it..."
    sudo systemctl start docker
  fi
  return 0
}

##############################
# Docker Submenu Functions   #
##############################

docker_deploy_detached() {
  print_separator
  echo "→ Deploying Kali Linux container in detached mode..."
  sudo docker run -d --name kali_container --shm-size=512m -p 6901:6901 -e VNC_PW=password kasmweb/kali-rolling-desktop:1.16.0
  echo "→ Container deployed. Access it at: https://172.17.0.2:6901"
}

docker_deploy_interactive() {
  print_separator
  echo "→ Deploying Kali Linux container in interactive mode..."
  sudo docker run --rm -it --shm-size=512m -p 6901:6901 -e VNC_PW=password kasmweb/kali-rolling-desktop:1.16.0
  echo "→ Container session ended."
}

select_wireless_interface() {
  print_separator
  echo "Detecting available wireless interfaces:"
  local wireless=($(ip -o link show | awk -F': ' '{print $2}' | grep '^wl'))
  if [ ${#wireless[@]} -eq 0 ]; then
    echo "No wireless interfaces found."
    return 1
  fi
  echo "Found wireless interfaces:"
  for i in "${!wireless[@]}"; do
    echo "$((i+1))) ${wireless[i]}"
  done
  read -p "Select a wireless interface [1-${#wireless[@]}]: " selection
  if [[ $selection -ge 1 && $selection -le ${#wireless[@]} ]]; then
    echo "${wireless[$((selection-1))]}"
  else
    echo "Invalid selection."
    return 1
  fi
}

docker_deploy_wireless() {
  print_separator
  echo "→ Deploying Kali container with wireless interface forwarding..."
  install_docker_if_needed || return 1
  echo "Select your wireless interface to forward:"
  local wlan_iface
  wlan_iface=$(select_wireless_interface) || return 1
  echo "→ Selected wireless interface: $wlan_iface"
  read -p "Enable monitor mode on $wlan_iface? (y/n): " mon_resp
  if [[ $mon_resp =~ ^[yY] ]]; then
    echo "→ Enabling monitor mode on $wlan_iface..."
    sudo airmon-ng start "$wlan_iface"
    wlan_iface="${wlan_iface}mon"
    echo "→ Monitor mode enabled. New interface: $wlan_iface"
  fi
  read -p "Deploy container with host network and privileged mode? (y/n): " deploy_resp
  if [[ $deploy_resp =~ ^[yY] ]]; then
    echo "→ Deploying container with --privileged and --net=host..."
    sudo docker run -d --name kali_container --privileged --net=host kasmweb/kali-rolling-desktop:1.16.0
    echo "→ Container deployed in host network mode."
    echo "→ Your public IP is:"
    curl -s ifconfig.me
    echo ""
  else
    echo "Operation cancelled."
  fi
}

docker_status() {
  print_separator
  echo "→ Checking status of container 'kali_container'..."
  sudo docker ps -f "name=kali_container"
}

docker_list() {
  print_separator
  echo "→ Listing all Docker containers..."
  sudo docker ps -a
}

docker_remove_container() {
  print_separator
  echo "→ Removing container 'kali_container' (will stop it if running)..."
  if sudo docker rm -f kali_container; then
    echo "✓ Container 'kali_container' removed."
  else
    echo "No container named 'kali_container' found."
  fi
}

docker_menu() {
  while true; do
    echo ""
    echo "============= Docker Menu ============="
    echo "1) Deploy Kali container in detached mode"
    echo "2) Deploy Kali container in interactive mode"
    echo "3) Deploy Kali container with wireless forwarding"
    echo "4) Check container status"
    echo "5) List all containers"
    echo "6) Remove container 'kali_container'"
    echo "0) Return to main menu"
    read -p "Select an option: " docker_option
    case $docker_option in
      1) docker_deploy_detached ;;
      2) docker_deploy_interactive ;;
      3) docker_deploy_wireless ;;
      4) docker_status ;;
      5) docker_list ;;
      6) docker_remove_container ;;
      0) break ;;
      *) echo "Invalid option. Please try again." ;;
    esac
    pause
  done
}

##############################
# VPN Client Functions       #
##############################

conectar_vpn_cliente() {
  print_separator
  disable_openvpn_server_config
  echo "→ Connecting to VPN as client..."
  if ! command -v openvpn &>/dev/null; then
    echo "→ OpenVPN not installed. Installing..."
    sudo apt update && sudo apt install -y openvpn
  fi
  local ovpn_source=""
  echo ""
  echo "Do you want to automatically search for a .ovpn file on your system?"
  read -p "Answer (y/n): " auto_resp
  if [[ $auto_resp =~ ^[yY] ]]; then
    local auto_file
    auto_file=$(auto_find_ovpn)
    if [ $? -eq 0 ] && [ -n "$auto_file" ]; then
      ovpn_source="$auto_file"
      echo "→ Using file: $ovpn_source"
    else
      echo "No .ovpn file found or selection failed."
    fi
  fi
  if [ -z "$ovpn_source" ]; then
    echo "For free VPN configurations visit: http://www.vpnbook.com"
    read -p "Enter a URL or local path to the .ovpn file: " user_input
    ovpn_source="$user_input"
  fi
  if [[ "$ovpn_source" =~ ^http ]]; then
    echo "→ Downloading .ovpn file from URL..."
    sudo wget -O /etc/openvpn/client.conf "$ovpn_source" || { echo "Error downloading configuration."; return 1; }
  else
    if [ -f "$ovpn_source" ]; then
      echo "→ Copying configuration file to /etc/openvpn/client.conf..."
      sudo cp "$ovpn_source" /etc/openvpn/client.conf
    else
      echo "The specified file does not exist: $ovpn_source"
      return 1
    fi
  fi
  # Add "dev tun" and "client" if missing
  if ! grep -qiE '^dev\s+(tun|tap)' /etc/openvpn/client.conf; then
    echo "→ 'dev tun' not found in configuration. Adding automatically..."
    sudo sed -i '1idev tun' /etc/openvpn/client.conf
  fi
  if ! grep -qi '^client' /etc/openvpn/client.conf; then
    echo "→ 'client' not found in configuration. Adding automatically..."
    sudo sed -i '1iclient' /etc/openvpn/client.conf
  fi
  echo "→ Starting openvpn@client service..."
  sudo systemctl stop openvpn@client &>/dev/null || true
  sudo systemctl start openvpn@client
  sudo systemctl enable openvpn@client
  sleep 2
  check_vpn_status
}

desconectar_vpn_cliente() {
  print_separator
  echo "→ Disconnecting VPN client..."
  sudo systemctl stop openvpn@client
  sudo systemctl disable openvpn@client &>/dev/null || true
  echo "✓ VPN disconnected."
}

vpn_cliente_menu() {
  while true; do
    echo ""
    echo "============= VPN Client Menu ============="
    echo "1) Connect VPN (change public IP)"
    echo "2) Disconnect VPN"
    echo "3) Check VPN status"
    echo "0) Return to main menu"
    read -p "Select an option: " vpn_option
    case $vpn_option in
      1) conectar_vpn_cliente ;;
      2) desconectar_vpn_cliente ;;
      3) check_vpn_status ;;
      0) break ;;
      *) echo "Invalid option. Please try again." ;;
    esac
    pause
  done
}

##############################
# ClamAV Antivirus Functions #
##############################

install_antivirus() {
  print_separator
  echo "→ Installing ClamAV..."
  sudo apt update -y && sudo apt install -y clamav clamav-daemon
  echo "✓ ClamAV installed."
}

update_antivirus() {
  print_separator
  echo "→ Updating ClamAV virus definitions..."
  sudo freshclam
  echo "✓ ClamAV database updated."
}

scan_system() {
  print_separator
  read -p "Enter directory to scan (default: $HOME): " scan_dir
  scan_dir=${scan_dir:-$HOME}
  echo "→ Scanning directory: $scan_dir"
  sudo clamscan -r "$scan_dir"
  echo "✓ Scan completed."
}

antivirus_menu() {
  while true; do
    echo ""
    echo "============= Antivirus Menu (ClamAV) ============="
    echo "1) Install ClamAV"
    echo "2) Update ClamAV virus definitions"
    echo "3) Scan system (default: Home directory)"
    echo "0) Return to main menu"
    read -p "Select an option: " av_option
    case $av_option in
      1) install_antivirus ;;
      2) update_antivirus ;;
      3) scan_system ;;
      0) break ;;
      *) echo "Invalid option. Please try again." ;;
    esac
    pause
  done
}

##############################
# MAC Spoofing Functions     #
##############################

select_interface() {
  print_separator
  echo "Detecting available network interfaces (WiFi and Ethernet):"
  local interfaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"))
  local available=()
  for iface in "${interfaces[@]}"; do
    if [[ $iface == wl* || $iface == eth* || $iface == en* ]]; then
      available+=("$iface")
    fi
  done
  if [ ${#available[@]} -eq 0 ]; then
    echo "No WiFi or Ethernet interfaces found."
    return 1
  fi
  echo "Found interfaces:"
  for i in "${!available[@]}"; do
    echo "$((i+1))) ${available[i]}"
  done
  read -p "Select an interface [1-${#available[@]}]: " selection
  if [[ $selection -ge 1 && $selection -le ${#available[@]} ]]; then
    echo "${available[$((selection-1))]}"
  else
    echo "Invalid selection."
    return 1
  fi
}

spoof_mac() {
  print_separator
  local iface
  iface=$(select_interface) || return 1
  echo "→ Selected interface: $iface"
  local backup_file="/tmp/original_mac_$iface"
  if [ ! -f "$backup_file" ]; then
    local orig_mac
    orig_mac=$(ip link show "$iface" | awk '/ether/ {print $2}')
    echo "$orig_mac" | sudo tee "$backup_file" > /dev/null
    echo "→ Original MAC ($orig_mac) saved to $backup_file."
  else
    echo "→ Backup for $iface already exists."
  fi
  read -p "Do you want to enter a custom MAC address? (y/n): " custom_mac_resp
  if [[ $custom_mac_resp =~ ^[yY] ]]; then
    read -p "Enter new MAC address (e.g., 00:11:22:33:44:55): " new_mac
  else
    if ! command -v macchanger &>/dev/null; then
      echo "macchanger is not installed. Installing..."
      sudo apt update -y && sudo apt install -y macchanger
    fi
    new_mac=$(sudo macchanger -r "$iface" | awk '/New MAC/ {print $3}')
    echo "→ Randomly generated MAC: $new_mac"
  fi
  echo "→ Applying MAC change to $iface..."
  sudo ip link set "$iface" down
  sudo ip link set "$iface" address "$new_mac"
  sudo ip link set "$iface" up
  echo "✓ MAC for $iface changed to $new_mac."
}

restore_mac() {
  print_separator
  local iface
  iface=$(select_interface) || return 1
  echo "→ Selected interface: $iface"
  local backup_file="/tmp/original_mac_$iface"
  if [ ! -f "$backup_file" ]; then
    echo "No backup found for $iface."
    return 1
  fi
  local orig_mac
  orig_mac=$(cat "$backup_file")
  echo "→ Restoring MAC for $iface to $orig_mac..."
  sudo ip link set "$iface" down
  sudo ip link set "$iface" address "$orig_mac"
  sudo ip link set "$iface" up
  echo "✓ MAC for $iface restored to $orig_mac."
  rm -f "$backup_file"
}

mac_menu() {
  while true; do
    echo ""
    echo "============= MAC Spoofing Menu ============="
    echo "1) Change (spoof) MAC"
    echo "2) Restore original MAC"
    echo "0) Return to main menu"
    read -p "Select an option: " mac_option
    case $mac_option in
      1) spoof_mac ;;
      2) restore_mac ;;
      0) break ;;
      *) echo "Invalid option. Please try again." ;;
    esac
    pause
  done
}

##############################
# Full Automation Function   #
##############################

ejecutar_todo() {
  update_system
  update_snap_flatpak
  clean_system
  update_distribution
  repair_packages
  install_pentest_tools
  install_office_tools
  check_reboot
}

##############################
# Main Menu                  #
##############################

print_banner
print_info

while true; do
  echo "========================================================"
  echo "          MAIN MENU - UBUNTU ADMINISTRATION             "
  echo "========================================================"
  echo "1)  Update system (APT update/upgrade/autoremove)"
  echo "2)  Clean system (logs, caches, temporary files)"
  echo "3)  Update Snap and Flatpak"
  echo "4)  Upgrade distribution (do-release-upgrade)"
  echo "5)  Repair broken packages"
  echo "6)  Install Pentesting and network tools"
  echo "7)  Install Office and basic utilities (including Brave, Chrome, Thunderbird)"
  echo "8)  Check if a restart is required"
  echo "9)  Docker Menu"
  echo "10) Run full automation process"
  echo "11) VPN Client Menu - Change Public IP"
  echo "12) Change/Restore MAC address"
  echo "13) Antivirus Menu (ClamAV)"
  echo "14) Uninstall installed tools (Pentesting and Office) [Non-essential Office tools only]"
  echo "0)  Exit"
  echo "========================================================"
  read -p "Select an option: " opcion
  case $opcion in
    1) update_system ;;
    2) clean_system ;;
    3) update_snap_flatpak ;;
    4) update_distribution ;;
    5) repair_packages ;;
    6) install_pentest_tools ;;
    7) install_office_tools ;;
    8) check_reboot ;;
    9) docker_menu ;;
    10) ejecutar_todo ;;
    11) vpn_cliente_menu ;;
    12) mac_menu ;;
    13) antivirus_menu ;;
    14) uninstall_tools ;;
    0)
      echo "Exiting the menu. Goodbye!"
      break
      ;;
    *)
      echo "Invalid option. Please choose a correct option."
      ;;
  esac
  pause
done

print_signature
