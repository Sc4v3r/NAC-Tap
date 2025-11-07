#!/bin/bash
#
# Wi-Fi Access Point Setup Script for NAC Tap Device
# Creates a management AP on wlan0 for remote access
# Tested on Ubuntu/Debian ARM (NanoPi, Raspberry Pi, etc.)
#
# Usage: sudo bash setup-wifi-ap.sh
#

set -e

echo "========================================"
echo "NAC Tap - Wi-Fi AP Setup"
echo "Management Interface Configuration"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo bash setup-wifi-ap.sh"
    exit 1
fi

echo "=== Installing required packages ==="
apt update
apt install -y hostapd dnsmasq

echo ""
echo "=== Stopping services temporarily ==="
systemctl stop hostapd dnsmasq 2>/dev/null || true
systemctl disable hostapd dnsmasq 2>/dev/null || true
systemctl mask hostapd 2>/dev/null || true

echo ""
# Prompt for SSID and Password
read -p "Enter the SSID for your AP: " AP_SSID
while true; do
    read -s -p "Enter the WPA2 password (min 8 chars): " AP_PASS
    echo
    read -s -p "Confirm the WPA2 password: " AP_PASS2
    echo
    if [ "$AP_PASS" = "$AP_PASS2" ] && [ ${#AP_PASS} -ge 8 ]; then
        break
    else
        echo "❌ Passwords do not match or are too short, try again."
    fi
done

echo ""
echo "=== Configuring static IP for wlan0 ==="
rm -f /etc/netplan/99-wlan-ap.yaml 2>/dev/null || true

cat > /etc/systemd/network/25-wlan0.network <<EOF
[Match]
Name=wlan0

[Network]
Address=172.31.250.1/24
IPForward=yes
EOF

systemctl restart systemd-networkd
ip link set wlan0 up
sleep 2

echo ""
echo "=== Configuring dnsmasq for DHCP ==="
systemctl stop dnsmasq 2>/dev/null || true
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null || true

cat > /etc/dnsmasq.conf <<EOF
# NAC Tap Management Interface DHCP
port=0
interface=wlan0
dhcp-range=172.31.250.50,172.31.250.150,12h
dhcp-option=3,172.31.250.1
dhcp-option=6,172.31.250.1
EOF

systemctl start dnsmasq
systemctl enable dnsmasq

echo ""
echo "=== Configuring hostapd ==="
cat > /etc/hostapd/hostapd.conf <<EOF
# NAC Tap Management AP Configuration
interface=wlan0
ssid=${AP_SSID}
hw_mode=g
channel=6
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=${AP_PASS}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

# Enable hostapd service
systemctl unmask hostapd
systemctl enable hostapd
systemctl start hostapd

echo ""
echo "========================================"
echo "✅ Wi-Fi AP Setup Complete!"
echo "========================================"
echo ""
echo "Network Details:"
echo "  SSID: $AP_SSID"
echo "  Static IP: 172.31.250.1"
echo "  DHCP Range: 172.31.250.50-150"
echo ""
echo "Access NAC Tap Web Interface:"
echo "  1. Connect to Wi-Fi: $AP_SSID"
echo "  2. Open browser: http://172.31.250.1:8080"
echo ""
echo "SSH Access:"
echo "  ssh user@172.31.250.1"
echo ""
echo "To start NAC Tap monitoring:"
echo "  sudo python3 nac-tap.py"
echo ""
echo "To check AP status:"
echo "  systemctl status hostapd"
echo "  systemctl status dnsmasq"
echo ""

