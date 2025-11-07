# NAC Tap - Quick Start Guide

## Initial Setup (First Time Only)

### 1. Install System Dependencies
```bash
sudo bash install-dependencies.sh
```

### 2. Setup Wi-Fi Management AP (Optional but Recommended)
This creates a Wi-Fi network you can connect to for managing the device:

```bash
sudo bash setup-wifi-ap.sh
```

You'll be prompted for:
- **SSID**: Network name (e.g., "NAC-Tap-MGMT")
- **Password**: WPA2 password (minimum 8 characters)

After setup:
- **Management IP**: 172.31.250.1
- **DHCP Range**: 172.31.250.50-150
- **Web Interface**: http://172.31.250.1:8080

## Running NAC Tap

### Option 1: Manual Start (Recommended)
```bash
sudo python3 nac-tap.py
```

### Option 2: Auto-start on Boot (systemd service)
```bash
# Copy files to /opt
sudo mkdir -p /opt/nac-tap
sudo cp nac-tap.py /opt/nac-tap/
sudo cp systemd/nac-tap.service /etc/systemd/system/

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable nac-tap.service
sudo systemctl start nac-tap.service

# Check status
sudo systemctl status nac-tap.service
```

## Connecting to NAC Tap

### Via Wi-Fi (If AP is configured)
1. Connect to Wi-Fi SSID you configured
2. Open browser: **http://172.31.250.1:8080**

### Via Ethernet
1. Connect to device's management port
2. Find device IP: `ip addr show`
3. Open browser: **http://<device-ip>:8080**

### Via localhost (SSH into device)
```bash
ssh user@172.31.250.1  # or device IP
```
Then open: **http://localhost:8080** in terminal browser, or forward port

## Using the Web Interface

### Status Tab - Basic Capture

#### Start Capture
1. Click **▶️ Start Capture**
2. Bridge automatically created between eth0 and eth1
3. Packets captured to `/var/log/nac-captures/capture-*.pcap`

#### View Credentials (Loot Tab)
1. Click **🎣 Loot** tab
2. Click **🔍 Analyze PCAP Now**
3. View raw PCredz output (includes NTLMv2 hashes, passwords, etc.)
4. Click **⬇️ Export Output (TXT)** to download

#### Stop Capture
1. Click **⏹️ Stop Capture**
2. Bridge remains active (transparent)
3. PCAP file saved and ready for download

#### Download PCAP
1. Click **⬇️ Download PCAP**
2. Analyze offline with Wireshark

### MITM Tab - Active Interception

#### Enable MITM Mode
1. Click **🎭 MITM** tab
2. (Optional) Enter remote VM IP if routing to external Kali/Responder
3. Click **🎭 Enable MITM**
4. Wait 30s for victim learning
5. Bridge learns victim MAC/IP automatically

#### Intercept Protocols
Click protocol cards to intercept:
- **SMB/NetBIOS** (ports 137, 138, 139, 445)
- **Name Resolution** (LLMNR, mDNS)
- **HTTP** (port 80)

Traffic redirected to:
- **Local**: Bridge IP 10.200.66.1 (run Responder/ntlmrelayx on device)
- **Remote**: Your external attack VM (via WiFi)

#### Run Attack Tools
On the device or remote VM:
```bash
# On bridge IP (local)
sudo responder -I br0 -wrf

# Or ntlmrelayx
ntlmrelayx.py -t smb://target -smb2support

# Remote VM gets traffic forwarded automatically
```

#### Disable MITM
1. Click **🛑 Disable MITM**
2. All rules and spoofing cleaned up automatically

## File Locations

- **PCAP files**: `/var/log/nac-captures/capture-*.pcap`
- **Credentials**: `/var/log/nac-captures/loot_raw.txt`
- **Logs**: `/var/log/auto-nac-bridge.log`
- **Config**: `/var/run/auto-nac-state.conf`

## Stopping NAC Tap

### If running in terminal
Press **Ctrl+C**

### If running as service
```bash
sudo systemctl stop nac-tap.service
```

## Troubleshooting

### Check logs
```bash
sudo tail -f /var/log/auto-nac-bridge.log
```

### Check service status
```bash
sudo systemctl status nac-tap.service
sudo journalctl -u nac-tap.service -f
```

### Check Wi-Fi AP
```bash
systemctl status hostapd
systemctl status dnsmasq
iw dev wlan0 info
```

### Verify bridge
```bash
ip link show br0
bridge link show
```

### Restart everything
```bash
sudo systemctl restart hostapd dnsmasq nac-tap
```

## Hardware Requirements

- **Minimum**: 2 Ethernet ports (eth0, eth1)
- **Recommended**: 1 Wi-Fi interface (wlan0) for management
- **CPU**: Any ARM/x86 with 2+ cores
- **RAM**: 512MB+ (1GB+ recommended for large captures)
- **Storage**: 8GB+ (depends on capture size)

## Network Topology

```
Client Device ←→ [eth0 ←→ br0 ←→ eth1] ←→ Switch/Network
                       ↓
                   tcpdump
                       ↓
                  PCAP files
                       ↓
                    PCredz
                       ↓
                 Credentials

Management:
  wlan0 (172.31.250.1) ← Wi-Fi AP for remote access
```

## Security Notes

- Script requires root privileges
- PCAP files contain sensitive network traffic
- Credential files restricted to root (600 permissions)
- Wi-Fi AP should use strong WPA2 password
- Keep management interface (wlan0) on isolated network
- Regularly clear old PCAP files to save space

## Next Steps

1. Setup Wi-Fi AP: `sudo bash setup-wifi-ap.sh`
2. Start NAC Tap: `sudo python3 nac-tap.py`
3. Connect to Wi-Fi and access http://172.31.250.1:8080
4. Start capture and monitor traffic

