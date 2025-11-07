# NAC Bridge Monitor - Installation Guide

## System Requirements

- **OS**: Linux (Debian/Ubuntu, RedHat/CentOS, or compatible)
- **Python**: 3.7 or higher
- **Privileges**: Must run as root (requires network bridge control)
- **Hardware**: Minimum 2 Ethernet interfaces (for inline tap)

## Quick Install

### Automated Installation (Recommended)

```bash
# Download and run installation script
sudo bash install-dependencies.sh
```

This will install:
- Python 3
- tcpdump (packet capture)
- iproute2 (network bridge management)
- bridge-utils (bridge utilities)
- ethtool (network interface configuration)
- wireshark-common/capinfos (packet analysis)
- net-tools (network utilities)

### Manual Installation

#### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y python3 tcpdump iproute2 bridge-utils ethtool wireshark-common net-tools
```

#### RedHat/CentOS
```bash
sudo yum install -y python3 tcpdump iproute bridge-utils ethtool wireshark-cli net-tools
```

## Python Dependencies

The script uses **only Python standard library** - no pip packages required!

Imports used:
- os, sys, json, subprocess, re, time, signal, threading
- datetime, http.server, urllib.parse

To verify Python version:
```bash
python3 --version  # Should be 3.7 or higher
```

## Optional: PCredz Installation

For automatic credential extraction from PCAP files:

```bash
# Clone PCredz
sudo git clone https://github.com/lgandx/PCredz.git /opt/PCredz

# Install PCredz dependencies
cd /opt/PCredz
sudo pip3 install -r requirements.txt

# Create wrapper script
sudo tee /opt/PCredz/pcredz-wrapper.sh > /dev/null << 'EOF'
#!/bin/bash
cd /opt/PCredz
python3 Pcredz "$@"
EOF

sudo chmod +x /opt/PCredz/pcredz-wrapper.sh
```

## Directory Setup

The script will automatically create these directories:
- `/var/log/nac-captures` - PCAP files storage
- `/var/run/` - PID and state files (temporary)

## Verification

After installation, verify all tools are available:

```bash
# Check Python
python3 --version

# Check network tools
which tcpdump ip bridge ethtool capinfos tail

# Check permissions
sudo python3 -c "import os; print('✓ Root check OK' if os.geteuid() == 0 else '✗ Not root')"
```

## Running the Script

```bash
# Make script executable (optional)
chmod +x script.py

# Run with root privileges
sudo python3 script.py

# Access web interface
# Open browser to: http://localhost:8080
```

## Systemd Service (Optional)

To run as a system service, see the `systemd/` directory for service files.

## Troubleshooting

### Missing capinfos
If `capinfos` is not found:
```bash
# Debian/Ubuntu
sudo apt-get install wireshark-common

# RedHat/CentOS  
sudo yum install wireshark-cli
```

### Permission Denied Errors
Ensure you're running with sudo:
```bash
sudo python3 script.py
```

### Network Interface Not Found
- Verify you have at least 2 Ethernet interfaces
- Check with: `ip link show`
- Wireless interfaces are automatically excluded

## Security Notes

- Script requires root for network bridge control
- PCAP files contain network traffic (stored with 600 permissions)
- Credential files are restricted to root only
- Web interface runs on port 8080 (configurable in script)

## Support

For issues:
1. Check logs: `/var/log/auto-nac-bridge.log`
2. Verify all tools are installed: `./install-dependencies.sh` (dry-run mode)
3. Check Python version: `python3 --version` (must be 3.7+)

