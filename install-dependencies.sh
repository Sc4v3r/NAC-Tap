#!/bin/bash
#
# NAC Bridge Monitor - Dependency Installation Script
# Run as root: sudo bash install-dependencies.sh
#

set -e

echo "========================================"
echo "NAC Bridge Monitor - Installing Dependencies"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo bash install-dependencies.sh"
    exit 1
fi

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
    echo "✓ Detected Debian/Ubuntu-based system"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    echo "✓ Detected RedHat/CentOS-based system"
else
    echo "⚠️  Unknown OS - attempting Debian/Ubuntu installation"
    OS="debian"
fi

echo ""
echo "Installing system packages..."
echo ""

if [ "$OS" = "debian" ]; then
    # Update package list
    apt-get update
    
    # Install required packages
    apt-get install -y \
        python3 \
        python3-pip \
        tcpdump \
        iproute2 \
        bridge-utils \
        ethtool \
        wireshark-common \
        net-tools \
        iptables \
        ebtables
    
    echo ""
    echo "✓ Debian/Ubuntu packages installed"
    
elif [ "$OS" = "redhat" ]; then
    # Install required packages
    yum install -y \
        python3 \
        python3-pip \
        tcpdump \
        iproute \
        bridge-utils \
        ethtool \
        wireshark-cli \
        net-tools \
        iptables \
        ebtables
    
    echo ""
    echo "✓ RedHat/CentOS packages installed"
fi

echo ""
echo "Verifying installations..."
echo ""

# Verify tools
MISSING=""
for tool in python3 tcpdump ip bridge ethtool capinfos tail iptables ebtables; do
    if command -v $tool >/dev/null 2>&1; then
        VERSION=$(command -v $tool)
        echo "✓ $tool: $VERSION"
    else
        echo "✗ $tool: NOT FOUND"
        MISSING="$MISSING $tool"
    fi
done

echo ""
echo "Creating directories..."
mkdir -p /var/log/nac-captures
chmod 700 /var/log/nac-captures
echo "✓ /var/log/nac-captures created"

echo ""
echo "========================================"
if [ -z "$MISSING" ]; then
    echo "✅ All dependencies installed successfully!"
else
    echo "⚠️  Missing tools:$MISSING"
    echo "You may need to install these manually."
fi
echo "========================================"
echo ""
echo "Optional: Install PCredz for credential extraction"
echo "  git clone https://github.com/lgandx/PCredz.git /opt/PCredz"
echo "  cd /opt/PCredz && pip3 install -r requirements.txt"
echo ""
echo "Next steps:"
echo "  1. Run the NAC Bridge Monitor:"
echo "     sudo python3 script.py"
echo ""
echo "  2. Access web interface at:"
echo "     http://localhost:8080"
echo ""

