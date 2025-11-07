#!/bin/bash
#
# Evilginx2 Automated Installation Script
# For NAC-Tap MITM Edition
#

set -e  # Exit on error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

EVILGINX_DIR="/opt/evilginx2"
GO_VERSION="1.21.0"  # Using stable version known to work on ARM64
ARCH=$(uname -m)

# Determine architecture for Go download
case "$ARCH" in
    x86_64)
        GO_ARCH="amd64"
        ;;
    aarch64|arm64)
        GO_ARCH="arm64"
        ;;
    armv7l)
        GO_ARCH="armv6l"
        ;;
    *)
        echo -e "${RED}[ERROR]${NC} Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Evilginx2 Automated Installation        ║${NC}"
echo -e "${BLUE}║   For NAC-Tap MITM Edition                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
   exit 1
fi

echo -e "${YELLOW}[INFO]${NC} Detected architecture: $ARCH ($GO_ARCH)"
echo ""

# Step 1: Check and install dependencies
echo -e "${BLUE}[1/6]${NC} Installing dependencies..."
apt-get update -qq
apt-get install -y git wget curl build-essential 2>&1 | grep -v "^Reading" | grep -v "^Building" || true
echo -e "${GREEN}[✓]${NC} Dependencies installed"
echo ""

# Step 2: Install Go
echo -e "${BLUE}[2/6]${NC} Checking Go installation..."
if command -v go &> /dev/null; then
    INSTALLED_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo -e "${GREEN}[✓]${NC} Go already installed: $INSTALLED_GO_VERSION"
else
    echo -e "${YELLOW}[INFO]${NC} Installing Go ${GO_VERSION}..."
    
    cd /tmp
    GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TARBALL}"
    
    if [ -f "$GO_TARBALL" ]; then
        rm -f "$GO_TARBALL"
    fi
    
    echo -e "${YELLOW}[INFO]${NC} Downloading from: ${GO_URL}"
    wget -q --show-progress "${GO_URL}" || {
        echo -e "${RED}[ERROR]${NC} Failed to download Go"
        echo -e "${YELLOW}[INFO]${NC} Trying alternative version (1.20.0)..."
        GO_VERSION="1.20.0"
        GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        GO_URL="https://go.dev/dl/${GO_TARBALL}"
        wget -q --show-progress "${GO_URL}" || {
            echo -e "${RED}[ERROR]${NC} Failed to download Go ${GO_VERSION}"
            echo -e "${YELLOW}[INFO]${NC} You may need to install Go manually"
            echo -e "${YELLOW}[INFO]${NC} Visit: https://go.dev/dl/"
            exit 1
        }
    }
    
    # Remove old Go installation
    rm -rf /usr/local/go
    
    # Extract new Go
    tar -C /usr/local -xzf "$GO_TARBALL"
    rm -f "$GO_TARBALL"
    
    # Add to PATH
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    # Make persistent
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        echo 'export GOPATH=$HOME/go' >> /etc/profile
        echo 'export PATH=$PATH:$GOPATH/bin' >> /etc/profile
    fi
    
    echo -e "${GREEN}[✓]${NC} Go ${GO_VERSION} installed successfully"
fi
echo ""

# Verify Go installation
if ! command -v go &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Go installation failed"
    exit 1
fi

GO_VERSION_CHECK=$(go version)
echo -e "${GREEN}[✓]${NC} Go version: $GO_VERSION_CHECK"
echo ""

# Step 3: Clone Evilginx2 repository
echo -e "${BLUE}[3/6]${NC} Cloning Evilginx2 repository..."

if [ -d "$EVILGINX_DIR" ]; then
    echo -e "${YELLOW}[INFO]${NC} Evilginx directory exists, removing..."
    rm -rf "$EVILGINX_DIR"
fi

mkdir -p "$EVILGINX_DIR"

git clone https://github.com/kgretzky/evilginx2.git "$EVILGINX_DIR" 2>&1 | grep -v "^Cloning" || true

if [ ! -d "$EVILGINX_DIR" ]; then
    echo -e "${RED}[ERROR]${NC} Failed to clone repository"
    exit 1
fi

echo -e "${GREEN}[✓]${NC} Repository cloned to $EVILGINX_DIR"
echo ""

# Step 4: Build Evilginx2
echo -e "${BLUE}[4/6]${NC} Building Evilginx2..."
cd "$EVILGINX_DIR"

# Ensure Go modules are enabled
export GO111MODULE=on

# Build the binary
go build -o evilginx main.go 2>&1 | grep -v "^go: downloading" || true

if [ ! -f "$EVILGINX_DIR/evilginx" ]; then
    echo -e "${RED}[ERROR]${NC} Build failed"
    exit 1
fi

echo -e "${GREEN}[✓]${NC} Evilginx2 built successfully"
echo ""

# Step 5: Set permissions
echo -e "${BLUE}[5/6]${NC} Configuring permissions..."

# Make binary executable
chmod +x "$EVILGINX_DIR/evilginx"

# Allow binding to privileged ports (80, 443)
setcap CAP_NET_BIND_SERVICE=+eip "$EVILGINX_DIR/evilginx" 2>&1 || {
    echo -e "${YELLOW}[WARN]${NC} Could not set capabilities. You may need to run Evilginx as root."
}

echo -e "${GREEN}[✓]${NC} Permissions configured"
echo ""

# Step 6: Verify installation
echo -e "${BLUE}[6/6]${NC} Verifying installation..."

if [ -f "$EVILGINX_DIR/evilginx" ]; then
    VERSION_OUTPUT=$("$EVILGINX_DIR/evilginx" -h 2>&1 | head -n 1 || echo "Evilginx2")
    echo -e "${GREEN}[✓]${NC} Evilginx2 installed successfully!"
    echo -e "${GREEN}[✓]${NC} Binary location: $EVILGINX_DIR/evilginx"
    echo -e "${GREEN}[✓]${NC} Version: $VERSION_OUTPUT"
else
    echo -e "${RED}[ERROR]${NC} Verification failed"
    exit 1
fi
echo ""

# Check phishlets
if [ -d "$EVILGINX_DIR/phishlets" ]; then
    PHISHLET_COUNT=$(ls -1 "$EVILGINX_DIR/phishlets"/*.yaml 2>/dev/null | wc -l)
    echo -e "${GREEN}[✓]${NC} Found $PHISHLET_COUNT phishlets"
    
    # Check for Microsoft phishlets
    if [ -f "$EVILGINX_DIR/phishlets/o365.yaml" ]; then
        echo -e "${GREEN}[✓]${NC} Microsoft O365 phishlet available"
    else
        echo -e "${YELLOW}[WARN]${NC} O365 phishlet not found"
    fi
    
    if [ -f "$EVILGINX_DIR/phishlets/outlook.yaml" ]; then
        echo -e "${GREEN}[✓]${NC} Microsoft Outlook phishlet available"
    else
        echo -e "${YELLOW}[WARN]${NC} Outlook phishlet not found"
    fi
else
    echo -e "${YELLOW}[WARN]${NC} Phishlets directory not found"
fi
echo ""

# Create NAC-Tap data directories
echo -e "${BLUE}[INFO]${NC} Creating NAC-Tap data directories..."
mkdir -p /var/log/nac-captures/evilginx-config
chmod 750 /var/log/nac-captures/evilginx-config
echo -e "${GREEN}[✓]${NC} Data directories created"
echo ""

# Summary
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Installation Complete!                  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo -e "📍 ${BLUE}Installation Path:${NC} $EVILGINX_DIR/evilginx"
echo -e "📦 ${BLUE}Phishlets:${NC} $EVILGINX_DIR/phishlets/"
echo -e "🗂️  ${BLUE}Data Directory:${NC} /var/log/nac-captures/"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Start NAC-Tap: ${BLUE}sudo python3 nac-tap.py${NC}"
echo -e "  2. Open Web UI: ${BLUE}http://10.200.66.1:8080${NC}"
echo -e "  3. Go to Evilginx tab and start phishing campaign"
echo ""
echo -e "${GREEN}[✓]${NC} Installation completed successfully!"

