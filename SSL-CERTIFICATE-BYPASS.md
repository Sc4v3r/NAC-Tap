# SSL Certificate Bypass for DNS Poisoning Attacks

## 🔐 The SSL Certificate Problem

When performing DNS poisoning attacks with Evilginx, you'll encounter a **critical SSL certificate issue**:

### Normal Flow (Without Attack):
```
Victim → DNS: "What's login.microsoftonline.com?" 
     → DNS: "It's 40.126.28.112" (Microsoft's real IP)
     → HTTPS to 40.126.28.112
     → Microsoft presents valid certificate (signed by trusted CA)
     → ✅ Browser accepts, shows green lock
```

### DNS Poisoning Flow:
```
Victim → DNS: "What's login.microsoftonline.com?"
     → DNS: "It's 10.200.66.1" (YOUR bridge IP - POISONED!)
     → HTTPS to 10.200.66.1
     → Evilginx presents self-signed certificate for login.microsoftonline.com
     → ❌ Browser rejects, shows BIG RED WARNING
     → Connection blocked or user must bypass warning
```

## 🎯 Why 10.200.66.1?

**10.200.66.1 is your bridge IP** - this is correct and necessary:

- **Bridge Interface**: `br0` is assigned IP 10.200.66.1
- **DNS Poisoning**: All Microsoft domains resolve to 10.200.66.1
- **Evilginx Listening**: Evilginx listens on 10.200.66.1:443 and 10.200.66.1:80
- **Traffic Flow**: Victim → 10.200.66.1 → Evilginx → Real Microsoft

## ⚠️ Why Sessions Aren't Captured

If sessions aren't being captured, it's because:

1. **Browser blocks connection** due to invalid SSL certificate
2. **Victim doesn't proceed** past the warning
3. **No traffic reaches Evilginx** = no session to capture

## ✅ Solutions (For Authorized Testing)

### Option 1: Manual Certificate Bypass (Testing Only)

**On the victim device:**

1. Browser will show "Your connection is not private" or similar
2. Click **"Advanced"**
3. Click **"Proceed to [domain] (unsafe)"**
4. Now the attack works and sessions will be captured

**Pros**: Quick for testing
**Cons**: Obvious warning, not realistic for real attacks

### Option 2: Install Evilginx CA Certificate (Best for Lab)

**Find the Evilginx CA certificate:**
```bash
# On the appliance
ls ~/.evilginx/crt/*.crt
# Or
ls /var/log/nac-captures/evilginx-config/*.crt
```

**Install on victim device:**

**Windows:**
1. Copy the `.crt` file to victim
2. Double-click → "Install Certificate"
3. Select "Local Machine"
4. Place in "Trusted Root Certification Authorities"
5. Restart browser

**macOS:**
1. Copy the `.crt` file to victim
2. Double-click → Keychain Access opens
3. Add to "System" keychain
4. Double-click cert → Trust → "Always Trust"
5. Restart browser

**Linux:**
```bash
sudo cp evilginx.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**Pros**: Transparent attack, no warnings
**Cons**: Requires victim device access

### Option 3: Firefox with Custom CA (Easy for Testing)

**On victim's Firefox:**
1. Type `about:config` in address bar
2. Search for: `security.enterprise_roots.enabled`
3. Set to `true`
4. Import Evilginx CA via Settings → Privacy & Security → Certificates → View Certificates

**Pros**: Firefox-specific, doesn't affect system
**Cons**: Only works in Firefox

### Option 4: HTTP Downgrade (Limited)

**NOT RECOMMENDED** for Microsoft 365:
- Microsoft uses HSTS (HTTP Strict Transport Security)
- Browsers force HTTPS for microsoft.com domains
- HTTP downgrade won't work

### Option 5: Custom Phishing Domain (Traditional Evilginx)

**Instead of DNS poisoning, use traditional phishing:**

1. Register similar domain: `micr0soft-login.com`
2. Get Let's Encrypt certificate for your domain
3. Configure Evilginx with your domain
4. Send phishing email with your domain
5. No SSL warnings!

**Pros**: No SSL warnings, works perfectly
**Cons**: Not transparent, requires phishing lure, victim sees fake domain

## 🔍 Troubleshooting: Is It Really the SSL Issue?

**Check Evilginx logs:**
```bash
tail -f /var/log/nac-captures/evilginx.log
```

**Look for:**
- `TLS handshake error` → SSL certificate problem
- `Client connected` → Victim bypassed warning!
- `HTTP REQUEST` → Traffic is flowing
- `SESSION CAPTURED` → Attack worked!

**Check if Evilginx is listening:**
```bash
ss -tlnp | grep 443
ss -tlnp | grep 80
```

Should show Evilginx listening on 10.200.66.1:443 and 10.200.66.1:80

**Test DNS poisoning:**
```bash
# From victim device
nslookup login.microsoftonline.com 10.200.66.1
# Should return 10.200.66.1
```

**Test HTTPS connection:**
```bash
# From victim device
curl -k https://login.microsoftonline.com -v
# -k ignores SSL errors
# Should connect to Evilginx
```

## 📊 Real-World Attack Scenarios

### Scenario 1: Corporate Environment (Realistic)

**Setup:**
1. Deploy NAC-Tap inline on corporate network
2. Push custom CA certificate via Group Policy (requires admin)
3. DNS poisoning becomes transparent
4. Users see no warnings
5. Sessions captured silently

**Success Rate**: High (if you control certificate deployment)

### Scenario 2: Evil Twin WiFi (Moderate)

**Setup:**
1. Create rogue WiFi AP
2. Victim connects to your WiFi
3. DNS poisoning works
4. Victim sees SSL warning
5. Some users click through

**Success Rate**: 10-30% (depends on user security awareness)

### Scenario 3: Traditional Phishing (High Success)

**Setup:**
1. Use phishing domain with valid certificate
2. Send targeted phishing email
3. No DNS poisoning needed
4. No SSL warnings
5. Looks completely legitimate

**Success Rate**: 50-70% (with good social engineering)

## 🎯 NAC-Tap Best Use Case

NAC-Tap's DNS poisoning is **ideal for**:
- **Authorized penetration testing** in corporate environments
- **Red team exercises** where you can pre-install CA certificates
- **Security awareness training** to demonstrate MITM attacks
- **Lab environments** for security research

**Not ideal for**:
- Real attacks without certificate deployment (too obvious)
- Public WiFi attacks (users will see warnings)
- Quick drive-by attacks (requires user interaction)

## 📝 Summary

**Why DNS queries go to 10.200.66.1**: That's your bridge IP, it's correct!

**Why sessions aren't captured**: Victim's browser blocks the connection due to invalid SSL certificate.

**Solution**: Install Evilginx's CA certificate on victim device, or have victim bypass the warning manually.

**Remember**: This is for **authorized security testing only**. Unauthorized access to computer systems is illegal.

