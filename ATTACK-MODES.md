# Evilginx Attack Modes Explained

## 🎯 Two Attack Modes

NAC-Tap supports two different Evilginx attack modes. Understanding the difference is critical.

---

## Mode 1: Transparent DNS Poisoning (Current Default)

### How It Works:
```
1. Victim types: login.microsoftonline.com
2. DNS poisoned to: 10.200.66.1 (your bridge IP)
3. Browser address bar shows: login.microsoftonline.com ✅
4. Browser connects to: https://10.200.66.1
5. ❌ SSL WARNING: Certificate invalid
6. User must bypass warning
7. If bypassed → Session captured
```

### Pros:
- ✅ **Truly transparent** - victim sees REAL Microsoft domain
- ✅ No phishing domain needed
- ✅ Works in airgapped environments
- ✅ Perfect for red team exercises with CA cert deployment

### Cons:
- ❌ **Requires SSL bypass** - victim sees big red warning
- ❌ Or requires pre-installing CA certificate on victim device
- ❌ Modern browsers block by default
- ❌ Success rate: Low without cert deployment

### Best For:
- Authorized penetration testing where you can install CA cert
- Corporate red team exercises
- Security awareness training
- Lab environments

### Setup:
```python
# In NAC-Tap WebUI, select:
Mode: Transparent
Phishlet: o365
Domain: (leave empty, uses login.microsoftonline.com)
```

---

## Mode 2: Phishing Domain (Traditional Evilginx)

### How It Works:
```
1. You own domain: micr0soft-login.com
2. You get Let's Encrypt cert for micr0soft-login.com ✅
3. DNS poisoning redirects login.microsoftonline.com → micr0soft-login.com
4. Browser address bar shows: micr0soft-login.com ⚠️
5. Browser connects to: https://micr0soft-login.com
6. ✅ No SSL warning - valid certificate!
7. Session captured
```

### Pros:
- ✅ **No SSL warnings** - valid certificate from Let's Encrypt
- ✅ No CA cert installation needed
- ✅ Higher success rate
- ✅ Works with any browser

### Cons:
- ❌ **NOT transparent** - victim sees fake domain in address bar
- ❌ Requires owning/registering a domain
- ❌ Requires getting SSL certificate for that domain
- ❌ Savvy users will notice fake domain
- ❌ Can be detected by DNS monitoring

### Best For:
- Traditional phishing campaigns
- When you can't install CA certs
- Public WiFi attacks
- Scenarios where user might not notice domain

### Setup:
```bash
# 1. Register domain (e.g., micr0soft-login.com)
# 2. Point A record to your server's public IP
# 3. Get Let's Encrypt certificate:
certbot certonly --standalone -d micr0soft-login.com

# 4. In NAC-Tap WebUI, select:
Mode: Phishing
Phishlet: o365
Domain: micr0soft-login.com
```

---

## 🤔 Which Mode Should You Use?

### Use **Transparent Mode** If:
- You're doing authorized red team testing
- You can pre-install CA certificate on victim devices
- You want the attack to be completely invisible
- Victim is in a controlled lab environment
- You're demonstrating MITM attacks for training

### Use **Phishing Mode** If:
- You can't install CA certificates
- You need higher success rate with no user interaction
- You have a convincing phishing domain
- You're testing social engineering effectiveness
- You're in a WiFi pineapple / evil twin scenario

---

## 🚫 What DOESN'T Work

### ❌ "Transparent Phishing" (What You Asked About)

**You CANNOT have:**
- Browser shows real domain (`login.microsoftonline.com`)
- AND valid SSL certificate (no warnings)
- Without installing custom CA certificate

**Why?** This is the entire point of SSL/TLS! It prevents exactly this attack.

The browser checks:
1. Domain in address bar: `login.microsoftonline.com`
2. Certificate CN/SAN: `login.microsoftonline.com`
3. Certificate issuer: Must be trusted CA

If you redirect DNS to your IP (10.200.66.1) and present a certificate for `login.microsoftonline.com`, the browser says:
- "This certificate is not signed by a trusted CA" → SSL WARNING

The ONLY ways around this:
1. Install your CA cert on victim device (Transparent Mode + CA cert)
2. Use your own domain with valid cert (Phishing Mode - not transparent)

---

## 📊 Comparison Table

| Feature | Transparent Mode | Phishing Mode |
|---------|------------------|---------------|
| **Domain in browser** | Real Microsoft domain | Your phishing domain |
| **SSL warnings** | Yes (unless CA installed) | No |
| **Requires own domain** | No | Yes |
| **Requires SSL cert** | No (self-signed) | Yes (Let's Encrypt) |
| **Truly invisible** | Yes | No |
| **Success rate (no prep)** | Low (10-20%) | High (50-70%) |
| **Success rate (with prep)** | Very high (90%+) | High (50-70%) |
| **Setup complexity** | Medium | High |
| **Best for** | Red team, training | Real phishing |

---

## 🛠️ Hybrid Approach: DNS Redirect to Phishing Domain

**What you originally suggested:**

```
1. Victim tries to visit: login.microsoftonline.com
2. DNS poisoning returns: micr0soft-login.com (your phishing domain)
3. Browser shows: micr0soft-login.com in address bar
4. Valid SSL cert, no warning
5. Session captured
```

**Is this better than traditional phishing?**

**Slightly**, because:
- User types the real domain (muscle memory)
- But still sees fake domain in browser
- So only marginally better than sending them a phishing link

**Setting this up:**

```bash
# In dnsmasq config
address=/login.microsoftonline.com/your-public-ip
address=/account.microsoft.com/your-public-ip

# Point those to your phishing domain
# But browser will still show the phishing domain!
```

**Verdict:** Not really better than traditional phishing. User still sees fake domain.

---

## ✅ Recommended Approach for NAC-Tap

**For maximum success, combine both:**

### Phase 1: Reconnaissance (Transparent Mode)
- Deploy NAC-Tap on network
- Use transparent mode with DNS poisoning
- See who bypasses SSL warnings (low security awareness)
- Capture those easy sessions

### Phase 2: Targeted Phishing (Phishing Mode)
- For users who didn't bypass SSL warning
- Switch to phishing mode with valid domain
- Send targeted phishing emails
- Higher success rate

---

## 🎓 Educational Summary

**The SSL Problem:**
- You can fool DNS (make victim go to wrong IP)
- You can't fool SSL (browser checks certificate)
- Browser WILL warn if certificate doesn't match
- Unless you install your own CA certificate

**The Transparency Problem:**
- Transparent = real domain in browser
- Real domain requires real certificate
- You can't get real certificate for Microsoft's domain
- So you must use self-signed → SSL warning

**The Only Solutions:**
1. Install CA cert (transparent, no warning)
2. Use fake domain with valid cert (not transparent, no warning)
3. Hope user bypasses warning (transparent, has warning)

**There is NO option for:** Transparent + No warning + No CA cert

This is working as intended to prevent MITM attacks!

---

## 🔐 Legal Notice

These techniques are for **authorized security testing only**. 

- ✅ Authorized penetration testing with written permission
- ✅ Red team exercises in corporate environments
- ✅ Security research in lab environments
- ✅ Security awareness training

- ❌ Unauthorized access to systems
- ❌ Real phishing attacks
- ❌ Stealing credentials
- ❌ Any illegal activity

Unauthorized computer access is a crime in most jurisdictions.

