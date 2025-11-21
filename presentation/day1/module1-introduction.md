# Day 1 - Module 1: Introduction & Lab Setup

**Duration:** 1.25 hours
**Prerequisites:** None (first module)

---

## Slide 1: Welcome & Course Introduction

### Advanced Web Application Exploitation Training

**Your Instructors:**
- [Instructor Names]
- [Credentials/Certifications]

**Course Objectives:**
- Master advanced web application exploitation techniques
- Build practical, hands-on security assessment skills
- Gain certification in web application security

---

## Slide 2: What Makes This Training Different?

### Real-World Focus

- **Scenario-Driven Labs:** Not just textbook vulnerabilities
- **Attack Chain Methodology:** Learn how attackers think and pivot
- **Modern Technologies:** OAuth, SAML, GraphQL, gRPC, modern crypto
- **Industry-Relevant:** Based on actual penetration testing engagements

### Hands-On Learning

- 40% instruction, 60% hands-on labs
- Capture-the-flag style challenges
- Capstone project simulating real assessments
- Build your own exploit toolkit

---

## Slide 3: Course Structure Overview

| Day | Focus Area | Key Deliverable |
|-----|------------|-----------------|
| 1 | Authentication Attacks | Auth bypass PoC |
| 2 | Business Logic Flaws | Race condition exploit |
| 3 | API Security & XXE | XXE + API chain |
| 4 | Crypto & RCE | RCE exploit |
| 5 | Capstone Assessment | Full attack chain |
| 6 | Certification Exam | Certificate |

---

## Slide 4: Web Application Architecture Overview

### The Modern Web Stack

```
┌─────────────────────────────────────┐
│      Client (Browser/Mobile)        │
│  JavaScript / React / Angular       │
└──────────────┬──────────────────────┘
               │ HTTPS
               │
┌──────────────▼──────────────────────┐
│     Load Balancer / CDN             │
│   (Cloudflare, AWS CloudFront)      │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│     Web Application Firewall        │
│   (ModSecurity, AWS WAF)            │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│     Application Server              │
│  Node.js / Django / Spring Boot     │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│     Database / Cache                │
│  PostgreSQL / MongoDB / Redis       │
└─────────────────────────────────────┘
```

### Attack Surface Areas

1. **Client-side:** XSS, CSRF, DOM-based attacks
2. **Network layer:** SSL/TLS vulnerabilities, MITM
3. **Application logic:** Auth bypass, IDOR, injection
4. **API layer:** GraphQL introspection, REST endpoint abuse
5. **Infrastructure:** Misconfigurations, exposed services

---

## Slide 5: HTTP Protocol Deep Dive

### HTTP Request Anatomy

```http
POST /api/v1/login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: application/json
Content-Type: application/json
Content-Length: 58
Cookie: sessionid=abc123; _ga=GA1.2.123456789
Authorization: Bearer eyJhbGc...

{"username":"admin","password":"P@ssw0rd"}
```

**Key Components to Analyze:**
- **Method:** GET, POST, PUT, DELETE, OPTIONS, PATCH
- **Headers:** Authorization, Cookie, Content-Type, X-Custom headers
- **Body:** JSON, XML, form-data, multipart
- **Parameters:** Query string, path parameters, body parameters

### HTTP Response Analysis

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: application/json
Set-Cookie: sessionid=xyz789; HttpOnly; Secure; SameSite=Strict
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Access-Control-Allow-Origin: https://trusted.com

{"token":"eyJhbGc...","user_id":1234,"role":"admin"}
```

**Security Headers to Check:**
- CSP, X-Frame-Options, HSTS, CORS
- Cookie attributes (HttpOnly, Secure, SameSite)
- Custom security headers

---

## Slide 6: Web Proxies - Your Primary Tool

### Why Use a Web Proxy?

1. **Intercept & Modify:** Change requests/responses in real-time
2. **Repeat & Automate:** Replay attacks with variations
3. **Decode & Analyze:** Automatically decode Base64, JWT, etc.
4. **Scan & Discover:** Find hidden endpoints and parameters
5. **Test & Exploit:** Built-in vulnerability scanners

### Burp Suite Components

- **Proxy:** Intercept HTTP/HTTPS traffic
- **Repeater:** Manual request manipulation
- **Intruder:** Automated fuzzing and brute-forcing
- **Scanner:** Active/passive vulnerability detection
- **Decoder:** Encoding/decoding utilities
- **Comparer:** Diff tool for responses
- **Extender:** Plugin ecosystem

### Alternative Tools

- **OWASP ZAP:** Free, open-source alternative
- **mitmproxy:** Python-based, scriptable proxy
- **Caido:** Modern alternative with great UX

---

## Slide 7: Penetration Testing Methodologies

### PTES (Penetration Testing Execution Standard)

1. **Pre-engagement:** Scope, rules of engagement, contracts
2. **Intelligence Gathering:** OSINT, subdomain enumeration
3. **Threat Modeling:** Identify attack vectors
4. **Vulnerability Analysis:** Find weaknesses
5. **Exploitation:** Prove impact
6. **Post-Exploitation:** Maintain access, lateral movement
7. **Reporting:** Document findings, remediation advice

### OWASP Testing Guide Phases

1. **Information Gathering**
2. **Configuration & Deployment Management**
3. **Identity Management**
4. **Authentication Testing**
5. **Authorization Testing**
6. **Session Management**
7. **Input Validation**
8. **Error Handling**
9. **Cryptography**
10. **Business Logic**
11. **Client-side Testing**

---

## Slide 8: Reconnaissance as an Expert

### Passive Reconnaissance

**Goal:** Gather information without touching the target

**Techniques:**
```bash
# Subdomain enumeration
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq

# OSINT gathering
theHarvester -d target.com -b all
shodan search hostname:target.com

# GitHub/GitLab reconnaissance
# Search for: target.com, API keys, credentials
truffleHog --regex --entropy=False https://github.com/target/repo
```

### Active Reconnaissance

**Goal:** Directly interact to map attack surface

**Techniques:**
```bash
# Port scanning
nmap -sV -sC -p- target.com

# Directory/file discovery
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,401,403

# Endpoint discovery
gospider -s https://target.com -d 3 -c 10

# Technology fingerprinting
whatweb target.com
wappalyzer (browser extension)

# JavaScript file analysis
# Extract endpoints from JS files
cat app.js | grep -oP '"/api/[^"]*"' | sort -u
```

### Smart Reconnaissance Strategy

1. **Map the application thoroughly:**
   - Sitemap generation with crawler
   - Identify all input points
   - Note authentication boundaries

2. **Identify technologies:**
   - Framework detection (React, Angular, Django, etc.)
   - Server fingerprinting
   - Third-party integrations

3. **Document interesting patterns:**
   - API versioning (/api/v1, /api/v2)
   - Parameter naming conventions
   - Authentication mechanisms

4. **Build target profile:**
   - Authentication methods (SSO, OAuth, local)
   - Session management approach
   - API architecture (REST, GraphQL, gRPC)

---

## Slide 9: Lab Environment Setup

### Required Tools Installation

**Linux (Kali/Ubuntu):**
```bash
# Update package lists
sudo apt update

# Install Burp Suite Community
wget -O burp.sh "https://portswigger.net/burp/releases/download?product=community&version=latest&type=Linux"
chmod +x burp.sh
sudo ./burp.sh

# Install Firefox ESR (recommended for Burp)
sudo apt install firefox-esr

# Install Python tools
pip3 install requests beautifulsoup4 pyjwt

# Install recon tools
sudo apt install subfinder ffuf gobuster nuclei

# Install Docker
sudo apt install docker.io docker-compose
sudo systemctl start docker
sudo usermod -aG docker $USER
```

**macOS:**
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Burp Suite
brew install --cask burpsuite

# Install tools
brew install python3 docker
pip3 install requests pyjwt
```

### Browser Configuration for Burp

**Step 1: Configure Proxy Settings**
- Firefox → Settings → Network Settings → Manual proxy
- HTTP Proxy: `127.0.0.1` Port: `8080`
- Check "Use this proxy server for all protocols"

**Step 2: Install Burp CA Certificate**
1. Start Burp Suite
2. Browse to http://burp (with proxy enabled)
3. Download CA certificate
4. Firefox → Settings → Privacy & Security → Certificates → Import
5. Trust for identifying websites

**Step 3: Verify Setup**
- Browse to https://example.com
- Check Burp Proxy → HTTP History for captured traffic

---

## Slide 10: Lab 1 - Setup & Reconnaissance

### Lab Objectives

1. Configure Burp Suite and browser proxy
2. Map the target application
3. Perform subdomain enumeration
4. Collect technology stack information
5. Generate reconnaissance report

### Target Application

**URL:** `https://lab1.webapp-training.local`

**Credentials:**
- Regular user: `user1:password123`
- Admin user: `admin:admin123`

### Lab Tasks

**Task 1: Burp Suite Configuration (15 min)**
- Install and configure Burp Suite
- Set up browser proxy
- Verify HTTPS interception
- Explore Burp interface

**Task 2: Application Mapping (30 min)**
```bash
# Use Burp's crawler
# Target → Site map → Right-click domain → Spider this host

# Manual exploration
# Browse all application features while Burp captures traffic:
- Registration page
- Login page
- User dashboard
- API endpoints
- Admin panel (if accessible)

# Export site map
# Target → Site map → Right-click → Save selected items
```

**Task 3: Reconnaissance (30 min)**
```bash
# Subdomain enumeration
subfinder -d webapp-training.local -o subdomains.txt
cat subdomains.txt

# Directory brute-forcing
ffuf -u https://lab1.webapp-training.local/FUZZ \
     -w /usr/share/wordlists/dirb/common.txt \
     -mc 200,301,302,401,403 \
     -o directories.json

# Technology detection
whatweb https://lab1.webapp-training.local

# Check robots.txt and sitemap.xml
curl https://lab1.webapp-training.local/robots.txt
curl https://lab1.webapp-training.local/sitemap.xml

# JavaScript file analysis
# Download main JS files and search for endpoints
curl https://lab1.webapp-training.local/static/js/main.js | \
  grep -oP '"/[^"]*"' | sort -u > endpoints.txt
```

**Task 4: Documentation (15 min)**

Create a reconnaissance report with:
- Target application overview
- Technology stack identified
- Discovered endpoints and subdomains
- Interesting findings (hidden pages, comments in source, etc.)
- Attack surface summary

### Expected Deliverables

1. Burp project file with captured traffic
2. List of discovered subdomains
3. List of discovered directories/endpoints
4. Technology fingerprint report
5. Initial reconnaissance notes

### Success Criteria

- Burp Suite properly intercepting HTTPS traffic
- At least 20+ endpoints discovered
- Technology stack documented
- Clear understanding of application structure

---

## Slide 11: Reconnaissance Findings to Look For

### High-Value Targets

**1. Hidden Endpoints**
```
/admin
/api/internal
/debug
/graphql
/actuator
/.git
/swagger.json
/api-docs
```

**2. Backup/Test Files**
```
/backup.sql
/database.sql.bak
/.env
/config.php.bak
/test.php
```

**3. Information Disclosure**
```
# Comments in HTML/JS source
<!-- TODO: Remove debug endpoint /api/internal/debug -->

# Verbose error messages
{"error": "SQL syntax error at line 42 in users.php"}

# Server headers
X-Powered-By: PHP/7.4.3
Server: Apache/2.4.41 (Ubuntu)
```

**4. API Versioning**
```
/api/v1/users
/api/v2/users
# Test if v1 has weaker security controls
```

**5. Authentication Mechanisms**
- SSO endpoints (SAML, OAuth callback URLs)
- Password reset flows
- Registration endpoints
- Session management approach

---

## Slide 12: Common Reconnaissance Mistakes

### Mistakes to Avoid

1. **Incomplete mapping**
   - Only testing logged-out state
   - Missing authenticated endpoints
   - Not testing different user roles

2. **Ignoring client-side code**
   - JavaScript files contain gold mines
   - API endpoints, internal URLs
   - Hard-coded secrets (it happens!)

3. **Not documenting findings**
   - Can't remember what you found later
   - Hard to chain attacks without notes

4. **Noisy scanning**
   - Getting blocked by WAF/rate limiting
   - Use throttling and smart wordlists

5. **Tunnel vision**
   - Focusing only on main application
   - Missing subdomains, mobile APIs, partner integrations

### Pro Tips

- Always test both HTTP and HTTPS versions
- Check for HTTP parameter pollution opportunities
- Note differences between API versions
- Screenshot interesting findings immediately
- Use Burp's "Copy as curl command" for repeatable tests

---

## Slide 13: Break & Next Module Preview

### Coffee Break (15 minutes)

### Coming Up Next: Module 2 - Authentication Attacks

We'll cover:
- JWT exploitation techniques
- SAML authorization bypass
- OAuth misconfiguration attacks
- 2FA bypass methods
- Subdomain takeover for auth bypass

**Action Items During Break:**
- Ensure Burp Suite is working
- Complete any remaining setup tasks
- Review your reconnaissance notes

---

## Instructor Notes

### Timing Breakdown
- Slides 1-3: 15 min (Introduction)
- Slides 4-6: 20 min (Web architecture & HTTP)
- Slides 7-8: 20 min (Methodology & Recon)
- Slide 9: 15 min (Setup walkthrough)
- Slides 10-11: 45 min (Hands-on lab)
- Slide 12-13: 5 min (Wrap-up)

### Common Student Issues
- Certificate installation problems (have backup instructions ready)
- Proxy configuration errors (prepare screenshots)
- Docker networking on various OSes
- Permission issues on Linux

### Lab Environment Setup
- Pre-build Docker images for vulnerable apps
- Have backup VMs ready if student machines fail
- Provide offline wordlist copies
- Test all lab targets before class

### Assessment Opportunities
- Check if students can capture HTTPS traffic
- Verify reconnaissance findings match expected results
- Ensure proper documentation practices

### Additional Resources
- Burp Suite documentation links
- OWASP Testing Guide
- Wordlist repositories
- Reconnaissance cheat sheets
