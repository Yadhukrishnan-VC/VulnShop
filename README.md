# 🛡️ VulnShop — Enterprise Vulnerable Django E-Commerce

> ⚠️ **FOR SECURITY TESTING AND EDUCATION ONLY**
> This application is intentionally insecure. Never deploy to production or expose to the internet.

---

## 🚀 Quick Start

```bash
git clone <repo>
cd vulnshop
docker-compose up --build
```

| Service        | URL                        | Credentials             |
|---------------|----------------------------|-------------------------|
| VulnShop App  | http://localhost:8000      | admin / admin123        |
| Scanner UI    | http://localhost:9000      | (no auth)               |
| Django Admin  | http://localhost:8000/admin| admin / admin123        |
| PostgreSQL    | localhost:5432             | admin / admin123        |

**Test users:**

| Username | Password     | Role   |
|----------|-------------|--------|
| admin    | admin123    | Superuser |
| alice    | password123 | Buyer  |
| bob      | password123 | Buyer  |
| vendor1  | vendor123   | Vendor |

---

## 🔍 Running the Scanner

1. Open http://localhost:9000
2. Click **▶ Start Scan**
3. Wait ~3–5 minutes for all modules to complete
4. Click **⬇ PDF Report** to download the full Burp Suite-style report

---

## 🔴 Complete Vulnerability Index

### INJECTION ATTACKS

| ID | Endpoint | Vulnerability | Payload |
|----|----------|--------------|---------|
| SQLI-001 | `GET /search/?q=` | SQL Injection (UNION/error/time/boolean) | `' UNION SELECT username,password FROM auth_user--` |
| SQLI-002 | `POST /login/` | Auth bypass via SQLi | `admin'--` |
| CMDI-001 | `GET /ping/?host=` | OS Command Injection → RCE | `127.0.0.1; id` |
| XSS-001 | `GET /search/?q=` | Reflected XSS | `<script>alert(document.cookie)</script>` |
| XSS-002 | `POST /review/<id>/` | Stored XSS via review | `<img src=x onerror=alert(1)>` |
| SSTI-001 | `GET /template/?name=` | SSTI → RCE | `{{ 7|add:7 }}` / `{{''.__class__.__mro__}}` |
| XXE-001 | `POST /import/xml/` | XML External Entity | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| DESER-001 | `POST /prefs/load/` | Pickle Deserialization → RCE | Crafted base64 pickle payload |
| PATH-001 | `GET /download/?file=` | Path Traversal | `../../../../etc/passwd` |
| SSRF-001 | `POST /webhook/test/` | Server-Side Request Forgery | `http://169.254.169.254/latest/meta-data/` |

### AUTHENTICATION & SESSION

| ID | Endpoint | Vulnerability |
|----|----------|--------------|
| AUTH-001 | `POST /login/` | No brute force protection / rate limiting |
| AUTH-002 | `POST /register/` | Username enumeration via error messages |
| SESS-001 | All | Session cookie missing Secure/HttpOnly/SameSite flags |
| CSRF-001 | All POST | CSRF middleware disabled |
| JWT-001 | `GET /api/jwt/verify/` | JWT "none" algorithm accepted |
| JWT-002 | `POST /api/login/` | JWT signed with weak secret "secret" |
| JWT-003 | All JWT | No expiry claim on JWT tokens |
| PR-001 | `POST /password-reset/` | Predictable reset token (MD5 of timestamp) |
| PR-002 | `POST /password-reset/` | Reset token stored plaintext |
| PR-003 | `GET /password-reset/confirm/` | Token timing attack (== comparison) |
| PR-004 | `POST /password-reset/` | Email enumeration via different responses |

### ACCESS CONTROL (IDOR)

| ID | Endpoint | Vulnerability |
|----|----------|--------------|
| IDOR-001 | `GET /api/users/<id>/` | Any user can read any user's full PII |
| IDOR-002 | `GET /order/<id>/` | Any user can view any order |
| IDOR-003 | `POST /order/<id>/update/` | Any user can update any order (mass assignment) |
| IDOR-004 | `POST /order/<id>/refund/` | Any user can refund any order |
| PRIV-001 | `GET /debug/` | Unauthenticated access to secrets endpoint |
| PRIV-002 | `GET /export/users/` | Unauthenticated mass user data export |
| PRIV-003 | `POST /order/<id>/update/` | Regular user can change order status to any value |

### BUSINESS LOGIC

| ID | Endpoint | Vulnerability |
|----|----------|--------------|
| BL-001 | `POST /cart/add/` | Negative quantity → negative cart total |
| BL-002 | `POST /cart/coupon/` | No per-user coupon limit (ADMIN100 = infinite 100% off) |
| BL-003 | `POST /checkout/` | Client-side price trusted by server (total=0.01) |
| BL-004 | `POST /order/<id>/update/` | Mass assignment on any Order field |
| BL-005 | `POST /order/<id>/refund/` | Refund amount > order total accepted |
| BL-006 | `POST /order/<id>/refund/` | Double refund (no duplicate check) |
| BL-007 | `POST /wallet/transfer/` | Race condition — double spend |
| BL-008 | `POST /wallet/transfer/` | Negative transfer (receives money) |
| BL-009 | `POST /wallet/transfer/` | Transfer to self (balance loop) |
| BL-010 | `POST /loyalty/apply/` | Loyalty points can go negative |
| BL-011 | `POST /review/<id>/` | user_id from POST — post as any user |
| BL-012 | `POST /review/<id>/` | No duplicate review prevention |
| BL-013 | `POST /review/<id>/` | Rating not validated (can be -999 or 99999) |

### SENSITIVE DATA EXPOSURE & CONFIGURATION

| ID | Location | Vulnerability |
|----|----------|--------------|
| DATA-001 | `settings.py` | SECRET_KEY hardcoded |
| DATA-002 | `settings.py` | DEBUG=True exposes stack traces |
| DATA-003 | `settings.py` | Stripe secret key hardcoded |
| DATA-004 | `settings.py` | Email password hardcoded |
| DATA-005 | `GET /debug/` | All env vars + secrets exposed via endpoint |
| DATA-006 | `GET /export/users/` | Password hashes in unauthenticated export |
| DATA-007 | `GET /api/users/<id>/` | national_id, reset_token, password hash in API |
| DATA-008 | `Payment` model | Full card number + CVV stored in DB (PCI DSS) |
| DATA-009 | `app_product` table | cost_price exposed in API |
| DATA-010 | All | Security headers missing (CSP, HSTS, X-Frame-Options) |
| DATA-011 | `POST /graphql/` | GraphQL introspection enabled in production |
| XXE-002 | `POST /import/xml/` | XML parsed without disabling external entities |

### API SECURITY

| ID | Endpoint | Vulnerability |
|----|----------|--------------|
| API-001 | `GET /api/products/` | No authentication required, all fields exposed |
| API-002 | `GET /api/products/` | No pagination — full catalog dump |
| API-003 | All API | No rate limiting — enumeration/DoS |
| API-004 | `POST /api/products/` | Mass assignment — create product with any field |
| API-005 | All | CORS allows all origins with credentials |

---

## 🛠️ Fix Reference

### Top Priority Fixes

```python
# 1. Fix SQL Injection — use ORM always
# ❌ VULNERABLE
cursor.execute(f"SELECT * FROM app_product WHERE name='{query}'")
# ✅ FIXED
Product.objects.filter(name__icontains=query)

# 2. Fix CSRF — enable middleware
# settings.py MIDDLEWARE — uncomment:
'django.middleware.csrf.CsrfViewMiddleware',

# 3. Fix IDOR
# ❌ order = get_object_or_404(Order, id=order_id)
# ✅
order = get_object_or_404(Order, id=order_id, user=request.user)

# 4. Fix client-side price manipulation
# Always recompute total server-side
total = sum(item.product.price * item.quantity for item in cart.items.all())

# 5. Fix JWT
jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'],
           options={'verify_exp': True})

# 6. Fix session cookies
SESSION_COOKIE_SECURE   = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'

# 7. Fix card storage — NEVER store card data
# Use Stripe tokens only:
# token = stripe.Token.create(card={...})
# charge = stripe.Charge.create(amount=total, source=token.id)

# 8. Fix path traversal
safe_dir = Path(settings.MEDIA_ROOT).resolve()
target   = (safe_dir / filename).resolve()
if not str(target).startswith(str(safe_dir)):
    return HttpResponse('Forbidden', status=403)

# 9. Fix command injection
# ❌ subprocess.run(f'ping -c 1 {host}', shell=True)
# ✅ Use Python socket library instead

# 10. Fix pickle deserialization
# ❌ pickle.loads(base64.b64decode(user_data))
# ✅ json.loads(base64.b64decode(user_data))
```

---

## 📁 Project Structure

```
vulnshop/
├── docker-compose.yml          # Multi-service orchestration
├── Dockerfile                  # Django app container
├── requirements.txt
├── manage.py
├── vulnshop/
│   ├── settings.py             # ⚠️ 15+ misconfigurations
│   └── urls.py                 # All vulnerable endpoints
├── app/
│   ├── models.py               # ⚠️ 45+ vulnerable model fields
│   ├── views.py                # ⚠️ All major vuln classes
│   ├── admin.py                # Card data in admin (PCI violation)
│   ├── serializers.py          # Insecure + secure versions
│   ├── templates/
│   │   ├── base.html
│   │   ├── auth/               # Login, register, reset
│   │   └── shop/               # Home, product, cart, checkout, order
│   └── management/commands/
│       └── seed_data.py        # Test data + exploit payloads
└── scanner/
    ├── scanner.py              # 7-module enterprise scanner
    ├── reporter.py             # PDF report generator
    ├── app.py                  # Flask scanner dashboard
    └── Dockerfile.scanner
```

---

## ⚠️ Legal Notice

This software is provided for **educational and authorized security testing purposes only**.
Using these techniques against systems you do not own or have explicit permission to test is illegal.

**Never deploy this application on the internet.**
