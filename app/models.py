"""
vulnshop Models
⚠️ Intentionally vulnerable Django e-commerce models — for security testing only
"""
from django.db import models
from django.contrib.auth.models import User
import hashlib
import os


# ══════════════════════════════════════════════════════════════════════════
# USERS & AUTH
# ══════════════════════════════════════════════════════════════════════════

class UserProfile(models.Model):
    user        = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    # VULN-016: PII stored in plaintext (should encrypt at rest)
    phone       = models.CharField(max_length=20, blank=True)
    address     = models.TextField(blank=True)
    # VULN-017: SSN/national ID stored plaintext — must be encrypted + access-controlled
    national_id = models.CharField(max_length=20, blank=True)
    # VULN-018: Date of birth exposed in API without masking
    date_of_birth = models.DateField(null=True, blank=True)
    avatar      = models.ImageField(upload_to='avatars/', blank=True)
    # VULN-019: Balance as plain decimal — no server-side verification on spend
    wallet_balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    loyalty_points = models.IntegerField(default=0)
    is_vendor   = models.BooleanField(default=False)
    reset_token = models.CharField(max_length=64, blank=True)
    # VULN-020: Token expiry not enforced server-side (password reset tokens live forever)
    reset_token_created = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} Profile"


class PasswordResetLog(models.Model):
    """VULN-021: Password reset tokens stored in DB unencrypted — hash them."""
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    token      = models.CharField(max_length=128)    # stored plaintext
    ip_address = models.GenericIPAddressField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used       = models.BooleanField(default=False)


# ══════════════════════════════════════════════════════════════════════════
# PRODUCTS & CATALOG
# ══════════════════════════════════════════════════════════════════════════

class Category(models.Model):
    name        = models.CharField(max_length=100)
    slug        = models.SlugField(unique=True)
    description = models.TextField(blank=True)
    parent      = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        verbose_name_plural = 'categories'

    def __str__(self):
        return self.name


class Product(models.Model):
    name        = models.CharField(max_length=255)
    slug        = models.SlugField(unique=True)
    category    = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True)
    vendor      = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField()  # VULN-022: renders raw HTML in template (stored XSS)
    price       = models.DecimalField(max_digits=10, decimal_places=2)
    # VULN-023: Stock not locked during concurrent purchases (race condition oversell)
    stock       = models.IntegerField(default=0)
    image       = models.ImageField(upload_to='products/')
    is_active   = models.BooleanField(default=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    # VULN-024: Internal cost price exposed via API serializer — business data leak
    cost_price  = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    discount_pct = models.IntegerField(default=0)

    def __str__(self):
        return self.name

    def get_price(self):
        return self.price * (1 - self.discount_pct / 100)


class ProductReview(models.Model):
    product    = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='reviews')
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    rating     = models.IntegerField(default=5)   # VULN-025: no range validation (can be -999 or 9999)
    # VULN-026: Review text rendered unescaped — stored XSS via Markdown/HTML
    content    = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    # VULN-027: Users can review same product unlimited times (logic bug)
    # FIX: unique_together = ('product', 'user')

    def __str__(self):
        return f"{self.user.username} review on {self.product.name}"


# ══════════════════════════════════════════════════════════════════════════
# CART & ORDERS
# ══════════════════════════════════════════════════════════════════════════

class Cart(models.Model):
    user        = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    session_key = models.CharField(max_length=40, blank=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    def get_total(self):
        return sum(item.get_subtotal() for item in self.items.all())


class CartItem(models.Model):
    cart     = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='items')
    product  = models.ForeignKey(Product, on_delete=models.CASCADE)
    # VULN-028: Quantity not validated server-side — can add qty=-1 to reduce cart total
    quantity = models.IntegerField(default=1)

    def get_subtotal(self):
        # VULN-029: Price taken from product at order time, not locked at cart-add time
        # Race condition: price can change between add-to-cart and checkout
        return self.product.price * self.quantity


class Coupon(models.Model):
    code            = models.CharField(max_length=20, unique=True)
    discount_type   = models.CharField(max_length=10, choices=[('pct','Percent'),('fixed','Fixed')])
    discount_value  = models.DecimalField(max_digits=6, decimal_places=2)
    min_order_value = models.DecimalField(max_digits=8, decimal_places=2, default=0)
    max_uses        = models.IntegerField(default=0)   # 0 = unlimited
    used_count      = models.IntegerField(default=0)
    # VULN-030: No per-user coupon use limit — same user can apply 1000 times
    is_active       = models.BooleanField(default=True)
    valid_from      = models.DateTimeField()
    valid_to        = models.DateTimeField()

    def __str__(self):
        return self.code


class Order(models.Model):
    STATUS = [
        ('pending','Pending'), ('paid','Paid'), ('processing','Processing'),
        ('shipped','Shipped'), ('delivered','Delivered'), ('cancelled','Cancelled'),
        ('refunded','Refunded'),
    ]
    user           = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    status         = models.CharField(max_length=20, choices=STATUS, default='pending')
    # VULN-031: Shipping address cloned from profile — no re-verification on checkout
    shipping_addr  = models.TextField()
    billing_addr   = models.TextField()
    subtotal       = models.DecimalField(max_digits=10, decimal_places=2)
    discount       = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    tax            = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total          = models.DecimalField(max_digits=10, decimal_places=2)
    coupon         = models.ForeignKey(Coupon, null=True, blank=True, on_delete=models.SET_NULL)
    payment_method = models.CharField(max_length=30, default='card')
    # VULN-032: Full card number logged in payment_ref (PCI DSS violation)
    payment_ref    = models.CharField(max_length=255, blank=True)
    notes          = models.TextField(blank=True)  # VULN-033: notes rendered as HTML in admin
    created_at     = models.DateTimeField(auto_now_add=True)
    updated_at     = models.DateTimeField(auto_now=True)
    # VULN-034: No order ownership check in API — IDOR: user A can view user B's order
    tracking_number = models.CharField(max_length=50, blank=True)

    def __str__(self):
        return f"Order #{self.pk} — {self.user}"


class OrderItem(models.Model):
    order       = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product     = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True)
    product_name = models.CharField(max_length=255)
    quantity    = models.IntegerField()
    unit_price  = models.DecimalField(max_digits=10, decimal_places=2)

    def get_subtotal(self):
        return self.unit_price * self.quantity


# ══════════════════════════════════════════════════════════════════════════
# PAYMENTS
# ══════════════════════════════════════════════════════════════════════════

class Payment(models.Model):
    order      = models.OneToOneField(Order, on_delete=models.CASCADE)
    amount     = models.DecimalField(max_digits=10, decimal_places=2)
    # VULN-035: Card details stored in plaintext — massive PCI DSS violation
    card_number     = models.CharField(max_length=19, blank=True)
    card_expiry     = models.CharField(max_length=7, blank=True)
    card_cvv        = models.CharField(max_length=4, blank=True)   # VULN-036: CVV must NEVER be stored
    card_holder     = models.CharField(max_length=100, blank=True)
    gateway_ref     = models.CharField(max_length=100, blank=True)
    gateway_response = models.JSONField(default=dict)
    status          = models.CharField(max_length=20, default='pending')
    created_at      = models.DateTimeField(auto_now_add=True)


class Refund(models.Model):
    order      = models.ForeignKey(Order, on_delete=models.CASCADE)
    amount     = models.DecimalField(max_digits=10, decimal_places=2)
    reason     = models.TextField()
    status     = models.CharField(max_length=20, default='pending')
    # VULN-037: Refund amount not validated against original order total
    # User can request refund > order value
    created_at = models.DateTimeField(auto_now_add=True)


# ══════════════════════════════════════════════════════════════════════════
# ADMIN & AUDIT
# ══════════════════════════════════════════════════════════════════════════

class AuditLog(models.Model):
    """VULN-038: Audit log not tamper-proof — admin can delete entries directly."""
    user       = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action     = models.CharField(max_length=100)
    model_name = models.CharField(max_length=50)
    object_id  = models.IntegerField(null=True)
    old_value  = models.JSONField(default=dict)
    new_value  = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField(null=True)
    timestamp  = models.DateTimeField(auto_now_add=True)


class SupportTicket(models.Model):
    """VULN-039: Support tickets visible to all staff — no role separation."""
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    subject    = models.CharField(max_length=200)
    # VULN-040: Message rendered as HTML in staff view — stored XSS targeting admin
    message    = models.TextField()
    status     = models.CharField(max_length=20, default='open')
    created_at = models.DateTimeField(auto_now_add=True)


class Wishlist(models.Model):
    user     = models.ForeignKey(User, on_delete=models.CASCADE)
    product  = models.ForeignKey(Product, on_delete=models.CASCADE)
    added_at = models.DateTimeField(auto_now_add=True)
    # VULN-041: Wishlists public by default — no privacy control
    is_public = models.BooleanField(default=True)


class Newsletter(models.Model):
    """VULN-042: Email enumeration — unsubscribe confirms email exists."""
    email      = models.EmailField(unique=True)
    is_active  = models.BooleanField(default=True)
    # VULN-043: Unsubscribe token not expiring and stored plaintext
    token      = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)


class APIKey(models.Model):
    """VULN-044: API keys stored plaintext in DB — should store only hash."""
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    key        = models.CharField(max_length=64)   # stored plaintext
    name       = models.CharField(max_length=100)
    scopes     = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used  = models.DateTimeField(null=True)
    is_active  = models.BooleanField(default=True)


class ProductImport(models.Model):
    """VULN-045: File import parsed with lxml without disabling entities — XXE vulnerability."""
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    file_path   = models.CharField(max_length=500)
    status      = models.CharField(max_length=20, default='pending')
    result      = models.JSONField(default=dict)
    created_at  = models.DateTimeField(auto_now_add=True)