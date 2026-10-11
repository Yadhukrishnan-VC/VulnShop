from django.contrib import admin
from .models import (
    Category, Product, ProductReview, UserProfile,
    Cart, CartItem, Order, OrderItem, Payment, Refund,
    Coupon, SupportTicket, Wishlist, Newsletter,
    APIKey, AuditLog, ProductImport, PasswordResetLog,
)

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display  = ['name', 'price', 'cost_price', 'stock', 'is_active', 'category']
    list_filter   = ['is_active', 'category']
    search_fields = ['name']
    prepopulated_fields = {'slug': ('name',)}

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    prepopulated_fields = {'slug': ('name',)}

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'total', 'status', 'created_at']
    list_filter  = ['status']

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    # VULN: card_number and cvv visible in admin — PCI violation
    list_display = ['order', 'amount', 'card_number', 'card_cvv', 'status']

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'phone', 'wallet_balance', 'loyalty_points', 'is_vendor']

@admin.register(Coupon)
class CouponAdmin(admin.ModelAdmin):
    list_display = ['code', 'discount_type', 'discount_value', 'is_active', 'used_count']

@admin.register(SupportTicket)
class SupportTicketAdmin(admin.ModelAdmin):
    list_display = ['user', 'subject', 'status', 'created_at']

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'model_name', 'timestamp']
    # VULN: admins can delete audit logs — tamper-proof log not implemented

admin.site.register(ProductReview)
admin.site.register(Cart)
admin.site.register(CartItem)
admin.site.register(OrderItem)
admin.site.register(Refund)
admin.site.register(Wishlist)
admin.site.register(Newsletter)
admin.site.register(APIKey)
admin.site.register(ProductImport)
admin.site.register(PasswordResetLog)

admin.site.site_header  = '⚠️ VulnShop Admin — VULNERABLE DEMO'
admin.site.site_title   = 'VulnShop Admin'
admin.site.index_title  = 'Vulnerability Testing Dashboard'
