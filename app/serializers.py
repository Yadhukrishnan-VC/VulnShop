"""
VulnShop Serializers
VULN: Many serializers intentionally expose sensitive fields
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Product, Category, Order, OrderItem,
    Payment, UserProfile, ProductReview,
)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model  = User
        # VULN: password hash exposed in API response
        fields = ['id', 'username', 'email', 'password',
                  'is_staff', 'date_joined', 'last_login']


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Product
        # VULN: cost_price (internal) exposed — business data leak
        fields = '__all__'


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Order
        fields = '__all__'


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Payment
        # VULN: full card number + CVV in API response — PCI violation
        fields = '__all__'


class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model  = ProductReview
        fields = '__all__'


# ── SECURE VERSIONS (reference for fixes) ──────────────────────────

class SecureProductSerializer(serializers.ModelSerializer):
    """FIX: explicit field whitelist, no internal data"""
    class Meta:
        model  = Product
        fields = ['id', 'name', 'slug', 'price', 'stock',
                  'image', 'category', 'description']
        # cost_price, vendor NOT included


class SecureUserSerializer(serializers.ModelSerializer):
    """FIX: never expose password or admin flags to end users"""
    class Meta:
        model  = User
        fields = ['id', 'username', 'email', 'date_joined']


class SecurePaymentSerializer(serializers.ModelSerializer):
    """FIX: mask card data, never return CVV"""
    card_number = serializers.SerializerMethodField()

    def get_card_number(self, obj):
        if obj.card_number:
            return '**** **** **** ' + obj.card_number[-4:]
        return None

    class Meta:
        model  = Payment
        fields = ['id', 'order', 'amount', 'card_number',
                  'card_holder', 'status', 'created_at']
        # card_cvv NEVER returned
