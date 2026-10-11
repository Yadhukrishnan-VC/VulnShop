from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from app import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('password-reset/', views.password_reset_request, name='password_reset'),
    path('password-reset/confirm/', views.password_reset_confirm, name='password_reset_confirm'),
    path('search/', views.product_search, name='search'),
    path('product/<slug:slug>/', views.product_detail, name='product_detail'),
    path('review/<int:product_id>/', views.submit_review, name='submit_review'),
    path('cart/', views.cart_view, name='cart'),
    path('cart/add/', views.add_to_cart, name='add_to_cart'),
    path('cart/coupon/', views.apply_coupon, name='apply_coupon'),
    path('checkout/', views.checkout, name='checkout'),
    path('order/<int:order_id>/', views.order_detail, name='order_detail'),
    path('order/<int:order_id>/update/', views.update_order_status, name='update_order'),
    path('order/<int:order_id>/refund/', views.refund_request, name='refund'),
    path('invoice/<int:order_id>/', views.render_invoice, name='invoice'),
    path('profile/', views.user_profile, name='profile'),
    path('wallet/transfer/', views.wallet_transfer, name='wallet_transfer'),
    path('loyalty/apply/', views.apply_loyalty, name='apply_loyalty'),
    # Vulnerable endpoints
    path('debug/', views.admin_debug, name='debug'),
    path('import/xml/', views.xml_import, name='xml_import'),
    path('ping/', views.server_ping, name='ping'),
    path('prefs/load/', views.deserialize_prefs, name='deserialize'),
    path('template/', views.template_render, name='ssti'),
    path('download/', views.download_file, name='download'),
    path('export/users/', views.export_users, name='export_users'),
    path('webhook/test/', views.ssrf_webhook, name='ssrf'),
    path('graphql/', views.graphql_endpoint, name='graphql'),
    # API
    path('api/login/', views.api_login, name='api_login'),
    path('api/products/', views.api_products, name='api_products'),
    path('api/users/<int:user_id>/', views.api_user_data, name='api_user'),
    path('api/jwt/verify/', views.api_jwt_verify, name='jwt_verify'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) \
  + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
