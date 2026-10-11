"""
URL configuration for VulnShop project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from app import views

urlpatterns = [
    # Admin (default, no extra protection)
    path('admin/', admin.site.urls),

    # Auth
    path('login/',             views.login_view,             name='login'),
    path('register/',          views.register_view,          name='register'),
    path('logout/',            views.logout_view,            name='logout') if hasattr(views, 'logout_view') else path('logout/', lambda r: __import__('django.contrib.auth', fromlist=['logout']).logout(r) or __import__('django.shortcuts', fromlist=['redirect']).redirect('/login/')),
    path('password-reset/',         views.password_reset_request,  name='password_reset'),
    path('password-reset/confirm/', views.password_reset_confirm,  name='password_reset_confirm'),

    # Shop
    path('',                        views.home,           name='home')        if hasattr(views, 'home') else path('', views.product_search, name='home'),
    path('search/',                 views.product_search, name='search'),
    path('product/<slug:slug>/',    views.product_detail, name='product_detail'),
    path('review/<int:product_id>/',views.submit_review,  name='submit_review'),

    # Cart & Orders
    path('cart/add/',               views.add_to_cart,       name='add_to_cart'),
    path('cart/coupon/',            views.apply_coupon,      name='apply_coupon'),
    path('checkout/',               views.checkout,          name='checkout'),
    path('order/<int:order_id>/',   views.order_detail,      name='order_detail'),
    path('order/<int:order_id>/update/', views.update_order_status, name='update_order'),
    path('order/<int:order_id>/refund/', views.refund_request,      name='refund'),
    path('invoice/<int:order_id>/', views.render_invoice,    name='invoice'),

    # Account
    path('profile/',               views.user_profile,    name='profile'),
    path('wallet/transfer/',       views.wallet_transfer, name='wallet_transfer'),
    path('loyalty/apply/',         views.apply_loyalty,   name='apply_loyalty'),

    # ══════════════════════════════════════════════════════════════
    # DANGEROUS ENDPOINTS — exposed without protection
    # ══════════════════════════════════════════════════════════════
    path('debug/',                 views.admin_debug,        name='debug'),       # exposes secrets
    path('import/xml/',            views.xml_import,         name='xml_import'),  # XXE
    path('ping/',                  views.server_ping,        name='ping'),        # CMDi
    path('prefs/load/',            views.deserialize_prefs,  name='deserialize'), # pickle RCE
    path('template/',              views.template_render,    name='ssti'),        # SSTI
    path('download/',              views.download_file,      name='download'),    # path traversal
    path('export/users/',          views.export_users,       name='export_users'),# mass data
    path('webhook/test/',          views.ssrf_webhook,       name='ssrf'),        # SSRF
    path('graphql/',               views.graphql_endpoint,   name='graphql'),     # introspection

    # API
    path('api/login/',             views.api_login,      name='api_login'),
    path('api/products/',          views.api_products,   name='api_products'),
    path('api/users/<int:user_id>/',views.api_user_data, name='api_user'),
    path('api/jwt/verify/',        views.api_jwt_verify, name='jwt_verify'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) \
  + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)