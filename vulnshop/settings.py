"""
VulnShop Settings
⚠️  INTENTIONALLY VULNERABLE — FOR SECURITY TESTING ONLY
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ══════════════════════════════════════════════════════════════════
# VULN-001: Hardcoded secret key (should use env var + rotate)
# FIX: SECRET_KEY = os.environ.get('SECRET_KEY') with random 50+ char key
# ══════════════════════════════════════════════════════════════════
SECRET_KEY = 'super-insecure-hardcoded-secret-key-never-do-this-12345'

# ══════════════════════════════════════════════════════════════════
# VULN-002: Debug=True in production (exposes stack traces, settings)
# FIX: DEBUG = os.environ.get('DEBUG', 'False') == 'True'
# ══════════════════════════════════════════════════════════════════
DEBUG = True

# ══════════════════════════════════════════════════════════════════
# VULN-003: ALLOWED_HOSTS wildcard (host header injection)
# FIX: ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']
# ══════════════════════════════════════════════════════════════════
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'app',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # ══════════════════════════════════════════════════════════════
    # VULN-004: CSRF middleware disabled (CSRF attacks possible)
    # FIX: Uncomment the line below
    # 'django.middleware.csrf.CsrfViewMiddleware',
    # ══════════════════════════════════════════════════════════════
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # VULN-005: Clickjacking protection disabled
    # FIX: Uncomment: 'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'vulnshop.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'app' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
            # ══════════════════════════════════════════════════════
            # VULN-006: Auto-escape disabled (XSS via templates)
            # FIX: Remove this line — auto-escape is True by default
            # ══════════════════════════════════════════════════════
            'autoescape': False,
        },
    },
]

WSGI_APPLICATION = 'vulnshop.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DB', 'vulnshop'),
        'USER': os.environ.get('POSTGRES_USER', 'admin'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD', 'admin123'),
        'HOST': os.environ.get('DB_HOST', 'db'),
        'PORT': '5432',
    }
}

# ══════════════════════════════════════════════════════════════════
# VULN-007: Weak password validators disabled
# FIX: Keep all validators, add custom complexity rules
# ══════════════════════════════════════════════════════════════════
AUTH_PASSWORD_VALIDATORS = []

# ══════════════════════════════════════════════════════════════════
# VULN-008: Sessions stored in DB without encryption
# FIX: Use signed cookies + encryption, set SESSION_COOKIE_SECURE=True
# ══════════════════════════════════════════════════════════════════
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_SECURE = False       # VULN: should be True in prod
SESSION_COOKIE_HTTPONLY = False     # VULN: allows JS to read cookie
SESSION_COOKIE_SAMESITE = None      # VULN: enables CSRF via cookies
SESSION_COOKIE_AGE = 86400 * 30    # VULN: 30 days — too long
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# ══════════════════════════════════════════════════════════════════
# VULN-009: Insecure CORS — all origins allowed
# FIX: CORS_ALLOWED_ORIGINS = ['https://yourdomain.com']
# ══════════════════════════════════════════════════════════════════
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# ══════════════════════════════════════════════════════════════════
# VULN-010: No rate limiting on anything
# FIX: Use django-ratelimit or DRF throttling
# ══════════════════════════════════════════════════════════════════
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',  # VULN: all API open
    ],
    # No throttling configured
}

# ══════════════════════════════════════════════════════════════════
# VULN-011: No security headers configured
# FIX: Set all of these to True/appropriate values
# ══════════════════════════════════════════════════════════════════
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False
SECURE_HSTS_SECONDS = 0
SECURE_SSL_REDIRECT = False
X_FRAME_OPTIONS = 'ALLOWALL'       # VULN: allows clickjacking

# ══════════════════════════════════════════════════════════════════
# VULN-012: File upload — no type/size validation
# FIX: Validate MIME type server-side, restrict to images only, limit size
# ══════════════════════════════════════════════════════════════════
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 100   # 100MB — too large
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 100

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'app' / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ══════════════════════════════════════════════════════════════════
# VULN-013: Logging — no security events logged
# FIX: Add SecurityHandler, log auth failures, admin access, errors
# ══════════════════════════════════════════════════════════════════
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,   # VULN: silences all logs
}

# ══════════════════════════════════════════════════════════════════
# VULN-014: Hardcoded payment keys
# FIX: Load from secrets manager / env vars, never commit
# ══════════════════════════════════════════════════════════════════
STRIPE_SECRET_KEY = 'sk_test_hardcoded_stripe_key_1234567890'
STRIPE_PUBLIC_KEY = 'pk_test_hardcoded_stripe_key_1234567890'

# ══════════════════════════════════════════════════════════════════
# VULN-015: Email credentials hardcoded
# FIX: Use env vars + app-specific passwords
# ══════════════════════════════════════════════════════════════════
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'admin@vulnshop.com'
EMAIL_HOST_PASSWORD = 'hardcoded-email-password-123'

REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': REDIS_URL,
        'OPTIONS': {'CLIENT_CLASS': 'django_redis.client.DefaultClient'},
    }
}

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
