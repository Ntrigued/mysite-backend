from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-pnk0ly_=5nqwq$q!s@t_b82snxjzbnm=7q&nrrq7ou5r83rv+r"

# SECURITY WARNING: define the correct hosts in production!
ALLOWED_HOSTS = ["*"]

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

CORS_ALLOWED_ORIGINS = [
    'http://localhost:3000'
]

try:
    from .local import *
except ImportError:
    pass
