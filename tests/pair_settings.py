"""C2 + Z1 settings for the preserved legacy core suite.

C1 ran this layout with ``INSTALLED_APPS=['trusts']`` only. After C2 the
kernel label is ``trusts_core``; Zero owns ``label='trusts'`` and the
historical test-app migrations that depend on ``trusts.0001_initial``.
"""
from os.path import dirname, join

SECRET_KEY = '01)%8q7ub=+yw7^#dz5s!6kkff6%al5f)_ayvep9_b&w1q-dvs'

USE_TZ = True
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'
LOGIN_URL = '/accounts/login/'
STATIC_URL = '/static/'
ALLOWED_HOSTS = ['beedesk.com', 'testserver', 'localhost']
# Junction docs still describe content = ForeignKey(..., unique=True).
SILENCED_SYSTEM_CHECKS = ['fields.W342']

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'trusts',
    'trusts.zero.apps.ZeroConfig',
    'tests.apps.TestsConfig',
)

AUTHENTICATION_BACKENDS = (
    'trusts.backends.TrustModelBackend',
)

MIDDLEWARE = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'DIRS': [
            join(dirname(__file__), 'templates'),
        ],
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

ROOT_URLCONF = 'tests.urls'

# Kernel has no migrations package. Zero owns trusts.0001 / 0002.
MIGRATION_MODULES = {
    'trusts_core': None,
}
