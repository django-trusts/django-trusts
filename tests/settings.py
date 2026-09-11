import os
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
    'tests.kernel_host.apps.KernelHostConfig',
    'tests.myapp.apps.DocumentConfig',
    'tests.gh_permissions.apps.GhPermissionsConfig',
    'tests.apps.TestsConfig',
)

# Test-app migrations depend on trusts.0001_initial (Zero-owned after C2).
MIGRATION_MODULES = {
    'trusts_tests': None,
    'myapp': None,
}

AUTHENTICATION_BACKENDS = (
    'tests.backends.HostTrustModelBackend',
    'tests.myapp.backends.DocumentBackend',
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

if os.environ.get('TRUSTS_TEST_DATABASE') == 'postgresql':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('TRUSTS_PG_NAME', 'trusts'),
            'USER': os.environ.get('TRUSTS_PG_USER', 'postgres'),
            'PASSWORD': os.environ.get('TRUSTS_PG_PASSWORD', 'postgres'),
            'HOST': os.environ.get('TRUSTS_PG_HOST', '127.0.0.1'),
            'PORT': os.environ.get('TRUSTS_PG_PORT', '5432'),
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
    }

ROOT_URLCONF = 'tests.urls'
