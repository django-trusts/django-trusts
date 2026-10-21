"""Database aliases the Along check rejects.

``other`` and ``also`` use ``tests.unsupported_backend``. That wrapper
quotes like SQLite and is not one of the three Along engines, so
``trusts.E005`` and policy rendering fail closed without a server.
The kernel and along jobs do not use this module as
``DJANGO_SETTINGS_MODULE``.
"""

from tests.settings import *  # noqa: E402,F403

DATABASES = dict(DATABASES)  # noqa: F405
DATABASES['other'] = {
    'ENGINE': 'tests.unsupported_backend',
    'NAME': 'other',
}
DATABASES['also'] = {
    'ENGINE': 'tests.unsupported_backend',
    'NAME': 'also',
}
