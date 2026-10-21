"""Database aliases the Along check rejects.

``other`` and ``also`` use ``tests.unsupported_backend``. That wrapper
quotes like SQLite and is not one of the three Along engines, so
``trusts.E005`` and policy rendering fail closed without a server.
The unsupported-alias CI step uses this module as
``DJANGO_SETTINGS_MODULE``. ``test_unsupported_and_several_aliases``
and ``test_along_failure_does_not_return_a_partial_document`` skip
when ``other`` and ``also`` are absent.
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
