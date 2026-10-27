"""Quote SQL like SQLite and stay outside the Along allowlist.

Policy rendering calls ``quote_name`` before the Along engine check.
``django.db.backends.dummy`` cannot quote, so an unsupported alias
uses this wrapper. The ENGINE string is not sqlite, postgresql, or
mysql, and render raises ``TrustsConfigurationError`` with no document.
"""

from django.db.backends.sqlite3.base import (
    DatabaseWrapper as SQLiteDatabaseWrapper,
)


class DatabaseWrapper(SQLiteDatabaseWrapper):
    vendor = 'unsupported'
