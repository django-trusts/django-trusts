"""Noun-independent relational authorization kernel.

``django-trusts`` owns this package and this ``__init__.py``. Concrete
Trust / Content / Role / Group models, historical migrations, and the
compatibility backend live in the optional ``django-trusts-zero`` add-on
as ``trusts.zero``. That add-on must not ship a replacement for this file.

``extend_path`` lets a second sys.path entry contribute ``trusts.zero``
(wheel+wheel into the same ``site-packages/trusts/`` tree, or
editable+editable with Zero shipping only ``trusts/zero/**``).
"""

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)
