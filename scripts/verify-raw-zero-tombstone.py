#!/usr/bin/env python3
"""Prove raw Zero 2.0.0.dev0 reaches the failure-only kernel_config tombstone.

Configures the raw-Zero layout (``'trusts'`` plus
``trusts.backends.TrustModelBackend``). Startup or the first
``kernel_config()`` call must raise actionable ``ImproperlyConfigured``,
not an unexplained ``ImportError`` / ``LookupError``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.pop('DJANGO_SETTINGS_MODULE', None)


def _put_kernel_first():
    kernel = Path(os.environ.get('KERNEL_CHECKOUT', ROOT)).resolve()
    zero = Path(os.environ.get('ZERO_CHECKOUT', ROOT / '.deps' / 'django-trusts-zero')).resolve()
    cleaned = []
    for p in sys.path:
        if '__editable__.django_trusts' in str(p):
            continue
        abs_p = Path(p or os.getcwd()).resolve()
        if abs_p in {ROOT.resolve(), kernel, zero}:
            continue
        if (abs_p / 'trusts' / '__init__.py').is_file() and abs_p != kernel:
            continue
        cleaned.append(p)
    sys.path[:] = cleaned
    sys.path.insert(0, str(kernel))
    if zero.is_dir():
        sys.path.append(str(zero))


_put_kernel_first()


def main() -> int:
    zero = Path(os.environ.get('ZERO_CHECKOUT', ROOT / '.deps' / 'django-trusts-zero'))
    if not (zero / 'trusts' / 'zero' / 'apps.py').is_file():
        raise SystemExit('ZERO_CHECKOUT missing raw Zero at %s' % zero)

    from django.conf import settings
    from django.core.exceptions import ImproperlyConfigured

    if settings.configured:
        raise SystemExit('Django already configured')
    settings.configure(
        SECRET_KEY='raw-zero-tombstone',
        USE_TZ=True,
        DEFAULT_AUTO_FIELD='django.db.models.AutoField',
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'trusts',
            'trusts.zero.apps.ZeroConfig',
        ],
        AUTHENTICATION_BACKENDS=[
            'trusts.backends.TrustModelBackend',
        ],
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },
    )

    import django

    try:
        django.setup()
    except ImproperlyConfigured as exc:
        message = str(exc)
    except Exception as exc:
        raise SystemExit(
            'raw Zero must fail as ImproperlyConfigured, not %s: %s'
            % (type(exc).__name__, exc)
        )
    else:
        from trusts.apps import kernel_config

        try:
            kernel_config()
        except ImproperlyConfigured as exc:
            message = str(exc)
        except Exception as exc:
            raise SystemExit(
                'kernel_config() must raise ImproperlyConfigured, not %s: %s'
                % (type(exc).__name__, exc)
            )
        else:
            raise SystemExit('raw Zero continued past kernel_config()')

    if '2.0.0.dev0' not in message:
        raise SystemExit('tombstone missing raw Zero 2.0.0.dev0: %s' % message)
    if '2.0.0.dev2' not in message and 'old-code' not in message:
        raise SystemExit('tombstone missing upgrade direction: %s' % message)
    print('raw-zero-tombstone ok')
    print(message)
    return 0


if __name__ == '__main__':
    os.chdir(ROOT)
    raise SystemExit(main())
