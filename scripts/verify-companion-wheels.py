#!/usr/bin/env python3
"""Companion wheel isolation: core 1.0.0.dev3 + Zero IIa.

Proves Zero RECORD does not own trusts/__init__.py or trusts/apps.py,
and that both companion layouts work:

1. Kernel wheel then Zero overlay (site-packages merge).
2. Isolated Zero wheel (no kernel trusts/__init__.py) still imports ZeroConfig.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZERO_HEAD = '94e0fa109a8a7a5f53a028438ada899cbc1be1ad'
FORBIDDEN_ZERO_PATHS = (
    'trusts/__init__.py',
    'trusts/apps.py',
)

OVERLAY_PROBE = r'''
import sys
from pathlib import Path
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

if not settings.configured:
    settings.configure(
        SECRET_KEY="companion-overlay",
        USE_TZ=True,
        DEFAULT_AUTO_FIELD="django.db.models.AutoField",
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "trusts.zero.apps.ZeroConfig",
        ],
        AUTHENTICATION_BACKENDS=["trusts.zero.backends.TrustModelBackend"],
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    )
import django
django.setup()
import trusts
import importlib
from trusts.apps import kernel_config
from trusts.backends import TrustModelBackendMixin
from trusts.zero.apps import ZeroConfig
from trusts.zero.models import Trust
from django.apps import apps as django_apps

assert ZeroConfig.label == "trusts"
assert django_apps.get_app_config("trusts").name == "trusts.zero"
assert Trust._meta.app_label == "trusts"
assert TrustModelBackendMixin.__module__ == "trusts.backends"
try:
    importlib.import_module("trusts.core_backends")
except ModuleNotFoundError:
    pass
else:
    raise SystemExit("trusts.core_backends still imports")
try:
    kernel_config()
except ImproperlyConfigured as exc:
    assert "2.0.0.dev0" in str(exc)
else:
    raise SystemExit("overlay kernel_config() must be a tombstone")
init = Path(trusts.__file__)
assert init.name == "__init__.py"
assert (init.parent / "zero" / "apps.py").is_file()
assert (init.parent / "apps.py").is_file()
assert not (init.parent / "core_backends.py").is_file()
print("companion-overlay-ok")
'''

ISOLATED_ZERO_PROBE = r'''
import sys
from pathlib import Path
from django.conf import settings

extracted = Path(%r)
kept = []
for p in sys.path:
    if Path(p, "trusts", "__init__.py").is_file():
        continue
    kept.append(p)
sys.path[:] = kept
sys.path.insert(0, str(extracted))
for name in list(sys.modules):
    if name == "trusts" or name.startswith("trusts."):
        del sys.modules[name]
if not settings.configured:
    settings.configure(SECRET_KEY="companion-zero-isolated")
from trusts.zero.apps import ZeroConfig
assert ZeroConfig.name == "trusts.zero"
assert ZeroConfig.label == "trusts"
print("companion-zero-isolated-ok")
'''


def _wheel(dist: Path, pattern: str) -> Path:
    wheels = sorted(dist.glob(pattern))
    if not wheels:
        raise SystemExit('no wheel matching %s in %s' % (pattern, dist))
    return wheels[-1]


def _ensure_kernel_wheel() -> Path:
    dist = ROOT / 'dist'
    wheels = sorted(dist.glob('django_trusts-*.whl'))
    if wheels:
        return wheels[-1]
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'build'], check=True)
    subprocess.run([sys.executable, '-m', 'build', '--wheel'], cwd=str(ROOT), check=True)
    return _wheel(ROOT / 'dist', 'django_trusts-*.whl')


def _ensure_zero_wheel(zero_root: Path) -> Path:
    dist = zero_root / 'dist'
    wheels = sorted(dist.glob('django_trusts_zero-*.whl'))
    if wheels:
        return wheels[-1]
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'build'], check=True)
    subprocess.run([sys.executable, '-m', 'build', '--wheel'], cwd=str(zero_root), check=True)
    return _wheel(zero_root / 'dist', 'django_trusts_zero-*.whl')


def _assert_zero_record(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
    for path in FORBIDDEN_ZERO_PATHS:
        if any(n == path or n.endswith('/' + path) for n in names):
            raise SystemExit('Zero wheel owns forbidden path %s' % path)
    if not any(n.endswith('trusts/zero/apps.py') for n in names):
        raise SystemExit('Zero wheel missing trusts/zero/apps.py')


def main() -> int:
    zero_root = Path(os.environ.get('ZERO_CHECKOUT', ROOT / '.deps' / 'django-trusts-zero'))
    if not zero_root.is_dir():
        raise SystemExit('ZERO_CHECKOUT missing: %s (expected IIa %s)' % (
            zero_root, ZERO_HEAD,
        ))

    kernel_wheel = _ensure_kernel_wheel()
    zero_wheel = _ensure_zero_wheel(zero_root)
    with zipfile.ZipFile(kernel_wheel) as zf:
        names = zf.namelist()
    if any(n.endswith('trusts/core_backends.py') for n in names):
        raise SystemExit('library wheel still ships trusts/core_backends.py')
    _assert_zero_record(zero_wheel)

    tmp = Path(tempfile.mkdtemp(prefix='trusts-dev3-companion-'))
    try:
        extracted = tmp / 'zero-extracted'
        extracted.mkdir()
        with zipfile.ZipFile(zero_wheel) as zf:
            zf.extractall(extracted)
        env = os.environ.copy()
        env.pop('DJANGO_SETTINGS_MODULE', None)
        out = subprocess.check_output(
            [sys.executable, '-c', ISOLATED_ZERO_PROBE % str(extracted)],
            env=env,
            cwd=str(tmp),
            text=True,
        )
        if 'companion-zero-isolated-ok' not in out:
            raise SystemExit('isolated Zero probe failed: %r' % out)

        site = tmp / 'overlay-site'
        site.mkdir()
        subprocess.check_call(
            [sys.executable, '-m', 'pip', 'install', '-q', '--target', str(site), str(kernel_wheel)],
        )
        with zipfile.ZipFile(zero_wheel) as zf:
            zf.extractall(site)
        if not (site / 'trusts' / 'zero' / 'apps.py').is_file():
            raise SystemExit('overlay missing trusts/zero/apps.py')
        if not (site / 'trusts' / '__init__.py').is_file():
            raise SystemExit('overlay lost kernel trusts/__init__.py')
        if not (site / 'trusts' / 'apps.py').is_file():
            raise SystemExit('overlay lost kernel trusts/apps.py')

        overlay_env = os.environ.copy()
        overlay_env['PYTHONPATH'] = str(site)
        overlay_env.pop('DJANGO_SETTINGS_MODULE', None)
        out2 = subprocess.check_output(
            [sys.executable, '-c', OVERLAY_PROBE],
            env=overlay_env,
            cwd=str(tmp),
            text=True,
        )
        if 'companion-overlay-ok' not in out2:
            raise SystemExit('overlay probe failed: %r' % out2)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print('companion wheels ok')
    print('kernel_wheel', kernel_wheel)
    print('zero_wheel', zero_wheel)
    print('zero_head', ZERO_HEAD)
    return 0


if __name__ == '__main__':
    os.chdir(ROOT)
    raise SystemExit(main())
