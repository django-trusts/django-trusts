#!/usr/bin/env python3
"""Prove this kernel revision against the *real* django-trusts-zero checkout.

Does not build a synthetic Zero wheel from in-tree sources. The companion
repository is authoritative for Zero version and Requires-Dist.

Proves:

1. kernel tree has no ``trusts/zero`` and no packaging mirror
2. companion ``pyproject.toml`` / wheel METADATA (version ``2.0.0.dev0``,
   ``django-trusts`` Requires-Dist)
3. wheel+wheel RECORD ownership
4. Zero uninstall/reinstall isolation
5. editable+editable isolation (this kernel checkout + companion tree)
6. AppConfig labels, import paths, and trusts migration identity
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import zero_companion  # noqa: E402

KERNEL_OWNED_RECORD_PARTS = (
    'trusts/__init__.py',
    'trusts/apps.py',
    'trusts/checks.py',
    'trusts/context.py',
    'trusts/trustee.py',
    'trusts/path.py',
    'trusts/conditions.py',
    'trusts/utils.py',
    'django_trusts.py',
)

_DJANGO_SETUP_BOTH = (
    'from django.conf import settings; '
    'settings.configure(SECRET_KEY="ns", USE_TZ=True, '
    'INSTALLED_APPS=["django.contrib.contenttypes","django.contrib.auth",'
    '"trusts.apps.KernelConfig","trusts.zero.apps.ZeroConfig"], '
    'DATABASES={"default":{"ENGINE":"django.db.backends.sqlite3","NAME":":memory:"}}); '
    'import django; django.setup(); '
)

_DJANGO_SETUP_KERNEL = (
    'from django.conf import settings; '
    'settings.configure(SECRET_KEY="ns", USE_TZ=True, '
    'INSTALLED_APPS=["trusts.apps.KernelConfig"], '
    'DATABASES={"default":{"ENGINE":"django.db.backends.sqlite3","NAME":":memory:"}}); '
    'import django; django.setup(); '
)


def _run(cmd, cwd=None, env=None, check=True):
    print('+', ' '.join(str(c) for c in cmd))
    result = subprocess.run(
        cmd, cwd=cwd, env=env, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
        if not result.stdout.endswith('\n'):
            sys.stdout.write('\n')
    if check and result.returncode != 0:
        raise SystemExit(result.returncode)
    return result


def _wheel_record(site_packages: Path, dist_name: str) -> list[str]:
    dist_dirs = sorted(site_packages.glob('%s-*.dist-info' % dist_name))
    if not dist_dirs:
        raise SystemExit('missing dist-info for %s in %s' % (
            dist_name, site_packages,
        ))
    record = dist_dirs[-1] / 'RECORD'
    return [
        line.split(',', 1)[0]
        for line in record.read_text().splitlines()
        if line.strip()
    ]


def _assert_record(paths: list[str], *, must_contain, must_not_contain, label: str) -> None:
    joined = '\n'.join(paths)
    for part in must_contain:
        if not any(part in p for p in paths):
            raise SystemExit('%s RECORD missing %s\n%s' % (label, part, joined))
    for part in must_not_contain:
        hits = [p for p in paths if part in p]
        if hits:
            raise SystemExit('%s RECORD owns forbidden %s: %s' % (label, part, hits))


def _ensurepip_available() -> bool:
    return subprocess.run(
        [sys.executable, '-c', 'import ensurepip'],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def _make_venv(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if _ensurepip_available():
        _run([sys.executable, '-m', 'venv', str(path)])
    else:
        _run([sys.executable, '-m', 'pip', 'install', 'virtualenv'])
        if path.exists():
            shutil.rmtree(path)
        _run([sys.executable, '-m', 'virtualenv', str(path)])
    py = path / 'bin' / 'python'
    if not py.exists():
        raise SystemExit('failed to create venv at %s' % path)
    _run([str(py), '-m', 'pip', 'install', '--upgrade', 'pip'])
    return py


def _site_packages(py: Path) -> Path:
    result = _run([
        str(py), '-c',
        'import sysconfig; print(sysconfig.get_path("purelib"))',
    ])
    line = result.stdout.strip().splitlines()[-1]
    site = Path(line)
    if not site.is_dir():
        raise SystemExit('purelib is not a directory: %s' % site)
    return site


def _python(py: Path, code: str, cwd: Path):
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    env['PYTHONNOUSERSITE'] = '1'
    return _run([str(py), '-c', code], env=env, cwd=str(cwd))


def _pip(py: Path, *args):
    _run([str(py), '-m', 'pip', 'install', '--no-warn-script-location', *args])


def main() -> int:
    zero_companion.assert_kernel_has_no_zero_tree(ROOT)
    py = sys.executable
    pin = zero_companion.read_pin()
    with tempfile.TemporaryDirectory(prefix='django-trusts-namespace-') as tmp:
        tmp_path = Path(tmp)
        zero_src = zero_companion.resolve_companion_src(tmp_path / 'zero-src')
        zero_sha = zero_companion.assert_companion_revision(zero_src)
        project = zero_companion.assert_companion_metadata(zero_src)
        print('companion_src', zero_src)
        print('companion_sha', zero_sha)
        print('companion_version', project['version'])

        dist_dir = tmp_path / 'dist'
        dist_dir.mkdir()
        _run([py, '-m', 'pip', 'install', 'build'])
        _run([py, '-m', 'build', '--wheel', '--outdir', str(dist_dir)], cwd=ROOT)
        _run([py, '-m', 'build', '--wheel', '--outdir', str(dist_dir)], cwd=zero_src)
        wheels = list(dist_dir.glob('*.whl'))
        kernel_wheels = [
            w for w in wheels
            if w.name.startswith('django_trusts-') and 'zero' not in w.name
        ]
        zero_wheels = [w for w in wheels if w.name.startswith('django_trusts_zero-')]
        if len(kernel_wheels) != 1 or len(zero_wheels) != 1:
            raise SystemExit(
                'expected one kernel wheel and one zero wheel, got %s' % wheels
            )
        kernel_wheel, zero_wheel = kernel_wheels[0], zero_wheels[0]
        zero_companion.assert_wheel_requires_dist(
            zero_wheel, pin.get('required_dist', 'django-trusts'),
        )

        ww_py = _make_venv(tmp_path / 'ww-venv')
        _pip(ww_py, str(kernel_wheel), str(zero_wheel))
        ww_site = _site_packages(ww_py)
        kernel_record = _wheel_record(ww_site, 'django_trusts')
        zero_record = _wheel_record(ww_site, 'django_trusts_zero')
        _assert_record(
            kernel_record,
            must_contain=[
                'trusts/__init__.py', 'trusts/context.py', 'trusts/path.py',
            ],
            must_not_contain=['trusts/zero/'],
            label='kernel wheel',
        )
        _assert_record(
            zero_record,
            must_contain=[
                'trusts/zero/__init__.py',
                'trusts/zero/models.py',
                'trusts/zero/migrations/0001_initial.py',
            ],
            must_not_contain=list(KERNEL_OWNED_RECORD_PARTS),
            label='zero wheel',
        )
        if any(p == 'trusts/__init__.py' or p.endswith('/trusts/__init__.py')
               for p in zero_record):
            raise SystemExit('Zero RECORD owns trusts/__init__.py')

        isolated = tmp_path / 'isolated-cwd'
        isolated.mkdir()
        _python(ww_py, (
            _DJANGO_SETUP_BOTH +
            'import trusts, trusts.context, trusts.zero, trusts.zero.models; '
            'from trusts.zero.models import Trust; '
            'from trusts.apps import KernelConfig; '
            'from trusts.zero.apps import ZeroConfig; '
            'from django.db import connection; '
            'from django.db.migrations.loader import MigrationLoader; '
            'from django.db.migrations.executor import MigrationExecutor; '
            'from django.db.migrations.recorder import MigrationRecorder; '
            'from django.core.management import call_command; '
            'assert KernelConfig.label == "trusts_kernel"; '
            'assert ZeroConfig.label == "trusts"; '
            'tf, zf = trusts.__file__, trusts.zero.__file__; '
            'assert "site-packages" in tf, tf; '
            'assert "site-packages" in zf, zf; '
            'loader = MigrationLoader(connection); '
            'assert ("trusts", "0001_initial") in loader.disk_migrations; '
            'assert loader.disk_migrations[("trusts", "0001_initial")].__module__ '
            '== "trusts.zero.migrations.0001_initial"; '
            'call_command("migrate", verbosity=0); '
            'applied = {name for app, name in MigrationRecorder(connection).applied_migrations() if app == "trusts"}; '
            'assert applied == {"0001_initial", "0002_trustgroup"}, applied; '
            'ex = MigrationExecutor(connection); '
            'plan = [(m.app_label, m.name) for m, _b in ex.migration_plan(ex.loader.graph.leaf_nodes()) if m.app_label == "trusts"]; '
            'assert plan == [], plan; '
            'print("wheel+wheel ok", tf, zf, Trust, sorted(applied))'
        ), cwd=isolated)

        _run([str(ww_py), '-m', 'pip', 'uninstall', '-y', 'django-trusts-zero'])
        _python(ww_py, (
            _DJANGO_SETUP_KERNEL +
            'import importlib.util, trusts, trusts.context; '
            'from trusts.apps import KernelConfig; '
            'assert KernelConfig.label == "trusts_kernel"; '
            'assert "site-packages" in trusts.__file__, trusts.__file__; '
            'assert importlib.util.find_spec("trusts.zero") is None, '
            'importlib.util.find_spec("trusts.zero"); '
            'print("uninstall zero ok", trusts.__file__)'
        ), cwd=isolated)
        _pip(ww_py, str(zero_wheel))
        _python(ww_py, (
            _DJANGO_SETUP_BOTH +
            'import trusts, trusts.zero; from trusts.zero.models import Trust; '
            'from trusts.apps import KernelConfig; '
            'assert "site-packages" in trusts.__file__, trusts.__file__; '
            'assert "site-packages" in trusts.zero.__file__, trusts.zero.__file__; '
            'print("reinstall zero ok", Trust, KernelConfig.label)'
        ), cwd=isolated)

        ee_py = _make_venv(tmp_path / 'ee-venv')
        _pip(ee_py, '-e', str(ROOT), '--config-settings', 'editable_mode=compat')
        _pip(
            ee_py, '--no-deps', '-e', str(zero_src),
            '--config-settings', 'editable_mode=compat',
        )
        kernel_marker = str(ROOT.resolve())
        zero_marker = str(zero_src.resolve())
        ee_code = (
            _DJANGO_SETUP_BOTH +
            'import trusts, trusts.zero, pathlib; '
            'from trusts.zero.models import Trust; '
            'from trusts.apps import KernelConfig; '
            'assert trusts.__file__, "kernel must own trusts/__init__.py"; '
            'tf = pathlib.Path(trusts.__file__).resolve(); '
            'zf = pathlib.Path(trusts.zero.__file__).resolve(); '
            'assert ' + repr(kernel_marker) + ' in str(tf), tf; '
            'assert ' + repr(zero_marker) + ' in str(zf), zf; '
            'assert not (tf.parent / "zero").exists(), tf.parent; '
            'assert KernelConfig.label == "trusts_kernel"; '
            'print("editable+editable ok", tf, zf, Trust)'
        )
        _python(ee_py, ee_code, cwd=isolated)

        print('namespace install ok')
        print('kernel_wheel', kernel_wheel.name)
        print('zero_wheel', zero_wheel.name)
        print('companion_sha', zero_sha)
        return 0


if __name__ == '__main__':
    sys.exit(main())
