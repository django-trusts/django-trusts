#!/usr/bin/env python3
"""Prove wheel/sdist identity: core 1.0.0.dev3, BSD-2-Clause, user README."""

from __future__ import annotations

import os
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = '1.0.0.dev3'
EXPECTED_NAME = 'django-trusts'
FORBIDDEN_LONG_DESC = (
    'Step I',
    'Step II',
    'Step III',
    'kernel_config',
    'trusts.core_backends',
    'pair pin',
    'multiple organizations and object-level permission settings',
)


def _dist() -> Path:
    return ROOT / 'dist'


def _require_dist(files: list[Path], kind: str) -> Path:
    if not files:
        raise SystemExit('no %s in dist/' % kind)
    return files[-1]


def _check_metadata(meta_text: str, origin: str) -> None:
    meta = Parser().parsestr(meta_text)
    if meta.get('Name') != EXPECTED_NAME:
        raise SystemExit('%s Name is %r, expected %s' % (origin, meta.get('Name'), EXPECTED_NAME))
    if meta.get('Version') != EXPECTED_VERSION:
        raise SystemExit(
            '%s Version is %r, expected %s' % (origin, meta.get('Version'), EXPECTED_VERSION)
        )
    license_expr = meta.get('License-Expression') or meta.get('License') or ''
    if 'BSD-2-Clause' not in license_expr:
        raise SystemExit('%s license is %r, expected BSD-2-Clause' % (origin, license_expr))
    description = meta.get('Description') or meta_text
    if 'non-standalone Python dependency' not in description:
        raise SystemExit('%s long description is not the user README' % origin)
    if "Do **not** list `'trusts'` in `INSTALLED_APPS`" not in description:
        raise SystemExit('%s long description missing INSTALLED_APPS warning' % origin)
    if 'pip install django-trusts' in description:
        raise SystemExit('%s long description still has a bare PyPI install' % origin)
    if 'BeeDesk, Inc., 2015–2026 (BSD-2-Clause)' not in description:
        raise SystemExit('%s long description missing BeeDesk 2015–2026 notice' % origin)
    for needle in FORBIDDEN_LONG_DESC:
        if needle in description:
            raise SystemExit(
                '%s long description still contains internal-status language: %s'
                % (origin, needle)
            )
    summary = meta.get('Summary') or ''
    if 'multiple organizations' in summary:
        raise SystemExit('%s summary still describes the removed concrete product' % origin)


def _check_wheel(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        meta_name = next(
            (name for name in names if name.endswith('.dist-info/METADATA')),
            None,
        )
        if meta_name is None:
            raise SystemExit('wheel missing METADATA: %s' % wheel.name)
        _check_metadata(zf.read(meta_name).decode(), wheel.name)
        license_hits = [
            name for name in names
            if name.endswith('/LICENSE') or name.endswith('.dist-info/LICENSE')
        ]
        if not license_hits:
            raise SystemExit('wheel missing LICENSE: %s' % names[-20:])
        notice = zf.read(license_hits[0]).decode()
        if 'Copyright (c) 2015-2026, BeeDesk, Inc.' not in notice:
            raise SystemExit('wheel LICENSE notice is not BeeDesk 2015-2026')
        if 'and contributors' in notice.split('THIS SOFTWARE')[0]:
            raise SystemExit('wheel LICENSE copyright adds "and contributors"')
        if 'django_trusts-1.0.0.dev3' not in wheel.name:
            raise SystemExit('wheel filename is not 1.0.0.dev3: %s' % wheel.name)
        management_hits = [
            name for name in names
            if '/trusts/management/' in name or name.endswith('/trusts/management')
            or name.endswith('trusts/management')
        ]
        if management_hits:
            raise SystemExit(
                'wheel still ships trusts/management/**: %s' % management_hits
            )
    print('wheel metadata ok', wheel.name)


def _check_sdist(sdist: Path) -> None:
    with tarfile.open(sdist, 'r:gz') as tf:
        names = tf.getnames()
        prefix = 'django_trusts-1.0.0.dev3'
        if not any(name == prefix or name.startswith(prefix + '/') for name in names):
            raise SystemExit('sdist is not 1.0.0.dev3: %s' % sdist.name)
        license_name = next((name for name in names if name.endswith('/LICENSE')), None)
        if license_name is None:
            raise SystemExit('sdist missing LICENSE')
        notice = tf.extractfile(license_name).read().decode()
        if 'Copyright (c) 2015-2026, BeeDesk, Inc.' not in notice:
            raise SystemExit('sdist LICENSE notice is not BeeDesk 2015-2026')
        pkg_info = next((name for name in names if name.endswith('/PKG-INFO')), None)
        if pkg_info is None:
            raise SystemExit('sdist missing PKG-INFO')
        _check_metadata(tf.extractfile(pkg_info).read().decode(), sdist.name)
        readme_name = next((name for name in names if name.endswith('/README.md')), None)
        if readme_name is None:
            raise SystemExit('sdist missing README.md')
        readme = tf.extractfile(readme_name).read().decode()
        if 'non-standalone Python dependency' not in readme:
            raise SystemExit('sdist README.md is not the user README')
        if any(name.endswith('/DEV.md') for name in names):
            pass
        else:
            raise SystemExit('sdist missing DEV.md')
        management_hits = [
            name for name in names
            if '/trusts/management/' in name or name.endswith('/trusts/management')
        ]
        if management_hits:
            raise SystemExit(
                'sdist still ships trusts/management/**: %s' % management_hits
            )
    print('sdist metadata ok', sdist.name)


def main() -> int:
    dist = _dist()
    wheels = sorted(dist.glob('django_trusts-*.whl'))
    sdists = sorted(dist.glob('django_trusts-*.tar.gz'))
    wheel = _require_dist(wheels, 'wheel')
    sdist = _require_dist(sdists, 'sdist')
    _check_wheel(wheel)
    _check_sdist(sdist)
    print('package metadata ok')
    print('core', EXPECTED_NAME + '==' + EXPECTED_VERSION)
    print('license BSD-2-Clause')
    return 0


if __name__ == '__main__':
    os.chdir(ROOT)
    raise SystemExit(main())
