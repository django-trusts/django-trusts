"""Resolve the authoritative django-trusts-zero checkout for kernel proofs.

The Zero repository owns version and Requires-Dist. This kernel tree must
not ship ``trusts/zero`` or a second ``pyproject.toml`` for that
distribution. Override the pin with ``DJANGO_TRUSTS_ZERO_REPO``,
``DJANGO_TRUSTS_ZERO_REF``, or ``DJANGO_TRUSTS_ZERO_SRC``.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = ROOT / 'scripts' / 'zero-companion.pin'
FORBIDDEN_KERNEL_ZERO_PATHS = (
    ROOT / 'trusts' / 'zero',
    ROOT / 'packaging' / 'django-trusts-zero',
)


def read_pin(path: Path = PIN_PATH) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or '=' not in stripped:
            continue
        key, value = stripped.split('=', 1)
        values[key.strip()] = value.strip()
    return values


def assert_kernel_has_no_zero_tree(root: Path = ROOT) -> None:
    hits = [
        path for path in (
            root / 'trusts' / 'zero',
            root / 'packaging' / 'django-trusts-zero',
        )
        if path.exists()
    ]
    if hits:
        raise SystemExit(
            'kernel checkout must not contain Zero sources or packaging '
            'mirrors (Chat #46 review): %s' % ', '.join(str(p) for p in hits)
        )


def resolve_companion_src(dest: Path) -> Path:
    """Return the companion checkout, cloning it when ``DJANGO_TRUSTS_ZERO_SRC`` is unset."""
    existing = os.environ.get('DJANGO_TRUSTS_ZERO_SRC')
    if existing:
        src = Path(existing)
        if not (src / 'pyproject.toml').is_file():
            raise SystemExit('DJANGO_TRUSTS_ZERO_SRC has no pyproject.toml: %s' % src)
        if (src / 'trusts' / '__init__.py').exists():
            raise SystemExit('companion must not ship trusts/__init__.py: %s' % src)
        return src

    pin = read_pin()
    repo = os.environ.get('DJANGO_TRUSTS_ZERO_REPO', pin['repo'])
    ref = os.environ.get('DJANGO_TRUSTS_ZERO_REF', pin['ref'])
    dest.mkdir(parents=True, exist_ok=True)
    if dest.exists() and any(dest.iterdir()):
        raise SystemExit('companion dest is not empty: %s' % dest)

    clone = subprocess.run(
        ['git', 'clone', '--depth', '1', '--branch', ref, repo, str(dest)],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if clone.returncode != 0:
        subprocess.run(['git', 'clone', repo, str(dest)], check=True)
        subprocess.run(['git', '-C', str(dest), 'checkout', ref], check=True)
    if (dest / 'trusts' / '__init__.py').exists():
        raise SystemExit('companion must not ship trusts/__init__.py: %s' % dest)
    return dest


def companion_sha(src: Path) -> str:
    result = subprocess.run(
        ['git', '-C', str(src), 'rev-parse', 'HEAD'],
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return result.stdout.strip().splitlines()[-1]


def assert_companion_metadata(src: Path) -> dict:
    pin = read_pin()
    expected_version = pin.get('expected_version', '2.0.0.dev0')
    required_dist = pin.get('required_dist', 'django-trusts')
    data = tomllib.loads((src / 'pyproject.toml').read_text())
    project = data.get('project') or {}
    name = project.get('name')
    version = project.get('version')
    deps = project.get('dependencies') or []
    if name != 'django-trusts-zero':
        raise SystemExit('companion project.name is %r, not django-trusts-zero' % name)
    if version != expected_version:
        raise SystemExit(
            'companion version is %r, expected %s (Zero repo is authoritative)' % (
                version, expected_version,
            )
        )
    if not any(_dist_matches(dep, required_dist) for dep in deps):
        raise SystemExit(
            'companion pyproject.toml must declare %s in [project.dependencies]; '
            'got %r' % (required_dist, deps)
        )
    return project


def _dist_matches(requirement: str, name: str) -> bool:
    token = requirement.strip().split(';')[0].strip()
    dist = token.split('[')[0].split('@')[0].strip()
    dist = re.split(r'\s*(===|==|>=|<=|~=|!=|>|<)\s*', dist, maxsplit=1)[0]
    return dist.strip().lower() == name.lower()


def wheel_requires_dist(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as zf:
        names = [n for n in zf.namelist() if n.endswith('.dist-info/METADATA')]
        if not names:
            raise SystemExit('%s has no METADATA' % wheel)
        text = zf.read(names[0]).decode('utf-8')
    return [
        line.split(':', 1)[1].strip()
        for line in text.splitlines()
        if line.startswith('Requires-Dist:')
    ]


def assert_wheel_requires_dist(wheel: Path, name: str) -> None:
    reqs = wheel_requires_dist(wheel)
    if not any(_dist_matches(req, name) for req in reqs):
        raise SystemExit(
            '%s METADATA is missing Requires-Dist %s; got %r' % (
                wheel.name, name, reqs,
            )
        )


def main() -> int:
    assert_kernel_has_no_zero_tree()
    pin = read_pin()
    print('zero companion pin', pin)
    return 0


if __name__ == '__main__':
    sys.exit(main())
