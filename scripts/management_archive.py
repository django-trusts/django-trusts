"""Detect ``trusts/management`` members in sdist/wheel archives.

Wheel members are normally root-relative (``trusts/management/__init__.py``).
Sdist members are prefixed (``django_trusts-1.0.0.dev3/trusts/management/...``).
A matcher that only looks for ``/trusts/management/`` misses the wheel root.
"""

from __future__ import annotations


def normalize_archive_member(name: str) -> str:
    return name.replace('\\', '/').lstrip('./')


def ships_trusts_management(names) -> list[str]:
    """Return archive members that ship ``trusts/management`` at root or prefixed."""
    hits = []
    for name in names:
        normalized = normalize_archive_member(name)
        if (
            normalized == 'trusts/management'
            or normalized.startswith('trusts/management/')
            or '/trusts/management/' in normalized
            or normalized.endswith('/trusts/management')
        ):
            hits.append(name)
    return hits
