"""Configured path: path, registry, and compiler. No methods.

Snapshot and checks take one value. Inquiry calls the registry and
the compiler. Registration lives on the recorder and ``RegistryFactory``.
"""

from __future__ import annotations

__all__ = []

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BackendHandle:
    path: str
    registry: object
    compiler: object


def pair(entry):
    if isinstance(entry, tuple):
        return entry
    return entry.registry, getattr(entry, 'compiler', None)
