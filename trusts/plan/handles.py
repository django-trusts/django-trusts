"""Configured path: a path and the registry that answers it.

Snapshot and checks take this value for the path string. The registry
carries its compiler. Inquiry calls the registry. Registration lives
on the recorder and ``RegistryFactory``.
"""

from __future__ import annotations

__all__ = []

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BackendHandle:
    path: str
    registry: object


def registry_of(entry):
    """Registry on a configured path, or the entry when it is one."""
    if hasattr(entry, 'registry'):
        return entry.registry
    return entry
