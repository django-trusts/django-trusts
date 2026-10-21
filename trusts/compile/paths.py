"""Resolved ``Along`` walks stored on a registration.

Role paths use the shared condition builder. This module keeps the walk
metadata only.
"""

__all__ = []

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AlongWalk:
    """Immutable walk metadata resolved from ``Along`` at ``register()``."""

    path: tuple
    bound: int
    shape: str
    walk_path: tuple
    walk_model: type
    walk_ident: str
    walk_field: str
    suffix_path: tuple
    suffix_field: str
    ident_family: str
    parent_attname: str | None
    edge_model: type | None
    edge_parent_attname: str | None
    edge_child_attname: str | None
    rewrite_attname: str | None

