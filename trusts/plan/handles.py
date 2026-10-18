"""Configured backend handle.

``BackendHandle`` is the path, registry, and compiler triple the
backend keeps. Registration and named filters forward to that registry.
``trusts.core`` re-exports this class. This module is not a public
import surface, and it does not import ``trusts.core`` at runtime.
"""

from __future__ import annotations

__all__ = []

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar

from django.db.models import Model

from trusts.errors import TrustsConfigurationError

if TYPE_CHECKING:
    from trusts.compile.factory import RegisteredDelegation, RegisteredRelation

T = TypeVar('T', bound=Model)


@dataclass(frozen=True, slots=True)
class BackendHandle:
    """Exact configured path, exact registry identity, and class compiler."""

    path: str
    registry: object
    compiler: object

    def register(
        self,
        *,
        trust: type[T],
        user: str | Callable[[T], object] | None = None,
        permission: str | Callable[[T], object] | None = None,
        content: str | Callable[[T], object],
        group: str | Callable[[T], object] | None = None,
        delegate: str | Callable[[T], object] | None = None,
        sponsor: str | Callable[[T], object] | None = None,
        condition: (
            Callable[[T], object]
            | Callable[[T, object], object]
            | None
        ) = None,
        along=None,
    ) -> RegisteredRelation | RegisteredDelegation:
        """Register one ordinary grant or delegated relationship.

        ``user`` and ``content`` accept a Django ``__`` path string or a
        one-argument symbolic path builder. A dependent ``content`` path may
        cross forward single-valued or reverse one-to-one prefix hops before
        its one reverse one-to-many gateway. ``permission`` and ``group``
        are mutually exclusive sources. ``permission`` is one direct
        single-valued hop, or zero or more forward single-valued hops
        followed by exactly one forward many-to-many to
        ``auth.Permission``. ``group`` is a forward single-valued path that
        must end at Django's ``auth.Group``. The compiler appends
        ``Group.permissions``; applications do not put ``permissions``
        on the group path. Supplying both, or neither, raises
        ``TrustsConfigurationError`` before any path builder runs. A
        ``permission=`` registration does not contribute to
        ``get_group_permissions``. Delegated mode instead requires exactly
        ``delegate=`` and ``sponsor=`` and forbids ``user=``, ``permission=``,
        and ``group=``. ``along=`` is the same bounded walk as an ordinary
        registration. A delegated row is not an ordinary grant: the delegate
        is allowed on an object only when that walk reaches the object and
        the sponsor's ordinary authority reaches it too.

        A builder is called once during registration with a value typed
        as ``trust``. Attribute access records a path; the callable is
        discarded and never stored or run during authorization.
        In ordinary mode, ``condition`` is a one-argument trust-rooted
        symbolic callable. In delegated mode it accepts either the
        relationship alone or ``(relationship, requested_permission)``.
        Conditions use path ``==``, collection-rooted
        ``.contains(member)``, and ``&``. They are invoked once after the
        freeze check; the stored overlay contains no callable. For
        ``group=``, ``.contains`` member is the compiler-owned permission
        path. Prebuilt predicate nodes are ``TypeError``. ``predicate`` is
        reserved and unsupported. ``along`` is ``(path, bound)``. Passing
        a ``Ref`` is ``TypeError``. A frozen backend raises
        ``TrustsConfigurationError`` before path parsing or builder
        invocation.

        Only an explicit ``group=`` record contributes to
        ``get_group_permissions``. That same record also participates in
        ordinary ``has_perm``, ``get_all_permissions``, and authorized
        querysets. A ``permission=`` record is never treated as
        group-derived because its user path is many-to-many.
        """
        return self.registry._register_public(
            trust=trust,
            user=user,
            permission=permission,
            content=content,
            group=group,
            delegate=delegate,
            sponsor=sponsor,
            condition=condition,
            along=along,
        )

    def add_named_filter(self, model, code, predicate):
        """Bind a named restricting predicate on this backend.

        Forwards the current registration-time permission-condition
        builder. A frozen/finalized backend raises
        ``TrustsConfigurationError`` before ``predicate`` is invoked.
        A prebuilt ``Expr`` is not accepted. The filter grants nothing
        independently.
        """
        if getattr(self.registry, 'frozen', False):
            raise TrustsConfigurationError(
                'Cannot register a permission condition on a frozen '
                'TrustsRegistry.'
            )
        return self.registry.register_permission_condition(
            model, code, predicate,
        )

    def build_registry(self):
        """Built query-time registry for this path, or ``None``.

        ``None`` is only the factory->backend signal for "no registry
        for this path" (``self.registry is None``); callers translate
        it to ``False`` / ``set()`` / an empty queryset and never return
        it as a Django backend result. A registry that is already built
        (``FrozenRegistry.build_registry`` returns itself) or a
        duck-typed registry without ``build_registry`` is returned
        as-is. A configured-but-empty builder builds an empty registry.
        """
        registry = self.registry
        if registry is None:
            return None
        build = getattr(registry, 'build_registry', None)
        return build() if callable(build) else registry

    @property
    def historical_fallback(self):
        """True when this route uses ``HistoricalGroupQueryCompiler``.

        Noun-blind core does not decide this. The flag identifies the
        concrete compiler for mixin isolation. It does not reopen a
        static content map; undeclared terminals fail closed.
        """
        return bool(getattr(self.compiler, 'historical_fallback', False))
