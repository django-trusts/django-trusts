"""Request-side named filters: tuple validation and Q compilation.

Request filters live in the type-scoped condition store
(``register_request_filter`` / ``register_permission_condition``).
This module does not parse colon suffixes and does not accept a
``conditions=`` alias.
"""

from __future__ import annotations

import re

from django.db.models import Model, Q, QuerySet


FILTER_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]*$')


def validate_filter_name(name, *, role='filter'):
    """Reject non-str / malformed names before any store lookup."""
    from trusts.core import TrustsConfigurationError

    if not isinstance(name, str) or isinstance(name, bool):
        raise TypeError(
            '%s name must be str, not %r.' % (role, type(name).__name__,)
        )
    if not FILTER_NAME_RE.fullmatch(name):
        raise TrustsConfigurationError(
            '%s name %r is malformed; expected '
            '[A-Za-z][A-Za-z0-9_]*.' % (role, name)
        )
    return name


def validate_request_filter(value):
    """Validate the outer request ``filter=`` value before iteration.

    A bare ``str`` is ``TypeError`` (never walked as an iterable of
    characters). Lists, sets, generators, and mappings are ``TypeError``.
    Omitted / ``None`` / ``()`` is the empty tuple. Duplicates and
    malformed names fail closed without silent dedupe.
    """
    from trusts.core import TrustsConfigurationError

    if value is None:
        value = ()
    if not isinstance(value, tuple):
        raise TypeError(
            'filter must be a tuple of str, not %r.' % (type(value).__name__,)
        )
    seen = []
    for name in value:
        validate_filter_name(name, role='request filter')
        if name in seen:
            raise TrustsConfigurationError(
                'Duplicate request filter name %r.' % (name,)
            )
        seen.append(name)
    return value


def request_filter_query_identity(value):
    """Canonical query identity: validate first, then sort.

    Diagnostics keep the supplied order (the validated tuple). Identity
    for manifests / query keys is the sorted tuple.
    """
    validated = validate_request_filter(value)
    return tuple(sorted(validated))


def _content_model(obj):
    from trusts.core import TrustsConfigurationError

    if isinstance(obj, QuerySet):
        return obj.model._meta.concrete_model
    if isinstance(obj, type) and issubclass(obj, Model):
        return obj._meta.concrete_model
    if isinstance(obj, Model):
        return obj._meta.concrete_model
    raise TrustsConfigurationError(
        'filter compilation requires a model instance or QuerySet, '
        'not %r.' % (obj,)
    )


def _expr_key(expr):
    to_tuple = getattr(expr, 'to_tuple', None)
    if callable(to_tuple):
        return to_tuple()
    return expr


def compile_request_filter_q(handles, obj, user, permission, filter=()):
    """AND compiled request-filter ``Q`` objects, or ``None`` when bare.

    Looks up each name on configured handle stores. Unknown names raise
    today's unknown-condition ``AttributeError``. Conflicting IR across
    handles is ``TrustsConfigurationError``. The overlay never creates a
    grant.
    """
    from trusts.conditions._ir import (
        _unknown_condition_error,
        compile_expression_q,
    )
    from trusts.core import TrustsConfigurationError

    names = validate_request_filter(filter)
    if not names:
        return None
    model = _content_model(obj)
    parts = []
    for name in names:
        found = None
        found_key = None
        for handle in handles:
            record = handle.registry.get_permission_condition_record(
                model, name,
            )
            if record is None:
                continue
            key = _expr_key(record.expr)
            if found is not None and key != found_key:
                raise TrustsConfigurationError(
                    'Request filter %r on %s has conflicting IR across '
                    'configured backends.' % (name, model._meta.label)
                )
            found = record
            found_key = key
        if found is None:
            raise _unknown_condition_error(model, name)
        parts.append(
            compile_expression_q(found.expr, model, user, permission)
        )
    overlay = parts[0]
    for part in parts[1:]:
        overlay = overlay & part
    return overlay


def combine_extra_q(extra_q, overlay):
    """AND an optional raw overlay with a request-filter overlay."""
    if overlay is None:
        return extra_q
    if extra_q is None:
        return overlay
    return extra_q & overlay
