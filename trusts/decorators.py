"""Native view decorators and request-data binders (issue #47 S3).

``@require_authorized(operation, resource_model=..., resource_kwarg=...)``
is the framework HTTP security boundary. Resource identity comes only
from declared request keys: URL kwargs via ``resource_kwarg`` or inert
``K`` / ``G`` / ``O`` selectors. There are no getter callbacks, no
content-type model inference, and no Django permission-string parser.

Authorization is the S1 runtime (``filter_authorized`` / the shared
``grant_q``). This module does not call the Django user-permission
helper and does not walk policy a second time. Active superuser status
does not bypass registered object policy.

HTTP outcomes:

* Missing or unresolvable resource identity → ``Http404`` (default).
* Existing but unauthorized, unusable principal, unknown operation
  data → ``PermissionDenied`` (403), or a login redirect when
  ``raise_exception=False``.
* ``AuthorizationConfigError`` → ``PermissionDenied`` (403). Malformed
  configuration cannot produce access.

Query contract (honest):

* Missing request key → 0 SQL.
* Unusable principal + existence check → 1 SQL (no auth ``Exists``).
* Granted path combines lookup + auth in **one** SQL
  (``filter_authorized`` on the lookup queryset, then ``.first()``).
* Unauthorized / not-found after a combined miss needs a **second**
  existence query so 403 and 404 stay distinct.
* ``P`` composition evaluates each leaf on that same machinery.

Zero's Django-permission compatibility decorator stays in
``trusts.zero.decorators``.
"""

from functools import wraps
from operator import and_, or_
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import (
    FieldError,
    PermissionDenied,
    ValidationError,
)
from django.http import Http404
from django.shortcuts import resolve_url

from trusts.runtime import (
    AuthorizationConfigError,
    filter_authorized,
    principal_is_usable,
)


_MISSING = object()

GRANTED = 'granted'
DENIED = 'denied'
NOT_FOUND = 'not_found'
CONFIG_ERROR = 'config_error'


class K(object):
    """Inert URL-kwarg key selector. Not a getter."""

    def __init__(self, key):
        if not isinstance(key, str) or not key:
            raise AuthorizationConfigError(
                'K() requires a non-empty request key string, not %r.' % (key,)
            )
        self.key = key

    def __repr__(self):
        return 'K(%r)' % (self.key,)


class G(object):
    """Inert GET-parameter key selector. Not a getter."""

    def __init__(self, key):
        if not isinstance(key, str) or not key:
            raise AuthorizationConfigError(
                'G() requires a non-empty request key string, not %r.' % (key,)
            )
        self.key = key

    def __repr__(self):
        return 'G(%r)' % (self.key,)


class O(object):
    """Inert POST-parameter key selector. Not a getter."""

    def __init__(self, key):
        if not isinstance(key, str) or not key:
            raise AuthorizationConfigError(
                'O() requires a non-empty request key string, not %r.' % (key,)
            )
        self.key = key

    def __repr__(self):
        return 'O(%r)' % (self.key,)


class P(object):
    """Operation-and-selector data. ``&`` / ``|`` compose over the same leaves.

    A leaf holds an operation (instance or ``operation_lookup`` string),
    an explicit ``resource_model``, and request-key selectors. Parent
    nodes created by ``&`` / ``|`` hold no operation of their own.
    Callables are rejected. This is not Zero's Django-permission ``P``.
    """

    def __init__(self, operation, resource_model=None, resource_kwarg=None, **fieldlookups):
        self._operation = operation
        self._resource_model = resource_model
        self._resource_kwarg = resource_kwarg
        self._fieldlookups = fieldlookups
        self._left_operand = None
        self._right_operand = None
        self._operator = None
        if resource_kwarg is not None and not isinstance(resource_kwarg, str):
            raise AuthorizationConfigError(
                'resource_kwarg must be a URL kwarg name string, not %r.' % (
                    resource_kwarg,
                )
            )
        for field, selector in fieldlookups.items():
            _require_selector(selector, field)

    def __and__(self, other):
        if not isinstance(other, P):
            raise TypeError(
                "unsupported operand type(s) for &: '%s' and '%s'" % (
                    type(self), type(other),
                )
            )
        parent = P('')
        parent._left_operand = self
        parent._right_operand = other
        parent._operator = and_
        return parent

    def __or__(self, other):
        if not isinstance(other, P):
            raise TypeError(
                "unsupported operand type(s) for |: '%s' and '%s'" % (
                    type(self), type(other),
                )
            )
        parent = P('')
        parent._left_operand = self
        parent._right_operand = other
        parent._operator = or_
        return parent

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        if self._operator:
            return 'P object'
        if isinstance(self._operation, str):
            return self._operation
        return 'P object'

    def get_leaves(self):
        if not self._operator:
            return [self]
        return self._left_operand.get_leaves() + self._right_operand.get_leaves()

    def with_defaults(self, resource_model=None, resource_kwarg=None, fieldlookups=None):
        """Copy this tree, filling missing model/selectors from decorator args."""
        if fieldlookups is None:
            fieldlookups = {}
        if self._operator:
            left = self._left_operand.with_defaults(
                resource_model, resource_kwarg, fieldlookups,
            )
            right = self._right_operand.with_defaults(
                resource_model, resource_kwarg, fieldlookups,
            )
            if self._operator is and_:
                return left & right
            return left | right
        merged = dict(fieldlookups)
        merged.update(self._fieldlookups)
        return P(
            self._operation,
            resource_model=self._resource_model or resource_model,
            resource_kwarg=self._resource_kwarg or resource_kwarg,
            **merged
        )


def _require_selector(value, field):
    if isinstance(value, (K, G, O)):
        return value
    if callable(value):
        raise AuthorizationConfigError(
            'Field %r must be a K, G, or O selector, not a callable.' % (field,)
        )
    raise AuthorizationConfigError(
        'Field %r must be a K, G, or O selector, not %r.' % (field, value)
    )


def _require_model(resource_model):
    meta = getattr(resource_model, '_meta', None)
    if not isinstance(resource_model, type) or meta is None:
        raise AuthorizationConfigError(
            'resource_model must be an explicit Django model class, not %r.' % (
                resource_model,
            )
        )
    return resource_model


def _source_has(source, key):
    try:
        return key in source
    except (TypeError, ValueError):
        return False


def _source_get(source, key):
    try:
        return source[key]
    except (KeyError, TypeError, ValueError):
        return _MISSING


def _bind_lookups(request, view_kwargs, resource_kwarg, fieldlookups):
    """Resolve declared keys to field lookups. Missing keys stay ``_MISSING``."""
    resolved = {}
    if resource_kwarg is not None:
        if _source_has(view_kwargs, resource_kwarg):
            resolved['pk'] = view_kwargs[resource_kwarg]
        else:
            resolved['pk'] = _MISSING
    for field, selector in fieldlookups.items():
        if isinstance(selector, K):
            source = view_kwargs
        elif isinstance(selector, G):
            source = request.GET
        elif isinstance(selector, O):
            source = request.POST
        else:
            raise AuthorizationConfigError(
                'Field %r must be a K, G, or O selector, not %r.' % (
                    field, selector,
                )
            )
        if _source_has(source, selector.key):
            resolved[field] = _source_get(source, selector.key)
        else:
            resolved[field] = _MISSING
    return resolved


def _lookups_usable(resolved):
    if not resolved:
        return False
    for value in resolved.values():
        if value is _MISSING or value is None or value == '':
            return False
    return True


def _evaluate_leaf(request, view_kwargs, leaf, runtime):
    try:
        resource_model = _require_model(leaf._resource_model)
        resolved = _bind_lookups(
            request, view_kwargs, leaf._resource_kwarg, leaf._fieldlookups,
        )
        if not resolved:
            raise AuthorizationConfigError(
                'require_authorized needs resource_kwarg or a K/G/O selector '
                'so resource identity comes from declared request keys.'
            )
        if not _lookups_usable(resolved):
            return NOT_FOUND
        principal = getattr(request, 'user', _MISSING)
        if principal is _MISSING:
            raise AuthorizationConfigError(
                'require_authorized requires request.user.'
            )
        candidates = resource_model._default_manager.filter(**resolved)
        if not principal_is_usable(principal):
            if candidates.exists():
                return DENIED
            return NOT_FOUND
        authorized = filter_authorized(
            candidates, principal, leaf._operation, **runtime,
        )
        if authorized.first() is not None:
            return GRANTED
        if candidates.exists():
            return DENIED
        return NOT_FOUND
    except AuthorizationConfigError:
        return CONFIG_ERROR
    except (ValidationError, ValueError, TypeError):
        return NOT_FOUND
    except FieldError:
        return CONFIG_ERROR


def _evaluate_expr(request, view_kwargs, expr, runtime):
    if expr._operator:
        left = _evaluate_expr(
            request, view_kwargs, expr._left_operand, runtime,
        )
        if expr._operator is and_:
            if left is not GRANTED:
                return left
            return _evaluate_expr(
                request, view_kwargs, expr._right_operand, runtime,
            )
        if left is GRANTED:
            return left
        right = _evaluate_expr(
            request, view_kwargs, expr._right_operand, runtime,
        )
        if right is GRANTED:
            return GRANTED
        if left is CONFIG_ERROR or right is CONFIG_ERROR:
            return CONFIG_ERROR
        if left is DENIED or right is DENIED:
            return DENIED
        return NOT_FOUND
    return _evaluate_leaf(request, view_kwargs, expr, runtime)


def request_passes_test(test_func, login_url=None, redirect_field_name=REDIRECT_FIELD_NAME):
    """Run ``test_func(request, *args, **kwargs)``; login-redirect on ``False``.

    ``Http404`` / ``PermissionDenied`` raised by the test propagate.
    Wrapped-view metadata is preserved with ``functools.wraps``.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if test_func(request, *args, **kwargs):
                return view_func(request, *args, **kwargs)
            path = request.build_absolute_uri()
            resolved_login_url = resolve_url(login_url or settings.LOGIN_URL)
            login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
            current_scheme, current_netloc = urlparse(path)[:2]
            if ((not login_scheme or login_scheme == current_scheme) and
                    (not login_netloc or login_netloc == current_netloc)):
                path = request.get_full_path()
            return redirect_to_login(
                path, resolved_login_url, redirect_field_name)
        return _wrapped_view
    return decorator


def require_authorized(
    operation,
    resource_model=None,
    resource_kwarg=None,
    raise_exception=True,
    login_url=None,
    redirect_field_name=REDIRECT_FIELD_NAME,
    context=None,
    trustee=None,
    names=None,
    **fieldlookups
):
    """Authorize a view from operation data and declared request keys.

    ``operation`` is an operation instance, an ``operation_lookup``
    string, or a ``P`` expression. ``resource_model`` is required on the
    decorator or on each ``P`` leaf. ``resource_kwarg`` names the URL
    kwarg that holds the resource primary key. Additional field lookups
    must use ``K`` / ``G`` / ``O``.

    Isolated tests pass ``context=`` / ``trustee=`` (process-wide maps
    remain the no-arg default).
    """
    if resource_kwarg is not None and not isinstance(resource_kwarg, str):
        raise AuthorizationConfigError(
            'resource_kwarg must be a URL kwarg name string, not %r.' % (
                resource_kwarg,
            )
        )
    for field, selector in fieldlookups.items():
        _require_selector(selector, field)
    if isinstance(operation, P):
        expr = operation.with_defaults(
            resource_model, resource_kwarg, fieldlookups,
        )
    else:
        expr = P(
            operation,
            resource_model=resource_model,
            resource_kwarg=resource_kwarg,
            **fieldlookups
        )
    runtime = dict(context=context, trustee=trustee, names=names)

    def _check(request, *args, **kwargs):
        outcome = _evaluate_expr(request, kwargs, expr, runtime)
        if outcome is GRANTED:
            return True
        if outcome is NOT_FOUND:
            raise Http404
        if outcome is CONFIG_ERROR:
            raise PermissionDenied
        if raise_exception:
            raise PermissionDenied
        return False

    return request_passes_test(
        _check, login_url=login_url, redirect_field_name=redirect_field_name,
    )


__all__ = [
    'G',
    'K',
    'O',
    'P',
    'require_authorized',
    'request_passes_test',
]
