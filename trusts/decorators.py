"""View authorization decorators.

``authorization_required`` is the Core 1.0 guard. ``permission_required``
and ``P`` / ``K`` / ``G`` / ``O`` remain unadvertised legacy/experimental
Zero compatibility; their behavior is preserved and is not the frozen
Core API.
"""

from functools import wraps
from urllib.parse import urlparse
from operator import and_, or_

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist, ValidationError
from django.shortcuts import resolve_url
from django.contrib.contenttypes.models import ContentType
from django.db.models import Model, Subquery
from django.db.models.base import ModelBase
from django.db.models.query import QuerySet
from django.http import Http404

from trusts import utils


class P(object):
    def __init__(self, perm, **fieldlookups):
        self._perm = perm
        self._fieldlookups = fieldlookups
        self._left_operand = None
        self._right_operand = None
        self._operator = None

    def __and__(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError("unsupported operand type(s) for &: '%s' and '%s'" % (type(self), type(other)))

        p = type(self)('')
        p._left_operand = self
        p._right_operand = other
        p._operator = and_
        return p

    def __or__(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError("unsupported operand type(s) for |: '%s' and '%s'" % (type(self), type(other)))

        p = type(self)('')
        p._left_operand = self
        p._right_operand = other
        p._operator = or_
        return p

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        if not self._operator:
            return self._perm

        return 'P object'

    def get_leaves(self):
        leaves = []
        if not self._operator:
            return [self]

        # Do not use += or leaves.extend here since it changes the original list
        leaves = leaves + self._left_operand.get_leaves()
        leaves = leaves + self._right_operand.get_leaves()

        return leaves

    def solve(self, fn):
        if self._operator:
            # Parent node, return result operation
            if self._operator == and_:
                return self._left_operand.solve(fn) and self._right_operand.solve(fn)
            elif self._operator == or_:
                return self._left_operand.solve(fn) or self._right_operand.solve(fn)
            else:
                raise TypeError('Unsupported Operator: ', self._operator)
        else:
            return fn(self._perm, **self._fieldlookups)


class R(object):
    def __init__(self, key):
        self.key = key


class K(R):
    pass


class G(R):
    pass


class O(R):
    pass


def request_passes_test(test_func, login_url=None, redirect_field_name=REDIRECT_FIELD_NAME, *args, **kwargs):
    '''
    Decorator for views that checks that the user passes the given test,
    redirecting to the log-in page if necessary. The test should be a callable
    that takes the user object and returns True if the user passes.

    Adapted from `django/contrib/auth/decorator.py`
    '''

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if test_func(request, *args, **kwargs):
                return view_func(request, *args, **kwargs)

            path = request.build_absolute_uri()
            resolved_login_url = resolve_url(login_url or settings.LOGIN_URL)
            # If the login url is the same scheme and net location then just
            # use the path as the "next" url.
            login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
            current_scheme, current_netloc = urlparse(path)[:2]
            if ((not login_scheme or login_scheme == current_scheme) and
                    (not login_netloc or login_netloc == current_netloc)):
                path = request.get_full_path()
            return redirect_to_login(
                path, resolved_login_url, redirect_field_name)
        return _wrapped_view
    return decorator


def _collect_args(args, fieldlookups):
    results = {}

    if not fieldlookups:
        return results

    for lookup, arg_name in fieldlookups.items():
        if arg_name in args:
            results[lookup] = args[arg_name]
        else:
            results[lookup] = None

    return results


def _get_permissible_items(perm, request, fieldlookups):
    if fieldlookups is None:
        return None

    applabel, modelname, action, cond = utils.parse_perm_code(perm)
    try:
        ctype = ContentType.objects.get_by_natural_key(applabel, modelname)

        return ctype.model_class().objects.filter(**fieldlookups)
    except ObjectDoesNotExist:
        raise ValueError('Permission code must be of the form "app_label.action_modelname". Actual: %s' % perm)


def _resolve_fieldlookups(request, kwargs, fieldlookups_kwargs=None, fieldlookups_getparams=None, fieldlookups_postparams=None, **fieldlookups):
    resolved_fields = {}

    resolved_fields.update(_collect_args(kwargs, fieldlookups_kwargs))
    resolved_fields.update(_collect_args(request.GET, fieldlookups_getparams))
    resolved_fields.update(_collect_args(request.POST, fieldlookups_postparams, ))

    for field, lookup in fieldlookups.items():
        if isinstance(lookup, K):
            source = kwargs
        elif isinstance(lookup, G):
            source = request.GET
        elif isinstance(lookup, O):
            source = request.POST
        else:
            continue
        resolved_fields[field] = source[lookup.key] if lookup.key in source else None

    return resolved_fields or None


def _check(perm, request, kwargs, raise_exception, **fieldlookups):
    if not isinstance(perm, (list, tuple)):
        perms = (perm, )
    else:
        perms = perm

    resolved_items = _resolve_fieldlookups(request, kwargs, **fieldlookups)

    items = None
    if fieldlookups is not None:
        items = _get_permissible_items(perm, request, resolved_items)
        if items is None:
            if raise_exception:
                raise Http404
            return False

    if request.user.has_perms(perms, items):
        return True

    # In case the 403 handler should be called raise the exception
    if raise_exception:
        raise PermissionDenied
    return False


def permission_required(perm, raise_exception=True, login_url=None, **fieldlookups):
    '''
    Decorator for views that checks whether a user has a particular permission
    enabled, redirecting to the log-in page if necessary.
    If the raise_exception parameter is given the PermissionDenied exception
    is raised.

    Adapted from `django/contrib/auth/decorator.py`
    '''

    def _check_perms(request, *args, **kwargs):
        def _wrapped_check(perm, **fieldlookups):
            return _check(perm, request, kwargs, raise_exception, **fieldlookups)

        if isinstance(perm, P):
            return perm.solve(_wrapped_check)

        return _check(perm, request, kwargs, raise_exception, **fieldlookups)

    return request_passes_test(_check_perms, login_url=login_url)


# --- Core 1.0 guard. Do not route this through permission_required / P / K / G / O. ---

_AUTHORIZATION_REQUIRED = []

_CONDITION_TYPE_ERROR = (
    'authorization_required conditions must be an exact tuple of names, '
    'not %r.'
)
_PERMISSION_FORM_ERROR = (
    'authorization_required permission must be one base '
    '"app_label.codename" string without a colon suffix, not %r.'
)
_MODEL_TYPE_ERROR = (
    'authorization_required model must be a Django model class, not %r.'
)
_APPS_NOT_READY = (
    'authorization_required cannot resolve configuration before Django '
    'apps are ready.'
)
_SILENCE_DOES_NOT_ENABLE_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'authorization_required still validates and fail-closes at first '
    'use; there is no fallback to the base grant.'
)


def iter_authorization_required_declarations():
    """Declared Core guards, in decoration order. Tests may unregister."""
    return tuple(_AUTHORIZATION_REQUIRED)


def forget_authorization_required(declaration):
    """Remove one test-created declaration so suite checks stay clean."""
    try:
        _AUTHORIZATION_REQUIRED.remove(declaration)
    except ValueError:
        return


def _ensure_authorization_checks_registered():
    from trusts import checks as _trusts_checks  # noqa: F401


def _is_model_class(model):
    return isinstance(model, ModelBase) and issubclass(model, Model)


def _validate_permission_string(permission, model):
    if not isinstance(permission, str):
        raise TypeError(_PERMISSION_FORM_ERROR % (permission,))
    if ':' in permission or permission.count('.') != 1:
        raise TypeError(_PERMISSION_FORM_ERROR % (permission,))
    app_label, codename = permission.split('.')
    if not app_label or not codename:
        raise TypeError(_PERMISSION_FORM_ERROR % (permission,))
    if app_label != model._meta.app_label:
        raise TypeError(
            'authorization_required permission app_label %r does not '
            'match model %s.' % (app_label, model._meta.label)
        )
    return app_label, codename


def _validate_condition_name(name):
    if not isinstance(name, str):
        raise TypeError(_CONDITION_TYPE_ERROR % (type(name).__name__,))
    if (
        not name
        or name != name.strip()
        or '.' in name
        or ':' in name
        or not name.isidentifier()
    ):
        raise TypeError(
            'authorization_required condition name %r is malformed.' % (name,)
        )
    return name


def _validate_conditions(conditions):
    if type(conditions) is not tuple:
        raise TypeError(_CONDITION_TYPE_ERROR % (type(conditions).__name__,))
    names = []
    seen = set()
    for name in conditions:
        _validate_condition_name(name)
        if name in seen:
            raise TypeError(
                'authorization_required condition name %r is duplicated.'
                % (name,)
            )
        seen.add(name)
        names.append(name)
    return tuple(names)


def _validate_declaration(model, permission, conditions):
    if not _is_model_class(model) or model._meta.abstract:
        raise TypeError(_MODEL_TYPE_ERROR % (model,))
    _validate_permission_string(permission, model)
    return _validate_conditions(conditions)


class AuthorizationRequiredDeclaration(object):
    """Immutable declaration for system checks and first-use resolution."""

    __slots__ = ('model', 'permission', 'conditions')

    def __init__(self, model, permission, conditions):
        self.model = model
        self.permission = permission
        self.conditions = conditions


def _apps_ready():
    from django.apps import apps
    return apps.ready


def _configured_handles():
    from trusts.apps import configured_implementation_handles
    return configured_implementation_handles()


def _condition_record(handles, model, name):
    for handle in handles:
        lookup = getattr(handle.registry, 'condition_lookup', None)
        if lookup is None:
            continue
        record_for = getattr(lookup, 'record_for', None)
        if not callable(record_for):
            continue
        record = record_for(model, name)
        if record is not None:
            return record
    return None


def authorization_required_problems(declaration, handles=None):
    """Return (kind, name) problems after apps are ready. Zero SQL."""
    from trusts.conditions import PermissionConditionError
    from trusts.conditions._ir import validate_expression

    if handles is None:
        handles = _configured_handles()
    problems = []
    for name in declaration.conditions:
        record = _condition_record(handles, declaration.model, name)
        if record is None:
            problems.append(('unknown', name))
            continue
        expr = getattr(record, 'expr', None)
        if expr is None:
            problems.append(('unsupported', name))
            continue
        try:
            validate_expression(expr, declaration.model)
        except PermissionConditionError:
            problems.append(('unsupported', name))
    return tuple(problems)


def authorization_required_check_messages():
    """System-check messages for every declared Core guard."""
    from django.core import checks as django_checks

    if not _apps_ready():
        return []
    messages = []
    handles = _configured_handles()
    for declaration in _AUTHORIZATION_REQUIRED:
        for kind, name in authorization_required_problems(declaration, handles):
            messages.append(django_checks.Error(
                'authorization_required(%s, %r, conditions) has %s '
                'condition name %r.' % (
                    declaration.model._meta.label,
                    declaration.permission,
                    kind,
                    name,
                ),
                hint=_SILENCE_DOES_NOT_ENABLE_HINT,
                obj=declaration.model,
                id='trusts.E008',
            ))
    return messages


def _fail_closed_configuration(declaration, problems):
    from trusts.core import TrustsConfigurationError

    parts = [
        '%s condition %r' % (kind, name) for kind, name in problems
    ]
    raise TrustsConfigurationError(
        'authorization_required(%s, %r) fail-closed: %s. '
        'There is no fallback to the base grant.' % (
            declaration.model._meta.label,
            declaration.permission,
            '; '.join(parts),
        )
    )


def _resolve_declaration(declaration):
    from trusts.core import TrustsConfigurationError

    if not _apps_ready():
        raise TrustsConfigurationError(_APPS_NOT_READY)
    problems = authorization_required_problems(declaration)
    if problems:
        _fail_closed_configuration(declaration, problems)
    return _configured_handles()


def _permission_identity(model, permission):
    """Unevaluated Permission pk for the explicit model + complete codename."""
    from django.contrib.auth.models import Permission

    _app_label, codename = permission.split('.')
    return Subquery(
        Permission.objects.filter(
            codename=codename,
            content_type__app_label=model._meta.app_label,
            content_type__model=model._meta.model_name,
        ).values('pk')[:1]
    )


def _compile_condition_overlay(handles, model, permission, names, user):
    from trusts.conditions import PermissionConditionError
    from trusts.conditions._ir import compile_expression_q
    from trusts.core import TrustsConfigurationError

    extra = None
    for name in names:
        record = _condition_record(handles, model, name)
        if record is None or getattr(record, 'expr', None) is None:
            _fail_closed_configuration(
                AuthorizationRequiredDeclaration(model, permission, names),
                (('unknown' if record is None else 'unsupported', name),),
            )
        try:
            part = compile_expression_q(record.expr, model, user, permission)
        except PermissionConditionError as exc:
            raise TrustsConfigurationError(
                'authorization_required condition %r on %s is unsupported: %s. '
                'There is no fallback to the base grant.' % (
                    name, model._meta.label, exc,
                )
            ) from exc
        extra = part if extra is None else extra & part
    return extra


def _candidate_pk(model, view_kwargs):
    if 'pk' not in view_kwargs:
        raise Http404
    raw = view_kwargs['pk']
    if raw is None or raw == '':
        raise Http404
    if isinstance(raw, (list, tuple, set, dict, QuerySet, Model)):
        raise Http404
    try:
        value = model._meta.pk.to_python(raw)
    except (ValidationError, ValueError, TypeError):
        raise Http404
    if value is None or value == '':
        raise Http404
    return value


def _is_active_superuser(user):
    from trusts.query import is_active_principal

    return is_active_principal(user) and bool(getattr(user, 'is_superuser', False))


def _enforce_authorization(declaration, request, view_kwargs):
    from trusts.core import granted
    from trusts.query import is_active_principal

    handles = _resolve_declaration(declaration)
    model = declaration.model
    pk = _candidate_pk(model, view_kwargs)
    candidate = model._default_manager.filter(pk=pk)
    user = getattr(request, 'user', None)

    if _is_active_superuser(user):
        if not candidate.exists():
            raise Http404
        return

    if not is_active_principal(user):
        raise PermissionDenied

    extra_q = _compile_condition_overlay(
        handles, model, declaration.permission, declaration.conditions, user,
    )
    binding = _permission_identity(model, declaration.permission)
    granted_q = granted(handles, candidate, user, binding, kind='complete')
    if granted_q is None:
        if not candidate.exists():
            raise Http404
        raise PermissionDenied
    authorized = candidate.filter(granted_q)
    if extra_q is not None:
        authorized = authorized.filter(extra_q)
    if authorized.exists():
        return
    if not candidate.exists():
        raise Http404
    raise PermissionDenied


def authorization_required(model, permission, conditions=()):
    """Trusts-only view guard: explicit model, base permission, URL ``pk``.

    ``model`` is the protected Django model class. ``permission`` is one
    complete ``app_label.codename`` string; the model is never inferred
    from the codename. ``conditions`` is an exact tuple of registered
    names, ANDed as a narrowing overlay. The candidate is only the
    scalar ``view_kwargs["pk"]``, bound to ``model._meta.pk``.

    Evaluates configured Trusts plans directly. Does not call
    ``user.has_perm()`` and does not consult Django authentication
    backend OR. Invalid type, duplicate, malformed, unknown, or
    unsupported condition names fail closed with no fallback to the
    base grant.
    """
    names = _validate_declaration(model, permission, conditions)
    declaration = AuthorizationRequiredDeclaration(model, permission, names)
    _AUTHORIZATION_REQUIRED.append(declaration)
    _ensure_authorization_checks_registered()

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            _enforce_authorization(declaration, request, kwargs)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
