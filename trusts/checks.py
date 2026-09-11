"""Django system checks for permission conditions and query compilers.

Model-aware semantic validation (field names, traversal, multi-valued
relations, operand types) and the legacy-callback policy are reported as
``CheckMessage`` objects with stable IDs. ``PermissionConditionError`` is
caught here so ``SILENCED_SYSTEM_CHECKS`` can filter the diagnostic.
Silencing an ID does not make the policy executable: ``has_perm`` and
``.permitted()`` still validate and fail closed.

``DeprecationWarning`` is commonly filtered; this module uses
``django.core.checks.Warning`` so the legacy-callback opt-in stays visible
under ``manage.py check``.
"""

from django.core import checks as django_checks

from trusts.conditions import PermissionConditionError, validate_expression
from trusts.models import Content, legacy_permission_callbacks_allowed


CHECK_ID_INVALID_EXPR = 'trusts.E001'
CHECK_ID_LEGACY_CALLBACK = 'trusts.E002'
CHECK_ID_MISSING_COMPILER = 'trusts.E004'
CHECK_ID_LEGACY_CALLBACK_WARNING = 'trusts.W001'

_SILENCE_DOES_NOT_ENABLE_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'has_perm() and .permitted() still validate and fail closed; there is '
    'no fallback to the base grant.'
)


def _model_label(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


def _messages_for_expr(model, cond_code, expr):
    try:
        validate_expression(expr, model)
    except PermissionConditionError as exc:
        return [django_checks.Error(
            'Permission condition %r on %s is invalid: %s' % (
                cond_code, _model_label(model), exc,
            ),
            hint=_SILENCE_DOES_NOT_ENABLE_HINT,
            obj=model,
            id=CHECK_ID_INVALID_EXPR,
        )]
    return []


def _messages_for_callable(model, cond_code):
    label = _model_label(model)
    if legacy_permission_callbacks_allowed():
        return [django_checks.Warning(
            'Callable permission condition %r on %s is a deprecated '
            'object-only escape hatch. Rewrite it as an Expr from '
            'condition_refs() for queryable policy. ContentQuerySet.permitted() '
            'still refuses callables.' % (cond_code, label),
            hint=(
                'TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS is True, so '
                'has_perm() may invoke this callback with real values. '
                'Rewrite the condition as an Expr to drop this warning.'
            ),
            obj=model,
            id=CHECK_ID_LEGACY_CALLBACK_WARNING,
        )]
    return [django_checks.Error(
        'Callable permission condition %r on %s is disabled. Set '
        'TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS = True to keep the '
        'object-only has_perm path, or rewrite it as an Expr from '
        'condition_refs().' % (cond_code, label),
        hint=(
            'Enabling TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS is the only '
            'way to run the callback. ' + _SILENCE_DOES_NOT_ENABLE_HINT
        ),
        obj=model,
        id=CHECK_ID_LEGACY_CALLBACK,
    )]


@django_checks.register()
def check_query_compilers(app_configs, **kwargs):
    """Every Trusts-derived AUTHENTICATION_BACKENDS path must be query-capable.

    Imports listed mixin classes and resolves ``query_compiler`` without
    constructing a backend instance. Zero SQL. ``trusts.E003`` stays
    reserved for S8 freeze. Silencing ``trusts.E004`` hides only this
    diagnostic; ``ContentQuerySet.permitted()`` still raises and does
    not fall back or omit the broken route.
    """
    from django.conf import settings
    from django.utils.module_loading import import_string

    from trusts.backends import TrustModelBackendMixin
    from trusts.core import TrustsCompilerError, compiler_for_class

    messages = []
    seen = []
    listed = getattr(settings, 'AUTHENTICATION_BACKENDS', ()) or ()
    for path in listed:
        if path in seen:
            continue
        seen.append(path)
        try:
            cls = import_string(path)
        except ImportError:
            continue
        if not issubclass(cls, TrustModelBackendMixin):
            continue
        try:
            compiler_for_class(cls)
        except TrustsCompilerError as exc:
            messages.append(django_checks.Error(
                str(exc),
                hint=(
                    'Silencing this check ID suppresses only the early '
                    'diagnostic. ContentQuerySet.permitted() still requires '
                    'a valid query compiler; there is no fallback or omission.'
                ),
                obj=cls,
                id=CHECK_ID_MISSING_COMPILER,
            ))
    return messages


@django_checks.register(django_checks.Tags.models)
def check_permission_conditions(app_configs, **kwargs):
    """Validate every registered condition after models are loaded.

    Does not import extra application modules and does not depend on
    ``INSTALLED_APPS`` order. ``app_configs`` is ignored so a subset
    ``manage.py check trusts`` still reports project-model conditions.
    Callables are never inspected or invoked. No database queries.
    """
    messages = []
    for model, cond_code, record in Content.iter_permission_conditions():
        if record.expr is not None:
            messages.extend(_messages_for_expr(model, cond_code, record.expr))
        elif record.func is not None:
            messages.extend(_messages_for_callable(model, cond_code))
    return messages
