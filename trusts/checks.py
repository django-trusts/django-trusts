"""Django system checks for registered permission conditions (issue #29).

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

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group as AuthGroup
from django.contrib.auth.models import Permission as AuthPermission
from django.core import checks as django_checks
from django.core.exceptions import ImproperlyConfigured

from trusts import get_entity_model, get_group_model, get_permission_model
from trusts.conditions import PermissionConditionError, validate_expression
from trusts.models import Content, legacy_permission_callbacks_allowed


CHECK_ID_INVALID_EXPR = 'trusts.E001'
CHECK_ID_LEGACY_CALLBACK = 'trusts.E002'
CHECK_ID_LEGACY_CALLBACK_WARNING = 'trusts.W001'
CHECK_ID_ENTITY_NOT_USER = 'trusts.E003'
CHECK_ID_GROUP_NOT_AUTH = 'trusts.E004'
CHECK_ID_PERMISSION_NOT_AUTH = 'trusts.E005'

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


@django_checks.register(django_checks.Tags.models)
def check_configured_auth_models(app_configs, **kwargs):
    """Report the verified AUTH_USER_MODEL-only contract (issue #26).

    Django does not swap ``auth.Group`` or ``auth.Permission``. A custom
    user is the supported entity swap. ``app_configs`` is ignored so
    ``manage.py check trusts`` still reports project settings.
    """
    try:
        Entity = get_entity_model()
        Group = get_group_model()
        Permission = get_permission_model()
        User = get_user_model()
    except ImproperlyConfigured as exc:
        return [django_checks.Error(
            str(exc),
            obj=None,
            id=CHECK_ID_ENTITY_NOT_USER,
        )]

    messages = []
    if Entity is not User:
        messages.append(django_checks.Error(
            'TRUSTS_ENTITY_MODEL (%s) must be AUTH_USER_MODEL (%s). '
            'Settlor and trustee rows are the same principal '
            'User.has_perm uses. A separate non-user model is not a '
            'Django permission principal.' % (
                _model_label(Entity), _model_label(User),
            ),
            hint=(
                'Set TRUSTS_ENTITY_MODEL to the same app_label.Model as '
                'AUTH_USER_MODEL (a custom user is the supported entity swap).'
            ),
            obj=Entity,
            id=CHECK_ID_ENTITY_NOT_USER,
        ))
    if Group is not AuthGroup:
        messages.append(django_checks.Error(
            'TRUSTS_GROUP_MODEL (%s) must be auth.Group. Django does not '
            'swap Group; django-trusts does not maintain a private '
            'parallel group model.' % _model_label(Group),
            hint=(
                'Leave TRUSTS_GROUP_MODEL unset (default auth.Group). '
                'Removal of the setting is tracked separately.'
            ),
            obj=Group,
            id=CHECK_ID_GROUP_NOT_AUTH,
        ))
    if Permission is not AuthPermission:
        messages.append(django_checks.Error(
            'TRUSTS_PERMISSION_MODEL (%s) must be auth.Permission. Django '
            'does not swap Permission; django-trusts does not maintain a '
            'private parallel permission model.' % _model_label(Permission),
            hint=(
                'Leave TRUSTS_PERMISSION_MODEL unset (default auth.Permission). '
                'Removal of the setting is tracked separately.'
            ),
            obj=Permission,
            id=CHECK_ID_PERMISSION_NOT_AUTH,
        ))
    return messages
