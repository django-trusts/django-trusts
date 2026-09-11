"""Django system checks for permission conditions, missing declarations,
query compilers, and Along renderer support.

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

from trusts.conditions import (
    PermissionConditionError,
    legacy_permission_callbacks_allowed,
    validate_expression,
)


CHECK_ID_INVALID_EXPR = 'trusts.E001'
CHECK_ID_LEGACY_CALLBACK = 'trusts.E002'
CHECK_ID_MISSING_DECLARATION = 'trusts.E003'
CHECK_ID_MISSING_COMPILER = 'trusts.E004'
CHECK_ID_ALONG_RENDERER = 'trusts.E005'
CHECK_ID_LEGACY_CALLBACK_WARNING = 'trusts.W001'

_SILENCE_DOES_NOT_ENABLE_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'has_perm() and .permitted() still validate and fail closed; there is '
    'no fallback to the base grant.'
)


def _trusts_abstract_base(model, name):
    for base in model.__mro__:
        meta = getattr(base, '_meta', None)
        if (
            meta is not None
            and meta.abstract
            and base.__name__ == name
            and meta.app_label == 'trusts'
        ):
            return base
    return None


def _historical_content_class(apps_registry):
    try:
        Trust = apps_registry.get_model('trusts', 'Trust')
    except LookupError:
        return None
    return _trusts_abstract_base(Trust, 'Content')


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
    constructing a backend instance. Zero SQL. Silencing ``trusts.E004``
    hides only this diagnostic; ``ContentQuerySet.permitted()`` still
    raises and does not fall back or omit the broken route.
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


_E003_HINT = (
    'Contribute an explicit AppConfig Ref on the intended exact backend '
    'path. Silencing trusts.E003 suppresses only this diagnostic; it '
    'never creates authorization.'
)


def _is_concrete_model(model):
    opts = getattr(model, '_meta', None)
    if opts is None:
        return False
    return not opts.abstract and not opts.proxy


def _covered_content_models(config):
    """Content terminals that already have a plan record on any valid handle.

    Path-scoped: coverage on one configured valid Trusts handle is
    enough. Does not register, does not invent union authority, and
    does not require every backend to hold the declaration.
    """
    from trusts.core import TrustsCompilerError, TrustsConfigurationError

    covered = set()
    try:
        paths = config._configured_trusts_paths()
    except TrustsConfigurationError:
        return covered
    for path in paths:
        try:
            handle = config.configured_backend(path)
        except (TrustsConfigurationError, TrustsCompilerError):
            continue
        for record in handle.registry.records:
            covered.add(record.content_model)
    return covered


def _junction_content_model(model):
    """Return the Junction content model or a CheckMessage for a bad contract."""
    try:
        content_model = model.get_content_model()
    except Exception as exc:
        return None, django_checks.Error(
            'Junction %s has a malformed content-model contract: %s'
            % (_model_label(model), exc),
            hint=_E003_HINT,
            obj=model,
            id=CHECK_ID_MISSING_DECLARATION,
        )
    opts = getattr(content_model, '_meta', None)
    if opts is None:
        return None, django_checks.Error(
            'Junction %s has a malformed content-model contract: '
            'get_content_model() did not return a Django model.'
            % _model_label(model),
            hint=_E003_HINT,
            obj=model,
            id=CHECK_ID_MISSING_DECLARATION,
        )
    return opts.concrete_model, None


@django_checks.register(django_checks.Tags.models)
def check_missing_declarations(app_configs, **kwargs):
    """Report structurally detectable missing Content/Junction declarations.

    Walks already-loaded models from the default Apps registry. Does not
    import host modules, does not call ``registry.register``, and issues
    zero SQL. ``app_configs`` is ignored so a subset
    ``manage.py check trusts`` still reports project models. Abstract
    and proxy models are excluded. Manual dependents that are neither
    Content nor Junction are outside this domain.

    Silencing ``trusts.E003`` hides only this diagnostic; undeclared
    terminals still fail closed at runtime.
    """
    from django.apps import apps as django_apps

    from trusts.apps import kernel_config

    try:
        kernel_config()
    except LookupError:
        return []

    config = kernel_config()
    covered = _covered_content_models(config)
    messages = []
    seen = set()

    for model in django_apps.get_models():
        if not _is_concrete_model(model):
            continue
        if _trusts_abstract_base(model, 'Content') is not None:
            terminal = model._meta.concrete_model
            if terminal in covered:
                continue
            key = ('content', model)
            if key in seen:
                continue
            seen.add(key)
            messages.append(django_checks.Error(
                'Content model %s has no covering relation-plan record '
                'on any configured Trusts handle.' % _model_label(model),
                hint=_E003_HINT,
                obj=model,
                id=CHECK_ID_MISSING_DECLARATION,
            ))
            continue
        if _trusts_abstract_base(model, 'Junction') is not None:
            content_model, error = _junction_content_model(model)
            if error is not None:
                key = ('junction-malformed', model)
                if key in seen:
                    continue
                seen.add(key)
                messages.append(error)
                continue
            if content_model in covered:
                continue
            key = ('junction', model)
            if key in seen:
                continue
            seen.add(key)
            messages.append(django_checks.Error(
                'Junction %s targets %s, which has no covering '
                'relation-plan record on any configured Trusts handle.'
                % (_model_label(model), _model_label(content_model)),
                hint=_E003_HINT,
                obj=model,
                id=CHECK_ID_MISSING_DECLARATION,
            ))

    messages.sort(key=lambda message: (
        getattr(getattr(message.obj, '_meta', None), 'label', ''),
        message.msg,
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
    from django.apps import apps as django_apps

    Content = _historical_content_class(django_apps)
    if Content is None:
        return []
    messages = []
    for model, cond_code, record in Content.iter_permission_conditions():
        if record.expr is not None:
            messages.extend(_messages_for_expr(model, cond_code, record.expr))
        elif record.func is not None:
            messages.extend(_messages_for_callable(model, cond_code))
    return messages


_E005_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'GrantReach still fail-closes on the actual query connection; '
    'there is no fallback grant.'
)


def _live_along_records(config):
    from trusts.core import TrustsCompilerError, TrustsConfigurationError

    found = []
    try:
        paths = config._configured_trusts_paths()
    except TrustsConfigurationError:
        return found
    for path in paths:
        try:
            handle = config.configured_backend(path)
        except (TrustsConfigurationError, TrustsCompilerError):
            continue
        for record in handle.registry.records:
            if record.along is not None:
                found.append(record)
    return found


def _along_engine(connection):
    return (getattr(connection, 'settings_dict', None) or {}).get('ENGINE')


@django_checks.register(django_checks.Tags.database)
def check_along_renderer(app_configs, **kwargs):
    """Report selected aliases that cannot render live Along records.

    Honors Django's ``databases`` argument exactly. ``None`` or empty
    opens no connections, executes no SQL, and is not an all-clear.
    Isolated ``TrustsRegistry()`` instances are not scanned.
    """
    databases = kwargs.get('databases')
    if not databases:
        return []

    from django.apps import apps as django_apps
    from django.db import connections
    from django.db.utils import OperationalError

    from trusts.apps import kernel_config
    from trusts.core import (
        along_connection_supported,
        probe_along_capabilities,
    )

    try:
        config = kernel_config()
    except LookupError:
        return []
    along_records = _live_along_records(config)
    if not along_records:
        return []

    messages = []
    for alias in databases:
        connection = connections[alias]
        engine = _along_engine(connection)
        vendor = getattr(connection, 'vendor', None)
        if not along_connection_supported(connection):
            messages.append(django_checks.Error(
                'Database alias %r (ENGINE=%s, vendor=%s) cannot render '
                'Along reachability: Django sqlite3 with JSON functions '
                'and recursive CTEs is required.'
                % (alias, engine, vendor),
                hint=_E005_HINT,
                obj=None,
                id=CHECK_ID_ALONG_RENDERER,
            ))
            continue
        try:
            probe_along_capabilities(connection)
        except OperationalError as exc:
            messages.append(django_checks.Error(
                'Database alias %r (ENGINE=%s, vendor=%s) cannot render '
                'Along reachability: JSON/recursive capability probe '
                'failed (%s).' % (alias, engine, vendor, exc),
                hint=_E005_HINT,
                obj=None,
                id=CHECK_ID_ALONG_RENDERER,
            ))
        except Exception as exc:
            messages.append(django_checks.Error(
                'Database alias %r (ENGINE=%s, vendor=%s) cannot render '
                'Along reachability: JSON/recursive capability probe '
                'failed (%s).' % (alias, engine, vendor, exc),
                hint=_E005_HINT,
                obj=None,
                id=CHECK_ID_ALONG_RENDERER,
            ))
    return messages
