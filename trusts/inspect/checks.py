"""Django system checks for missing declarations and Along renderer support.

``trusts.E007`` reports the deleted runtime-callback setting still
being ``True``. That setting never enables callbacks. ``trusts.E001``,
``trusts.E002``, ``trusts.E006``, and ``trusts.W001`` are retired.
OrderedFold vendor diagnostics live in ``django-trusts-ordered-fold`` as
``trusts_ordered_fold.E001``.
"""

__all__ = []

from django.apps import apps as django_apps
from django.conf import settings
from django.core import checks as django_checks
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from django.db import connections

# Importing the lockfile module registers the trusts.E009 model check.
import trusts.inspect.snapshot  # noqa: F401
from trusts.apps import TrustsConfigMixin, catalog_of
from trusts.backends import TrustModelBackendMixin
from trusts.compile.factory import probe_along_capabilities
from trusts.decorators import _declared_authorization_guards
from trusts.errors import (
    TrustsConfigurationError,
    TrustsMixinRequired,
)
from trusts.plan.conditions import obsolete_legacy_callback_setting_enabled
from trusts.plan.walk import along_connection_supported


CHECK_ID_MISSING_DECLARATION = 'trusts.E003'
CHECK_ID_ALONG_RENDERER = 'trusts.E005'
CHECK_ID_OBSOLETE_CALLBACK_SETTING = 'trusts.E007'
CHECK_ID_AUTHORIZATION_REQUIRED = 'trusts.E008'
CHECK_ID_UNLISTED_CATALOG = 'trusts.E010'
CHECK_ID_UNBUILDABLE_BACKEND = 'trusts.E011'
CHECK_ID_MIXIN_REQUIRED = 'trusts.E012'

_SILENCE_DOES_NOT_ENABLE_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'has_perm() and .permitted() still validate and fail closed; there is '
    'no fallback to the base grant.'
)

_E003_HINT = (
    'Contribute an explicit AppConfig Ref on the intended exact backend '
    'path. Silencing trusts.E003 suppresses only this diagnostic; it '
    'never creates authorization.'
)

_E005_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'GrantReach still fail-closes on the actual query connection; '
    'there is no fallback grant.'
)


def _trusts_abstract_base(model, label):
    """Abstract base whose Django model label is ``label``."""
    for base in model.__mro__:
        meta = getattr(base, '_meta', None)
        if meta is not None and meta.abstract and meta.label == label:
            return base
    return None


def _model_label(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


def _messages_for_obsolete_callback_setting():
    if not obsolete_legacy_callback_setting_enabled():
        return []
    return [django_checks.Error(
        'TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS is True, but runtime '
        'permission callbacks are removed. The setting does not enable '
        'callbacks. Register a builder '
        '(backend.add_named_filter(model, code, '
        'lambda u, p, o: ...)).',
        hint=(
            'Remove TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS from settings. '
            'It cannot restore object-only has_perm callbacks. '
            + _SILENCE_DOES_NOT_ENABLE_HINT
        ),
        obj=None,
        id=CHECK_ID_OBSOLETE_CALLBACK_SETTING,
    )]


def _is_concrete_model(model):
    opts = getattr(model, '_meta', None)
    if opts is None:
        return False
    return not opts.abstract and not opts.proxy


def _require_mixin(errors, config, path, message):
    key = config if config is not None else path
    if any(
        message_row.id == CHECK_ID_MIXIN_REQUIRED and message_row.obj == key
        for message_row in errors
    ):
        return
    errors.append(django_checks.Error(
        message,
        hint=(
            'Move the backend into an app whose config extends '
            'TrustsConfigMixin.'
            if config is None else
            'Extend TrustsConfigMixin on the app config.'
        ),
        obj=key, id=CHECK_ID_MIXIN_REQUIRED,
    ))


def _load_listed():
    catalogs, errors, listed = {}, [], set()
    for path in settings.AUTHENTICATION_BACKENDS:
        config = django_apps.get_containing_app_config(path.rpartition('.')[0])
        try:
            backend = import_string(path)()
        except TrustsMixinRequired as exc:
            _require_mixin(errors, config, path, str(exc))
            continue
        except (ImportError, ImproperlyConfigured, TrustsConfigurationError) as exc:
            errors.append(django_checks.Error(
                'Authentication backend %s could not be built: %s' % (path, exc),
                hint='Fix AUTHENTICATION_BACKENDS so the backend constructs.',
                id=CHECK_ID_UNBUILDABLE_BACKEND,
            ))
            continue
        if isinstance(backend, TrustModelBackendMixin):
            catalogs.setdefault(id(backend._catalog()), backend._catalog())
            listed.add(id(config))
    return tuple(catalogs.values()), errors, listed


def _covered_content_models(catalogs):
    """Content terminals that a listed backend's catalog already records."""
    covered = set()
    for catalog in catalogs:
        for record in catalog.records:
            covered.add(record.content_model)
        for record in catalog.delegations:
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

    Walks already-loaded models from the default Apps registry. Host
    modules stay unloaded, ``registry.register`` is not called, and the
    check issues zero SQL. ``app_configs`` is ignored so a subset
    ``manage.py check trusts`` still reports project models. Abstract
    and proxy models are excluded. Manual dependents that are neither
    Content nor Junction are outside this domain.

    Silencing ``trusts.E003`` hides only this diagnostic; undeclared
    terminals still fail closed at runtime.
    """

    catalogs = _load_listed()[0]
    if not catalogs:
        return []

    covered = _covered_content_models(catalogs)
    messages = []

    for model in django_apps.get_models():
        if not _is_concrete_model(model):
            continue
        if _trusts_abstract_base(model, 'trusts.Content') is not None:
            terminal = model._meta.concrete_model
            if terminal in covered:
                continue
            messages.append(django_checks.Error(
                'Content model %s has no covering relation-plan record '
                'on any listed Trusts catalog.' % _model_label(model),
                hint=_E003_HINT,
                obj=model,
                id=CHECK_ID_MISSING_DECLARATION,
            ))
            continue
        if _trusts_abstract_base(model, 'trusts.Junction') is not None:
            content_model, error = _junction_content_model(model)
            if error is not None:
                messages.append(error)
                continue
            if content_model in covered:
                continue
            messages.append(django_checks.Error(
                'Junction %s targets %s, which has no covering '
                'relation-plan record on any listed Trusts catalog.'
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


@django_checks.register()
def check_obsolete_legacy_callback_setting(app_configs, **kwargs):
    """Fail loud if the deleted runtime-callback setting is still True."""
    return _messages_for_obsolete_callback_setting()


@django_checks.register()
def check_authorization_required_conditions(app_configs, **kwargs):
    """Report unsupported or incomplete ``authorization_required`` guards.

    Uses the same zero-SQL preflight as first use: at least one
    applicable ``auth.Permission`` plan is required, and when names
    are selected one participating backend must own the complete
    queryable tuple. A global union of names across registries is
    not enough. Guards whose model app is absent are skipped
    so a host that does not load that app (pair Zero, isolated Apps)
    is not failed by imported fixtures. Silencing ``trusts.E008``
    hides only the diagnostic; first use still fails closed before
    the superuser shortcut and never falls back to an unconditioned
    grant.
    """
    catalogs = _load_listed()[0]
    messages = []
    seen = set()
    for model, _permission, conditions in _declared_authorization_guards:
        app_label = getattr(getattr(model, '_meta', None), 'app_label', None)
        try:
            django_apps.get_app_config(app_label)
        except LookupError:
            continue
        key = (model, conditions)
        if key in seen:
            continue
        seen.add(key)
        participating = False
        complete = False
        for catalog in catalogs:
            has_plan, owns = catalog.authorization_preflight(model, conditions)
            if not has_plan:
                continue
            participating = True
            if owns:
                complete = True
                break
        if participating and complete:
            continue
        if not participating:
            messages.append(django_checks.Error(
                'authorization_required has no applicable auth.Permission '
                'plan for %s.' % _model_label(model),
                hint=(
                    'Register an auth.Permission plan for this model on a '
                    'configured Trusts backend. Silencing trusts.E008 '
                    'suppresses only this diagnostic; first use still '
                    'fails closed.'
                ),
                obj=model,
                id=CHECK_ID_AUTHORIZATION_REQUIRED,
            ))
            continue
        messages.append(django_checks.Error(
            'authorization_required conditions %r are not registered '
            'together on any auth.Permission backend for %s.'
            % (conditions, _model_label(model)),
            hint=(
                'Register the complete name set on one auth.Permission '
                'backend with backend.add_named_filter in '
                'AppConfig.ready(). Silencing trusts.E008 suppresses only '
                'this diagnostic; first use still fails closed.'
            ),
            obj=model,
            id=CHECK_ID_AUTHORIZATION_REQUIRED,
        ))
    messages.sort(key=lambda message: (
        getattr(getattr(message.obj, '_meta', None), 'label', ''),
        message.msg,
    ))
    return messages


@django_checks.register()
def check_unlisted_catalog(app_configs, **kwargs):
    """Registrations need a listed backend whose module lives in that app."""
    _catalogs, messages, listed = _load_listed()
    for config in django_apps.get_app_configs():
        if not isinstance(config, TrustsConfigMixin):
            continue
        catalog = catalog_of(config)
        if not (catalog.records or catalog.delegations):
            continue
        if id(config) in listed:
            continue
        messages.append(django_checks.Error(
            'Trusts app %s has registrations but no AUTHENTICATION_BACKENDS '
            'entry resolves to it.' % config.label,
            hint='List a backend whose module lives in this app.',
            obj=config, id=CHECK_ID_UNLISTED_CATALOG))
    return messages


@django_checks.register(django_checks.Tags.database)
def check_along_renderer(app_configs, **kwargs):
    """Report selected aliases that cannot render live Along records.

    Honors Django's ``databases`` argument exactly. ``None`` or empty
    opens no connections, executes no SQL, and is not an all-clear.
    Only configured catalogs are scanned.
    """
    databases = kwargs.get('databases')
    if not databases:
        return []
    catalogs = _load_listed()[0]
    if not catalogs:
        return []
    along_records = [
        record for catalog in catalogs for record in catalog.records
        if record.along is not None]
    if not along_records:
        return []

    messages = []
    for alias in databases:
        connection = connections[alias]
        engine = (getattr(connection, 'settings_dict', None) or {}).get('ENGINE')
        vendor = getattr(connection, 'vendor', None)
        if not along_connection_supported(connection):
            messages.append(django_checks.Error(
                'Database alias %r (ENGINE=%s, vendor=%s) cannot render '
                'Along reachability: a recursive CTE on Django sqlite3, '
                'postgresql, or mysql is required.'
                % (alias, engine, vendor),
                hint=_E005_HINT,
                obj=None,
                id=CHECK_ID_ALONG_RENDERER,
            ))
            continue
        try:
            probe_along_capabilities(connection)
        except Exception as exc:
            messages.append(django_checks.Error(
                'Database alias %r (ENGINE=%s, vendor=%s) cannot render '
                'Along reachability: recursive CTE probe '
                'failed (%s).' % (alias, engine, vendor, exc),
                hint=_E005_HINT,
                obj=None,
                id=CHECK_ID_ALONG_RENDERER,
            ))
    return messages
