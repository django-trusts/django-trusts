"""Kernel system checks for frozen Context / Trustee maps.

Adapter re-walks are noun-independent. Companion Zero diagnostics
(``trusts.E001``–``E005``, ``W001``–``W003``, and leftover
compatibility ``E006``) stay in that add-on's check module. This
module must not import the add-on, even optionally.
"""

from django.core import checks as django_checks

from trusts.context import Context, ContextRegistrationError
from trusts.trustee import Trustee, TrusteeRegistrationError


CHECK_ID_INVALID_CONTEXT = 'trusts.E006'
CHECK_ID_INVALID_TRUSTEE = 'trusts.E007'
CHECK_ID_INCOMPLETE_CONFIG = 'trusts.E008'


_SILENCE_DOES_NOT_ENABLE_CONTEXT_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'Invalid Context paths stay fail-closed at registration and at '
    'authorization query time; they are never executed as getters or '
    'callbacks.'
)


@django_checks.register(django_checks.Tags.models)
def check_context_registry(app_configs, **kwargs):
    """Re-validate the frozen Context registry after models are loaded.

    Missing, cyclic, ambiguous, scalar, many-valued, and wrong-terminal
    paths are rejected at ``register_direct`` / ``register_related`` /
    ``register_identity``.
    This check re-walks every installed adapter so ``manage.py check``
    reports ``trusts.E006`` if the map is stale. ``app_configs`` is
    ignored so ``manage.py check trusts_kernel`` still sees the full
    registry. No getters, properties, or callbacks are executed. No
    database queries. Leftover Zero compatibility declarations are
    not inspected here.
    """
    Context.ensure_frozen()
    messages = []
    for adapter in Context.adapters():
        try:
            Context.registry.revalidate(adapter)
        except ContextRegistrationError as exc:
            messages.append(django_checks.Error(
                'Context %s registration for %s is invalid: %s' % (
                    adapter.kind, adapter.label, exc,
                ),
                hint=_SILENCE_DOES_NOT_ENABLE_CONTEXT_HINT,
                obj=adapter.model,
                id=CHECK_ID_INVALID_CONTEXT,
            ))
    return messages


_SILENCE_DOES_NOT_ENABLE_TRUSTEE_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'Invalid Trustee paths stay fail-closed at registration and at '
    'authorization query time; they are never executed as getters or '
    'callbacks.'
)


def _prepare_trustee_registry_for_checks(registry):
    """Run declared Trustee finalizers / freeze without raising.

    Django registers checks in a set, so E007 and E008 may run in
    either order. Both call this helper so a pending finalizer that
    completes a valid map is visible to completeness, and a failing
    freeze becomes a check result instead of an uncaught exception.
    Only the registry's declared finalizers run. No SQL.
    """
    try:
        registry.ensure_frozen()
    except TrusteeRegistrationError as exc:
        return exc
    except Exception as exc:
        return exc
    return None


def _trustee_finalization_message(exc):
    return django_checks.Error(
        'Trustee registry finalization failed: %s' % exc,
        hint=_SILENCE_DOES_NOT_ENABLE_TRUSTEE_HINT,
        obj=None,
        id=CHECK_ID_INVALID_TRUSTEE,
    )


@django_checks.register(django_checks.Tags.models)
def check_trustee_registry(app_configs, registry=None, **kwargs):
    """Re-validate the frozen Trustee registry after models are loaded.

    Duplicate, incomplete, scalar, callable, wrong-terminal, ambiguous,
    and many-valued grant-identity paths are rejected at ``register``.
    This check re-walks every installed adapter so ``manage.py check``
    reports ``trusts.E007`` if the map is stale. ``app_configs`` is
    ignored so ``manage.py check trusts_kernel`` still sees the full
    registry. Isolated tests may pass ``registry=``. No getters,
    properties, or callbacks are executed beyond declared finalizers.
    No database queries.
    """
    if registry is None:
        registry = Trustee.registry
    freeze_error = _prepare_trustee_registry_for_checks(registry)
    messages = []
    if freeze_error is not None and not isinstance(
        freeze_error, TrusteeRegistrationError,
    ):
        messages.append(_trustee_finalization_message(freeze_error))
    for adapter in registry.adapters():
        try:
            registry.revalidate(adapter)
        except TrusteeRegistrationError as exc:
            messages.append(django_checks.Error(
                'Trustee %s registration %r is invalid: %s' % (
                    adapter.kind, adapter.name, exc,
                ),
                hint=_SILENCE_DOES_NOT_ENABLE_TRUSTEE_HINT,
                obj=adapter.grant_model,
                id=CHECK_ID_INVALID_TRUSTEE,
            ))
    return messages


_SILENCE_DOES_NOT_ENABLE_CONFIG_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'Incomplete Trustee terminals and string-operation configuration '
    'stay fail-closed at authorization time as AuthorizationConfigError. '
    'They are never executed as getters or callbacks.'
)


def _trustee_registry_is_declared(registry):
    """True when the map has any authorization declaration.

    Presence of a requester / scope / operation terminal, an
    ``operation_lookup``, or any installed adapter counts as used.
    A pristine empty registry is not declared. This is metadata only:
    runtime APIs are not consulted.
    """
    return any((
        registry._requester_model is not None,
        registry._scope_model is not None,
        registry._operation_model is not None,
        registry._operation_lookup is not None,
        bool(registry._adapters),
    ))


def _missing_trustee_terminals(registry):
    missing = []
    if registry._requester_model is None:
        missing.append('requester')
    if registry._scope_model is None:
        missing.append('scope')
    if registry._operation_model is None:
        missing.append('operation')
    return missing


def _format_missing_terminals(missing):
    if len(missing) == 1:
        return 'missing %s terminal' % missing[0]
    if len(missing) == 2:
        return 'missing %s and %s terminals' % (missing[0], missing[1])
    return 'missing %s, %s, and %s terminals' % (
        missing[0], missing[1], missing[2],
    )


def _incomplete_configuration_messages(registry):
    """E008 completeness messages for one prepared Trustee registry.

    Does not re-walk adapter paths (E006 / E007). Does not call
    ``requester_model()`` / ``scope_model()`` / ``operation_model()``.
    No queries.
    """
    if not _trustee_registry_is_declared(registry):
        return []
    missing = _missing_trustee_terminals(registry)
    lookup_incomplete = (
        registry._operation_lookup is not None
        and registry._operation_model is None
    )
    if not missing and not lookup_incomplete:
        return []
    parts = []
    if missing:
        parts.append(_format_missing_terminals(missing))
    if lookup_incomplete:
        parts.append(
            'operation_lookup %r is set without operation_model' % (
                registry._operation_lookup,
            )
        )
    return [django_checks.Error(
        'Trustee authorization configuration is incomplete: %s.' % (
            '; '.join(parts),
        ),
        hint=_SILENCE_DOES_NOT_ENABLE_CONFIG_HINT,
        obj=None,
        id=CHECK_ID_INCOMPLETE_CONFIG,
    )]


@django_checks.register(django_checks.Tags.models)
def check_trustee_configuration(app_configs, registry=None, **kwargs):
    """Report incomplete Trustee terminals / string-operation config.

    A pristine registry that has not declared authorization
    configuration is valid. A partial ``configure()`` / leftover
    adapter map is ``trusts.E008``. ``app_configs`` is ignored so
    ``manage.py check trusts_kernel`` still sees the process-wide map.
    Isolated tests may pass ``registry=``. Finalizers run through the
    same prepare helper as E007 so check order cannot hide a complete
    map or turn a failed freeze into an uncaught exception. This check
    does not re-walk adapter paths and issues no database queries.
    """
    if registry is None:
        registry = Trustee.registry
    _prepare_trustee_registry_for_checks(registry)
    return _incomplete_configuration_messages(registry)
