"""Kernel system checks for frozen Context and Trustee adapters.

Adapter re-walks are noun-independent. Zero-specific diagnostics
(``trusts.E001``–``E005``, ``W001``–``W003``, Content leftover ``E006``)
live in ``trusts.zero.checks``.
"""

from django.core import checks as django_checks

from trusts.context import Context, ContextRegistrationError
from trusts.trustee import Trustee, TrusteeRegistrationError


CHECK_ID_INVALID_CONTEXT = 'trusts.E006'
CHECK_ID_INVALID_TRUSTEE = 'trusts.E007'


def _model_label(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


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
    paths are rejected at ``register_direct`` / ``register_related``.
    This check re-walks every installed adapter so ``manage.py check``
    reports ``trusts.E006`` if the map is stale. ``app_configs`` is
    ignored so ``manage.py check trusts_kernel`` still sees the full
    registry. No getters, properties, or callbacks are executed. No
    database queries.
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
    # Zero Content leftovers that never became adapters. Optional: the
    # kernel has no Content map when django-trusts-zero is not installed.
    try:
        from trusts.zero.models import Content
    except ImportError:
        Content = None
    if Content is not None:
        for model, fieldlookup in Content.iter_unresolved_content_registrations():
            err = Content.compatibility_context_error(model, fieldlookup)
            if err is None:
                continue
            messages.append(django_checks.Error(
                'Context compatibility registration for %s is invalid: %s' % (
                    model._meta.label, err,
                ),
                hint=_SILENCE_DOES_NOT_ENABLE_CONTEXT_HINT,
                obj=model,
                id=CHECK_ID_INVALID_CONTEXT,
            ))
    return messages


_SILENCE_DOES_NOT_ENABLE_TRUSTEE_HINT = (
    'Silencing this check ID suppresses only the early diagnostic. '
    'Invalid Trustee paths stay fail-closed at registration and at '
    'authorization query time; they are never executed as getters or '
    'callbacks.'
)


@django_checks.register(django_checks.Tags.models)
def check_trustee_registry(app_configs, **kwargs):
    """Re-validate the frozen Trustee registry after models are loaded.

    Duplicate, incomplete, scalar, callable, wrong-terminal, ambiguous,
    and many-valued grant-identity paths are rejected at ``register``.
    This check re-walks every installed adapter so ``manage.py check``
    reports ``trusts.E007`` if the map is stale. ``app_configs`` is
    ignored so ``manage.py check trusts_kernel`` still sees the full
    registry. No getters, properties, or callbacks are executed. No
    database queries.
    """
    Trustee.ensure_frozen()
    messages = []
    for adapter in Trustee.adapters():
        try:
            Trustee.registry.revalidate(adapter)
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
