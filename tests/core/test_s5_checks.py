"""Isolated kernel tests for #47 S5 (generic configuration checks).

Covers noun-independent ``trusts.E008`` completeness, order-independent
Trustee finalization, preserved ``E006`` / ``E007`` re-walks, and
kernel+Zero leftover Content ``E006`` ownership. Isolated registries
for partial states. Does not close #47.
"""

import inspect
import re
from pathlib import Path

from django.conf import settings
from django.core.checks import Error, run_checks
from django.test import TestCase, override_settings

from trusts.checks import (
    CHECK_ID_INCOMPLETE_CONFIG,
    CHECK_ID_INVALID_CONTEXT,
    CHECK_ID_INVALID_TRUSTEE,
    _SILENCE_DOES_NOT_ENABLE_CONFIG_HINT,
    check_context_registry,
    check_trustee_configuration,
    check_trustee_registry,
)
from trusts.context import Context, ContextRegistry
from trusts.runtime import AuthorizationConfigError, is_authorized
from trusts.trustee import (
    KIND_GRANT,
    Trustee,
    TrusteeAdapter,
    TrusteeRegistrationError,
    TrusteeRegistry,
)
from tests.core.test_s1_kernel import S1_TEAM, _s1_maps
from tests.models import (
    S1Account,
    S1Operation,
    S1Repository,
)


def _e008(messages):
    return [m for m in messages if m.id == CHECK_ID_INCOMPLETE_CONFIG]


def _assert_one_e008(testcase, messages, *needles):
    errors = _e008(messages)
    testcase.assertEqual(len(errors), 1)
    testcase.assertIsInstance(errors[0], Error)
    testcase.assertEqual(errors[0].id, 'trusts.E008')
    testcase.assertEqual(errors[0].hint, _SILENCE_DOES_NOT_ENABLE_CONFIG_HINT)
    testcase.assertIsNone(errors[0].obj)
    for needle in needles:
        testcase.assertIn(needle, errors[0].msg)
    return errors[0]


class S5ChecksModuleTest(TestCase):
    def test_checks_module_has_no_zero_or_content_import(self):
        from trusts import checks
        source = Path(inspect.getfile(checks)).read_text()
        self.assertIsNone(
            re.search(r'^\s*(from|import)\s+trusts\.zero', source, re.M),
        )
        self.assertNotIn('iter_unresolved_content_registrations', source)
        self.assertNotIn('compatibility_context_error', source)
        self.assertIsNone(re.search(r'\bContent\b', source))
        self.assertNotIn('GitHub', source)
        self.assertNotIn('add_operation', source)
        self.assertNotIn('scope_field', source)
        self.assertNotIn('parent_field', source)
        for noun in ('Trust', 'Junction'):
            self.assertIsNone(
                re.search(r'\b%s\b' % noun, source),
                '%r appears as a product noun in trusts.checks' % (noun,),
            )


class S5PristineAndCompleteTest(TestCase):
    def test_pristine_registry_is_valid(self):
        registry = TrusteeRegistry()
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        self.assertEqual(_e008(messages), [])

    def test_complete_terminals_without_adapters_or_lookup_are_valid(self):
        registry = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
        )
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        self.assertEqual(_e008(messages), [])

    def test_complete_s1_maps_are_valid(self):
        _context, trustee = _s1_maps()
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=trustee)
        self.assertEqual(_e008(messages), [])

    def test_process_wide_zero_install_has_no_e008(self):
        Trustee.ensure_frozen()
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None)
        self.assertEqual(_e008(messages), [])
        all_messages = run_checks()
        self.assertFalse(
            any(m.id == CHECK_ID_INCOMPLETE_CONFIG for m in all_messages)
        )


class S5PartialConfigurationTest(TestCase):
    def test_requester_only(self):
        registry = TrusteeRegistry()
        registry.configure(requester_model=S1Account)
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        _assert_one_e008(self, messages, 'scope', 'operation')

    def test_scope_only(self):
        registry = TrusteeRegistry()
        registry.configure(scope_model=S1Repository)
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        _assert_one_e008(self, messages, 'requester', 'operation')

    def test_operation_only(self):
        registry = TrusteeRegistry()
        registry.configure(operation_model=S1Operation)
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        _assert_one_e008(self, messages, 'requester', 'scope')

    def test_requester_and_scope_missing_operation(self):
        registry = TrusteeRegistry()
        registry.configure(
            requester_model=S1Account, scope_model=S1Repository,
        )
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        error = _assert_one_e008(self, messages, 'operation')
        self.assertNotIn('requester', error.msg)
        self.assertNotIn('scope', error.msg)

    def test_requester_and_operation_missing_scope(self):
        registry = TrusteeRegistry()
        registry.configure(
            requester_model=S1Account, operation_model=S1Operation,
        )
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        error = _assert_one_e008(self, messages, 'scope')
        self.assertNotIn('requester', error.msg)
        self.assertNotIn('operation terminal', error.msg)

    def test_scope_and_operation_missing_requester(self):
        registry = TrusteeRegistry()
        registry.configure(
            scope_model=S1Repository, operation_model=S1Operation,
        )
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        error = _assert_one_e008(self, messages, 'requester')
        self.assertNotIn('scope', error.msg)
        self.assertNotIn('operation', error.msg)

    def test_operation_lookup_only(self):
        registry = TrusteeRegistry()
        registry.configure(operation_lookup='code')
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        _assert_one_e008(
            self, messages,
            'requester', 'scope', 'operation',
            "operation_lookup 'code' is set without operation_model",
        )

    def test_lookup_without_operation_model(self):
        registry = TrusteeRegistry()
        registry.configure(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_lookup='code',
        )
        with self.assertNumQueries(0):
            messages = check_trustee_configuration(None, registry=registry)
        _assert_one_e008(
            self, messages,
            'operation',
            "operation_lookup 'code' is set without operation_model",
        )


class S5SilenceAndFailClosedTest(TestCase):
    def test_silenced_e008_still_raises_at_runtime(self):
        context = ContextRegistry()
        context.register_identity(S1Repository)
        registry = TrusteeRegistry()
        registry.configure(
            requester_model=S1Account,
            scope_model=S1Repository,
        )
        messages = check_trustee_configuration(None, registry=registry)
        self.assertTrue(_e008(messages))

        account = S1Account(name='pat')
        repo = S1Repository(title='repo')
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(
                account, 'read', repo, context=context, trustee=registry,
            )

        with override_settings(
            SILENCED_SYSTEM_CHECKS=['trusts.E008', 'fields.W342'],
        ):
            visible = [
                m for m in messages
                if m.id not in settings.SILENCED_SYSTEM_CHECKS
            ]
            self.assertEqual(_e008(visible), [])
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(
                account, 'read', repo, context=context, trustee=registry,
            )


class S5TrusteeCheckOrderTest(TestCase):
    def test_completeness_before_rewalk_runs_completing_finalizer(self):
        registry = TrusteeRegistry()
        registry.configure(requester_model=S1Account)

        def complete():
            registry.configure(
                scope_model=S1Repository,
                operation_model=S1Operation,
            )

        registry.add_finalizer(complete)
        with self.assertNumQueries(0):
            config_messages = check_trustee_configuration(
                None, registry=registry,
            )
            rewalk_messages = check_trustee_registry(None, registry=registry)
        self.assertEqual(_e008(config_messages), [])
        self.assertFalse(
            any(m.id == CHECK_ID_INVALID_TRUSTEE for m in rewalk_messages)
        )
        self.assertIs(registry.requester_model(), S1Account)
        self.assertIs(registry.scope_model(), S1Repository)
        self.assertIs(registry.operation_model(), S1Operation)

    def test_completeness_before_rewalk_failed_finalizer_is_deterministic(self):
        registry = TrusteeRegistry()
        registry.configure(requester_model=S1Account)

        def fail():
            raise TrusteeRegistrationError('finalizer refused to complete')

        registry.add_finalizer(fail)
        with self.assertNumQueries(0):
            config_messages = check_trustee_configuration(
                None, registry=registry,
            )
            rewalk_messages = check_trustee_registry(None, registry=registry)
        _assert_one_e008(self, config_messages, 'scope', 'operation')
        self.assertFalse(
            any(m.id == CHECK_ID_INVALID_TRUSTEE for m in rewalk_messages)
        )
        self.assertFalse(registry.is_frozen())

    def test_lookup_freeze_failure_is_e008_not_an_exception(self):
        registry = TrusteeRegistry()
        registry.configure(operation_lookup='code')
        with self.assertNumQueries(0):
            config_messages = check_trustee_configuration(
                None, registry=registry,
            )
            rewalk_messages = check_trustee_registry(None, registry=registry)
        _assert_one_e008(
            self, config_messages,
            "operation_lookup 'code' is set without operation_model",
        )
        self.assertFalse(
            any(m.id == CHECK_ID_INVALID_TRUSTEE for m in rewalk_messages)
        )

    def test_non_registration_finalizer_failure_is_e007(self):
        registry = TrusteeRegistry()
        registry.configure(requester_model=S1Account)

        def boom():
            raise RuntimeError('finalizer crashed')

        registry.add_finalizer(boom)
        with self.assertNumQueries(0):
            config_messages = check_trustee_configuration(
                None, registry=registry,
            )
            rewalk_messages = check_trustee_registry(None, registry=registry)
        _assert_one_e008(self, config_messages, 'scope', 'operation')
        e007 = [m for m in rewalk_messages if m.id == CHECK_ID_INVALID_TRUSTEE]
        self.assertEqual(len(e007), 1)
        self.assertIn('finalizer crashed', e007[0].msg)


class S5NoDuplicateDiagnosticsTest(TestCase):
    def test_e008_does_not_revalidate_stale_adapters(self):
        _context, trustee = _s1_maps()
        saved = trustee.get(S1_TEAM)
        trustee._adapters[S1_TEAM] = TrusteeAdapter(
            KIND_GRANT, S1_TEAM, saved.trustee_model, saved.membership_path,
            saved.grant_model, saved.trustee_path, saved.scope_path,
            'not_a_field', saved.constraint_paths, trustee,
            alignment_paths=saved.alignment_paths,
        )
        try:
            with self.assertNumQueries(0):
                messages = check_trustee_configuration(None, registry=trustee)
            self.assertEqual(_e008(messages), [])
            with self.assertRaises(TrusteeRegistrationError) as ctx:
                trustee.revalidate(trustee.get(S1_TEAM))
            self.assertIn('not a field', str(ctx.exception))
        finally:
            trustee._adapters[S1_TEAM] = saved

    def test_e006_and_e007_ids_remain_distinct(self):
        self.assertEqual(CHECK_ID_INVALID_CONTEXT, 'trusts.E006')
        self.assertEqual(CHECK_ID_INVALID_TRUSTEE, 'trusts.E007')
        self.assertEqual(CHECK_ID_INCOMPLETE_CONFIG, 'trusts.E008')
        with self.assertNumQueries(0):
            context_messages = check_context_registry(None)
            trustee_messages = check_trustee_registry(None)
            config_messages = check_trustee_configuration(None)
        self.assertFalse(
            any(m.id == CHECK_ID_INCOMPLETE_CONFIG for m in context_messages)
        )
        self.assertFalse(
            any(m.id == CHECK_ID_INCOMPLETE_CONFIG for m in trustee_messages)
        )
        self.assertFalse(
            any(m.id == CHECK_ID_INVALID_CONTEXT for m in config_messages)
        )
        self.assertFalse(
            any(m.id == CHECK_ID_INVALID_TRUSTEE for m in config_messages)
        )


class S5ZeroLeftoverOwnershipTest(TestCase):
    """Companion Zero owns and registers leftover Content E006 exactly once."""

    def test_kernel_plus_zero_emits_exactly_one_leftover_e006(self):
        from django.core.checks.registry import registry as check_registry
        from trusts.utils import get_short_model_name
        from trusts.zero.checks import (
            _kernel_owns_adapter_rewalks,
            check_context_registry as zero_combined_context,
            check_trustee_registry as zero_combined_trustee,
            check_unresolved_content_registrations,
        )
        from trusts.zero.models import Content, prepare_context_registry
        from tests.models import Receipt, Ticket, UnregisteredReceiptNote
        from trusts.context import ContextAdapter, KIND_DIRECT

        self.assertTrue(_kernel_owns_adapter_rewalks())
        registered = check_registry.registered_checks
        self.assertIn(check_unresolved_content_registrations, registered)
        self.assertNotIn(zero_combined_context, registered)
        self.assertNotIn(zero_combined_trustee, registered)

        short = get_short_model_name(UnregisteredReceiptNote)
        invalid = '%s__title' % Content.get_content_fieldlookup(Receipt)
        self.assertNotIn(short, Content._contents)
        Content._contents[short] = invalid
        Context.registry._frozen = False
        prepare_context_registry()
        key = Ticket._meta.concrete_model
        saved = Context.registry._adapters[key]
        Context.registry._adapters[key] = ContextAdapter(
            KIND_DIRECT, Ticket, 'title', Context.registry,
        )
        try:
            with self.assertNumQueries(0):
                kernel_messages = check_context_registry(None)
                leftover_only = check_unresolved_content_registrations(None)
                all_messages = run_checks()

            kernel_leftover = [
                m for m in kernel_messages
                if m.id == CHECK_ID_INVALID_CONTEXT
                and m.obj is UnregisteredReceiptNote
            ]
            self.assertEqual(kernel_leftover, [])

            adapter_e006 = [
                m for m in kernel_messages
                if m.id == CHECK_ID_INVALID_CONTEXT and m.obj is Ticket
            ]
            self.assertEqual(len(adapter_e006), 1)

            zero_leftover = [
                m for m in leftover_only
                if m.id == CHECK_ID_INVALID_CONTEXT
                and m.obj is UnregisteredReceiptNote
            ]
            self.assertEqual(len(zero_leftover), 1)

            registered_leftover = [
                m for m in all_messages
                if m.id == CHECK_ID_INVALID_CONTEXT
                and m.obj is UnregisteredReceiptNote
            ]
            self.assertEqual(len(registered_leftover), 1)

            registered_ticket = [
                m for m in all_messages
                if m.id == CHECK_ID_INVALID_CONTEXT and m.obj is Ticket
            ]
            self.assertEqual(len(registered_ticket), 1)

            self.assertFalse(
                any(m.id == CHECK_ID_INCOMPLETE_CONFIG for m in leftover_only)
            )
        finally:
            Context.registry._adapters[key] = saved
            Content._contents.pop(short, None)
            Context.registry.freeze()
