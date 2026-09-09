"""Isolated kernel tests for #47 S5 (generic configuration checks).

Covers noun-independent ``trusts.E008`` completeness, preserved
``E006`` / ``E007`` re-walks, and the removal of the kernel
``trusts.zero`` Content leftover probe. Isolated registries for
partial states. Does not close #47. Does not modify Zero.
"""

import inspect
import re
from io import StringIO
from pathlib import Path

from django.conf import settings
from django.core.checks import Error, run_checks
from django.core.management import call_command
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
            out = StringIO()
            err = StringIO()
            call_command('check', stdout=out, stderr=err)
            combined = out.getvalue() + err.getvalue()
            self.assertNotIn('trusts.E008', combined)
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(
                account, 'read', repo, context=context, trustee=registry,
            )


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
    """Companion Zero still owns leftover Content diagnostics.

    Kernel ``check_context_registry`` must not emit them. Zero's
    ``check_context_registry`` function still walks leftovers. When
    KernelConfig is present, Zero does **not** register that function
    (no-kernel fallback only). This test does not modify Zero.
    """

    def test_kernel_check_does_not_walk_content_leftovers(self):
        from trusts.utils import get_short_model_name
        from trusts.zero.models import Content, prepare_context_registry
        from tests.models import Receipt, UnregisteredReceiptNote

        short = get_short_model_name(UnregisteredReceiptNote)
        invalid = '%s__title' % Content.get_content_fieldlookup(Receipt)
        self.assertNotIn(short, Content._contents)
        Content._contents[short] = invalid
        Context.registry._frozen = False
        try:
            prepare_context_registry()
            with self.assertNumQueries(0):
                kernel_messages = check_context_registry(None)
            leftover = [
                m for m in kernel_messages
                if m.id == CHECK_ID_INVALID_CONTEXT
                and m.obj is UnregisteredReceiptNote
            ]
            self.assertEqual(leftover, [])

            from trusts.zero.checks import (
                check_context_registry as zero_check_context,
            )
            with self.assertNumQueries(0):
                zero_messages = zero_check_context(None)
            zero_leftover = [
                m for m in zero_messages
                if m.id == CHECK_ID_INVALID_CONTEXT
                and m.obj is UnregisteredReceiptNote
            ]
            self.assertEqual(len(zero_leftover), 1)
            self.assertEqual(zero_leftover[0].id, 'trusts.E006')

            from trusts.zero.checks import _kernel_owns_adapter_rewalks
            self.assertTrue(_kernel_owns_adapter_rewalks())
            registered = run_checks()
            registered_leftover = [
                m for m in registered
                if m.id == CHECK_ID_INVALID_CONTEXT
                and m.obj is UnregisteredReceiptNote
            ]
            self.assertEqual(
                registered_leftover, [],
                'Zero leftover E006 is not registered when KernelConfig '
                'is present; kernel must not reintroduce it.',
            )
        finally:
            Content._contents.pop(short, None)
            Context.registry.freeze()
