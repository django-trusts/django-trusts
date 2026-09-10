"""Public terminal-validation surface for Zero compatibility façades.

``require_configured_terminal`` is the narrowly public kernel API that
replaces ``_require_instance``. Zero ``require_configured_requester`` /
``require_configured_operation`` call it and translate
``AuthorizationConfigError`` to ``AuthorizationPathError``.
"""

import inspect

from django.test import TransactionTestCase

from trusts.runtime import (
    AuthorizationConfigError,
    require_configured_terminal,
)
from tests.models import S1Account, S1Operation, S1Organization, S1Repository


class S1AccountProxy(S1Account):
    """Proxy of the S1 requester. Same concrete model as ``S1Account``."""

    class Meta:
        proxy = True
        app_label = 'tests'


class RequireConfiguredTerminalTest(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        super(RequireConfiguredTerminalTest, self).setUp()
        self.org = S1Organization.objects.create(name='acme')
        self.account = S1Account.objects.create(name='pat')
        self.repo = S1Repository.objects.create(
            organization=self.org, title='repo',
        )
        self.read = S1Operation.objects.create(code='read')

    def test_require_configured_terminal_accepts_matching_instance(self):
        self.assertIs(
            require_configured_terminal(self.account, S1Account, 'requester'),
            self.account,
        )
        self.assertIs(
            require_configured_terminal(self.read, S1Operation, 'operation'),
            self.read,
        )

    def test_require_configured_terminal_rejects_class_pk_and_wrong_model(self):
        with self.assertRaises(AuthorizationConfigError) as ctx:
            require_configured_terminal(S1Account, S1Account, 'requester')
        self.assertIn('model class', str(ctx.exception))
        with self.assertRaises(AuthorizationConfigError) as ctx:
            require_configured_terminal(self.account.pk, S1Account, 'requester')
        self.assertIn('primary key', str(ctx.exception).lower())
        with self.assertRaises(AuthorizationConfigError) as ctx:
            require_configured_terminal(self.repo, S1Account, 'requester')
        self.assertIn('requester', str(ctx.exception))
        with self.assertRaises(AuthorizationConfigError) as ctx:
            require_configured_terminal(self.account, S1Operation, 'operation')
        self.assertIn('operation', str(ctx.exception))

    def test_require_configured_terminal_rejects_malformed_expected_model(self):
        cases = (
            self.account,
            object,
            object(),
            1,
            'S1Account',
        )
        for expected in cases:
            with self.assertRaises(AuthorizationConfigError) as ctx:
                require_configured_terminal(self.account, expected, 'requester')
            self.assertIn('Django model class', str(ctx.exception))
            self.assertNotIsInstance(ctx.exception, AttributeError)

    def test_require_configured_terminal_accepts_proxy_expected_model(self):
        self.assertIs(
            require_configured_terminal(self.account, S1AccountProxy, 'requester'),
            self.account,
        )
        proxied = S1AccountProxy.objects.get(pk=self.account.pk)
        self.assertIs(
            require_configured_terminal(proxied, S1Account, 'requester'),
            proxied,
        )

    def test_require_configured_terminal_is_public_export(self):
        import trusts.runtime as runtime_mod
        self.assertIn('require_configured_terminal', runtime_mod.__all__)
        self.assertFalse(
            inspect.getsource(require_configured_terminal).lstrip().startswith('def _')
        )
        self.assertNotIn('_require_instance', runtime_mod.__all__)
        self.assertTrue(hasattr(runtime_mod, 'require_configured_terminal'))
        self.assertFalse(hasattr(runtime_mod, '_require_instance'))
