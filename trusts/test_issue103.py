"""#103 step 1: generic ``trusts.core_backends`` boundary.

Additive public mixin import plus a deprecated same-object alias on
``trusts.backends``. Historical ``TrustModelBackend`` and TrustGroup
SQL stay on ``trusts.backends``. No Zero or GH retarget.
"""

import ast
import inspect
from unittest.mock import Mock, patch

from django.contrib.auth.models import AnonymousUser, User
from django.test import SimpleTestCase

from trusts.core import PlanQueryCompiler, TrustsConfigurationError
from trusts.core_backends import TrustModelBackendMixin


class CoreBackendsBoundaryTest(SimpleTestCase):
    def test_canonical_mixin_import_and_plan_compiler(self):
        self.assertIsInstance(
            TrustModelBackendMixin.query_compiler, PlanQueryCompiler,
        )
        self.assertFalse(
            TrustModelBackendMixin.query_compiler.historical_fallback,
        )

    def test_backends_mixin_is_core_backends_mixin(self):
        from trusts.backends import (
            TrustModelBackendMixin as AliasMixin,
        )
        self.assertIs(AliasMixin, TrustModelBackendMixin)
        self.assertIs(
            __import__('trusts.backends', fromlist=['TrustModelBackendMixin'])
            .TrustModelBackendMixin,
            __import__(
                'trusts.core_backends', fromlist=['TrustModelBackendMixin']
            ).TrustModelBackendMixin,
        )

    def test_historical_backend_path_still_imports(self):
        from trusts.backends import (
            HistoricalGroupQueryCompiler,
            TrustModelBackend,
        )
        self.assertTrue(issubclass(TrustModelBackend, TrustModelBackendMixin))
        self.assertIsInstance(
            TrustModelBackend.query_compiler, HistoricalGroupQueryCompiler,
        )
        self.assertTrue(TrustModelBackend.query_compiler.historical_fallback)

    def test_core_backends_has_no_trustgroup_dependency(self):
        import trusts.core_backends as core_backends

        self.assertFalse(hasattr(core_backends, 'HistoricalGroupQueryCompiler'))
        self.assertFalse(hasattr(core_backends, 'TrustModelBackend'))
        self.assertFalse(hasattr(core_backends, 'historical_group_grant_exists'))
        self.assertFalse(hasattr(core_backends, 'TrustGroup'))
        self.assertNotIn('TrustGroup', core_backends.__dict__)

        tree = ast.parse(inspect.getsource(core_backends))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported.add(alias.name)
                    if node.module:
                        imported.add(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name)
        self.assertNotIn('historical_group_grant_exists', imported)
        self.assertNotIn('group_local_grant_exists', imported)
        self.assertNotIn('trust_grant_q', imported)
        self.assertNotIn('HistoricalGroupQueryCompiler', imported)
        self.assertNotIn('TrustGroup', imported)


class MixinMissingKernelTest(SimpleTestCase):
    def _active_user(self):
        user = Mock()
        user.is_anonymous = False
        user.is_authenticated = True
        user.is_active = True
        return user

    def _model_obj(self):
        return User(username='issue103')

    def test_lookuperror_is_configuration_error_not_false(self):
        mixin = TrustModelBackendMixin()
        with patch(
            'trusts.apps.kernel_config',
            side_effect=LookupError('No installed Trusts kernel AppConfig.'),
        ):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                mixin._trusts_config()
            message = str(ctx.exception)
            self.assertIn('kernel AppConfig is not in INSTALLED_APPS', message)
            self.assertIn("'trusts'", message)
            self.assertIn('trusts.zero.apps.ZeroConfig', message)
            self.assertIsInstance(ctx.exception.__cause__, LookupError)

            with self.assertRaises(TrustsConfigurationError):
                mixin.has_perm(
                    self._active_user(), 'auth.view_user', self._model_obj(),
                )
            with self.assertRaises(TrustsConfigurationError):
                mixin.get_all_permissions(
                    self._active_user(), self._model_obj(),
                )
            with self.assertRaises(TrustsConfigurationError):
                mixin.get_group_permissions(
                    self._active_user(), self._model_obj(),
                )

    def test_importerror_is_configuration_error_not_false(self):
        mixin = TrustModelBackendMixin()
        with patch(
            'trusts.apps.kernel_config',
            side_effect=ImportError('No module named trusts.apps'),
        ):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                mixin._trusts_config()
            message = str(ctx.exception)
            self.assertIn('django-trusts distribution is not installed', message)
            self.assertIn('pip install django-trusts', message)
            self.assertIn("'trusts'", message)
            self.assertIsInstance(ctx.exception.__cause__, ImportError)

            with self.assertRaises(TrustsConfigurationError):
                mixin.has_perm(
                    self._active_user(), 'auth.view_user', self._model_obj(),
                )

    def test_anonymous_and_obj_none_remain_false(self):
        mixin = TrustModelBackendMixin()
        with patch(
            'trusts.apps.kernel_config',
            side_effect=LookupError('No installed Trusts kernel AppConfig.'),
        ):
            self.assertFalse(
                mixin.has_perm(AnonymousUser(), 'auth.view_user', self._model_obj()),
            )
            self.assertFalse(
                mixin.has_perm(self._active_user(), 'auth.view_user', None),
            )
            self.assertEqual(
                mixin.get_all_permissions(AnonymousUser(), self._model_obj()),
                set(),
            )
            self.assertEqual(
                mixin.get_group_permissions(self._active_user(), None),
                set(),
            )
