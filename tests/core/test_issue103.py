"""#103 / #111: generic mixin lives only on ``trusts.backends``.

``trusts.core_backends`` is gone. Historical ``TrustModelBackend`` and
TrustGroup SQL live only on ``trusts.zero.backends``.
"""

import importlib

from django.test import SimpleTestCase

from tests.core import kernel_host_listed
from trusts.plan.relations import PlanQueryCompiler


class BackendsMixinBoundaryTest(SimpleTestCase):
    def test_canonical_mixin_import_and_plan_compiler(self):
        if not kernel_host_listed():
            self.skipTest('kernel-only host path is not listed on the pair')
        from django.apps import apps

        catalog = apps.get_app_config('trusts_kernel_host').get_catalog()
        self.assertIsInstance(catalog.compiler, PlanQueryCompiler)

    def test_core_backends_module_is_gone(self):
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module('trusts.core_backends')


    def test_zero_ui_surfaces_are_gone_from_core(self):
        import importlib

        for name in (
            'trusts.authorization',
            'trusts.views',
            'trusts.urls',
            'trusts.admin',
            'trusts.management',
            'trusts.management.commands',
            'trusts.management.commands.create_trust_root',
            'trusts.management.commands.grandfather_trust_group_permissions',
            'trusts.management.commands.update_roles_permissions',
        ):
            with self.assertRaises(ModuleNotFoundError):
                importlib.import_module(name)
