from pathlib import Path

from django.test import SimpleTestCase


ROOT = Path(__file__).resolve().parents[2]


class FinalDocumentationSurfaceTest(SimpleTestCase):
    def test_rst_introduces_the_current_permission_system(self):
        rst = (ROOT / 'docs' / 'source' / 'index.rst').read_text()
        forbidden = (
            'from trusts.models import',
            'Content.register_permission_condition',
            'TrustGroup.grant_permission',
            'HistoricalGroupQueryCompiler',
            'trust_grant_q',
            'kernel_config',
            'C1 default',
            'pip install django-trusts',
            'TeamRepositoryGrant',
            'permission_bundles',
            'non-standalone Python dependency',
            'Core supplies',
            'core compiles',
        )
        self.assertEqual([needle for needle in forbidden if needle in rst], [])
        self.assertIn('Django permission system for object-level', rst)
        self.assertIn('permission is a persisted relationship', rst)
        self.assertIn('TrustsImplementationConfig', rst)
        self.assertIn('TrustModelBackendMixin', rst)
        self.assertIn('class DocumentPermission(models.Model)', rst)
        self.assertIn('Document.objects.authorized(', rst)
        self.assertIn('user.get_all_permissions(document)', rst)
        self.assertIn('from trusts.decorators import permission_required', rst)
        self.assertIn('register_permission_condition', rst)
        self.assertIn('o.confidential != True', rst)
        self.assertIn('confidential = models.BooleanField(default=False)', rst)
        self.assertIn('Along', rst)
        self.assertIn('OrderedFold', rst)
        self.assertIn('django-trusts-zero', rst)
        self.assertIn('django-trusts-gh-permissions', rst)
        self.assertIn('django-trusts-windows-acl', rst)
        self.assertIn('django-trusts-zero-example', rst)

    def test_sphinx_and_package_metadata_point_to_current_docs(self):
        conf = (ROOT / 'docs' / 'source' / 'conf.py').read_text()
        self.assertIn("copyright = '2015-2026, BeeDesk, Inc.'", conf)
        self.assertIn("author = 'BeeDesk, Inc.'", conf)

        pyproject = (ROOT / 'pyproject.toml').read_text()
        self.assertNotIn('readthedocs.org', pyproject)
        self.assertNotIn('blob/master/', pyproject)
        self.assertIn(
            'blob/dev/docs/source/index.rst',
            pyproject,
        )
        self.assertIn('blob/dev/migrates.md', (ROOT / 'docs' / 'source' / 'index.rst').read_text())

    def test_migration_record_leads_with_current_contract(self):
        migration = (ROOT / 'migrates.md').read_text()
        current = migration[:1800]
        self.assertIn('Current 1.x contract', current)
        self.assertIn('schema-neutral dependency', current)
        self.assertIn('TrustModelBackendMixin', current)
        self.assertIn('trusts.zero.apps.ZeroConfig', current)
