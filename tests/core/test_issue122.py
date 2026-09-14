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
        self.assertIn('from trusts.decorators import authorization_required', rst)
        self.assertNotIn('from trusts.decorators import permission_required', rst)
        self.assertNotIn('from trusts.decorators import P', rst)
        self.assertIn('add_named_filter', rst)
        self.assertIn('backend.register(', rst)
        self.assertIn('trust=DocumentPermission', rst)
        self.assertNotIn('register_relationship', rst)
        self.assertIn('register_ordered_fold()', rst)
        self.assertNotIn('backend.register_ordered_fold(', rst)
        self.assertNotIn('source_descriptor="document"', rst)
        self.assertNotIn('content=WinNode', rst)
        self.assertIn('django-trusts-ordered-fold', rst)
        self.assertIn('TrustsOrderedFoldModelBackend', rst)
        self.assertIn('AUTHENTICATION_BACKENDS', rst)
        self.assertIn('relationship-family', rst)
        self.assertIn('_authorization_family', rst)
        self.assertIn('mixed-family one-SQL', rst)
        self.assertNotIn('family-local OR', rst)
        self.assertNotIn('Until the OrderedFold engine leaves Core', rst)
        self.assertIn('does not veto an independent', rst)
        self.assertNotIn('strategy=OrderedFold', rst)
        self.assertNotIn('from trusts.core import Ref', rst)
        self.assertNotIn('.registry.register(', rst)
        self.assertIn('o.confidential != True', rst)
        self.assertIn('confidential = models.BooleanField(default=False)', rst)
        self.assertIn('Inherited relationships are provisional', rst)
        self.assertIn('along=("parent", 8)', rst)
        self.assertIn('Ordered allow and deny support is provisional', rst)
        self.assertIn('OrderedFold', rst)
        self.assertIn('django-trusts-zero', rst)
        self.assertIn('django-trusts-gh-permissions', rst)
        self.assertIn('django-trusts-ordered-fold', rst)
        self.assertIn('django-trusts-windows-acl', rst)
        self.assertIn('django-trusts-zero-example', rst)

    def test_security_audit_records_the_frozen_boundary(self):
        guide = (ROOT / 'SECURITY_AUDIT.md').read_text()
        for needle in (
            'security boundary that implementation and',
            'register(*, trust, user, permission, content, condition=None, along=None)',
            'add_named_filter(...)',
            'Named filters are outer restrictions',
            'Runtime callbacks are unsupported',
            'Django treats an active superuser as globally authorized',
            'Trusts cannot revoke authorization supplied by another backend',
            'relationship-family',
            '_authorization_family',
            'mixed-family one-SQL',
            'django-trusts-ordered-fold',
            'trusts_ordered_fold.E001',
            'cannot veto an',
            'independent relationship grant',
            'Django\'s object-level backend OR is a different',
            'Discrepancies must be surfaced in the PR',
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, guide)
        self.assertIn('future policy manifest/lockfile', guide)
        self.assertIn('not part', guide)
        self.assertIn('of the 1.0 public contract', guide)
        self.assertNotIn('TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS = True', guide)
        self.assertNotIn('## Change sizing and surface discovery', guide)

        dev = (ROOT / 'DEV.md').read_text()
        self.assertIn('## Change sizing and surface discovery', dev)
        self.assertIn('Whole ticket: 34–144', dev)
        self.assertIn('Completed: 5 (S1 accepted)', dev)

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
        self.assertIn('# Migrating to django-trusts 1.0', current)
        self.assertIn('schema-neutral authorization library', current)
        self.assertIn('django-trusts-zero', current)
        self.assertIn('supported 0.x migration path', current)

    def test_live_router_points_at_merged_zero_and_rejects_zero_schema(self):
        path = ROOT / 'migrates.md'
        text = path.read_text()
        rst = (ROOT / 'docs' / 'source' / 'index.rst').read_text()
        readme = (ROOT / 'README.md').read_text()
        pyproject = (ROOT / 'pyproject.toml').read_text()

        self.assertIn('# Migrating to django-trusts 1.0', text[:80])
        self.assertIn('does not provide a direct migration', text)
        self.assertIn(
            'https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md',
            text,
        )
        self.assertIn('https://django-trusts.readthedocs.io/en/dev/', text)
        self.assertIn('## Archaeology', text)
        self.assertIn(
            'https://github.com/django-trusts/django-trusts/blob/'
            'migration-archive-pre-1.0/migrates.md',
            text,
        )
        self.assertIn(
            'https://github.com/django-trusts/django-trusts/blob/'
            '7414886263faafb6edfb44c0c5fcf9fc8fa14e79/migrates.md',
            text,
        )
        self.assertIn('historical reference', text)
        self.assertIn('not an alternative 0.x migration path', text)
        self.assertNotIn('Current 1.x contract', text)
        self.assertNotIn('backend.register_relationship', text)
        self.assertIn('[Migration guide](migrates.md)', readme)
        self.assertIn(
            'https://github.com/django-trusts/django-trusts/blob/dev/migrates.md',
            rst,
        )
        self.assertIn(
            'Migration = "https://github.com/django-trusts/'
            'django-trusts/blob/dev/migrates.md"',
            pyproject,
        )
        self.assertLess(path.stat().st_size, 211222 // 4)
        for banned in (
            'create_trust_root',
            'grandfather_trust_group_permissions',
            'update_roles_permissions',
            'TrustUserPermission',
            'TrustGroupPermission',
            '0002_trustgroup',
            "include('trusts.urls')",
            'trusts_zero/',
            'Content.grant',
            'associate_group',
            'HistoricalGroupQueryCompiler',
            '# Issue #151 C1',
            '# Issue #8 recovery',
            '2.0.0.dev2',
            '# Archived: unpublished',
        ):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, text)
