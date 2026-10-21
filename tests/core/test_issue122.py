from pathlib import Path

from django.test import SimpleTestCase


ROOT = Path(__file__).resolve().parents[2]


class FinalDocumentationSurfaceTest(SimpleTestCase):


    def test_live_router_points_at_merged_zero_and_rejects_zero_schema(self):
        path = ROOT / 'docs/source/migrates.md'
        text = path.read_text()
        rst = (ROOT / 'docs' / 'source' / 'index.rst').read_text()
        readme = (ROOT / 'README.md').read_text()
        pyproject = (ROOT / 'pyproject.toml').read_text()

        self.assertIn('# Migrating from django-trusts 1.0 to 1.1', text[:80])
        self.assertIn('does not provide a direct migration', text)
        self.assertIn('## Relationship condition language (#210)', text)
        self.assertIn('## Permitted content queryset (#270)', text)
        self.assertIn('`1.0.0 → 1.1.0`', text)
        self.assertIn(
            '| Membership | `permission_in("team__allowed_operations")` |',
            text,
        )
        self.assertNotIn('Python `in` or `permission_in', text)
        self.assertTrue((ROOT / 'docs/dev' / 'core-registry.md').is_file())
        self.assertFalse((ROOT / 'docs' / 'registry.md').exists())
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
        self.assertIn('[Migration boundary](docs/source/migrates.md)', readme)
        self.assertIn(
            'https://github.com/django-trusts/django-trusts/blob/dev/docs/source/migrates.md',
            rst,
        )
        self.assertIn(
            'Migration = "https://github.com/django-trusts/'
            'django-trusts/blob/dev/docs/source/migrates.md"',
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
