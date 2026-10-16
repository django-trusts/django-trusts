"""Documentation routing and links after the #318 consolidation."""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

from django.test import SimpleTestCase


ROOT = Path(__file__).resolve().parents[2]
REPO_DOC_URL = 'https://github.com/django-trusts/django-trusts/blob/dev/'


class FinalDocumentationSurfaceTest(SimpleTestCase):
    def test_user_guide_keeps_the_working_example(self):
        guide = (ROOT / 'docs/source/index.rst').read_text()
        for example in (
            'class DocumentPermission(models.Model)',
            'class DocumentQuerySet(PermittedQuerySetMixin, models.QuerySet)',
            'objects = DocumentQuerySet.as_manager()',
            'class DocumentsConfig(TrustsImplementationConfig)',
            'def ready(self):',
            'super().ready()',
            'backend.register(',
            'trust=DocumentPermission',
            'user.has_perm("documents.change_document", document)',
            'user.get_all_permissions(document)',
            'document.get_permitted_users(',
            '@authorization_required(Document, "documents.change_document")',
        ):
            with self.subTest(example=example):
                self.assertIn(example, guide)
        for implementation_detail in (
            'from trusts.core import Ref', 'from trusts.models import',
            'registry.register(', 'backend.add_named_filter(',
            'WITH RECURSIVE', 'schema_version:',
        ):
            self.assertNotIn(implementation_detail, guide)

    def test_development_docs_have_one_location_and_review_status(self):
        allowed = {'docs/source/index.rst', 'docs/whats-new.md'}
        documents = list((ROOT / 'docs').rglob('*.md'))
        documents += list((ROOT / 'docs').rglob('*.rst'))
        for path in documents:
            relative = path.relative_to(ROOT).as_posix()
            if relative.startswith('docs/_build/'):
                continue
            with self.subTest(path=relative):
                self.assertTrue(relative in allowed or relative.startswith('docs/dev/'))
                if relative.startswith('docs/dev/'):
                    text = path.read_text()
                    self.assertIn('Historical development record', text)
                    self.assertIn('reviewed by a human', text)
                    self.assertRegex(text, r'2026-\d\d-\d\d')
        for removed in ('docs/permitted-queryset-inquiry.md',
                        'docs/reverse-permission-inquiry.md'):
            self.assertFalse((ROOT / removed).exists())
        reference = (ROOT / 'docs/dev/permission-inquiries.md').read_text()
        for surface in ('get_permitted_users', 'filter_by_permitted_content',
                        'queryset.permitted', 'queryset.authorized',
                        'authorization_required', 'all_match'):
            self.assertIn(surface, reference)

    def test_repository_document_links_resolve(self):
        paths = [ROOT / name for name in
                 ('README.md', 'DEV.md', 'RELEASING.md',
                  'SECURITY_AUDIT.md', 'migrates.md')]
        paths += list((ROOT / 'docs/dev').glob('*.md'))
        paths += list((ROOT / 'docs/dev').glob('*.rst'))
        paths += [ROOT / 'docs/source/index.rst', ROOT / 'docs/whats-new.md']
        for path in paths:
            text = path.read_text()
            links = re.findall(r'\]\(([^)\s]+)\)', text)
            links += re.findall(r'<([^<>\s]+)>`_', text)
            for link in links:
                if link.startswith(REPO_DOC_URL):
                    target = ROOT / unquote(urlsplit(link).path.split('/blob/dev/', 1)[1])
                else:
                    parts = urlsplit(link)
                    if parts.scheme or parts.netloc:
                        continue
                    target = path.parent / unquote(parts.path) if parts.path else path
                with self.subTest(source=str(path.relative_to(ROOT)), link=link):
                    self.assertTrue(target.exists(), str(target))

    def test_metadata_and_migration_routes(self):
        conf = (ROOT / 'docs/source/conf.py').read_text()
        self.assertIn("copyright = '2015-2026, BeeDesk, Inc.'", conf)
        pyproject = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('blob/dev/docs/source/index.rst', pyproject)
        self.assertIn('blob/dev/docs/dev/legacy-baseline.md', pyproject)
        migration = (ROOT / 'migrates.md').read_text()
        self.assertTrue(migration.startswith('# Migrating from django-trusts 1.0 to 1.1'))
        self.assertIn('django-trusts-zero/blob/dev/migrates.md', migration)
        self.assertIn('migration-archive-pre-1.0/migrates.md', migration)
        for schema_instruction in ('create_trust_root', 'TrustUserPermission',
                                   "include('trusts.urls')"):
            self.assertNotIn(schema_instruction, migration)
