"""The four canonical questions live on the built catalog.

``Catalog`` answers Q1 has_permission, Q2 filter_authorized
(plus the scope-prefix variant filter_by_permitted_content), Q3
permitted_users, and Q4 permissions_for (complete and group kinds),
with production delegation semantics. ``Compiler`` stores rows;
these questions are asked on ``built_catalog()``. Where a production
handle-based aggregate is the comparison
(the handle is the subject there), SQL is compared literally;
otherwise results are compared.
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps
from tests.core.test_issue282 import _tables
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.compile.factory import Compiler
from trusts.compile.nodes import Ref
from trusts.plan.aggregates import _compile_common_permissions, instance_match
from trusts.plan.contents import _compile_granted
from trusts.compile.catalogs import Question
from trusts.plan.relations import PlanQueryCompiler
from trusts.plan.rewrites import bind_once
from tests.support import built_catalog


def _permission(model, codename):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(content_type=content_type, codename=codename, defaults={'name': codename})
    return permission

def _pks(qs):
    return set(qs.values_list('pk', flat=True))

class CatalogQuestionsSuiteRegistrationTest(SimpleTestCase):

    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_catalog_questions', KERNEL_SUITE)
        self.assertIn('tests.core.test_catalog_questions', PAIR_KERNEL_SUITE)

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class CatalogQuestionsTest(TransactionTestCase):

    def setUp(self):
        super().setUp()
        self.User = get_user_model()
        self.Folder, self.Document, self.Grant, self.Share, self.GroupGrant = self._models()
        self._table_cm = _tables(self.Folder, self.Document, self.Grant, self.Share, self.GroupGrant)
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        self.read = _permission(self.Document, 'read_document')
        self.write = _permission(self.Document, 'write_document')
        self.alice = self.User.objects.create_user('rq-alice', password='x')
        self.bob = self.User.objects.create_user('rq-bob', password='x')
        self.outsider = self.User.objects.create_user('rq-out', password='x')
        self.folder_a = self.Folder.objects.create(title='a')
        self.folder_b = self.Folder.objects.create(title='b')
        self.doc_a = self.Document.objects.create(title='a', folder=self.folder_a)
        self.doc_b = self.Document.objects.create(title='b', folder=self.folder_b)

    def _models(self):

        class Folder(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'rq_folder'

        class Document(models.Model):
            title = models.CharField(max_length=40)
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='documents')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'rq_document'

        class Grant(models.Model):
            user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='+')
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE, null=True)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'rq_grant'

        class Share(models.Model):
            delegate = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='+')
            sponsor = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='+')
            document = models.ForeignKey(Document, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'rq_share'

        class GroupGrant(models.Model):
            user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='+')
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            group = models.ForeignKey(Group, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'rq_group_grant'
        return (Folder, Document, Grant, Share, GroupGrant)

    def _compiler(self, *, delegated=False, group=False):
        compiler = Compiler()
        grant = Ref(self.Grant)
        compiler.register_relation(content=grant.document, user=grant.user, permission=grant.permission)
        if delegated:
            share = Ref(self.Share)
            compiler.register_delegation(content=share.document, delegate=share.delegate, sponsor=share.sponsor)
        if group:
            grouped = Ref(self.GroupGrant)
            compiler.register_relation(content=grouped.document, user=grouped.user, group=grouped.group)
        return compiler

    def _production_handle(self, compiler):
        compiler.path = 'tests.core.catalog-questions'
        return compiler

    def test_q1_to_q4_ordinary_sql_matches_production(self):
        compiler = self._compiler()
        self.Grant.objects.create(user=self.alice, document=self.doc_a, permission=self.read)
        built = built_catalog(compiler)
        self.assertTrue(built.has_perm(self.alice, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a))
        self.assertFalse(built.has_perm(self.alice, '%s.%s' % (self.write.content_type.app_label, self.write.codename), self.doc_a))
        self.assertFalse(built.has_perm(self.bob, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a))
        handle = self._production_handle(compiler)
        self.assertEqual(built.has_perm(self.alice, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a), instance_match(built_catalog(handle), self.doc_a, self.alice, self.read))
        built_qs = built.filter_authorized(self.Document.objects.all(), self.alice, self.read)
        granted_q = _compile_granted(built_catalog(handle), self.Document.objects.all(), self.alice, self.read)
        production_qs = bind_once(self.Document.objects.filter(granted_q).distinct())
        self.assertEqual(str(built_qs.query), str(production_qs.query))
        self.assertEqual(_pks(built_qs), {self.doc_a.pk})
        self.assertEqual(_pks(built.permissions_for(self.alice, self.doc_a)), {self.read.pk})
        self.assertEqual(str(built.permissions_for(self.alice, self.doc_a).query), str(built_catalog(compiler).permissions_for(self.alice, self.doc_a).query))
        self.assertEqual(built.has_perm(self.alice, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a), built_catalog(compiler).has_perm(self.alice, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a))
        self.assertEqual(str(built.filter_authorized(self.Document.objects.all(), self.alice, self.read).query), str(built_catalog(compiler).filter_authorized(self.Document.objects.all(), self.alice, self.read).query))
        self.assertEqual(_pks(built.permitted_users(self.doc_a, self.read)), {self.alice.pk})
        code = '%s.%s' % (self.read.content_type.app_label, self.read.codename)
        self.assertEqual(_pks(built.permitted_users(self.doc_a, code)), {self.alice.pk})
        prefix_compiler = Compiler()
        grant = Ref(self.Grant)
        prefix_compiler.register_relation(content=grant.folder.documents, user=grant.user, permission=grant.permission)
        self.Grant.objects.filter(user=self.alice).update(folder=self.folder_a)
        folders = built_catalog(prefix_compiler).filter_by_permitted_content(self.Folder.objects.all(), self.alice, self.read, content=self.Document)
        self.assertEqual(_pks(folders), {self.folder_a.pk})

    def test_delegation_uses_production_semantics_on_built_compiler(self):
        compiler = self._compiler(delegated=True)
        self.Grant.objects.create(user=self.alice, document=self.doc_a, permission=self.read)
        self.Share.objects.create(delegate=self.bob, sponsor=self.alice, document=self.doc_a)
        built = built_catalog(compiler)
        handle = self._production_handle(compiler)
        self.assertTrue(built.has_perm(self.bob, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a))
        self.assertEqual(built.has_perm(self.bob, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a), instance_match(built_catalog(handle), self.doc_a, self.bob, self.read))
        self.assertFalse(built.has_perm(self.outsider, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a))
        self.assertEqual(_pks(built.filter_authorized(self.Document.objects.all(), self.bob, self.read)), {self.doc_a.pk})
        self.assertEqual(_pks(built.permissions_for(self.bob, self.doc_a)), {self.read.pk})
        production_permissions = _compile_common_permissions(built_catalog(handle), self.doc_a, self.bob, kind='complete')
        self.assertEqual(str(built.permissions_for(self.bob, self.doc_a).query), str(production_permissions.query))
        self.assertEqual(_pks(built.permitted_users(self.doc_a, self.read)), {self.alice.pk, self.bob.pk})
        self.assertTrue(built_catalog(compiler).has_perm(self.bob, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a))
        self.assertEqual(_pks(built_catalog(compiler).permissions_for(self.bob, self.doc_a)), {self.read.pk})
        self.Share.objects.create(delegate=self.bob, sponsor=self.alice, document=self.doc_b)
        built = built_catalog(compiler)
        self.assertFalse(built.has_perm(self.bob, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_b))

    def test_walk_questions_order_descriptors_and_bound_answers(self):
        compiler = self._compiler(group=True)
        group = Group.objects.create(name='rq-walkers')
        group.permissions.add(self.read)
        self.Grant.objects.create(user=self.alice, document=self.doc_a, permission=self.read)
        self.GroupGrant.objects.create(user=self.alice, document=self.doc_a, group=group)
        built = built_catalog(compiler)
        seen = []

        class _RecordingVisitor(object):

            def visit(self, question):
                seen.append(question)
                return question.name
        names = built.walk_questions(_RecordingVisitor())
        self.assertEqual(names, ('permitted', 'has_perm', 'get_all_permissions', 'get_group_permissions', 'get_permitted_users'))
        self.assertTrue(all((isinstance(q, Question) for q in seen)))
        self.assertTrue(all((q.content_model is self.Document for q in seen)))
        self.assertEqual(len(seen[0].records), 2)
        self.assertEqual(seen[0].delegations, ())
        with self.assertRaises(Exception):
            seen[0].name = 'other'
        by_name = {q.name: q for q in seen}
        self.assertEqual(_pks(by_name['permitted'].question(self.alice, self.read)), {self.doc_a.pk})
        self.assertTrue(by_name['has_perm'].question(self.alice, self.doc_a, self.read))
        self.assertFalse(by_name['has_perm'].question(self.bob, self.doc_a, self.read))
        self.assertEqual(_pks(by_name['get_all_permissions'].question(self.alice, self.doc_a)), {self.read.pk})
        self.assertEqual(_pks(by_name['get_group_permissions'].question(self.alice, self.doc_a)), {self.read.pk})
        self.assertEqual(_pks(by_name['get_permitted_users'].question(self.doc_a, self.read)), {self.alice.pk})
        with self.assertRaises(AttributeError):
            built.walk_questions(object())

    def test_walk_questions_prefix_and_delegation_descriptors(self):
        prefix_compiler = Compiler()
        grant = Ref(self.Grant)
        prefix_compiler.register_relation(content=grant.folder.documents, user=grant.user, permission=grant.permission)
        self.Grant.objects.create(user=self.alice, document=self.doc_a, folder=self.folder_a, permission=self.read)
        built = built_catalog(prefix_compiler)
        seen = []

        class _Visitor(object):

            def visit(self, question):
                seen.append(question)
                return question
        built.walk_questions(_Visitor())
        self.assertEqual([q.name for q in seen], ['permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users', 'filter_by_permitted_content'])
        prefix_q = seen[-1]
        self.assertIs(prefix_q.content_model, self.Document)
        self.assertEqual(_pks(prefix_q.question(self.Folder.objects.all(), self.alice, self.read)), {self.folder_a.pk})
        delegated = self._compiler(delegated=True)
        self.Grant.objects.create(user=self.alice, document=self.doc_b, permission=self.read)
        self.Share.objects.create(delegate=self.bob, sponsor=self.alice, document=self.doc_b)
        built_delegated = built_catalog(delegated)
        seen2 = []

        class _Visitor2(object):

            def visit(self, question):
                seen2.append(question)
                return question.name
        built_delegated.walk_questions(_Visitor2())
        by_name = {q.name: q for q in seen2}
        self.assertEqual(len(by_name['permitted'].delegations), 1)
        self.assertTrue(by_name['has_perm'].question(self.bob, self.doc_b, self.read))

    def test_group_kind_and_empty_compiler(self):
        compiler = self._compiler(group=True)
        group = Group.objects.create(name='rq-readers')
        group.permissions.add(self.read)
        self.GroupGrant.objects.create(user=self.alice, document=self.doc_a, group=group)
        built = built_catalog(compiler)
        self.assertEqual(_pks(built.permissions_for(self.alice, self.doc_a, kind='group')), {self.read.pk})
        self.assertEqual(_pks(built.permissions_for(self.alice, self.doc_a)), {self.read.pk})
        self.assertEqual(list(built.permissions_for(self.bob, self.doc_a, kind='group')), [])
        empty_factory = Compiler(user_model=self.User)
        empty = built_catalog(empty_factory)
        self.assertFalse(empty.has_perm(self.alice, '%s.%s' % (self.read.content_type.app_label, self.read.codename), self.doc_a))
        self.assertEqual(list(empty.permissions_for(self.alice, self.doc_a)), [])
        self.assertEqual(list(empty.filter_authorized(self.Document.objects.all(), self.alice, self.read)), [])
        self.assertEqual(list(empty.permitted_users(self.doc_a, self.read)), [])
