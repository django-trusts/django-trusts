"""Permitted content agrees with the forward and reverse checks (#282).

``filter_by_permitted_content`` follows the same ``along=`` walk and the
same one-level delegation as ``filter_authorized`` and
``get_permitted_users``. A prefix at the bound is listed. One step past
the bound is not. A cycle stays inside the bound. A delegate is listed
only where the delegation and the sponsor's ordinary permission both
reach the prefix.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied
from django.db import models
from django.http import HttpRequest
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.core.test_issue282 import _handle, _listed, _permission, _tables
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.core import (
    TrustsConfigurationError,
    filter_by_permitted_content,
)
from trusts.plan.aggregates import common_permissions
from trusts.decorators import authorization_required
from trusts.query import AuthorizedQuerySet, PermittedQuerySetMixin, PermittedUsersMixin


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


def _assert_lock_matches_executed(test, handle, prefix_model, content_model):
    """The lockfile statement is the SQL Django runs.

    A ``source=value`` token is that executed constant. A bare
    ``$user.id`` style token is a call input and is not compared to
    the sentinel. The SQL text is that statement broken between tokens.
    """
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from trusts.policy_lock import (
        _CALL_INPUT,
        _json_const,
        _load_policy_sql_document,
        _presented_const,
        _role_sentinel,
        render_policy_sql_bytes,
    )
    from trusts.policy_sql_format import _format_policy_sql, _tokenize_policy_sql

    document = _load_policy_sql_document(
        render_policy_sql_bytes(handles=[handle]),
    )
    test.assertEqual(document['schema_version'], 1)
    content = document['backends'][0]['contents'][0]
    label = prefix_model._meta.label
    rows = [
        row for row in content['filter_by_permitted_content']
        if row['model'] == label
    ]
    test.assertEqual(len(rows), 1)
    row = rows[0]
    record = handle.registry.plan_for(content_model).records[0]
    queryset = filter_by_permitted_content(
        prefix_model._default_manager.all(),
        _role_sentinel(record, 'user', 'default'),
        _role_sentinel(record, 'permission', 'default'),
        content=content_model,
        handles=(handle,),
    )
    recorded = []

    def wrapper(execute, sql, params, many, context):
        result = execute(sql, params, many, context)
        db_cursor = context['cursor'].cursor
        logged = connection.ops.last_executed_query(
            db_cursor, sql, () if params is None else params,
        )
        recorded.append((
            sql,
            () if params is None else tuple(params),
            logged,
        ))
        return result

    with CaptureQueriesContext(connection) as captured:
        with connection.execute_wrapper(wrapper):
            list(queryset)
    test.assertEqual(len(recorded), 1)
    test.assertEqual(len(captured.captured_queries), 1)
    raw_sql, raw_params, logged = recorded[0]
    test.assertEqual(captured.captured_queries[0]['sql'], logged)
    test.assertEqual(row['sql'], _format_policy_sql(raw_sql))
    test.assertEqual(
        [token for token, _spaced in _tokenize_policy_sql(row['sql'])],
        [token for token, _spaced in _tokenize_policy_sql(raw_sql)],
    )
    test.assertEqual(row['sql'].count('%s'), len(row['params']))
    test.assertEqual(len(row['params']), len(raw_params))
    for token, value in zip(row['params'], raw_params):
        parsed = _presented_const(token)
        if parsed is _CALL_INPUT:
            continue
        test.assertEqual(parsed, _json_const(value))
    return row


class Issue282PermittedContentSuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue282_permitted_content', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue282_permitted_content', PAIR_KERNEL_SUITE)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PermittedContentAlongAgreementTest(TransactionTestCase):
    """Cabinet → child → past, plus a two-node cycle with one step past it.

    Shape S (``parent``) walks toward children. Depth 0 is the grant's
    cabinet. Bound 1 reaches the child and not the cabinet past that.
    """

    def setUp(self):
        super().setUp()
        self.User = get_user_model()
        (
            self.Cabinet, self.Sheet, self.Grant,
        ) = self._models()
        self._table_cm = _tables(self.Cabinet, self.Sheet, self.Grant)
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        self.change = _permission(self.Sheet, 'change_sheet')
        self.alice = self.User.objects.create_user('pc-alice', password='x')
        self.outsider = self.User.objects.create_user('pc-out', password='x')
        self.root = self.Cabinet.objects.create(title='root')
        self.child = self.Cabinet.objects.create(title='child', parent=self.root)
        self.past = self.Cabinet.objects.create(title='past', parent=self.child)
        self.left = self.Cabinet.objects.create(title='left')
        self.right = self.Cabinet.objects.create(title='right', parent=self.left)
        self.left.parent = self.right
        self.left.save(update_fields=['parent'])
        self.beyond = self.Cabinet.objects.create(title='beyond', parent=self.right)
        self.side = self.Cabinet.objects.create(title='side')
        self.sheets = {}
        for cabinet in (
            self.root, self.child, self.past,
            self.left, self.right, self.beyond, self.side,
        ):
            self.sheets[cabinet.pk] = self.Sheet.objects.create(
                title=cabinet.title, cabinet=cabinet,
            )
        self.Grant.objects.create(
            user=self.alice, cabinet=self.root, permission=self.change,
        )
        self.Grant.objects.create(
            user=self.alice, cabinet=self.left, permission=self.change,
        )

    def _models(self):
        class Cabinet(models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_cabinet'

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            cabinet = models.ForeignKey(
                Cabinet, related_name='sheets', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_grant'

        return Cabinet, Sheet, Grant

    def _handle(self):
        handle = _handle('tests.core.issue282-permitted-content')
        handle.register(
            trust=self.Grant,
            user='user',
            permission='permission',
            content='cabinet__sheets',
            along=('cabinet__parent', 1),
        )
        return handle

    def _agree(self, handle, user, permission, allowed_cabinets, *,
               skip_is_active=False):
        sheets = list(self.Sheet.objects.all())
        with _listed(handle):
            authorized = set(handle.registry.filter_authorized(
                self.Sheet.objects.all(), user, permission,
                skip_is_active=skip_is_active,
            ).values_list('pk', flat=True))
            for sheet in sheets:
                permitted = set(sheet.get_permitted_users(
                    permission, skip_is_active=skip_is_active,
                ).values_list('pk', flat=True))
                self.assertEqual(
                    user.pk in permitted,
                    sheet.pk in authorized,
                    sheet.title,
                )
            listed = filter_by_permitted_content(
                self.Cabinet.objects.all(), user, permission,
                content=self.Sheet, handles=(handle,),
                skip_is_active=skip_is_active,
            )
            self.assertIsNone(listed._result_cache)
            with self.assertNumQueries(1):
                found = set(listed.values_list('pk', flat=True))
        expected = {cabinet.pk for cabinet in allowed_cabinets}
        self.assertEqual(found, expected)
        self.assertEqual(
            authorized,
            {self.sheets[cabinet.pk].pk for cabinet in allowed_cabinets},
        )
        if allowed_cabinets:
            self.assertIn('with recursive', str(listed.query).lower())
        return found

    def test_along_agrees_at_bound_one_past_and_on_a_cycle(self):
        handle = self._handle()
        self._agree(handle, self.alice, self.change, (
            self.root, self.child, self.left, self.right,
        ))
        self._agree(handle, self.outsider, self.change, ())

    def test_later_prefix_follows_the_same_walk(self):
        User = self.User

        class Folder(models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_folder'

        class Payload(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_payload'

        class Row(models.Model):
            folder = models.ForeignKey(
                Folder, related_name='rows', on_delete=models.CASCADE,
            )
            content = models.ForeignKey(
                Payload, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_row'

        class FolderGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_folder_grant'

        with _tables(Folder, Payload, Row, FolderGrant):
            handle = _handle('tests.core.issue282-permitted-content-suffix')
            handle.register(
                trust=FolderGrant,
                user='user',
                permission='permission',
                content='folder__rows__content',
                along=('folder__parent', 1),
            )
            change = _permission(Payload, 'change_payload')
            root = Folder.objects.create(title='root')
            child = Folder.objects.create(title='child', parent=root)
            past = Folder.objects.create(title='past', parent=child)
            payloads = {}
            rows = {}
            for folder in (root, child, past):
                payloads[folder.pk] = Payload.objects.create(title=folder.title)
                rows[folder.pk] = Row.objects.create(
                    folder=folder, content=payloads[folder.pk],
                )
            FolderGrant.objects.create(
                user=self.alice, folder=root, permission=change,
            )
            with _listed(handle):
                authorized = set(handle.registry.filter_authorized(
                    Payload.objects.all(), self.alice, change,
                ).values_list('pk', flat=True))
            self.assertEqual(
                authorized,
                {payloads[root.pk].pk, payloads[child.pk].pk},
            )
            folders = set(filter_by_permitted_content(
                Folder.objects.all(), self.alice, change,
                content=Payload, handles=(handle,),
            ).values_list('pk', flat=True))
            self.assertEqual(folders, {root.pk, child.pk})
            found_rows = set(filter_by_permitted_content(
                Row.objects.all(), self.alice, change,
                content=Payload, handles=(handle,),
            ).values_list('pk', flat=True))
            self.assertEqual(
                found_rows, {rows[root.pk].pk, rows[child.pk].pk},
            )

    def test_ancestor_prefix_stays_on_the_stored_row(self):
        """An ancestor of the walk site is the grant's own prefix.

        ``office__cabinets__parent`` walks cabinets. Listing offices keeps
        the office stored on the grant. A second office is not listed
        merely because the walk reaches another cabinet.
        """
        User = self.User

        class Office(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_office'

        class AncCabinet(models.Model):
            title = models.CharField(max_length=40)
            office = models.ForeignKey(
                Office, related_name='cabinets', on_delete=models.CASCADE,
            )
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_anc_cabinet'

        class AncSheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            cabinet = models.ForeignKey(
                AncCabinet, related_name='sheets', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_anc_sheet'

        class OfficeGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            office = models.ForeignKey(Office, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282s_office_grant'

        with _tables(Office, AncCabinet, AncSheet, OfficeGrant):
            handle = _handle('tests.core.issue282-permitted-content-ancestor')
            handle.register(
                trust=OfficeGrant,
                user='user',
                permission='permission',
                content='office__cabinets__sheets',
                along=('office__cabinets__parent', 1),
            )
            change = _permission(AncSheet, 'change_ancestor_sheet')
            office = Office.objects.create(title='office')
            other = Office.objects.create(title='other')
            root = AncCabinet.objects.create(title='root', office=office)
            child = AncCabinet.objects.create(
                title='child', office=other, parent=root,
            )
            past = AncCabinet.objects.create(
                title='past', office=other, parent=child,
            )
            side = AncCabinet.objects.create(title='side', office=other)
            sheets = {}
            for cabinet in (root, child, past, side):
                sheets[cabinet.pk] = AncSheet.objects.create(
                    title=cabinet.title, cabinet=cabinet,
                )
            OfficeGrant.objects.create(
                user=self.alice, office=office, permission=change,
            )
            with _listed(handle):
                authorized = set(handle.registry.filter_authorized(
                    AncSheet.objects.all(), self.alice, change,
                ).values_list('pk', flat=True))
            self.assertEqual(
                authorized,
                {sheets[root.pk].pk, sheets[child.pk].pk},
            )
            offices = set(filter_by_permitted_content(
                Office.objects.all(), self.alice, change,
                content=AncSheet, handles=(handle,),
            ).values_list('pk', flat=True))
            self.assertEqual(offices, {office.pk})
            self.assertNotIn(other.pk, offices)
            cabinets = set(filter_by_permitted_content(
                AncCabinet.objects.all(), self.alice, change,
                content=AncSheet, handles=(handle,),
            ).values_list('pk', flat=True))
            self.assertEqual(cabinets, {root.pk, child.pk})
            self.assertNotIn(past.pk, cabinets)

    def test_walked_grant_lockfile_matches_the_executed_statement(self):
        handle = self._handle()
        row = _assert_lock_matches_executed(
            self, handle, self.Cabinet, self.Sheet,
        )
        self.assertIn('WITH RECURSIVE', row['sql'])
        self.assertEqual(
            [param for param in row['params'] if param.startswith('$along_bound=')],
            ['$along_bound=1'],
        )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class DelegatedPermittedContentAgreementTest(TransactionTestCase):
    """One-level delegation on cabinets that hold sheets.

    root → child → past → beyond. Shape S walks toward children.
    """

    def setUp(self):
        super().setUp()
        self.User = get_user_model()
        (
            self.Cabinet, self.Sheet, self.Grant, self.Delegation,
        ) = self._models()
        self._table_cm = _tables(
            self.Cabinet, self.Sheet, self.Grant, self.Delegation,
        )
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        self.change = _permission(self.Sheet, 'change_sheet_deleg')
        self.sponsor = self.User.objects.create_user('d-sponsor', password='x')
        self.delegate = self.User.objects.create_user('d-delegate', password='x')
        self.second = self.User.objects.create_user('d-second', password='x')
        self.outsider = self.User.objects.create_user('d-out', password='x')
        self.root = self.Cabinet.objects.create(title='root')
        self.child = self.Cabinet.objects.create(title='child', parent=self.root)
        self.past = self.Cabinet.objects.create(title='past', parent=self.child)
        self.beyond = self.Cabinet.objects.create(title='beyond', parent=self.past)
        self.sheets = {
            cabinet.pk: self.Sheet.objects.create(
                title=cabinet.title, cabinet=cabinet,
            )
            for cabinet in (self.root, self.child, self.past, self.beyond)
        }

    def _models(self):
        class Cabinet(models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_cabinet'

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            cabinet = models.ForeignKey(
                Cabinet, related_name='sheets', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_grant'

        class Delegation(models.Model):
            delegate = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_delegation'

        return Cabinet, Sheet, Grant, Delegation

    def _register(self, *, sponsor_along=None, delegation_along=None):
        handle = _handle('tests.core.issue282-delegated-permitted-content')
        handle.register(
            trust=self.Grant,
            user='user',
            permission='permission',
            content='cabinet__sheets',
            along=sponsor_along,
        )
        handle.register(
            trust=self.Delegation,
            delegate='delegate',
            sponsor='sponsor',
            content='cabinet__sheets',
            along=delegation_along,
        )
        return handle

    def _permitted_content(self, handle, user, *, skip_is_active=False):
        return set(filter_by_permitted_content(
            self.Cabinet.objects.all(), user, self.change,
            content=self.Sheet, handles=(handle,),
            skip_is_active=skip_is_active,
        ).values_list('pk', flat=True))

    def _agree_user(self, handle, user, allowed_cabinets, *, skip_is_active=False):
        with _listed(handle):
            authorized = set(AuthorizedQuerySet(self.Sheet).authorized(
                user, self.change, skip_is_active=skip_is_active,
            ).values_list('pk', flat=True))
            for cabinet in (self.root, self.child, self.past, self.beyond):
                sheet = self.sheets[cabinet.pk]
                permitted = set(sheet.get_permitted_users(
                    self.change, skip_is_active=skip_is_active,
                ).values_list('pk', flat=True))
                self.assertEqual(
                    user.pk in permitted,
                    sheet.pk in authorized,
                    cabinet.title,
                )
        listed = self._permitted_content(handle, user, skip_is_active=skip_is_active)
        expected = {cabinet.pk for cabinet in allowed_cabinets}
        self.assertEqual(listed, expected)
        self.assertEqual(
            authorized,
            {self.sheets[cabinet.pk].pk for cabinet in allowed_cabinets},
        )

    def test_sponsor_walk_with_an_exact_delegation(self):
        handle = self._register(sponsor_along=('cabinet__parent', 1))
        self.Grant.objects.create(
            user=self.sponsor, cabinet=self.root, permission=self.change,
        )
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, cabinet=self.child,
        )
        self._agree_user(handle, self.delegate, (self.child,))
        self._agree_user(handle, self.sponsor, (self.root, self.child))
        self._agree_user(handle, self.outsider, ())

    def test_delegation_walk_with_an_exact_sponsor_grant(self):
        handle = self._register(delegation_along=('cabinet__parent', 1))
        self.Grant.objects.create(
            user=self.sponsor, cabinet=self.child, permission=self.change,
        )
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, cabinet=self.root,
        )
        self._agree_user(handle, self.delegate, (self.child,))
        self._agree_user(handle, self.sponsor, (self.child,))

    def test_both_walks_intersect(self):
        handle = self._register(
            sponsor_along=('cabinet__parent', 2),
            delegation_along=('cabinet__parent', 1),
        )
        self.Grant.objects.create(
            user=self.sponsor, cabinet=self.root, permission=self.change,
        )
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, cabinet=self.child,
        )
        self._agree_user(handle, self.delegate, (self.child, self.past))
        self._agree_user(handle, self.sponsor, (self.root, self.child, self.past))
        self.assertNotIn(self.beyond.pk, self._permitted_content(handle, self.delegate))
        self.assertNotIn(self.root.pk, self._permitted_content(handle, self.delegate))

    def test_second_delegation_level_is_denied(self):
        handle = self._register(
            sponsor_along=('cabinet__parent', 2),
            delegation_along=('cabinet__parent', 1),
        )
        self.Grant.objects.create(
            user=self.sponsor, cabinet=self.root, permission=self.change,
        )
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, cabinet=self.child,
        )
        self.Delegation.objects.create(
            delegate=self.second, sponsor=self.delegate, cabinet=self.child,
        )
        self._agree_user(handle, self.second, ())
        self._agree_user(handle, self.delegate, (self.child, self.past))

    def test_inactive_delegate_and_sponsor_keep_the_current_gate(self):
        handle = self._register(sponsor_along=('cabinet__parent', 1))
        self.Grant.objects.create(
            user=self.sponsor, cabinet=self.root, permission=self.change,
        )
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, cabinet=self.child,
        )
        self.delegate.is_active = False
        self.delegate.save(update_fields=['is_active'])
        self._agree_user(handle, self.delegate, ())
        self._agree_user(
            handle, self.delegate, (self.child,), skip_is_active=True,
        )
        self.delegate.is_active = True
        self.delegate.save(update_fields=['is_active'])
        self.sponsor.is_active = False
        self.sponsor.save(update_fields=['is_active'])
        self._agree_user(handle, self.delegate, ())
        self._agree_user(
            handle, self.delegate, (self.child,), skip_is_active=True,
        )

    def test_longer_content_suffix_fails_closed(self):
        User = self.User
        issue_model = self.Cabinet

        class Attachment(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_attachment'

        class Note(models.Model):
            cabinet = models.ForeignKey(
                issue_model, related_name='notes', on_delete=models.CASCADE,
            )
            attachment = models.ForeignKey(Attachment, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_note'

        class AttachmentGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            attachment = models.ForeignKey(Attachment, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_attachment_grant'

        class SuffixDelegation(models.Model):
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            cabinet = models.ForeignKey(issue_model, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_suffix_delegation'

        change = _permission(Attachment, 'change_attachment')
        with _tables(Attachment, Note, AttachmentGrant, SuffixDelegation):
            attachment = Attachment.objects.create(title='sheet')
            Note.objects.create(cabinet=self.child, attachment=attachment)
            AttachmentGrant.objects.create(
                user=self.sponsor, attachment=attachment, permission=change,
            )
            SuffixDelegation.objects.create(
                delegate=self.delegate, sponsor=self.sponsor, cabinet=self.child,
            )
            handle = _handle('tests.core.issue282-suffix')
            handle.register(
                trust=AttachmentGrant,
                user='user',
                permission='permission',
                content='attachment',
            )
            handle.register(
                trust=SuffixDelegation,
                delegate='delegate',
                sponsor='sponsor',
                content='cabinet__notes__attachment',
                along=('cabinet__parent', 2),
            )
            with _listed(handle):
                with self.assertRaises(TrustsConfigurationError):
                    AuthorizedQuerySet(Attachment).authorized(
                        self.delegate, change,
                    )
                with self.assertRaises(TrustsConfigurationError):
                    attachment.get_permitted_users(change)
            with self.assertRaises(TrustsConfigurationError):
                filter_by_permitted_content(
                    self.Cabinet.objects.all(), self.delegate, change,
                    content=Attachment, handles=(handle,),
                )

    def test_delegation_without_an_ordinary_grant_lists_nothing(self):
        handle = _handle('tests.core.issue282-deleg-no-grant')
        handle.register(
            trust=self.Delegation,
            delegate='delegate',
            sponsor='sponsor',
            content='cabinet__sheets',
        )
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, cabinet=self.child,
        )
        self._agree_user(handle, self.delegate, ())

    def test_delegated_ancestor_stays_on_the_stored_office(self):
        """A delegated walk does not list a neighboring ancestor.

        The delegation walks ``office__cabinets__parent``. The sponsor's
        ordinary grant is the office row itself. The listed office is
        that stored office. The child cabinet is inside the walk and
        outside the sponsor's exact grant, so it is not listed.
        """
        User = self.User

        class Office(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_office'

        class AncCabinet(models.Model):
            title = models.CharField(max_length=40)
            office = models.ForeignKey(
                Office, related_name='cabinets', on_delete=models.CASCADE,
            )
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_anc_cabinet'

        class AncSheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            cabinet = models.ForeignKey(
                AncCabinet, related_name='sheets', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_anc_sheet'

        class OfficeGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            office = models.ForeignKey(Office, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_office_grant'

        class OfficeDelegation(models.Model):
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            office = models.ForeignKey(Office, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_office_delegation'

        with _tables(
            Office, AncCabinet, AncSheet, OfficeGrant, OfficeDelegation,
        ):
            handle = _handle('tests.core.issue282-deleg-ancestor')
            handle.register(
                trust=OfficeGrant,
                user='user',
                permission='permission',
                content='office__cabinets__sheets',
            )
            handle.register(
                trust=OfficeDelegation,
                delegate='delegate',
                sponsor='sponsor',
                content='office__cabinets__sheets',
                along=('office__cabinets__parent', 1),
            )
            change = _permission(AncSheet, 'change_deleg_ancestor')
            office = Office.objects.create(title='office')
            other = Office.objects.create(title='other')
            root = AncCabinet.objects.create(title='root', office=office)
            child = AncCabinet.objects.create(
                title='child', office=other, parent=root,
            )
            side = AncCabinet.objects.create(title='side', office=other)
            sheets = {
                cabinet.pk: AncSheet.objects.create(
                    title=cabinet.title, cabinet=cabinet,
                )
                for cabinet in (root, child, side)
            }
            OfficeGrant.objects.create(
                user=self.sponsor, office=office, permission=change,
            )
            OfficeDelegation.objects.create(
                delegate=self.delegate, sponsor=self.sponsor, office=office,
            )
            with _listed(handle):
                authorized = set(AuthorizedQuerySet(AncSheet).authorized(
                    self.delegate, change,
                ).values_list('pk', flat=True))
            self.assertEqual(authorized, {sheets[root.pk].pk})
            offices = set(filter_by_permitted_content(
                Office.objects.all(), self.delegate, change,
                content=AncSheet, handles=(handle,),
            ).values_list('pk', flat=True))
            self.assertEqual(offices, {office.pk})
            self.assertNotIn(other.pk, offices)
            cabinets = set(filter_by_permitted_content(
                AncCabinet.objects.all(), self.delegate, change,
                content=AncSheet, handles=(handle,),
            ).values_list('pk', flat=True))
            self.assertEqual(cabinets, {root.pk})
            self.assertNotIn(child.pk, cabinets)

    def test_sponsor_walk_keeps_the_stored_ancestor(self):
        """An ordinary sponsor walk still lists its stored ancestor.

        The grant walks ``office__cabinets__parent``. The delegation is
        exact on that same office. The root sheet is permitted. The
        child cabinet is inside the walk and belongs to the other
        office, so that office stays out of the listing.
        """
        User = self.User

        class Office(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_spon_office'

        class WalkCabinet(models.Model):
            title = models.CharField(max_length=40)
            office = models.ForeignKey(
                Office, related_name='cabinets', on_delete=models.CASCADE,
            )
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_spon_cabinet'

        class WalkSheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            cabinet = models.ForeignKey(
                WalkCabinet, related_name='sheets', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_spon_sheet'

        class OfficeGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            office = models.ForeignKey(Office, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_spon_grant'

        class OfficeDelegation(models.Model):
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            office = models.ForeignKey(Office, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_spon_delegation'

        with _tables(
            Office, WalkCabinet, WalkSheet, OfficeGrant, OfficeDelegation,
        ):
            handle = _handle('tests.core.issue282-sponsor-ancestor')
            handle.register(
                trust=OfficeGrant,
                user='user',
                permission='permission',
                content='office__cabinets__sheets',
                along=('office__cabinets__parent', 1),
            )
            handle.register(
                trust=OfficeDelegation,
                delegate='delegate',
                sponsor='sponsor',
                content='office__cabinets__sheets',
            )
            change = _permission(WalkSheet, 'change_sponsor_ancestor')
            office = Office.objects.create(title='office')
            other = Office.objects.create(title='other')
            root = WalkCabinet.objects.create(title='root', office=office)
            child = WalkCabinet.objects.create(
                title='child', office=other, parent=root,
            )
            side = WalkCabinet.objects.create(title='side', office=other)
            sheets = {
                cabinet.pk: WalkSheet.objects.create(
                    title=cabinet.title, cabinet=cabinet,
                )
                for cabinet in (root, child, side)
            }
            OfficeGrant.objects.create(
                user=self.sponsor, office=office, permission=change,
            )
            OfficeDelegation.objects.create(
                delegate=self.delegate, sponsor=self.sponsor, office=office,
            )
            with _listed(handle):
                authorized = set(AuthorizedQuerySet(WalkSheet).authorized(
                    self.delegate, change,
                ).values_list('pk', flat=True))
                permitted = set(sheets[root.pk].get_permitted_users(
                    change,
                ).values_list('pk', flat=True))
            self.assertEqual(authorized, {sheets[root.pk].pk})
            self.assertIn(self.delegate.pk, permitted)
            offices = set(filter_by_permitted_content(
                Office.objects.all(), self.delegate, change,
                content=WalkSheet, handles=(handle,),
            ).values_list('pk', flat=True))
            self.assertEqual(offices, {office.pk})
            self.assertNotIn(other.pk, offices)
            cabinets = set(filter_by_permitted_content(
                WalkCabinet.objects.all(), self.delegate, change,
                content=WalkSheet, handles=(handle,),
            ).values_list('pk', flat=True))
            self.assertEqual(cabinets, {root.pk})
            both = _handle('tests.core.issue282-sponsor-ancestor-both')
            both.register(
                trust=OfficeGrant,
                user='user',
                permission='permission',
                content='office__cabinets__sheets',
                along=('office__cabinets__parent', 1),
            )
            both.register(
                trust=OfficeDelegation,
                delegate='delegate',
                sponsor='sponsor',
                content='office__cabinets__sheets',
                along=('office__cabinets__parent', 1),
            )
            with _listed(both):
                both_sheets = set(AuthorizedQuerySet(WalkSheet).authorized(
                    self.delegate, change,
                ).values_list('pk', flat=True))
            self.assertEqual(
                both_sheets,
                {sheets[root.pk].pk, sheets[child.pk].pk},
            )
            both_offices = set(filter_by_permitted_content(
                Office.objects.all(), self.delegate, change,
                content=WalkSheet, handles=(both,),
            ).values_list('pk', flat=True))
            self.assertEqual(both_offices, {office.pk})
            self.assertNotIn(other.pk, both_offices)

    def test_sponsor_walk_with_a_longer_suffix_fails_closed(self):
        """A later prefix is not a supported delegated sponsor walk.

        ``folder__rows__content`` leaves two hops after ``folder``. The
        forward check raises. Listing the folder and the row raises the
        same ``TrustsConfigurationError`` instead of returning an empty
        queryset.
        """
        User = self.User

        class Folder(models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_later_folder'

        class Payload(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_later_payload'

        class Row(models.Model):
            folder = models.ForeignKey(
                Folder, related_name='rows', on_delete=models.CASCADE,
            )
            content = models.ForeignKey(Payload, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_later_row'

        class FolderGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_later_grant'

        class FolderDelegation(models.Model):
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282d_later_delegation'

        with _tables(Folder, Payload, Row, FolderGrant, FolderDelegation):
            handle = _handle('tests.core.issue282-sponsor-later')
            handle.register(
                trust=FolderGrant,
                user='user',
                permission='permission',
                content='folder__rows__content',
                along=('folder__parent', 1),
            )
            handle.register(
                trust=FolderDelegation,
                delegate='delegate',
                sponsor='sponsor',
                content='folder__rows__content',
            )
            change = _permission(Payload, 'change_sponsor_later')
            root = Folder.objects.create(title='root')
            child = Folder.objects.create(title='child', parent=root)
            payload = Payload.objects.create(title='child')
            Row.objects.create(folder=child, content=payload)
            FolderGrant.objects.create(
                user=self.sponsor, folder=root, permission=change,
            )
            FolderDelegation.objects.create(
                delegate=self.delegate, sponsor=self.sponsor, folder=child,
            )
            with _listed(handle):
                with self.assertRaises(TrustsConfigurationError):
                    list(AuthorizedQuerySet(Payload).authorized(
                        self.delegate, change,
                    ))
            for model in (Folder, Row):
                with self.assertRaises(TrustsConfigurationError):
                    filter_by_permitted_content(
                        model.objects.all(), self.delegate, change,
                        content=Payload, handles=(handle,),
                    )

    def test_delegated_grant_lockfile_matches_the_executed_statement(self):
        handle = self._register(sponsor_along=('cabinet__parent', 1))
        row = _assert_lock_matches_executed(
            self, handle, self.Cabinet, self.Sheet,
        )
        self.assertIn('WITH RECURSIVE', row['sql'])
        self.assertIn('i282d_delegation', row['sql'])
        bounds = [
            param for param in row['params']
            if param.startswith('$along_bound=')
        ]
        self.assertEqual(bounds, ['$along_bound=1'])


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongSurfaceAgreementTest(TransactionTestCase):
    """``common_permissions``, ``authorization_required``, and Trust content.

    The protected object is a Trust. ``along=`` walks ``parent`` with
    bound 1, so the child trust is permitted and the trust past that
    child is not.
    """

    def setUp(self):
        super().setUp()
        self.User = get_user_model()

        class TrustQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Trust(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(TrustQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282t_trust'

        class TrustGrant(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            trust = models.ForeignKey(Trust, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'i282t_grant'

        self.Trust = Trust
        self.TrustGrant = TrustGrant
        self._table_cm = _tables(Trust, TrustGrant)
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        self.change = _permission(Trust, 'change_trust')
        self.code = 'trusts_tests.change_trust'
        self.alice = self.User.objects.create_user('t-alice', password='x')
        self.root = Trust.objects.create(title='root')
        self.child = Trust.objects.create(title='child', parent=self.root)
        self.past = Trust.objects.create(title='past', parent=self.child)
        TrustGrant.objects.create(
            user=self.alice, trust=self.root, permission=self.change,
        )
        self.handle = _handle('tests.core.issue282-trust-content')
        self.handle.register(
            trust=TrustGrant,
            user='user',
            permission='permission',
            content='trust',
            along=('trust__parent', 1),
        )

    def test_common_permissions_respects_the_bound(self):
        child_only = self.Trust.objects.filter(pk=self.child.pk)
        past_only = self.Trust.objects.filter(pk=self.past.pk)
        mixed = self.Trust.objects.filter(pk__in=[self.child.pk, self.past.pk])
        self.assertEqual(
            set(common_permissions(
                (self.handle,), child_only, self.alice,
            ).values_list('pk', flat=True)),
            {self.change.pk},
        )
        self.assertEqual(
            list(common_permissions((self.handle,), past_only, self.alice)),
            [],
        )
        self.assertEqual(
            list(common_permissions((self.handle,), mixed, self.alice)),
            [],
        )

    def test_authorization_required_respects_the_bound(self):
        @authorization_required(self.Trust, self.code)
        def view(request, pk):
            return 'ok'

        with _listed(self.handle):
            self.assertEqual(
                view(_request(self.alice), pk=self.child.pk), 'ok',
            )
            with self.assertRaises(PermissionDenied):
                view(_request(self.alice), pk=self.past.pk)

    def test_trust_content_follows_along(self):
        found = set(self.handle.registry.filter_authorized(
            self.Trust.objects.all(), self.alice, self.change,
        ).values_list('pk', flat=True))
        self.assertEqual(found, {self.root.pk, self.child.pk})
        with _listed(self.handle):
            child_users = set(self.child.get_permitted_users(
                self.change,
            ).values_list('pk', flat=True))
            past_users = set(self.past.get_permitted_users(
                self.change,
            ).values_list('pk', flat=True))
        self.assertIn(self.alice.pk, child_users)
        self.assertNotIn(self.alice.pk, past_users)
