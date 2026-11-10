"""An inherited column is read from the parent table that stores it.

Multi-table inheritance keeps the parent columns on the parent table.
A path that reaches the child and then names that column has to join
the parent link. Reading the column from the child alias is the bug.
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.support import compiler, published_class_catalog
from trusts.backends import TrustModelBackendMixin
from trusts.models import PermittedQuerySet, PermittedUsersMixin
from trusts.plan.grammar import Tree
from trusts.plan.trivalent import field_operand, grant_q, reachable_operand
from trusts.plan.via import _user_expr


class _Backend(TrustModelBackendMixin, ModelBackend):
    pass


def _add_manager(test, model):
    field = models.ForeignKey(
        'self', null=True, related_name='mti_reports',
        on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
    )
    model.add_to_class('via_manager', field)
    stored = model._meta.get_field('via_manager')
    with connection.schema_editor() as editor:
        editor.add_field(model, stored)

    def detach():
        with connection.cursor() as cursor:
            present = {
                item.name
                for item in connection.introspection.get_table_description(
                    cursor, model._meta.db_table,
                )
            }
            if stored.column in present:
                cursor.execute(
                    'ALTER TABLE %s DROP COLUMN %s' % (
                        connection.ops.quote_name(model._meta.db_table),
                        connection.ops.quote_name(stored.column),
                    )
                )
        meta = model._meta
        if stored in meta.local_fields:
            meta.local_fields.remove(stored)
        meta._expire_cache()
        if hasattr(model, stored.name):
            delattr(model, stored.name)

    test.addCleanup(detach)


def _create(editor, *model_classes):
    for model in model_classes:
        editor.create_model(model)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class InheritedColumnTests(TransactionTestCase):
    """Parent columns stay on the parent table under multi-table inheritance."""

    def test_three_paths_read_the_parent_table(self):
        class Stone(models.Model):
            pname = models.CharField(max_length=20, null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mti_stone'

        class Piece(PermittedUsersMixin, Stone):
            objects = models.Manager.from_queryset(PermittedQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mti_piece'

        class Tray(PermittedUsersMixin, models.Model):
            objects = models.Manager.from_queryset(PermittedQuerySet)()
            piece = models.ForeignKey(
                Piece, null=True, db_constraint=False,
                on_delete=models.DO_NOTHING, related_name='trays',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mti_tray'

        reverse = Stone._meta.get_field('piece')
        self.assertTrue(reverse.one_to_one)
        self.assertFalse(reverse.concrete)
        self.assertIs(Piece._meta.get_field('pname').model, Stone)

        quoted = connection.ops.quote_name
        direct = field_operand(
            Piece, ('pname',), ('alias', quoted('p')), quoted,
        )
        through_child = field_operand(
            Stone, ('piece', 'pname'), ('alias', quoted('s')), quoted,
        )
        through_fk = field_operand(
            Tray, ('piece', 'pname'), ('alias', quoted('t')), quoted,
        )
        reached = reachable_operand(
            Piece, ('pname',), ('alias', quoted('p')), quoted,
        )
        via_sql, _via_field = _user_expr(Piece, ('pname',), 'mti', quoted)
        for label, sql in (
            ('direct', direct.value_sql),
            ('reverse', through_child.value_sql),
            ('fk', through_fk.value_sql),
            ('reachable', reached.reached_sql),
            ('via', via_sql),
        ):
            self.assertIn('mti_stone', sql, label)
            self.assertNotIn('mti_piece"."pname', sql, label)
            self.assertNotIn('mti_piece`.`pname', sql, label)

        with connection.schema_editor() as editor:
            _create(editor, Stone, Piece, Tray)
        self.addCleanup(self._drop, Tray, Piece, Stone)

        kept = Piece.objects.create(pname='kept')
        other = Piece.objects.create(pname='other')
        bare = Stone.objects.create(pname='kept')
        linked = Tray.objects.create(piece=kept)
        other_tray = Tray.objects.create(piece=other)
        missing = Tray.objects.create(piece=None)

        def selected(model, path):
            node = Tree(
                'eq',
                left=Tree('field', root='object', path=path),
                right=Tree('const', value='kept'),
            )
            return set(model.objects.filter(
                grant_q(node, {'object': ('alias', model, ())}),
            ).values_list('pk', flat=True))

        self.assertEqual(selected(Piece, ('pname',)), {kept.pk})
        self.assertEqual(
            selected(Stone, ('piece', 'pname')), {kept.stone_ptr_id},
        )
        self.assertEqual(selected(Tray, ('piece', 'pname')), {linked.pk})
        self.assertNotIn(bare.pk, selected(Stone, ('piece', 'pname')))
        self.assertNotIn(other.pk, selected(Piece, ('pname',)))
        self.assertNotIn(missing.pk, selected(Tray, ('piece', 'pname')))
        self.assertNotIn(other_tray.pk, selected(Tray, ('piece', 'pname')))

    def test_entry_points_agree_including_via(self):
        User = get_user_model()
        _add_manager(self, User)

        class Stone(PermittedUsersMixin, models.Model):
            objects = models.Manager.from_queryset(PermittedQuerySet)()
            pname = models.CharField(max_length=20, null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mti_gate_stone'

        class Piece(Stone):
            objects = models.Manager.from_queryset(PermittedQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mti_gate_piece'

        class Tray(PermittedUsersMixin, models.Model):
            objects = models.Manager.from_queryset(PermittedQuerySet)()
            piece = models.ForeignKey(
                Piece, null=True, db_constraint=False,
                on_delete=models.DO_NOTHING, related_name='gate_trays',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mti_gate_tray'

        class PieceGrant(models.Model):
            piece = models.ForeignKey(Piece, on_delete=models.CASCADE)
            holder = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mti_gate_piece_grant'

        class StoneGrant(models.Model):
            stone = models.ForeignKey(Stone, on_delete=models.CASCADE)
            holder = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mti_gate_stone_grant'

        class TrayGrant(models.Model):
            tray = models.ForeignKey(Tray, on_delete=models.CASCADE)
            holder = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mti_gate_tray_grant'

        handle = compiler(path='tests.core.mti-gate')
        handle.set_user_condition(
            'open', lambda user: user.username != 'nobody',
        )
        handle.add_named_filter(
            Piece, 'kept', lambda u, p, o: o.pname == 'kept',
        )
        handle.add_named_filter(
            Stone, 'kept', lambda u, p, o: o.piece.pname == 'kept',
        )
        handle.add_named_filter(
            Tray, 'kept', lambda u, p, o: o.piece.pname == 'kept',
        )
        handle.register(
            trust=PieceGrant, user='holder', permission='permission',
            content='piece', via=('holder__via_manager', 8),
        )
        handle.register(
            trust=StoneGrant, user='holder', permission='permission',
            content='stone', via=('holder__via_manager', 8),
        )
        handle.register(
            trust=TrayGrant, user='holder', permission='permission',
            content='tray', via=('holder__via_manager', 8),
        )
        with connection.schema_editor() as editor:
            _create(
                editor, Stone, Piece, Tray, PieceGrant, StoneGrant, TrayGrant,
            )
        self.addCleanup(
            self._drop, TrayGrant, StoneGrant, PieceGrant, Tray, Piece, Stone,
        )
        kept = Piece.objects.create(pname='kept')
        other = Piece.objects.create(pname='other')
        bare = Stone.objects.create(pname='kept')
        linked = Tray.objects.create(piece=kept)
        Tray.objects.create(piece=other)
        Tray.objects.create(piece=None)
        ada = User.objects.create_user('mti-ada', password='x')
        ben = User.objects.create_user('mti-ben', password='x')
        ben.via_manager = ada
        ben.save()

        def permit(model, codename, name):
            return Permission.objects.create(
                content_type=ContentType.objects.get_for_model(model),
                codename=codename, name=name,
            )

        piece_perm = permit(Piece, 'change_mtipiece', 'Can change piece')
        stone_perm = permit(Stone, 'change_mtistone', 'Can change stone')
        tray_perm = permit(Tray, 'change_mtitray', 'Can change tray')
        PieceGrant.objects.create(
            piece=kept, holder=ada, permission=piece_perm,
        )
        PieceGrant.objects.create(
            piece=other, holder=ada, permission=piece_perm,
        )
        for stone in Stone.objects.all():
            StoneGrant.objects.create(
                stone=stone, holder=ada, permission=stone_perm,
            )
        for tray in Tray.objects.all():
            TrayGrant.objects.create(
                tray=tray, holder=ada, permission=tray_perm,
            )
        cases = (
            (Piece, 'trusts_tests.change_mtipiece', kept, True),
            (Piece, 'trusts_tests.change_mtipiece', other, False),
            (Stone, 'trusts_tests.change_mtistone', kept.stone_ptr, True),
            (Stone, 'trusts_tests.change_mtistone', other.stone_ptr, False),
            (Stone, 'trusts_tests.change_mtistone', bare, False),
            (Tray, 'trusts_tests.change_mtitray', linked, True),
        )
        with published_class_catalog(
            _Backend, handle,
        ), override_settings(
            AUTHENTICATION_BACKENDS=(
                'tests.core.test_mti_column._Backend',
            ),
        ):
            for model, code, obj, allowed in cases:
                filtered = '%s:kept' % code
                for person in (ada, ben):
                    with self.subTest(model=model.__name__, who=person.username, pk=obj.pk):
                        has = person.has_perm(filtered, obj)
                        permitted = obj.pk in set(model.objects.permitted(
                            code, person, conditions=('kept',),
                        ).values_list('pk', flat=True))
                        reached = obj.get_permitted_users(filtered).filter(
                            pk=person.pk,
                        ).exists()
                        self.assertEqual(
                            (has, permitted, reached),
                            (allowed, allowed, allowed),
                        )

    def _drop(self, *model_classes):
        with connection.schema_editor() as editor:
            for model in model_classes:
                editor.delete_model(model)
