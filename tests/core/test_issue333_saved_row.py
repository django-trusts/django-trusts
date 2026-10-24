"""#333: get_permitted_users reads object fields from the saved row.

``u == o.project.owner`` and a two-hop path agree with ``has_perm`` and
with a Python oracle. A never-saved object raises before SQL.
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from trusts.apps import Recorder
from trusts.backends import TrustModelBackendMixin
from trusts.conditions import PermissionConditionError
from trusts.models import PermittedQuerySet, PermittedUsersMixin
from tests.support import compiler, published_class_catalog

PERM = 'trusts_tests.change_savednote'
BACKEND = 'tests.core.test_issue333_saved_row._SavedBackend'


class _SavedBackend(TrustModelBackendMixin, ModelBackend):
    pass


def _owner_id(row):
    project = row.project
    if project is None:
        return None
    return project.owner_id


def _lead_id(row):
    project = row.project
    if project is None or project.team_id is None:
        return None
    return project.team.lead_id


def _saved_models():
    User = get_user_model()

    class SavedTeam(models.Model):
        lead = models.ForeignKey(
            User, null=True, on_delete=models.CASCADE, related_name='+',
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_saved_team'

    class SavedProject(models.Model):
        owner = models.ForeignKey(
            User, null=True, on_delete=models.CASCADE, related_name='+',
        )
        team = models.ForeignKey(
            SavedTeam, null=True, on_delete=models.CASCADE, related_name='+',
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_saved_project'

    class SavedNote(PermittedUsersMixin, models.Model):
        owner = models.ForeignKey(
            User, null=True, on_delete=models.CASCADE, related_name='+',
        )
        project = models.ForeignKey(
            SavedProject, null=True, on_delete=models.CASCADE, related_name='+',
        )
        objects = models.Manager.from_queryset(PermittedQuerySet)()

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_saved_note'

    class SavedGrant(models.Model):
        note = models.ForeignKey(SavedNote, on_delete=models.CASCADE)
        user = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_saved_grant'

    return SavedTeam, SavedProject, SavedNote, SavedGrant


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class SavedRowPermittedUsersTest(TransactionTestCase):
    """Hops follow the saved row, in one statement, or the object is unsaved."""

    def test_hops_agree_and_unsaved_object_raises(self):
        User = get_user_model()
        SavedTeam, SavedProject, SavedNote, SavedGrant = _saved_models()
        filters = {
            'owner': (
                lambda u, p, o: u == o.project.owner,
                lambda user, row: _owner_id(row) == user.pk,
            ),
            'lead': (
                lambda u, p, o: u == o.project.team.lead,
                lambda user, row: _lead_id(row) == user.pk,
            ),
            'direct': (
                lambda u, p, o: u == o.owner,
                lambda user, row: row.owner_id == user.pk,
            ),
        }
        with connection.schema_editor() as editor:
            for model in (SavedTeam, SavedProject, SavedNote, SavedGrant):
                editor.create_model(model)
        try:
            recorder = Recorder()
            recorder.register(
                trust=SavedGrant, user='user', permission='permission',
                content='note',
            )
            for code, (builder, _allowed) in filters.items():
                recorder.add_named_filter(SavedNote, code, builder)
            recorder.freeze()
            factory = compiler(path=BACKEND)
            recorder.play(factory.get_recorder_target())
            with published_class_catalog(
                _SavedBackend, factory,
            ), override_settings(AUTHENTICATION_BACKENDS=(BACKEND,)):
                alice = User.objects.create_user('alice-saved', password='x')
                bob = User.objects.create_user('bob-saved', password='x')
                change = Permission.objects.get_or_create(
                    content_type=ContentType.objects.get_for_model(SavedNote),
                    codename='change_savednote',
                    defaults={'name': 'Can change saved note'},
                )[0]
                owned = SavedProject.objects.create(
                    owner=alice,
                    team=SavedTeam.objects.create(lead=alice),
                )
                other = SavedProject.objects.create(
                    owner=bob,
                    team=SavedTeam.objects.create(lead=bob),
                )
                no_owner = SavedProject.objects.create(
                    owner=None,
                    team=SavedTeam.objects.create(lead=alice),
                )
                no_team = SavedProject.objects.create(owner=alice, team=None)
                no_lead = SavedProject.objects.create(
                    owner=alice,
                    team=SavedTeam.objects.create(lead=None),
                )
                rows = (
                    SavedNote.objects.create(owner=alice, project=owned),
                    SavedNote.objects.create(owner=bob, project=other),
                    SavedNote.objects.create(owner=alice, project=no_owner),
                    SavedNote.objects.create(owner=bob, project=None),
                    SavedNote.objects.create(owner=alice, project=no_team),
                    SavedNote.objects.create(owner=bob, project=no_lead),
                )
                for row in rows:
                    for holder in (alice, bob):
                        SavedGrant.objects.create(
                            note=row, user=holder, permission=change,
                        )
                users = (alice, bob)
                rows = tuple(SavedNote.objects.get(pk=row.pk) for row in rows)
                for code, (_builder, allowed) in filters.items():
                    perm = '%s:%s' % (PERM, code)
                    for user in users:
                        expected = {
                            row.pk for row in rows if allowed(user, row)
                        }
                        with self.subTest(code=code, user=user.username):
                            listed = SavedNote.objects.permitted(
                                PERM, user, conditions=(code,),
                            )
                            self.assertEqual(
                                set(listed.values_list('pk', flat=True)),
                                expected,
                            )
                            held = {
                                row.pk for row in rows
                                if user.has_perm(perm, row)
                            }
                            self.assertEqual(held, expected)
                    for row in rows:
                        expected = {
                            user.pk for user in users if allowed(user, row)
                        }
                        with self.subTest(code=code, row=row.pk):
                            with self.assertNumQueries(0):
                                found = row.get_permitted_users(perm)
                            with self.assertNumQueries(1):
                                self.assertEqual(
                                    set(found.values_list('pk', flat=True)),
                                    expected,
                                )
                dirty = SavedNote.objects.get(pk=rows[0].pk)
                dirty.owner = bob
                direct = '%s:direct' % PERM
                with self.subTest(check='saved-row'):
                    with self.assertNumQueries(1):
                        found = set(
                            dirty.get_permitted_users(direct).values_list(
                                'pk', flat=True,
                            )
                        )
                    self.assertEqual(found, {alice.pk})
                unsaved = SavedNote(project=owned)
                with self.subTest(check='unsaved'):
                    with self.assertNumQueries(0):
                        with self.assertRaises(PermissionConditionError) as caught:
                            unsaved.get_permitted_users('%s:owner' % PERM)
                    self.assertEqual(str(caught.exception), 'Save the object first.')
        finally:
            with connection.schema_editor() as editor:
                for model in (SavedGrant, SavedNote, SavedProject, SavedTeam):
                    editor.delete_model(model)
