"""Test-only fixtures and helpers. Not part of the installable trusts package."""

import uuid

from django.conf import settings
from django.contrib.auth.models import Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command

from trusts.zero.models import Trust, TrustGroup
from tests.models import Category, TestGroupJunction


def create_test_users(test):
    # Create a user.
    test.username = 'daniel'
    test.password = 'pass'
    test.user = User.objects.create_user(test.username, 'daniel@example.com', test.password)
    test.user.is_active = True
    test.user.save()

    # Create another
    test.name1 = 'anotheruser'
    test.pass1 = 'pass'
    test.user1 = User.objects.create_user(test.name1, 'another@example.com', test.pass1)
    test.user1.is_active = True
    test.user1.save()

def get_or_create_root_user(test):
    # Create a user.

    pk = getattr(settings, 'TRUSTS_ROOT_SETTLOR', 1)
    test.user_root, created = User.objects.get_or_create(pk=pk)

def reload_test_users(self):
    # reloading user to purge the _trust_perm_cache
    self.user_root = User._default_manager.get(pk=self.user_root.pk)
    self.user = User._default_manager.get(pk=self.user.pk)
    self.user1 = User._default_manager.get(pk=self.user1.pk)


def enable_local_group_grant(trust, group, *permissions):
    """Associate ``group`` with ``trust`` and enable the given local grants.

    Each permission must already be in the group's global ceiling
    (``Group.permissions`` or a role assigned to the group).
    """
    trust.groups.add(group)
    tg = TrustGroup.objects.get(trust=trust, group=group)
    for perm in permissions:
        tg.grant_permission(perm)
    return tg


class ContentModel(object):
    def create_test_fixtures(self):
        self.group = Group(name="Test Group")
        self.group.save()

    def get_perm_code(self, perm):
        return '%s.%s' % (
            perm.content_type.app_label, perm.codename
         )

    def set_perms(self):
        for codename in ['change', 'add', 'delete', 'read']:
            setattr(self, 'perm_%s' % codename,
                Permission.objects.get_by_natural_key('%s_%s' % (codename, self.model_name), self.app_label, self.model_name)
            )

    def setUp(self):
        super(ContentModel, self).setUp()

        get_or_create_root_user(self)

        call_command('create_trust_root')

        create_test_users(self)

        self.create_test_fixtures()

        content_model = self.content_model if hasattr(self, 'content_model') else self.model
        self.app_label = content_model._meta.app_label
        self.model_name = content_model._meta.model_name

        # Junction content_roles reference extra Group permissions.
        group_ct = ContentType.objects.get_for_model(Group)
        Permission.objects.get_or_create(codename='read_group', content_type=group_ct)
        Permission.objects.get_or_create(codename='add_topic_to_group', content_type=group_ct)

        self.set_perms()


class ContentModelMixin(ContentModel):
    def setUp(self):
        self.model = Category
        self._original_roles = tuple(Category._meta.roles)
        super(ContentModelMixin, self).setUp()

    def tearDown(self):
        Category._meta.roles = self._original_roles
        super(ContentModelMixin, self).tearDown()

    def create_content(self, trust):
        content = self.model(trust=trust, name='category-%s' % uuid.uuid4())
        content.save()
        return content

    def append_model_roles(self, rolename, perms):
        self.model._meta.roles += ((rolename, perms, ), )

    def remove_model_roles(self, rolename):
        self.model._meta.roles = [row for row in self.model._meta.roles if row[0] != rolename]

    def get_model_roles(self):
        return self.model._meta.roles


class JunctionModelMixin(ContentModel):
    def setUp(self):
        self.model = TestGroupJunction
        self.content_model = Group
        self._original_roles = tuple(TestGroupJunction._meta.content_roles)

        ctype = ContentType.objects.get_for_model(Group)
        Permission.objects.get_or_create(codename='read_group', content_type=ctype)
        Permission.objects.get_or_create(codename='add_topic_to_group', content_type=ctype)

        super(JunctionModelMixin, self).setUp()

    def tearDown(self):
        TestGroupJunction._meta.content_roles = self._original_roles
        super(JunctionModelMixin, self).tearDown()

    def append_model_roles(self, rolename, perms):
        self.model._meta.content_roles += ((rolename, perms, ), )

    def remove_model_roles(self, rolename):
        self.model._meta.content_roles = [row for row in self.model._meta.content_roles if row[0] != rolename]

    def get_model_roles(self):
        return self.model._meta.content_roles

    def create_content(self, trust):
        content = self.content_model(name=str(uuid.uuid4()))
        content.save()

        junction = self.model(content=content, trust=trust, name='junction-%s' % content.pk)
        junction.save()

        return content


class TrustAsContentMixin(ContentModel):
    serialized_rollback = True
    count = 0

    def setUp(self):
        self.model = Trust
        self.content_model = Trust

        super(TrustAsContentMixin, self).setUp()

    def create_content(self, trust):
        self.count += 1
        content = Trust(title='Test Trust as Content %s' % self.count, trust=trust)
        content.save()
        return content
