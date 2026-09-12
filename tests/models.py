from django.db import models
from django.contrib.auth.models import Group, User

from django.conf import settings


def ticket_meta_own(u, p, o):
    """Core Ticket fixture builder: principal is the ticket owner."""
    return u == o.owner

_ZERO_LISTED = any(
    entry == 'trusts.zero' or str(entry).startswith('trusts.zero')
    for entry in (getattr(settings, 'INSTALLED_APPS', ()) or ())
)

if _ZERO_LISTED:
    from trusts.zero.models import Content, Junction
else:
    Content = Junction = None


class Organization(models.Model):
    """Non-content related model for permission-condition traversal tests."""

    name = models.CharField(max_length=40, null=False, blank=False)
    manager = models.ForeignKey(
        User, null=False, blank=False, related_name='managed_organizations',
        on_delete=models.CASCADE,
    )

    class Meta:
        app_label = 'trusts_tests'

    def __str__(self):
        return self.name


if Content is not None:

    class Category(Content):
        name = models.CharField(max_length=40, null=False, blank=False)

        class Meta:
            default_permissions = ('add', 'read', 'change', 'delete')
            permissions = (
                ('add_topic_to_category', 'Add topic to a category'),
            )
            roles = (
                ('public', ('read_category', 'add_topic_to_category')),
                ('admin', ('read_category', 'add_category', 'change_category', 'add_topic_to_category')),
                ('write', ('read_category', 'change_category', 'add_topic_to_category')),
            )


    class TestGroupJunction(Junction):
        content = models.ForeignKey(Group, unique=True, null=False, blank=False, on_delete=models.CASCADE)
        name = models.CharField(max_length=40, null=False, blank=False)

        class Meta:
            content_roles = (
                ('public', ('read_group', 'add_topic_to_group')),
                ('admin', ('read_group', 'add_group', 'change_group', 'add_topic_to_group')),
                ('write', ('read_group', 'change_group', 'add_topic_to_group')),
            )


    class AutoAdminCategory(Category):
        """Proxy Content subclass opting into auto ModelAdmin registration."""

        class Meta:
            proxy = True
            auto_modeladmin = True


    class ManualAdminCategory(Category):
        """Proxy Content subclass that must stay unregistered."""

        class Meta:
            proxy = True
            auto_modeladmin = False


    class AutoAdminJunction(TestGroupJunction):
        """Proxy Junction subclass opting into auto ModelAdmin registration."""

        class Meta:
            proxy = True
            auto_modeladmin = True


class Ticket(Content if Content is not None else models.Model):
    """Content/fixture model with owner / organization / status for V1 conditions."""

    title = models.CharField(max_length=40, null=False, blank=False)
    owner = models.ForeignKey(
        User, null=False, blank=False, related_name='tickets',
        on_delete=models.CASCADE,
    )
    organization = models.ForeignKey(
        Organization, null=False, blank=False, related_name='tickets',
        on_delete=models.CASCADE,
    )
    status = models.CharField(max_length=20, null=False, blank=False, default='open')
    region = models.CharField(max_length=40, null=True, blank=True)

    class Meta:
        app_label = 'trusts_tests'
        default_permissions = ('add', 'read', 'change', 'delete')
        permission_conditions = (
            ('meta_own', ticket_meta_own),
        )

    def __str__(self):
        return self.title
