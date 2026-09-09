from django.db import models
from django.contrib.auth.models import Group, User

from trusts.conditions import condition_refs
from trusts.context import Context
from trusts.models import Content, Junction

_u, _p, _o = condition_refs()


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


class Organization(models.Model):
    """Non-content related model for permission-condition traversal tests."""

    name = models.CharField(max_length=40, null=False, blank=False)
    manager = models.ForeignKey(
        User, null=False, blank=False, related_name='managed_organizations',
        on_delete=models.CASCADE,
    )

    def __str__(self):
        return self.name


class Ticket(Content):
    """Content model with owner / organization / status for V1 conditions."""

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
        default_permissions = ('add', 'read', 'change', 'delete')
        permission_conditions = (
            ('meta_own', _u == _o.owner),
        )

    def __str__(self):
        return self.title


class Receipt(Content):
    """Content model whose Trust is reused by dependent image/meta rows."""

    title = models.CharField(max_length=40, null=False, blank=False)

    class Meta:
        default_permissions = ('add', 'read', 'change', 'delete')

    def __str__(self):
        return self.title


class ReceiptImage(models.Model):
    """One-hop dependent content: no Trust of its own."""

    receipt = models.ForeignKey(
        Receipt, related_name='image', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    caption = models.CharField(max_length=80, null=False, blank=False, default='')

    class Meta:
        default_permissions = ('add', 'read', 'change', 'delete')

    def __str__(self):
        return self.caption


class ReceiptImageMeta(models.Model):
    """Two-hop dependent content: no Trust of its own."""

    image = models.ForeignKey(
        ReceiptImage, related_name='meta', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    note = models.CharField(max_length=80, null=False, blank=False, default='')

    class Meta:
        default_permissions = ('add', 'read', 'change', 'delete')

    def __str__(self):
        return self.note


class UnregisteredReceiptNote(models.Model):
    """Dependent row that must stay unregistered so missing lookup denies."""

    receipt = models.ForeignKey(
        Receipt, related_name='notes', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    text = models.CharField(max_length=80, null=False, blank=False, default='')

    class Meta:
        default_permissions = ('add', 'read', 'change', 'delete')


Content.register_content(
    ReceiptImage,
    Content.compose_content_fieldlookup(Receipt, 'image'),
)
Content.register_content(
    ReceiptImageMeta,
    Content.compose_content_fieldlookup(ReceiptImage, 'meta'),
)


class ContextScope(models.Model):
    """Policy scope for Context contract tests. Not a Trusts convenience."""

    title = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.title


class ContextDocument(models.Model):
    """Direct Context resource: owns a single-valued relation to its scope."""

    scope = models.ForeignKey(
        ContextScope, related_name='documents', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    title = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.title


class ContextAttachment(models.Model):
    """Related Context resource: one hop to a registered document."""

    document = models.ForeignKey(
        ContextDocument, related_name='attachments', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    caption = models.CharField(max_length=80, null=False, blank=False, default='')

    def __str__(self):
        return self.caption


class ContextAnnotation(models.Model):
    """Two-hop related Context resource."""

    attachment = models.ForeignKey(
        ContextAttachment, related_name='annotations', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    note = models.CharField(max_length=80, null=False, blank=False, default='')

    def __str__(self):
        return self.note


class ContextTrap(models.Model):
    """Direct resource whose Python getters must never run during resolution."""

    scope = models.ForeignKey(
        ContextScope, related_name='traps', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    @property
    def forbidden(self):
        raise AssertionError('Context must not execute properties')

    def get_scope(self):
        raise AssertionError('Context must not execute getters')


Context.register_direct(ContextDocument, scope_field='scope')
Context.register_related(ContextAttachment, through='document')
Context.register_related(ContextAnnotation, through='attachment')
Context.register_direct(ContextTrap, scope_field='scope')
