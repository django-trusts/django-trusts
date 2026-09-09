from django.conf import settings
from django.db import models
from django.contrib.auth.models import Group, User

from trusts.conditions import condition_refs
from trusts.context import Context
from trusts.query import AuthorizedManager
from trusts.zero.models import Content, Junction
from trusts.trustee import Trustee, TrusteeMixin

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


class TrusteeRequester(models.Model):
    """Kernel requester. Not AUTH_USER_MODEL."""

    name = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.name


class TrusteeScope(models.Model):
    """Kernel policy scope. Not a Trusts convenience."""

    title = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.title


class TrusteeOperation(models.Model):
    """Kernel operation. Not auth.Permission."""

    code = models.CharField(max_length=40, null=False, blank=False, unique=True)

    def __str__(self):
        return self.code


class TrusteeResource(models.Model):
    """Kernel resource that points at a scope."""

    scope = models.ForeignKey(
        TrusteeScope, related_name='resources', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    title = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.title


class TrusteeCollective(models.Model):
    """External collective trustee registered without inheritance."""

    name = models.CharField(max_length=40, null=False, blank=False)
    members = models.ManyToManyField(
        TrusteeRequester, related_name='collectives', blank=True,
    )
    operations = models.ManyToManyField(
        TrusteeOperation, related_name='ceiling_collectives', blank=True,
    )

    def __str__(self):
        return self.name


class TrusteeBundle(TrusteeMixin, models.Model):
    """Mixin inheritance without schema side effects. Ceiling only."""

    name = models.CharField(max_length=40, null=False, blank=False, unique=True)
    collectives = models.ManyToManyField(
        TrusteeCollective, related_name='bundles', blank=True,
    )
    operations = models.ManyToManyField(
        TrusteeOperation, related_name='bundles', blank=True,
    )

    def __str__(self):
        return self.name


class TrusteeDirectGrant(models.Model):
    """Direct requester grant on a scope."""

    scope = models.ForeignKey(
        TrusteeScope, related_name='direct_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    requester = models.ForeignKey(
        TrusteeRequester, related_name='direct_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    operation = models.ForeignKey(
        TrusteeOperation, related_name='direct_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ('scope', 'requester', 'operation')


class TrusteeCollectiveGrant(models.Model):
    """Collective grant on a scope. Constraints never create authorization."""

    scope = models.ForeignKey(
        TrusteeScope, related_name='collective_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    collective = models.ForeignKey(
        TrusteeCollective, related_name='grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    operation = models.ForeignKey(
        TrusteeOperation, related_name='collective_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ('scope', 'collective', 'operation')


class TrusteeDesk(models.Model):
    """Multi-hop membership origin: desk → collective → requester."""

    title = models.CharField(max_length=40, null=False, blank=False)
    collective = models.ForeignKey(
        TrusteeCollective, related_name='desks', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    def __str__(self):
        return self.title


class TrusteeDeskGrant(models.Model):
    scope = models.ForeignKey(
        TrusteeScope, related_name='desk_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    desk = models.ForeignKey(
        TrusteeDesk, related_name='grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    operation = models.ForeignKey(
        TrusteeOperation, related_name='desk_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )


class TrusteeTrapGrant(models.Model):
    """Grant whose Python getters must never run during resolution."""

    scope = models.ForeignKey(
        TrusteeScope, related_name='trap_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    requester = models.ForeignKey(
        TrusteeRequester, related_name='trap_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    operation = models.ForeignKey(
        TrusteeOperation, related_name='trap_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    @property
    def forbidden(self):
        raise AssertionError('Trustee must not execute properties')

    def get_requester(self):
        raise AssertionError('Trustee must not execute getters')


class UnregisteredTrusteeNote(models.Model):
    """Must stay unregistered so late registration can be rejected."""

    scope = models.ForeignKey(
        TrusteeScope, related_name='notes', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    text = models.CharField(max_length=80, null=False, blank=False, default='')


TEST_TEAM_TRUSTEE = 'team'


class TrusteeTeam(models.Model):
    """Test-only extra trustee for process-wide registry completeness."""

    name = models.CharField(max_length=40, null=False, blank=False)
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL, related_name='trustee_teams', blank=True,
    )

    def __str__(self):
        return self.name


class TrusteeTeamGrant(models.Model):
    """Scoped grant for the test-only extra trustee adapter."""

    trust = models.ForeignKey(
        'trusts.Trust', related_name='trustee_team_grants',
        null=False, blank=False, on_delete=models.CASCADE,
    )
    team = models.ForeignKey(
        TrusteeTeam, related_name='grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    permission = models.ForeignKey(
        'auth.Permission', related_name='trustee_team_grants',
        null=False, blank=False, on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ('trust', 'team', 'permission')


def sync_test_team_trustee_adapter():
    """Register the extra test trustee on the process-wide map."""
    Trustee.register(
        name=TEST_TEAM_TRUSTEE,
        trustee_model=TrusteeTeam,
        grant_model=TrusteeTeamGrant,
        trustee_path='team',
        scope_path='trust',
        operation_path='permission',
        membership_path='members',
    )


Trustee.add_finalizer(sync_test_team_trustee_adapter)


class S1Account(models.Model):
    """S1 requester. No Django auth flags (attribute protocol ignores missing)."""

    name = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.name


class S1Organization(models.Model):
    """S1 alignment terminal. Not a requester."""

    name = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.name


class S1Team(models.Model):
    """S1 collective. ``organization`` is nullable so NULL alignment can deny."""

    organization = models.ForeignKey(
        S1Organization, related_name='teams', null=True, blank=True,
        on_delete=models.CASCADE,
    )
    name = models.CharField(max_length=40, null=False, blank=False)
    members = models.ManyToManyField(
        S1Account, related_name='teams', blank=True,
    )

    def __str__(self):
        return self.name


class S1Operation(models.Model):
    """S1 operation with unique ``code`` for ``operation_lookup``."""

    code = models.CharField(max_length=40, null=False, blank=False, unique=True)

    def __str__(self):
        return self.code


class S1Bundle(models.Model):
    """Operation ceiling. Constraints never create a grant."""

    team = models.ForeignKey(
        S1Team, related_name='bundles', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    name = models.CharField(max_length=40, null=False, blank=False)
    operations = models.ManyToManyField(
        S1Operation, related_name='bundles', blank=True,
    )

    def __str__(self):
        return self.name


class S1Repository(models.Model):
    """Identity resource and Trustee scope. ``organization`` may be NULL."""

    organization = models.ForeignKey(
        S1Organization, related_name='repositories', null=True, blank=True,
        on_delete=models.CASCADE,
    )
    title = models.CharField(max_length=40, null=False, blank=False)

    objects = AuthorizedManager()

    def __str__(self):
        return self.title


class S1Issue(models.Model):
    """Related Context resource through an identity-registered repository."""

    repository = models.ForeignKey(
        S1Repository, related_name='issues', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    title = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.title


class S1TeamGrant(models.Model):
    """Team → repository grant. Alignment compares team and repository orgs."""

    team = models.ForeignKey(
        S1Team, related_name='repo_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    repository = models.ForeignKey(
        S1Repository, related_name='team_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    operation = models.ForeignKey(
        S1Operation, related_name='team_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ('team', 'repository', 'operation')


class S1DirectGrant(models.Model):
    """Direct account → repository grant. No alignment_paths."""

    account = models.ForeignKey(
        S1Account, related_name='repo_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    repository = models.ForeignKey(
        S1Repository, related_name='direct_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    operation = models.ForeignKey(
        S1Operation, related_name='direct_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ('account', 'repository', 'operation')


class S1TrapGrant(models.Model):
    """Grant whose Python getters must never run during S1 resolution."""

    team = models.ForeignKey(
        S1Team, related_name='trap_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    repository = models.ForeignKey(
        S1Repository, related_name='trap_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    operation = models.ForeignKey(
        S1Operation, related_name='trap_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    @property
    def forbidden(self):
        raise AssertionError('S1 kernel must not execute properties')

    def get_team(self):
        raise AssertionError('S1 kernel must not execute getters')


class S1UnregisteredNote(models.Model):
    """Must stay unregistered so missing compose fails closed."""

    repository = models.ForeignKey(
        S1Repository, related_name='notes', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    text = models.CharField(max_length=80, null=False, blank=False, default='')
