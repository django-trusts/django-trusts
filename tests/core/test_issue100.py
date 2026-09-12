"""Bounded ordered remaining-bits strategy (issue #100).

Closed ``register_strategy(OrderedFold)`` beside unchanged AnyPath.
Registration and system-check proofs are zero SQL. Runtime fold proofs
require PostgreSQL and skip on other vendors.
"""

from contextlib import contextmanager
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.apps import isolate_live_registry, live_config
from trusts.backends import TrustModelBackendMixin
from trusts.checks import CHECK_ID_ORDERED_FOLD_RENDERER, check_ordered_fold_renderer
from trusts.core import (
    BackendHandle,
    FlatToken,
    MaskEntry,
    OrderedFold,
    OrderedFoldAllowed,
    PermissionMaskDomain,
    PlanQueryCompiler,
    PolarityMap,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    all_match,
    filter_authorized_scopes,
)
from trusts.query import AuthorizedManager, is_active_principal


ALLOW = 1
DENY = 2


def _postgres():
    return connection.vendor == 'postgresql'


@contextmanager
def _tables(*model_classes):
    with connection.schema_editor() as editor:
        for model in model_classes:
            editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            for model in reversed(model_classes):
                editor.delete_model(model)


def _direct_models(*, suffix='', mask_cls=models.BigIntegerField,
                   order_null=False, mask_null=False, polarity_null=False,
                   trustee_null=False):
    User = get_user_model()

    Permission = type('Permission%s' % suffix, (models.Model,), {
        '__module__': __name__,
        'codename': models.CharField(max_length=64),
        'Meta': type('Meta', (), {'app_label': 'trusts_tests'}),
    })
    Document = type('Document%s' % suffix, (models.Model,), {
        '__module__': __name__,
        'title': models.CharField(max_length=40),
        'objects': AuthorizedManager(),
        'Meta': type('Meta', (), {'app_label': 'trusts_tests'}),
    })
    Ace = type('Ace%s' % suffix, (models.Model,), {
        '__module__': __name__,
        'document': models.ForeignKey(Document, on_delete=models.CASCADE),
        'ace_order': models.IntegerField(null=order_null),
        'ace_type': models.IntegerField(null=polarity_null),
        'access_mask': mask_cls(**({'null': True} if mask_null else {})),
        'user': models.ForeignKey(
            User, null=trustee_null, on_delete=models.CASCADE,
        ),
        'Meta': type('Meta', (), {'app_label': 'trusts_tests'}),
    })
    return Permission, Document, Ace


def _register_direct(registry, Ace, Permission, Document, *, masks=None):
    if masks is None:
        masks = (
            MaskEntry('read', 0x1),
            MaskEntry('write', 0x2),
            MaskEntry('readwrite', 0x3),
        )
    ace = Ref(Ace)
    doc = Ref(Document)
    user = Ref(get_user_model())
    return registry.register_strategy(OrderedFold(
        content=doc,
        descriptor=doc,
        source=ace,
        source_descriptor=ace.document,
        order=ace.ace_order,
        polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
        mask=ace.access_mask,
        trustee=ace.user,
        token=FlatToken(
            principal=user, principal_user=user, principal_identity=user,
        ),
        domain=PermissionMaskDomain(Permission, masks),
    ))


def _perm(Permission, action, document_model):
    return Permission.objects.create(
        codename='%s_%s' % (action, document_model._meta.model_name),
    )


def _handles(registry):
    return (BackendHandle(
        path='issue100',
        registry=registry,
        compiler=PlanQueryCompiler(),
    ),)


def _pks(rows):
    return {row.pk for row in rows}


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class OrderedFoldRegistrationTest(SimpleTestCase):
    def test_core_exports_closed_strategy_types(self):
        import trusts.core as core

        self.assertTrue(hasattr(core, 'OrderedFold'))
        self.assertTrue(hasattr(core, 'PermissionMaskDomain'))
        self.assertTrue(hasattr(core, 'MaskEntry'))
        self.assertTrue(hasattr(core, 'PolarityMap'))
        self.assertTrue(hasattr(core, 'FlatToken'))
        self.assertIs(OrderedFold, core.OrderedFold)

    def test_direct_token_registers_with_zero_sql(self):
        Permission, Document, Ace = _direct_models()
        registry = TrustsRegistry()
        compiled = _register_direct(registry, Ace, Permission, Document)
        self.assertEqual(len(registry.strategies), 1)
        self.assertEqual(registry.records, ())
        self.assertIs(compiled.content_model, Document)
        self.assertIs(compiled.permission_model, Permission)
        self.assertEqual(compiled.identity_attname, get_user_model()._meta.pk.attname)
        self.assertTrue(compiled.principal_is_user)
        self.assertFalse(compiled.has_content_type)

    def test_canonical_content_type_pk_permission_registers(self):
        User = get_user_model()

        class Permission(models.Model):
            codename = models.CharField(max_length=64)
            content_type = models.ForeignKey(
                ContentType, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()
            user = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        ace = Ref(Ace)
        doc = Ref(Document)
        user = Ref(User)
        compiled = registry.register_strategy(OrderedFold(
            content=doc,
            descriptor=doc,
            source=ace,
            source_descriptor=ace.document,
            order=ace.ace_order,
            polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
            mask=ace.access_mask,
            trustee=ace.user,
            token=FlatToken(
                principal=user, principal_user=user, principal_identity=user,
            ),
            domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
        ))
        self.assertTrue(compiled.has_content_type)

    def test_unrelated_content_type_fk_rejected(self):
        User = get_user_model()

        class Other(models.Model):
            name = models.CharField(max_length=16)

            class Meta:
                app_label = 'trusts_tests'

        class Permission(models.Model):
            codename = models.CharField(max_length=64)
            content_type = models.ForeignKey(Other, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()
            user = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        ace = Ref(Ace)
        doc = Ref(Document)
        user = Ref(User)
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'content_type.*ContentType',
        ):
            registry.register_strategy(OrderedFold(
                content=doc,
                descriptor=doc,
                source=ace,
                source_descriptor=ace.document,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
                mask=ace.access_mask,
                trustee=ace.user,
                token=FlatToken(
                    principal=user, principal_user=user, principal_identity=user,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertEqual(registry.strategies, ())

    def test_content_type_non_pk_to_field_rejected(self):
        User = get_user_model()

        class Permission(models.Model):
            codename = models.CharField(max_length=64)
            ct_key = models.CharField(max_length=100)
            content_type = models.ForeignObject(
                ContentType,
                from_fields=['ct_key'],
                to_fields=['app_label'],
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()
            user = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        ace = Ref(Ace)
        doc = Ref(Document)
        user = Ref(User)
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'content_type.*ContentType',
        ):
            registry.register_strategy(OrderedFold(
                content=doc,
                descriptor=doc,
                source=ace,
                source_descriptor=ace.document,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
                mask=ace.access_mask,
                trustee=ace.user,
                token=FlatToken(
                    principal=user, principal_user=user, principal_identity=user,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertEqual(registry.strategies, ())

    def test_virtual_content_type_foreignobject_to_pk_rejected(self):
        User = get_user_model()

        class Permission(models.Model):
            codename = models.CharField(max_length=64)
            ct_key = models.IntegerField()
            content_type = models.ForeignObject(
                ContentType,
                from_fields=['ct_key'],
                to_fields=['id'],
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()
            user = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        ace = Ref(Ace)
        doc = Ref(Document)
        user = Ref(User)
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'concrete single-column',
        ):
            registry.register_strategy(OrderedFold(
                content=doc,
                descriptor=doc,
                source=ace,
                source_descriptor=ace.document,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
                mask=ace.access_mask,
                trustee=ace.user,
                token=FlatToken(
                    principal=user, principal_user=user, principal_identity=user,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertEqual(registry.strategies, ())

    def test_frozen_raises_before_strategy_validation(self):
        Permission, Document, Ace = _direct_models()
        registry = TrustsRegistry()
        registry.freeze()
        with self.assertRaisesRegex(TrustsConfigurationError, r'frozen'):
            _register_direct(registry, Ace, Permission, Document)
        self.assertEqual(registry.strategies, ())

    def test_anypath_xor_orderedfold_rejects_with_zero_sql(self):
        Permission, Document, Ace = _direct_models()
        User = get_user_model()

        class Grant(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        g = Ref(Grant)
        registry.register(content=g.document, user=g.user, permission=g.permission)
        stored = registry.records
        with self.assertRaisesRegex(TrustsConfigurationError, r'AnyPath'):
            _register_direct(registry, Ace, Permission, Document)
        self.assertEqual(registry.records, stored)
        self.assertEqual(registry.strategies, ())

        other = TrustsRegistry()
        _register_direct(other, Ace, Permission, Document)
        with self.assertRaisesRegex(TrustsConfigurationError, r'OrderedFold'):
            other.register(content=g.document, user=g.user, permission=g.permission)
        self.assertEqual(len(other.strategies), 1)
        self.assertEqual(other.records, ())

    def test_two_orderedfold_on_one_terminal_rejected(self):
        Permission, Document, Ace = _direct_models()
        registry = TrustsRegistry()
        _register_direct(registry, Ace, Permission, Document)
        with self.assertRaisesRegex(TrustsConfigurationError, r'Conflicting OrderedFold'):
            _register_direct(registry, Ace, Permission, Document)
        self.assertEqual(len(registry.strategies), 1)

    def test_nullable_configured_fields_rejected(self):
        cases = (
            dict(suffix='Order', order_null=True),
            dict(suffix='Mask', mask_null=True),
            dict(suffix='Polarity', polarity_null=True),
            dict(suffix='Trustee', trustee_null=True),
        )
        for kwargs in cases:
            Permission, Document, Ace = _direct_models(**kwargs)
            registry = TrustsRegistry()
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'non-null|nullable',
            ):
                _register_direct(registry, Ace, Permission, Document)
            self.assertEqual(registry.strategies, ())

    def test_partial_member_triad_rejected(self):
        Permission, Document, Ace = _direct_models()
        User = get_user_model()

        class Membership(models.Model):
            member = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
            group = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        ace = Ref(Ace)
        doc = Ref(Document)
        user = Ref(User)
        member = Ref(Membership)
        registry = TrustsRegistry()
        with self.assertRaisesRegex(TrustsConfigurationError, r'member triad'):
            registry.register_strategy(OrderedFold(
                content=doc,
                descriptor=doc,
                source=ace,
                source_descriptor=ace.document,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
                mask=ace.access_mask,
                trustee=ace.user,
                token=FlatToken(
                    principal=user, principal_user=user, principal_identity=user,
                    member=member,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertEqual(registry.strategies, ())

    def test_cross_to_field_token_rejected(self):
        User = get_user_model()

        class Identity(models.Model):
            code = models.CharField(max_length=8, unique=True)
            slug = models.SlugField(unique=True)

            class Meta:
                app_label = 'trusts_tests'

        class Permission(models.Model):
            codename = models.CharField(max_length=64)

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()
            trustee = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Principal(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            identity = models.ForeignKey(
                Identity, to_field='slug', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        ace = Ref(Ace)
        doc = Ref(Document)
        principal = Ref(Principal)
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'resolved comparison field',
        ):
            registry.register_strategy(OrderedFold(
                content=doc,
                descriptor=doc,
                source=ace,
                source_descriptor=ace.document,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
                mask=ace.access_mask,
                trustee=ace.trustee,
                token=FlatToken(
                    principal=principal,
                    principal_user=principal.user,
                    principal_identity=principal.identity,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertEqual(registry.strategies, ())

    def test_multi_hop_source_and_token_paths_store_full_chains(self):
        User = get_user_model()

        class Identity(models.Model):
            code = models.CharField(max_length=16, unique=True)

            class Meta:
                app_label = 'trusts_tests'

        class Permission(models.Model):
            codename = models.CharField(max_length=64)

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Wrapper(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Holder(models.Model):
            identity = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            wrapper = models.ForeignKey(Wrapper, on_delete=models.CASCADE)
            holder = models.ForeignKey(Holder, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()

            class Meta:
                app_label = 'trusts_tests'

        class Profile(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Card(models.Model):
            identity = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Principal(models.Model):
            profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
            card = models.ForeignKey(Card, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Person(models.Model):
            identity = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Team(models.Model):
            identity = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Membership(models.Model):
            person = models.ForeignKey(Person, on_delete=models.CASCADE)
            group = models.ForeignKey(Team, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        ace = Ref(Ace)
        document = Ref(Document)
        principal = Ref(Principal)
        member = Ref(Membership)
        compiled = registry.register_strategy(OrderedFold(
            content=document,
            descriptor=document,
            source=ace,
            source_descriptor=ace.wrapper.document,
            order=ace.ace_order,
            polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
            mask=ace.access_mask,
            trustee=ace.holder.identity,
            token=FlatToken(
                principal=principal,
                principal_user=principal.profile.user,
                principal_identity=principal.card.identity,
                member=member,
                member_identity=member.person.identity,
                member_group=member.group.identity,
            ),
            domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
        ))
        self.assertGreater(len(compiled.source_desc_hops), 1)
        self.assertGreater(len(compiled.trustee_hops), 1)
        self.assertGreater(len(compiled.principal_user_hops), 1)
        self.assertGreater(len(compiled.principal_identity_hops), 1)
        self.assertGreater(len(compiled.member_identity_hops), 1)
        self.assertGreater(len(compiled.member_group_hops), 1)
        self.assertEqual(compiled.identity_attname, 'code')
        self.assertEqual(compiled.source_desc_hops[-1].attname, 'document_id')
        self.assertEqual(compiled.trustee_hops[-1].attname, 'identity_id')

    def test_matching_non_pk_to_field_registers(self):
        User = get_user_model()

        class Identity(models.Model):
            code = models.CharField(max_length=8, unique=True)

            class Meta:
                app_label = 'trusts_tests'

        class Permission(models.Model):
            codename = models.CharField(max_length=64)

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()
            trustee = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Principal(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            identity = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        ace = Ref(Ace)
        doc = Ref(Document)
        principal = Ref(Principal)
        compiled = registry.register_strategy(OrderedFold(
            content=doc,
            descriptor=doc,
            source=ace,
            source_descriptor=ace.document,
            order=ace.ace_order,
            polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
            mask=ace.access_mask,
            trustee=ace.trustee,
            token=FlatToken(
                principal=principal,
                principal_user=principal.user,
                principal_identity=principal.identity,
            ),
            domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
        ))
        self.assertEqual(compiled.identity_attname, 'code')
        self.assertFalse(compiled.principal_is_user)

    def test_mask_range_is_field_family_not_windows_width(self):
        Permission, Document, Ace = _direct_models(
            suffix='Wide', mask_cls=models.BigIntegerField,
        )
        registry = TrustsRegistry()
        compiled = _register_direct(
            registry, Ace, Permission, Document,
            masks=(MaskEntry('wide', 1 << 40),),
        )
        self.assertEqual(compiled.mask_rows[0][2], 1 << 40)

        Permission, Document, Ace = _direct_models(
            suffix='Int32', mask_cls=models.IntegerField,
        )
        other = TrustsRegistry()
        with self.assertRaisesRegex(TrustsConfigurationError, r'does not fit'):
            _register_direct(
                other, Ace, Permission, Document,
                masks=(MaskEntry('win', 0x80000000),),
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'non-boolean|int'):
            _register_direct(
                other, Ace, Permission, Document,
                masks=(MaskEntry('flag', True),),
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'does not fit|range'):
            _register_direct(
                other, Ace, Permission, Document,
                masks=(MaskEntry('zero', 0),),
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'does not fit|range'):
            _register_direct(
                other, Ace, Permission, Document,
                masks=(MaskEntry('neg', -1),),
            )

    def test_duplicate_actions_and_bad_permission_keys_rejected(self):
        Permission, Document, Ace = _direct_models()
        registry = TrustsRegistry()
        with self.assertRaisesRegex(TrustsConfigurationError, r'unique'):
            _register_direct(
                registry, Ace, Permission, Document,
                masks=(MaskEntry('read', 1), MaskEntry('read', 2)),
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'action'):
            _register_direct(
                registry, Ace, Permission, Document,
                masks=(MaskEntry('read_doc', 1),),
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'non-empty|entries'):
            ace = Ref(Ace)
            doc = Ref(Document)
            user = Ref(get_user_model())
            registry.register_strategy(OrderedFold(
                content=doc,
                descriptor=doc,
                source=ace,
                source_descriptor=ace.document,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
                mask=ace.access_mask,
                trustee=ace.user,
                token=FlatToken(
                    principal=user, principal_user=user, principal_identity=user,
                ),
                domain=PermissionMaskDomain(Permission, ()),
            ))

    def test_distinct_polarity_type_rules(self):
        Permission, Document, Ace = _direct_models()
        ace = Ref(Ace)
        doc = Ref(Document)
        user = Ref(get_user_model())
        registry = TrustsRegistry()
        with self.assertRaisesRegex(TrustsConfigurationError, r'distinct'):
            registry.register_strategy(OrderedFold(
                content=doc,
                descriptor=doc,
                source=ace,
                source_descriptor=ace.document,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=1, deny_value=1),
                mask=ace.access_mask,
                trustee=ace.user,
                token=FlatToken(
                    principal=user, principal_user=user, principal_identity=user,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        with self.assertRaisesRegex(TrustsConfigurationError, r'not bool'):
            registry.register_strategy(OrderedFold(
                content=doc,
                descriptor=doc,
                source=ace,
                source_descriptor=ace.document,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=True, deny_value=False),
                mask=ace.access_mask,
                trustee=ace.user,
                token=FlatToken(
                    principal=user, principal_user=user, principal_identity=user,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))

    def test_raw_permission_at_registry_api_is_configuration_error(self):
        Permission, Document, Ace = _direct_models()
        registry = TrustsRegistry()
        _register_direct(registry, Ace, Permission, Document)
        user = get_user_model()(username='probe')
        doc = Document(title='x')
        with self.assertRaisesRegex(TrustsConfigurationError, r'model instance'):
            registry.has_permission(user, doc, 1)
        with self.assertRaisesRegex(TrustsConfigurationError, r'model instance'):
            registry.has_permission(user, doc, 'read')
        with self.assertRaisesRegex(TrustsConfigurationError, r'model instance'):
            registry.filter_authorized(Document.objects.all(), user, 0x1)

    def test_wrong_strategy_type_rejected(self):
        registry = TrustsRegistry()
        with self.assertRaisesRegex(TrustsConfigurationError, r'OrderedFold'):
            registry.register_strategy(object())

    def test_e006_absent_databases_is_zero_sql_not_all_clear(self):
        Permission, Document, Ace = _direct_models(suffix='E006')
        registry = TrustsRegistry()
        _register_direct(registry, Ace, Permission, Document)
        live = live_config()
        saved = dict(live.registries)
        isolate_live_registry(live, registry)
        try:
            # SimpleTestCase forbids connections. Completing these
            # calls is the zero-SQL proof.
            self.assertEqual(check_ordered_fold_renderer(None), [])
            self.assertEqual(check_ordered_fold_renderer(None, databases=None), [])
            self.assertEqual(check_ordered_fold_renderer(None, databases=()), [])
        finally:
            live.registries.clear()
            live.registries.update(saved)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class OrderedFoldVendorGateTest(TransactionTestCase):
    def test_unsupported_vendor_fails_closed_without_fold_sql(self):
        Permission, Document, Ace = _direct_models()
        with _tables(Permission, Document, Ace):
            User = get_user_model()
            alice = User.objects.create_user(username='alice-vendor', password='x')
            doc = Document.objects.create(title='d')
            read = _perm(Permission, 'read', Document)
            Ace.objects.create(
                document=doc, ace_order=0, ace_type=ALLOW,
                access_mask=1, user=alice,
            )
            registry = TrustsRegistry()
            compiled = _register_direct(registry, Ace, Permission, Document)
            expr = OrderedFoldAllowed(compiled, alice, read)
            compiler = Document.objects.filter(pk=doc.pk).query.get_compiler('default')

            class Stub(object):
                vendor = 'sqlite'
                alias = 'replica'
                settings_dict = {'ENGINE': 'django.db.backends.sqlite3'}
                ops = connection.ops

            with self.assertRaises(TrustsConfigurationError) as ctx:
                expr.as_sql(compiler, Stub())
            message = str(ctx.exception).lower()
            self.assertIn('postgresql', message)
            self.assertIn('sqlite', message)
            self.assertIn('replica', str(ctx.exception))
            self.assertNotIn('with recursive', message)

    def test_inactive_and_anonymous_fail_closed_on_mixin(self):
        Permission, Document, Ace = _direct_models()
        with _tables(Permission, Document, Ace):
            User = get_user_model()
            alice = User.objects.create_user(
                username='alice-inactive', password='x', is_active=False,
            )
            doc = Document.objects.create(title='d')
            self.assertFalse(is_active_principal(alice))
            self.assertFalse(is_active_principal(AnonymousUser()))
            backend = TrustModelBackendMixin()
            with self.assertNumQueries(0):
                self.assertFalse(
                    backend.has_perm(alice, 'trusts_tests.read_document', doc)
                )
                self.assertFalse(
                    backend.has_perm(
                        AnonymousUser(), 'trusts_tests.read_document', doc,
                    )
                )

    def test_e006_reports_non_postgres_alias(self):
        Permission, Document, Ace = _direct_models(suffix='E006Live')
        registry = TrustsRegistry()
        _register_direct(registry, Ace, Permission, Document)
        live = live_config()
        saved = dict(live.registries)
        isolate_live_registry(live, registry)
        try:
            messages = check_ordered_fold_renderer(None, databases=['default'])
            errors = [
                message for message in messages
                if message.id == CHECK_ID_ORDERED_FOLD_RENDERER
            ]
            if connection.vendor == 'postgresql':
                self.assertEqual(errors, [])
            else:
                self.assertEqual(len(errors), 1)
                self.assertIn('PostgreSQL', errors[0].msg)
        finally:
            live.registries.clear()
            live.registries.update(saved)

    def test_anypath_sql_and_results_remain_exists(self):
        User = get_user_model()

        class Permission(models.Model):
            codename = models.CharField(max_length=64)

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            objects = AuthorizedManager()

            class Meta:
                app_label = 'trusts_tests'

        class Grant(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Permission, Document, Grant):
            alice = User.objects.create_user(username='alice-anypath', password='x')
            read = Permission.objects.create(codename='read')
            write = Permission.objects.create(codename='write')
            doc = Document.objects.create(title='kept')
            other = Document.objects.create(title='other')
            Grant.objects.create(document=doc, user=alice, permission=read)
            registry = TrustsRegistry()
            g = Ref(Grant)
            registry.register(
                content=g.document, user=g.user, permission=g.permission,
            )
            sql = str(registry.filter_authorized(
                Document.objects.all(), alice, read,
            ).query).upper()
            self.assertIn('EXISTS', sql)
            self.assertNotIn('WITH RECURSIVE', sql)
            self.assertTrue(registry.has_permission(alice, doc, read))
            self.assertFalse(registry.has_permission(alice, doc, write))
            self.assertFalse(registry.has_permission(alice, other, read))
            self.assertEqual(
                _pks(registry.filter_authorized(
                    Document.objects.all(), alice, read,
                )),
                {doc.pk},
            )


class _FoldRuntimeMixin(object):
    def _agree(self, registry, user, permission, obj, expected):
        handles = _handles(registry)
        with self.assertNumQueries(1):
            via_obj = registry.has_permission(user, obj, permission)
        with self.assertNumQueries(1):
            via_list = obj in list(
                registry.filter_authorized(
                    obj._meta.concrete_model.objects.filter(pk=obj.pk),
                    user, permission,
                )
            )
        with patch(
            'trusts.apps.configured_implementation_handles',
            return_value=handles,
        ):
            with self.assertNumQueries(1):
                via_manager = obj in list(
                    obj._meta.concrete_model.objects.filter(pk=obj.pk).authorized(
                        user, permission,
                    )
                )
        enumerated = {
            row.pk for row in registry.permissions_for(user, obj)
        }
        with self.assertNumQueries(1):
            matched = all_match(handles, obj, user, permission)
        self.assertEqual(via_obj, expected)
        self.assertEqual(via_list, expected)
        self.assertEqual(via_manager, expected)
        self.assertEqual(matched, expected)
        if expected:
            self.assertIn(permission.pk, enumerated)
        else:
            self.assertNotIn(permission.pk, enumerated)


@skipUnless(_postgres(), 'OrderedFold renderer is PostgreSQL')
@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class OrderedFoldAuthorizationTest(_FoldRuntimeMixin, TransactionTestCase):
    def setUp(self):
        self.Permission, self.Document, self.Ace = _direct_models()
        self._table_cm = _tables(self.Permission, self.Document, self.Ace)
        self._table_cm.__enter__()
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice-fold', password='x')
        self.bob = User.objects.create_user(username='bob-fold', password='x')
        self.read = _perm(self.Permission, 'read', self.Document)
        self.write = _perm(self.Permission, 'write', self.Document)
        self.readwrite = _perm(self.Permission, 'readwrite', self.Document)
        self.doc = self.Document.objects.create(title='target')
        self.other = self.Document.objects.create(title='other')
        self.registry = TrustsRegistry()
        _register_direct(self.registry, self.Ace, self.Permission, self.Document)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def _ace(self, *, order, polarity, mask, user=None, document=None):
        return self.Ace.objects.create(
            document=document or self.doc,
            ace_order=order,
            ace_type=polarity,
            access_mask=mask,
            user=user or self.alice,
        )

    def test_allow_before_deny_allows_and_deny_before_allow_denies(self):
        self._ace(order=0, polarity=ALLOW, mask=0x1)
        self._ace(order=1, polarity=DENY, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, True)

        self.Ace.objects.all().delete()
        self._ace(order=0, polarity=DENY, mask=0x1)
        self._ace(order=1, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, False)

    def test_one_bit_and_multibit_identities(self):
        self._ace(order=0, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, True)
        self._agree(self.registry, self.alice, self.write, self.doc, False)
        self._agree(self.registry, self.alice, self.readwrite, self.doc, False)

        self._ace(order=1, polarity=ALLOW, mask=0x2)
        self._agree(self.registry, self.alice, self.read, self.doc, True)
        self._agree(self.registry, self.alice, self.write, self.doc, True)
        self._agree(self.registry, self.alice, self.readwrite, self.doc, True)

        self.Ace.objects.filter(access_mask=0x2).delete()
        self._ace(order=1, polarity=DENY, mask=0x2)
        self._agree(self.registry, self.alice, self.read, self.doc, True)
        self._agree(self.registry, self.alice, self.readwrite, self.doc, False)

    def test_missing_membership_grant_empty_bag_and_wrong_model(self):
        self._agree(self.registry, self.alice, self.read, self.doc, False)
        self._agree(self.registry, self.bob, self.read, self.doc, False)
        self._ace(order=0, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.bob, self.read, self.doc, False)
        self._agree(self.registry, self.alice, self.read, self.other, False)

        class OtherPerm(models.Model):
            codename = models.CharField(max_length=64)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(OtherPerm):
            other = OtherPerm.objects.create(codename='read_document')
            self.assertFalse(
                self.registry.has_permission(self.alice, self.doc, other)
            )

    def test_unknown_polarity_and_null_rows_gate_denial(self):
        self._ace(order=0, polarity=99, mask=0x1)
        self._ace(order=1, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, False)

        self.Ace.objects.all().delete()
        self._ace(order=1, polarity=ALLOW, mask=0x1)
        table = self.Ace._meta.db_table
        order_col = self.Ace._meta.get_field('ace_order').column
        with connection.cursor() as cursor:
            cursor.execute(
                'ALTER TABLE %s ALTER COLUMN %s DROP NOT NULL'
                % (connection.ops.quote_name(table), connection.ops.quote_name(order_col))
            )
            cursor.execute(
                'INSERT INTO %s (%s, %s, %s, %s, %s) VALUES (%%s, NULL, %%s, %%s, %%s)'
                % (
                    connection.ops.quote_name(table),
                    connection.ops.quote_name(self.Ace._meta.get_field('document').column),
                    connection.ops.quote_name(order_col),
                    connection.ops.quote_name(self.Ace._meta.get_field('ace_type').column),
                    connection.ops.quote_name(self.Ace._meta.get_field('access_mask').column),
                    connection.ops.quote_name(self.Ace._meta.get_field('user').column),
                ),
                [self.doc.pk, ALLOW, 0x1, self.alice.pk],
            )
        self._agree(self.registry, self.alice, self.read, self.doc, False)

    def test_negative_masks_gate_including_foreign_trustee(self):
        self._ace(order=0, polarity=ALLOW, mask=-1)
        self._ace(order=1, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, False)

        self.Ace.objects.all().delete()
        self._ace(order=0, polarity=DENY, mask=-1)
        self._ace(order=1, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, False)

        self.Ace.objects.all().delete()
        self._ace(order=0, polarity=ALLOW, mask=-1, user=self.bob)
        self._ace(order=1, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, False)

        self.Ace.objects.all().delete()
        self._ace(order=0, polarity=DENY, mask=-1, user=self.bob)
        self._ace(order=1, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, False)

        self.Ace.objects.all().delete()
        self._ace(order=1, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, True)

        self.Ace.objects.all().delete()
        self._ace(order=0, polarity=ALLOW, mask=0)
        self._ace(order=1, polarity=ALLOW, mask=0x1)
        self._agree(self.registry, self.alice, self.read, self.doc, True)

    def test_query_construction_is_lazy_fixed_count_and_filter_before_page(self):
        self._ace(order=0, polarity=ALLOW, mask=0x1)
        with self.assertNumQueries(0):
            qs = self.registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.read,
            )
            enumerated = self.registry.permissions_for(self.alice, self.doc)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsInstance(enumerated, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs), {self.doc.pk})
        page = self.registry.filter_authorized(
            self.Document.objects.order_by('pk'), self.alice, self.read,
        )[:1]
        with self.assertNumQueries(1):
            self.assertEqual(list(page), [self.doc])
        sql = str(
            self.registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.read,
            ).query
        ).upper()
        self.assertIn('WITH RECURSIVE', sql)
        self.assertIn('&', sql)

    def test_filter_authorized_scopes_is_none_for_orderedfold(self):
        self._ace(order=0, polarity=ALLOW, mask=0x1)
        scoped = filter_authorized_scopes(
            self.Document.objects.all(),
            self.alice,
            self.read,
            content=self.doc,
            handles=_handles(self.registry),
        )
        self.assertEqual(list(scoped), [])

    def test_independent_anypath_or_keeps_orderedfold_deny_local(self):
        User = get_user_model()

        class Grant(models.Model):
            document = models.ForeignKey(self.Document, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(self.Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Grant):
            Grant.objects.create(
                document=self.doc, user=self.alice, permission=self.read,
            )
            anypath = TrustsRegistry()
            g = Ref(Grant)
            anypath.register(
                content=g.document, user=g.user, permission=g.permission,
            )
            self._ace(order=0, polarity=ALLOW, mask=-1)
            fold_handles = _handles(self.registry)
            any_handles = _handles(anypath)
            self.assertFalse(
                self.registry.has_permission(self.alice, self.doc, self.read)
            )
            self.assertTrue(
                anypath.has_permission(self.alice, self.doc, self.read)
            )
            with self.assertNumQueries(1):
                combined = all_match(
                    any_handles + fold_handles,
                    self.doc, self.alice, self.read,
                )
            self.assertTrue(combined)


@skipUnless(_postgres(), 'OrderedFold renderer is PostgreSQL')
@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class OrderedFoldFlatTokenTest(_FoldRuntimeMixin, TransactionTestCase):
    def test_direct_and_one_level_flat_group_token(self):
        User = get_user_model()

        class Identity(models.Model):
            code = models.CharField(max_length=16, unique=True)

            class Meta:
                app_label = 'trusts_tests'

        class Permission(models.Model):
            codename = models.CharField(max_length=64)

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            objects = AuthorizedManager()

            class Meta:
                app_label = 'trusts_tests'

        class Principal(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            identity = models.ForeignKey(Identity, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Membership(models.Model):
            member = models.ForeignKey(
                Identity, related_name='+', on_delete=models.CASCADE,
            )
            group = models.ForeignKey(
                Identity, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()
            trustee = models.ForeignKey(Identity, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Identity, Permission, Document, Principal, Membership, Ace):
            alice = User.objects.create_user(username='alice-token', password='x')
            stranger = User.objects.create_user(username='stranger-token', password='x')
            alice_sid = Identity.objects.create(code='alice')
            group_sid = Identity.objects.create(code='writers')
            Principal.objects.create(user=alice, identity=alice_sid)
            Membership.objects.create(member=alice_sid, group=group_sid)
            doc = Document.objects.create(title='shared')
            read = _perm(Permission, 'read', Document)
            Ace.objects.create(
                document=doc, ace_order=0, ace_type=ALLOW,
                access_mask=1, trustee=group_sid,
            )
            registry = TrustsRegistry()
            ace = Ref(Ace)
            document = Ref(Document)
            principal = Ref(Principal)
            member = Ref(Membership)
            registry.register_strategy(OrderedFold(
                content=document,
                descriptor=document,
                source=ace,
                source_descriptor=ace.document,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
                mask=ace.access_mask,
                trustee=ace.trustee,
                token=FlatToken(
                    principal=principal,
                    principal_user=principal.user,
                    principal_identity=principal.identity,
                    member=member,
                    member_identity=member.member,
                    member_group=member.group,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
            self._agree(registry, alice, read, doc, True)
            self._agree(registry, stranger, read, doc, False)
            Membership.objects.all().delete()
            self._agree(registry, alice, read, doc, False)


@skipUnless(_postgres(), 'OrderedFold renderer is PostgreSQL')
@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class OrderedFoldDescriptorTest(_FoldRuntimeMixin, TransactionTestCase):
    def test_missing_descriptor_denies_and_null_descriptor_is_empty_bag(self):
        User = get_user_model()

        class Permission(models.Model):
            codename = models.CharField(max_length=64)

            class Meta:
                app_label = 'trusts_tests'

        class Descriptor(models.Model):
            name = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)
            descriptor = models.ForeignKey(
                Descriptor, null=True, on_delete=models.CASCADE,
            )

            objects = AuthorizedManager()

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            descriptor = models.ForeignKey(Descriptor, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()
            user = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Permission, Descriptor, Document, Ace):
            alice = User.objects.create_user(username='alice-desc', password='x')
            desc = Descriptor.objects.create(name='dacl')
            attached = Document.objects.create(title='attached', descriptor=desc)
            missing = Document.objects.create(title='missing', descriptor=None)
            read = _perm(Permission, 'read', Document)
            Ace.objects.create(
                descriptor=desc, ace_order=0, ace_type=ALLOW,
                access_mask=1, user=alice,
            )
            registry = TrustsRegistry()
            ace = Ref(Ace)
            document = Ref(Document)
            user = Ref(User)
            registry.register_strategy(OrderedFold(
                content=document,
                descriptor=document.descriptor,
                source=ace,
                source_descriptor=ace.descriptor,
                order=ace.ace_order,
                polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
                mask=ace.access_mask,
                trustee=ace.user,
                token=FlatToken(
                    principal=user, principal_user=user, principal_identity=user,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
            self._agree(registry, alice, read, attached, True)
            self._agree(registry, alice, read, missing, False)


@skipUnless(_postgres(), 'OrderedFold renderer is PostgreSQL')
@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class OrderedFoldMultiHopPathTest(_FoldRuntimeMixin, TransactionTestCase):
    """Runtime SQL must resolve every accepted multi-hop path to its terminal.

    First-hop-only compares (``wrapper_id`` vs Document/Identity, reused
    ``of_p_h0`` / ``of_m_h0`` aliases) change authorization when
    intermediate and terminal keys collide.
    """

    def _graph(self):
        User = get_user_model()

        class Identity(models.Model):
            code = models.CharField(max_length=16, unique=True)

            class Meta:
                app_label = 'trusts_tests'

        class Permission(models.Model):
            codename = models.CharField(max_length=64)

            class Meta:
                app_label = 'trusts_tests'

        class Document(models.Model):
            title = models.CharField(max_length=40)

            objects = AuthorizedManager()

            class Meta:
                app_label = 'trusts_tests'

        class Wrapper(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Holder(models.Model):
            identity = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            wrapper = models.ForeignKey(Wrapper, on_delete=models.CASCADE)
            holder = models.ForeignKey(Holder, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()

            class Meta:
                app_label = 'trusts_tests'

        class Profile(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Card(models.Model):
            identity = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Principal(models.Model):
            profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
            card = models.ForeignKey(Card, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Person(models.Model):
            identity = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Team(models.Model):
            identity = models.ForeignKey(
                Identity, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Membership(models.Model):
            person = models.ForeignKey(Person, on_delete=models.CASCADE)
            group = models.ForeignKey(Team, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        return (
            Identity, Permission, Document, Wrapper, Holder, Ace,
            Profile, Card, Principal, Person, Team, Membership,
        )

    def _register(self, registry, models):
        (
            _Identity, Permission, Document, _Wrapper, _Holder, Ace,
            _Profile, _Card, Principal, _Person, _Team, Membership,
        ) = models
        ace = Ref(Ace)
        document = Ref(Document)
        principal = Ref(Principal)
        member = Ref(Membership)
        return registry.register_strategy(OrderedFold(
            content=document,
            descriptor=document,
            source=ace,
            source_descriptor=ace.wrapper.document,
            order=ace.ace_order,
            polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
            mask=ace.access_mask,
            trustee=ace.holder.identity,
            token=FlatToken(
                principal=principal,
                principal_user=principal.profile.user,
                principal_identity=principal.card.identity,
                member=member,
                member_identity=member.person.identity,
                member_group=member.group.identity,
            ),
            domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
        ))

    def _force_pk(self, model, pk, **kwargs):
        row = model(pk=pk, **kwargs)
        row.save(force_insert=True)
        return row

    def test_multi_hop_source_descriptor_ignores_colliding_wrapper_pk(self):
        models_ = self._graph()
        (
            Identity, Permission, Document, Wrapper, Holder, Ace,
            Profile, Card, Principal, Person, Team, Membership,
        ) = models_
        User = get_user_model()
        with _tables(
            Identity, Permission, Document, Wrapper, Holder, Ace,
            Profile, Card, Principal, Person, Team, Membership,
        ):
            alice = User.objects.create_user(username='alice-mh-src', password='x')
            alice_sid = Identity.objects.create(code='alice-mh-src')
            real = Document.objects.create(title='real-src')
            decoy = Document.objects.create(title='decoy-src')
            wrapper = self._force_pk(Wrapper, decoy.pk, document=real)
            holder = Holder.objects.create(identity=alice_sid)
            profile = Profile.objects.create(user=alice)
            card = Card.objects.create(identity=alice_sid)
            Principal.objects.create(profile=profile, card=card)
            read = _perm(Permission, 'read', Document)
            Ace.objects.create(
                wrapper=wrapper, holder=holder, ace_order=0,
                ace_type=ALLOW, access_mask=1,
            )
            registry = TrustsRegistry()
            self._register(registry, models_)
            self._agree(registry, alice, read, real, True)
            self._agree(registry, alice, read, decoy, False)

    def test_multi_hop_source_descriptor_malformed_row_does_not_poison_decoy(self):
        models_ = self._graph()
        (
            Identity, Permission, Document, Wrapper, Holder, Ace,
            Profile, Card, Principal, Person, Team, Membership,
        ) = models_
        User = get_user_model()
        with _tables(
            Identity, Permission, Document, Wrapper, Holder, Ace,
            Profile, Card, Principal, Person, Team, Membership,
        ):
            alice = User.objects.create_user(username='alice-mh-poison', password='x')
            alice_sid = Identity.objects.create(code='alice-mh-poison')
            victim = Document.objects.create(title='victim')
            other = Document.objects.create(title='other-poison')
            holder = Holder.objects.create(identity=alice_sid)
            profile = Profile.objects.create(user=alice)
            card = Card.objects.create(identity=alice_sid)
            Principal.objects.create(profile=profile, card=card)
            # First-hop wrapper_id == victim.pk would correlate this
            # negative-mask ACE onto victim; the terminal document is other.
            poison_wrapper = self._force_pk(Wrapper, victim.pk, document=other)
            Ace.objects.create(
                wrapper=poison_wrapper, holder=holder, ace_order=0,
                ace_type=ALLOW, access_mask=-1,
            )
            ok_wrapper = self._force_pk(
                Wrapper, victim.pk + 1000, document=victim,
            )
            Ace.objects.create(
                wrapper=ok_wrapper, holder=holder, ace_order=1,
                ace_type=ALLOW, access_mask=1,
            )
            read = _perm(Permission, 'read', Document)
            registry = TrustsRegistry()
            self._register(registry, models_)
            self._agree(registry, alice, read, victim, True)
            self._agree(registry, alice, read, other, False)

    def test_multi_hop_trustee_principal_member_terminals_and_to_field(self):
        models_ = self._graph()
        (
            Identity, Permission, Document, Wrapper, Holder, Ace,
            Profile, Card, Principal, Person, Team, Membership,
        ) = models_
        User = get_user_model()
        with _tables(
            Identity, Permission, Document, Wrapper, Holder, Ace,
            Profile, Card, Principal, Person, Team, Membership,
        ):
            alice = User.objects.create_user(username='alice-mh-tok', password='x')
            bob = User.objects.create_user(username='bob-mh-tok', password='x')
            alice_sid = Identity.objects.create(code='alice-mh-tok')
            bob_sid = Identity.objects.create(code='bob-mh-tok')
            writers = Identity.objects.create(code='writers-mh-tok')
            doc = Document.objects.create(title='shared-mh')
            group_doc = Document.objects.create(title='group-mh')
            wrapper = Wrapper.objects.create(document=doc)
            group_wrapper = Wrapper.objects.create(document=group_doc)

            # holder.pk == card_bob.pk: first-hop trustee/token FKs collide
            # while terminal codes (alice vs bob) differ.
            holder = Holder.objects.create(identity=alice_sid)
            card_bob = self._force_pk(Card, holder.pk, identity=bob_sid)
            card_alice = self._force_pk(
                Card, holder.pk + 1000, identity=alice_sid,
            )

            # profile.pk == bob.pk: first-hop principal_user would bind bob
            # to alice's profile.
            profile_alice = self._force_pk(Profile, bob.pk, user=alice)
            profile_bob = self._force_pk(
                Profile, bob.pk + 1000, user=bob,
            )
            Principal.objects.create(profile=profile_alice, card=card_alice)
            Principal.objects.create(profile=profile_bob, card=card_bob)

            # person.pk == team.pk: independent member paths share no alias.
            team = Team.objects.create(identity=writers)
            person = self._force_pk(Person, team.pk, identity=alice_sid)
            Membership.objects.create(person=person, group=team)

            read = _perm(Permission, 'read', Document)
            Ace.objects.create(
                wrapper=wrapper, holder=holder, ace_order=0,
                ace_type=ALLOW, access_mask=1,
            )
            writers_holder = Holder.objects.create(identity=writers)
            Ace.objects.create(
                wrapper=group_wrapper, holder=writers_holder, ace_order=0,
                ace_type=ALLOW, access_mask=1,
            )

            registry = TrustsRegistry()
            compiled = self._register(registry, models_)
            self.assertGreater(len(compiled.source_desc_hops), 1)
            self.assertGreater(len(compiled.trustee_hops), 1)
            self.assertGreater(len(compiled.principal_user_hops), 1)
            self.assertGreater(len(compiled.principal_identity_hops), 1)
            self.assertGreater(len(compiled.member_identity_hops), 1)
            self.assertGreater(len(compiled.member_group_hops), 1)
            sql = str(
                registry.filter_authorized(
                    Document.objects.all(), alice, read,
                ).query
            )
            for prefix in (
                'of_sdesc', 'of_strust', 'of_pident', 'of_puser',
                'of_mident', 'of_mgroup',
            ):
                self.assertIn(prefix, sql)

            self._agree(registry, alice, read, doc, True)
            self._agree(registry, bob, read, doc, False)
            self._agree(registry, alice, read, group_doc, True)
            self._agree(registry, bob, read, group_doc, False)
            Membership.objects.all().delete()
            self._agree(registry, alice, read, group_doc, False)
