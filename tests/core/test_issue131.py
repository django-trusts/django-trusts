"""#131 C1 / C-unify: BackendHandle public AnyPath and OrderedFold APIs.

Handle-bound Django ``__`` paths, string condition leaves,
``along=(path, bound)``, and ``register(source_model,
strategy=OrderedFold(...))``. ``Ref`` input is TypeError. Freeze
raises before path resolution. Dual handles stay isolated. Internal
``TrustsRegistry.register(Ref)`` and ``register_strategy(OrderedFold)``
remain for compiler tests.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.core.test_issue100 import ALLOW, DENY, _direct_models, _register_direct
from tests.myapp.models import Document, DocumentGrant
from trusts.core import (
    All,
    Along,
    BackendHandle,
    Equal,
    FlatToken,
    MaskEntry,
    OrderedFold,
    PermissionMaskDomain,
    PlanQueryCompiler,
    PolarityMap,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    _public_path_segments,
    _resolve_forward_singles,
    _resolve_path,
    _validate_condition,
    permission_in,
)
from trusts.ordered_fold import validate_ordered_fold


def _handle(registry=None, path='tests.core.handle-a'):
    if registry is None:
        registry = TrustsRegistry()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler(),
    )


class HandleRegisterSurfaceTest(SimpleTestCase):
    def test_register_is_the_public_donation_verb(self):
        handle = _handle()
        self.assertTrue(hasattr(BackendHandle, 'register'))
        self.assertFalse(hasattr(BackendHandle, 'register_strategy'))
        self.assertTrue(hasattr(handle, 'register'))
        self.assertFalse(hasattr(handle, 'register_strategy'))
        self.assertTrue(hasattr(handle.registry, 'register'))
        self.assertTrue(hasattr(handle.registry, 'register_strategy'))

    def test_string_register_matches_internal_ref_record(self):
        via_ref = TrustsRegistry()
        j = Ref(DocumentGrant)
        expected = via_ref.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )
        handle = _handle()
        record = handle.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(record, expected)
        self.assertIs(record.content_model, Document)
        self.assertEqual(record.user_path, ('user',))
        self.assertEqual(record.content_field, 'document')

    def test_public_ref_input_is_type_error(self):
        handle = _handle()
        j = Ref(DocumentGrant)
        with self.assertRaises(TypeError):
            handle.register(
                j,
                user='user',
                permission='permission',
                content='document',
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user=j.user,
                permission='permission',
                content='document',
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission=j.permission,
                content='document',
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content=j.document,
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                condition=Equal(j.user, j.permission),
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                along=Along(j.document, 8),
            )
        self.assertEqual(handle.registry.records, ())

    def test_invalid_public_path_grammar_is_rejected(self):
        handle = _handle()
        for path in (
            '',
            '__user',
            'user__',
            'folder.documents',
            'team____members',
            1,
            None,
            ['user'],
        ):
            with self.subTest(path=path):
                with self.assertRaises(TrustsConfigurationError):
                    handle.register(
                        DocumentGrant,
                        user=path,
                        permission='permission',
                        content='document',
                    )
        self.assertEqual(handle.registry.records, ())

    def test_string_condition_is_not_legal_on_bare_registry(self):
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=j.document,
                user=j.user,
                permission=j.permission,
                condition=Equal('user', 'permission'),
            )
        self.assertEqual(registry.records, ())

    def test_duplicate_and_conflict_leave_store_unchanged(self):
        handle = _handle()
        first = handle.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content='document',
            )
        self.assertEqual(handle.registry.records, (first,))
        with self.assertRaisesRegex(TrustsConfigurationError, r'Conflicting'):
            handle.register(
                DocumentGrant,
                user='permission',
                permission='user',
                content='document',
            )
        self.assertEqual(handle.registry.records, (first,))


class HandleFreezeOrderTest(SimpleTestCase):
    def test_freeze_raises_before_path_resolution(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        with patch(
            'trusts.core._public_path_segments',
            wraps=_public_path_segments,
        ) as segments:
            with patch('trusts.core._resolve_path', wraps=_resolve_path) as resolve:
                with patch(
                    'trusts.core._validate_condition',
                    wraps=_validate_condition,
                ) as validate:
                    with self.assertRaises(TrustsConfigurationError) as ctx:
                        handle.register(
                            DocumentGrant,
                            user='user',
                            permission='permission',
                            content='document',
                        )
        self.assertIn('frozen', str(ctx.exception).lower())
        segments.assert_not_called()
        resolve.assert_not_called()
        validate.assert_not_called()
        self.assertEqual(registry.records, ())

    def test_freeze_wins_over_invalid_grammar(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            handle.register(
                DocumentGrant,
                user='',
                permission='permission',
                content='document',
            )
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, ())


class HandleIsolationTest(SimpleTestCase):
    def test_dual_handle_string_register_does_not_leak(self):
        left = _handle(path='tests.core.handle-left')
        right = _handle(path='tests.core.handle-right')
        left.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(len(left.registry.records), 1)
        self.assertEqual(right.registry.records, ())
        right.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(len(left.registry.records), 1)
        self.assertEqual(len(right.registry.records), 1)
        self.assertIsNot(left.registry.records[0], right.registry.records[0])
        self.assertEqual(left.registry.records[0], right.registry.records[0])


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class HandleConditionAndAlongTest(SimpleTestCase):
    def test_string_condition_tree_matches_ref_registration(self):
        from tests.core.test_issue98 import _gh_models, _register_team

        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        via_ref = TrustsRegistry()
        expected = _register_team(via_ref, TeamRepoGrant)
        handle = _handle()
        record = handle.register(
            TeamRepoGrant,
            user='team__members',
            permission='operation',
            content='repository',
            condition=All(
                permission_in('team__permission_bundles__operations'),
                Equal(
                    'team__organization',
                    'repository__organization',
                ),
            ),
        )
        self.assertEqual(record, expected)
        self.assertEqual(record.user_path, ('team', 'members'))
        self.assertEqual(record.user_field, 'team__members')

    def test_along_tuple_matches_internal_along(self):
        from tests.core.test_issue92 import _node_graph_models

        _Node, _p, _r, _i, _im, _meta, _port, _link, Grant, _np = (
            _node_graph_models()
        )
        via_ref = TrustsRegistry()
        j = Ref(Grant)
        expected = via_ref.register(
            content=j.node,
            user=j.user,
            permission=j.permission,
            along=Along(j.node.parent, bound=8),
        )
        handle = _handle()
        record = handle.register(
            Grant,
            user='user',
            permission='permission',
            content='node',
            along=('node__parent', 8),
        )
        self.assertEqual(record, expected)
        self.assertEqual(record.along.shape, 'S')
        self.assertEqual(record.along.bound, 8)


def _public_direct_fold(Ace, Permission, Document, *, token=None):
    User = get_user_model()
    if token is None:
        token = FlatToken(
            principal=User,
            principal_user='',
            principal_identity='',
        )
    return OrderedFold(
        content='document',
        descriptor='',
        order='ace_order',
        polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
        mask='access_mask',
        trustee='user',
        token=token,
        domain=PermissionMaskDomain(Permission, (
            MaskEntry('read', 0x1),
            MaskEntry('write', 0x2),
            MaskEntry('readwrite', 0x3),
        )),
    )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class HandleRegisterStrategySurfaceTest(SimpleTestCase):
    def test_no_root_form_is_type_error(self):
        Permission, Document, Ace = _direct_models()
        handle = _handle()
        strategy = _public_direct_fold(Ace, Permission, Document)
        with self.assertRaises(TypeError):
            handle.register(strategy=strategy)
        self.assertEqual(handle.registry.strategies, ())

    def test_anypath_and_strategy_are_mutually_exclusive(self):
        Permission, Document, Ace = _direct_models()
        handle = _handle()
        strategy = _public_direct_fold(Ace, Permission, Document)
        with self.assertRaises(TypeError):
            handle.register(
                Ace,
                user='user',
                permission='permission',
                content='document',
                strategy=strategy,
            )
        with self.assertRaises(TypeError):
            handle.register(Ace, along=('document', 8), strategy=strategy)
        with self.assertRaises(TypeError):
            handle.register(
                Ace,
                condition=Equal('user', 'permission'),
                strategy=strategy,
            )
        self.assertEqual(handle.registry.strategies, ())
        self.assertEqual(handle.registry.records, ())

    def test_incomplete_anypath_is_type_error(self):
        handle = _handle()
        with self.assertRaises(TypeError):
            handle.register(DocumentGrant, user='user')
        with self.assertRaises(TypeError):
            handle.register(DocumentGrant)
        self.assertEqual(handle.registry.records, ())
        self.assertEqual(handle.registry.strategies, ())

    def test_string_strategy_matches_internal_ref_record(self):
        Permission, Document, Ace = _direct_models()
        via_ref = TrustsRegistry()
        expected = _register_direct(via_ref, Ace, Permission, Document)
        handle = _handle()
        compiled = handle.register(
            Ace, strategy=_public_direct_fold(Ace, Permission, Document),
        )
        self.assertEqual(compiled, expected)
        self.assertIs(compiled.content_model, Document)
        self.assertIs(compiled.source_model, Ace)
        self.assertTrue(compiled.principal_is_user)
        self.assertIsNone(compiled.member_model)

    def test_public_ref_input_is_type_error(self):
        Permission, Document, Ace = _direct_models()
        handle = _handle()
        ace = Ref(Ace)
        doc = Ref(Document)
        user = Ref(get_user_model())
        with self.assertRaises(TypeError):
            handle.register(
                ace, strategy=_public_direct_fold(Ace, Permission, Document),
            )
        with self.assertRaises(TypeError):
            handle.register(Ace, strategy=OrderedFold(
                content=doc,
                descriptor='',
                order='ace_order',
                polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='user',
                token=FlatToken(
                    principal=get_user_model(),
                    principal_user='',
                    principal_identity='',
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        with self.assertRaises(TypeError):
            handle.register(Ace, strategy=OrderedFold(
                content='document',
                descriptor='',
                source=ace,
                source_descriptor=ace.document,
                order='ace_order',
                polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='user',
                token=FlatToken(
                    principal=get_user_model(),
                    principal_user='',
                    principal_identity='',
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        with self.assertRaises(TypeError):
            handle.register(Ace, strategy=OrderedFold(
                content='document',
                descriptor='',
                order='ace_order',
                polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='user',
                token=FlatToken(
                    principal=get_user_model(),
                    principal_user='',
                    principal_identity='',
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        with self.assertRaises(TypeError):
            handle.register(Ace, strategy=OrderedFold(
                content='document',
                descriptor='',
                order='ace_order',
                polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='user',
                token=FlatToken(
                    principal=user,
                    principal_user='',
                    principal_identity='',
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertEqual(handle.registry.strategies, ())

    def test_invalid_public_path_grammar_is_rejected(self):
        Permission, Document, Ace = _direct_models()
        handle = _handle()
        for path in (
            '',
            '__document',
            'document__',
            'wrapper.document',
            'document____title',
            1,
            None,
            ['document'],
        ):
            with self.subTest(path=path):
                with self.assertRaises(TrustsConfigurationError):
                    handle.register(Ace, strategy=OrderedFold(
                        content=path,
                        descriptor='',
                        order='ace_order',
                        polarity=PolarityMap(
                            'ace_type', allow_value=ALLOW, deny_value=DENY,
                        ),
                        mask='access_mask',
                        trustee='user',
                        token=FlatToken(
                            principal=get_user_model(),
                            principal_user='',
                            principal_identity='',
                        ),
                        domain=PermissionMaskDomain(
                            Permission, (MaskEntry('read', 1),),
                        ),
                    ))
        self.assertEqual(handle.registry.strategies, ())

    def test_nonempty_descriptor_matches_internal_ref_record(self):
        User = get_user_model()

        class SecurityDescriptor(models.Model):
            name = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Node(models.Model):
            title = models.CharField(max_length=40)
            security_descriptor = models.ForeignKey(
                SecurityDescriptor, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Ace(models.Model):
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            ace_order = models.IntegerField()
            ace_type = models.IntegerField()
            access_mask = models.BigIntegerField()
            user = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Permission(models.Model):
            codename = models.CharField(max_length=64)

            class Meta:
                app_label = 'trusts_tests'

        via_ref = TrustsRegistry()
        ace = Ref(Ace)
        node = Ref(Node)
        user = Ref(User)
        expected = via_ref.register_strategy(OrderedFold(
            content=node,
            descriptor=node.security_descriptor,
            source=ace,
            source_descriptor=ace.node.security_descriptor,
            order=ace.ace_order,
            polarity=PolarityMap(ace.ace_type, allow_value=ALLOW, deny_value=DENY),
            mask=ace.access_mask,
            trustee=ace.user,
            token=FlatToken(
                principal=user, principal_user=user, principal_identity=user,
            ),
            domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
        ))
        handle = _handle()
        compiled = handle.register(Ace, strategy=OrderedFold(
            content='node',
            descriptor='security_descriptor',
            order='ace_order',
            polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
            mask='access_mask',
            trustee='user',
            token=FlatToken(
                principal=User,
                principal_user='',
                principal_identity='',
            ),
            domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
        ))
        self.assertEqual(compiled, expected)
        self.assertIs(compiled.content_model, Node)
        self.assertEqual(compiled.content_desc_path, ('security_descriptor',))
        self.assertGreater(len(compiled.source_desc_hops), 1)
        self.assertEqual(
            tuple(hop.name for hop in compiled.source_desc_hops),
            ('node', 'security_descriptor'),
        )

    def test_string_principal_or_member_is_type_error(self):
        Permission, Document, Ace = _direct_models()
        handle = _handle()
        with self.assertRaises(TypeError):
            handle.register(Ace, strategy=OrderedFold(
                content='document',
                descriptor='',
                order='ace_order',
                polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='user',
                token=FlatToken(
                    principal='auth.User',
                    principal_user='',
                    principal_identity='',
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        User = get_user_model()

        class Membership(models.Model):
            member = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
            group = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with self.assertRaises(TypeError):
            handle.register(Ace, strategy=OrderedFold(
                content='document',
                descriptor='',
                order='ace_order',
                polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='user',
                token=FlatToken(
                    principal=User,
                    principal_user='',
                    principal_identity='',
                    member='Membership',
                    member_identity='member',
                    member_group='group',
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertEqual(handle.registry.strategies, ())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class HandleRegisterStrategyTokenTest(SimpleTestCase):
    def _principal_member_graph(self):
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

        return (
            Permission, Document, Ace, Principal, Membership, Identity,
        )

    def test_distinct_principal_member_roots_match_ref_form(self):
        Permission, Document, Ace, Principal, Membership, Identity = (
            self._principal_member_graph()
        )
        via_ref = TrustsRegistry()
        ace = Ref(Ace)
        document = Ref(Document)
        principal = Ref(Principal)
        member = Ref(Membership)
        expected = via_ref.register_strategy(OrderedFold(
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
        handle = _handle()
        compiled = handle.register(Ace, strategy=OrderedFold(
            content='wrapper__document',
            descriptor='',
            order='ace_order',
            polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
            mask='access_mask',
            trustee='holder__identity',
            token=FlatToken(
                principal=Principal,
                principal_user='profile__user',
                principal_identity='card__identity',
                member=Membership,
                member_identity='person__identity',
                member_group='group__identity',
            ),
            domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
        ))
        self.assertEqual(compiled, expected)
        self.assertIs(compiled.principal_model, Principal)
        self.assertIs(compiled.member_model, Membership)
        self.assertGreater(len(compiled.principal_user_hops), 1)
        self.assertGreater(len(compiled.member_identity_hops), 1)
        self.assertGreater(len(compiled.member_group_hops), 1)
        self.assertEqual(compiled.identity_attname, 'code')

    def test_misbound_member_paths_are_rejected(self):
        Permission, Document, Ace, Principal, Membership, Identity = (
            self._principal_member_graph()
        )
        handle = _handle()
        with self.assertRaises(TrustsConfigurationError):
            handle.register(Ace, strategy=OrderedFold(
                content='wrapper__document',
                descriptor='',
                order='ace_order',
                polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='holder__identity',
                token=FlatToken(
                    principal=Principal,
                    principal_user='profile__user',
                    principal_identity='card__identity',
                    member=Membership,
                    member_identity='profile__user',
                    member_group='card__identity',
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertEqual(handle.registry.strategies, ())

    def test_member_triad_is_all_or_none(self):
        Permission, Document, Ace, Principal, Membership, Identity = (
            self._principal_member_graph()
        )
        handle = _handle()
        with self.assertRaisesRegex(TrustsConfigurationError, r'member triad'):
            handle.register(Ace, strategy=OrderedFold(
                content='wrapper__document',
                descriptor='',
                order='ace_order',
                polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='holder__identity',
                token=FlatToken(
                    principal=Principal,
                    principal_user='profile__user',
                    principal_identity='card__identity',
                    member=Membership,
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        with self.assertRaisesRegex(TrustsConfigurationError, r'member triad'):
            handle.register(Ace, strategy=OrderedFold(
                content='wrapper__document',
                descriptor='',
                order='ace_order',
                polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='holder__identity',
                token=FlatToken(
                    principal=Principal,
                    principal_user='profile__user',
                    principal_identity='card__identity',
                    member_identity='person__identity',
                    member_group='group__identity',
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertEqual(handle.registry.strategies, ())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class HandleRegisterStrategyFreezeTest(SimpleTestCase):
    def test_freeze_raises_before_path_resolution(self):
        Permission, Document, Ace = _direct_models()
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        with patch(
            'trusts.core._public_path_segments',
            wraps=_public_path_segments,
        ) as segments:
            with patch(
                'trusts.core._resolve_forward_singles',
                wraps=_resolve_forward_singles,
            ) as resolve:
                with patch(
                    'trusts.core._resolve_path',
                    wraps=_resolve_path,
                ) as anypath:
                    with patch(
                        'trusts.ordered_fold.validate_ordered_fold',
                        wraps=validate_ordered_fold,
                    ) as validate:
                        with self.assertRaises(TrustsConfigurationError) as ctx:
                            handle.register(
                                Ace,
                                strategy=_public_direct_fold(
                                    Ace, Permission, Document,
                                ),
                            )
        self.assertIn('frozen', str(ctx.exception).lower())
        segments.assert_not_called()
        resolve.assert_not_called()
        anypath.assert_not_called()
        validate.assert_not_called()
        self.assertEqual(registry.strategies, ())

    def test_freeze_wins_over_invalid_grammar(self):
        Permission, Document, Ace = _direct_models()
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            handle.register(Ace, strategy=OrderedFold(
                content='',
                descriptor='',
                order='ace_order',
                polarity=PolarityMap('ace_type', allow_value=ALLOW, deny_value=DENY),
                mask='access_mask',
                trustee='user',
                token=FlatToken(
                    principal=get_user_model(),
                    principal_user='',
                    principal_identity='',
                ),
                domain=PermissionMaskDomain(Permission, (MaskEntry('read', 1),)),
            ))
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.strategies, ())

    def test_freeze_wins_over_mixed_form(self):
        Permission, Document, Ace = _direct_models()
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            handle.register(
                Ace,
                user='user',
                permission='permission',
                content='document',
                strategy=_public_direct_fold(Ace, Permission, Document),
            )
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, ())
        self.assertEqual(registry.strategies, ())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class HandleRegisterStrategyIsolationTest(SimpleTestCase):
    def test_dual_handle_string_strategy_does_not_leak(self):
        Permission, Document, Ace = _direct_models()
        left = _handle(path='tests.core.fold-left')
        right = _handle(path='tests.core.fold-right')
        left.register(
            Ace, strategy=_public_direct_fold(Ace, Permission, Document),
        )
        self.assertEqual(len(left.registry.strategies), 1)
        self.assertEqual(right.registry.strategies, ())
        right.register(
            Ace, strategy=_public_direct_fold(Ace, Permission, Document),
        )
        self.assertEqual(len(left.registry.strategies), 1)
        self.assertEqual(len(right.registry.strategies), 1)
        self.assertIsNot(
            left.registry.strategies[0], right.registry.strategies[0],
        )
        self.assertEqual(
            left.registry.strategies[0], right.registry.strategies[0],
        )
