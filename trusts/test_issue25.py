"""Acceptance tests for issue #25: dependent-content Trust resolution.

Receipt(Content) ← ReceiptImage ← ReceiptImageMeta share one Trust
relationally. This is reuse of that Trust through related rows, not
parent/child ceilings, explicit deny, or ACL inheritance.
"""

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.test import TestCase

from trusts.models import Content, Trust, TrustUserPermission
from trusts.tests import create_test_users, get_or_create_root_user, reload_test_users
from trusts.utils import get_short_model_name
from tests.models import (
    Category,
    Receipt,
    ReceiptImage,
    ReceiptImageMeta,
    TestGroupJunction,
    UnregisteredReceiptNote,
)


RECEIPT_LOOKUP = 'trusts_tests_receipt_content'
IMAGE_LOOKUP = '%s__image' % RECEIPT_LOOKUP
META_LOOKUP = '%s__meta' % IMAGE_LOOKUP


class DependentContentTrustTest(TestCase):
    def setUp(self):
        super(DependentContentTrustTest, self).setUp()
        call_command('create_trust_root')
        get_or_create_root_user(self)
        create_test_users(self)

        self.trust_a = Trust(
            settlor=self.user, trust=Trust.objects.get_root(), title='Org A',
        )
        self.trust_a.save()
        self.trust_b = Trust(
            settlor=self.user1, trust=Trust.objects.get_root(), title='Org B',
        )
        self.trust_b.save()

        self.receipt_a = Receipt.objects.create(trust=self.trust_a, title='A')
        self.image_a = ReceiptImage.objects.create(
            receipt=self.receipt_a, caption='A image',
        )
        self.meta_a = ReceiptImageMeta.objects.create(
            image=self.image_a, note='A meta',
        )
        self.note_a = UnregisteredReceiptNote.objects.create(
            receipt=self.receipt_a, text='unregistered',
        )

        self.receipt_b = Receipt.objects.create(trust=self.trust_b, title='B')
        self.image_b = ReceiptImage.objects.create(
            receipt=self.receipt_b, caption='B image',
        )
        self.meta_b = ReceiptImageMeta.objects.create(
            image=self.image_b, note='B meta',
        )

        self.perm_receipt = self._perm(Receipt, 'change')
        self.perm_image = self._perm(ReceiptImage, 'change')
        self.perm_meta = self._perm(ReceiptImageMeta, 'change')
        self.perm_note = self._perm(UnregisteredReceiptNote, 'change')

    def _perm(self, model, action):
        ct = ContentType.objects.get_for_model(model)
        return Permission.objects.get(
            content_type=ct, codename='%s_%s' % (action, model._meta.model_name),
        )

    def _code(self, perm):
        return '%s.%s' % (perm.content_type.app_label, perm.codename)

    def _grant(self, trust, user, *permissions):
        for permission in permissions:
            TrustUserPermission.objects.get_or_create(
                trust=trust, entity=user, permission=permission,
            )

    def _sql(self, qs):
        return str(qs.query)

    def test_documented_composition_no_longer_produces_none_image(self):
        """Historical RST interpolated get_content_fieldlookup(Receipt) as None."""
        lookup = Content.get_content_fieldlookup(Receipt)
        self.assertEqual(lookup, RECEIPT_LOOKUP)
        self.assertIsInstance(lookup, str)
        documented = '%s__image' % lookup
        self.assertEqual(documented, IMAGE_LOOKUP)
        self.assertFalse(documented.startswith('None'))
        self.assertNotIn('None__', documented)
        self.assertEqual(
            documented,
            Content.compose_content_fieldlookup(Receipt, 'image'),
        )
        self.assertEqual(
            Content.get_content_fieldlookup('trusts_tests.Receipt'),
            RECEIPT_LOOKUP,
        )

    def test_existing_content_and_junction_lookups_are_strings(self):
        self.assertEqual(
            Content.get_content_fieldlookup(Category),
            'trusts_tests_category_content',
        )
        self.assertEqual(
            Content.get_content_fieldlookup(Trust),
            Content.direct_content_fieldlookup(Trust),
        )
        self.assertEqual(
            Content.get_content_fieldlookup(Group),
            TestGroupJunction.get_fieldlookup(),
        )
        self.assertIsInstance(Content.get_content_fieldlookup(Trust), str)

    def test_supported_one_and_two_hop_registration_api(self):
        self.assertTrue(Content.is_content_model(Receipt))
        self.assertTrue(Content.is_content_model(ReceiptImage))
        self.assertTrue(Content.is_content_model(ReceiptImageMeta))
        self.assertEqual(Content.get_content_fieldlookup(Receipt), RECEIPT_LOOKUP)
        self.assertEqual(Content.get_content_fieldlookup(ReceiptImage), IMAGE_LOOKUP)
        self.assertEqual(Content.get_content_fieldlookup(ReceiptImageMeta), META_LOOKUP)
        self.assertEqual(
            Content.compose_content_fieldlookup(ReceiptImage, 'meta'),
            META_LOOKUP,
        )
        self.assertEqual(
            Content.direct_content_fieldlookup(Receipt),
            RECEIPT_LOOKUP,
        )

    def test_has_perm_allow_deny_and_isolation_at_each_hop(self):
        self._grant(
            self.trust_a, self.user,
            self.perm_receipt, self.perm_image, self.perm_meta,
        )
        self._grant(
            self.trust_b, self.user1,
            self.perm_receipt, self.perm_image, self.perm_meta,
        )
        reload_test_users(self)

        self.assertTrue(self.user.has_perm(self._code(self.perm_receipt), self.receipt_a))
        self.assertTrue(self.user.has_perm(self._code(self.perm_image), self.image_a))
        self.assertTrue(self.user.has_perm(self._code(self.perm_meta), self.meta_a))

        self.assertFalse(self.user.has_perm(self._code(self.perm_receipt), self.receipt_b))
        self.assertFalse(self.user.has_perm(self._code(self.perm_image), self.image_b))
        self.assertFalse(self.user.has_perm(self._code(self.perm_meta), self.meta_b))

        self.assertTrue(self.user1.has_perm(self._code(self.perm_receipt), self.receipt_b))
        self.assertTrue(self.user1.has_perm(self._code(self.perm_image), self.image_b))
        self.assertTrue(self.user1.has_perm(self._code(self.perm_meta), self.meta_b))
        self.assertFalse(self.user1.has_perm(self._code(self.perm_receipt), self.receipt_a))
        self.assertFalse(self.user1.has_perm(self._code(self.perm_image), self.image_a))
        self.assertFalse(self.user1.has_perm(self._code(self.perm_meta), self.meta_a))

        mixed_images = ReceiptImage.objects.filter(
            pk__in=[self.image_a.pk, self.image_b.pk],
        )
        mixed_meta = ReceiptImageMeta.objects.filter(
            pk__in=[self.meta_a.pk, self.meta_b.pk],
        )
        self.assertFalse(self.user.has_perm(self._code(self.perm_image), mixed_images))
        self.assertFalse(self.user.has_perm(self._code(self.perm_meta), mixed_meta))

    def test_shared_trust_does_not_grant_other_model_permissions(self):
        self._grant(self.trust_a, self.user, self.perm_receipt)
        reload_test_users(self)
        self.assertTrue(self.user.has_perm(self._code(self.perm_receipt), self.receipt_a))
        self.assertFalse(self.user.has_perm(self._code(self.perm_image), self.image_a))
        self.assertFalse(self.user.has_perm(self._code(self.perm_meta), self.meta_a))

    def test_filter_by_content_instance_and_queryset(self):
        for obj, trust in (
            (self.receipt_a, self.trust_a),
            (self.image_a, self.trust_a),
            (self.meta_a, self.trust_a),
            (self.receipt_b, self.trust_b),
            (self.image_b, self.trust_b),
            (self.meta_b, self.trust_b),
        ):
            qs = Trust.objects.filter_by_content(obj)
            self.assertEqual(list(qs.values_list('pk', flat=True)), [trust.pk])
            sql = self._sql(qs)
            self.assertTrue(
                'JOIN' in sql.upper() or RECEIPT_LOOKUP in sql,
                'filter_by_content must resolve Trust in SQL. SQL was: %s' % sql,
            )

        image_qs = ReceiptImage.objects.filter(pk=self.image_a.pk)
        self.assertEqual(
            list(Trust.objects.filter_by_content(image_qs).values_list('pk', flat=True)),
            [self.trust_a.pk],
        )
        meta_qs = ReceiptImageMeta.objects.filter(pk=self.meta_a.pk)
        self.assertEqual(
            list(Trust.objects.filter_by_content(meta_qs).values_list('pk', flat=True)),
            [self.trust_a.pk],
        )
        mixed = ReceiptImage.objects.filter(pk__in=[self.image_a.pk, self.image_b.pk])
        self.assertEqual(
            set(Trust.objects.filter_by_content(mixed).values_list('pk', flat=True)),
            {self.trust_a.pk, self.trust_b.pk},
        )
        empty = ReceiptImage.objects.none()
        self.assertFalse(Trust.objects.filter_by_content(empty).exists())
        self.assertIsInstance(Trust.objects.filter_by_content(self.meta_a), type(Trust.objects.all()))

    def test_missing_registration_denies(self):
        self._grant(self.trust_a, self.user, self.perm_note)
        reload_test_users(self)
        self.assertFalse(Content.is_content_model(UnregisteredReceiptNote))
        self.assertIsNone(Content.get_content_fieldlookup(UnregisteredReceiptNote))
        self.assertFalse(
            self.user.has_perm(self._code(self.perm_note), self.note_a)
        )
        self.assertFalse(Trust.objects.filter_by_content(self.note_a).exists())

    def test_compose_and_register_reject_invalid_lookups(self):
        with self.assertRaises(AttributeError):
            Content.compose_content_fieldlookup(UnregisteredReceiptNote, 'foo')
        with self.assertRaises(ValueError):
            Content.compose_content_fieldlookup(Receipt, '')
        with self.assertRaises(ValueError):
            Content.compose_content_fieldlookup(Receipt, 'image__meta')
        with self.assertRaises(AttributeError):
            Content.register_content(UnregisteredReceiptNote)

        key = get_short_model_name(UnregisteredReceiptNote)
        try:
            with self.assertRaises(ValueError):
                Content.register_content(UnregisteredReceiptNote, 'None__image')
            with self.assertRaises(ValueError):
                Content.register_content(UnregisteredReceiptNote, '%s__image' % None)
            with self.assertRaises(ValueError):
                Content.register_content(UnregisteredReceiptNote, '')
            self.assertFalse(Content.is_content_model(UnregisteredReceiptNote))

            Content.register_content(UnregisteredReceiptNote, 'not_a_trust_relation')
            self.assertTrue(Content.is_content_model(UnregisteredReceiptNote))
            with self.assertRaises(Exception):
                list(Trust.objects.filter_by_content(self.note_a))
        finally:
            Content._contents.pop(key, None)
        self.assertFalse(Content.is_content_model(UnregisteredReceiptNote))

    def test_resolution_is_orm_path_not_python_loop(self):
        qs = Trust.objects.filter_by_content(self.meta_a)
        sql = self._sql(qs)
        upper = sql.upper()
        self.assertIn('JOIN', upper)
        self.assertIn('trusts_tests_receipt', sql)
        self.assertIn('trusts_tests_receiptimage', sql)
        self.assertIn('trusts_tests_receiptimagemeta', sql)
        field_names = {f.name for f in Trust._meta.get_fields()}
        self.assertIn(RECEIPT_LOOKUP, field_names)
        # Two hops stay in the lookup string consumed by one QuerySet.filter.
        self.assertEqual(
            Content.get_content_fieldlookup(ReceiptImageMeta).count('__'),
            2,
        )
