"""Provisional-contract regression for the complete OrderedFold public surface."""

from inspect import getdoc

from django.test import SimpleTestCase

from trusts import core


class OrderedFoldProvisionalApiTest(SimpleTestCase):
    public_surface = (
        core.BackendHandle.register_ordered_fold,
        core.OrderedFold,
        core.PermissionMaskDomain,
        core.MaskEntry,
        core.PolarityMap,
        core.FlatToken,
    )

    def test_every_public_entry_point_is_marked_provisional(self):
        for entry_point in self.public_surface:
            with self.subTest(entry_point=entry_point.__qualname__):
                doc = getdoc(entry_point)
                self.assertIn('Provisional API:', doc)
                self.assertIn('excluded from the normal 1.x', doc)
                self.assertIn('future feature release', doc)

    def test_core_defines_the_complete_supported_surface(self):
        doc = getdoc(core)
        self.assertIn(
            'complete supported OrderedFold\nsurface',
            doc,
        )
        self.assertIn(
            'other OrderedFold compiler, validation, expression, and renderer\n'
            'names are implementation details',
            doc,
        )


    def test_internal_helpers_are_not_reexported_from_core(self):
        for name in (
            'OrderedFoldAllowed',
            'RegisteredStrategy',
            'ordered_fold_connection_supported',
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(core, name))

    def test_implementation_module_does_not_advertise_helpers(self):
        doc = getdoc(__import__('trusts.ordered_fold', fromlist=['']))
        self.assertIn(
            'The supported construction surface is',
            doc,
        )
        self.assertIn(
            'Every other name in this module',
            doc,
        )
        self.assertIn(
            'is an implementation detail',
            doc,
        )
