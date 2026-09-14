#!/usr/bin/env python3
"""Rewrite P2 dual-write leftovers so they assert C2 Core deletion.

Pinned OrderedFold P2 ``c8c649aa5278db2b11fc380fa1646ae73df471ac`` still
proves C1 coexistence: ``core.OrderedFold``, ``import trusts.ordered_fold``,
and Core ``registry.strategies``. C2 deletes those surfaces. PR-scoped
compatibility jobs apply this rewrite to the pinned P2 checkout and then
run the unmodified product suite (package, registration, backend,
helpers, fixed-query, #100, PostgreSQL).
"""

from __future__ import annotations

import argparse
from pathlib import Path

P2_SHA = 'c8c649aa5278db2b11fc380fa1646ae73df471ac'

DECLARATION_OLD = """\
    def test_declaration_types_are_extension_owned(self):
        self.assertIsNot(OrderedFold, core.OrderedFold)
        self.assertIsNot(PermissionMaskDomain, core.PermissionMaskDomain)
        self.assertIsNot(MaskEntry, core.MaskEntry)
        self.assertIsNot(PolarityMap, core.PolarityMap)
        self.assertIsNot(FlatToken, core.FlatToken)
        self.assertEqual(OrderedFold.__module__, 'trusts_ordered_fold')
        self.assertEqual(register_ordered_fold.__module__, 'trusts_ordered_fold.registry')
"""

DECLARATION_NEW = """\
    def test_declaration_types_are_extension_owned(self):
        for name in (
            'OrderedFold',
            'PermissionMaskDomain',
            'MaskEntry',
            'PolarityMap',
            'FlatToken',
        ):
            self.assertFalse(hasattr(core, name))
        self.assertEqual(OrderedFold.__module__, 'trusts_ordered_fold')
        self.assertEqual(register_ordered_fold.__module__, 'trusts_ordered_fold.registry')
"""

IMPORT_ROOT_OLD = """\
    def test_import_root_is_not_trusts_ordered_fold_submodule(self):
        import trusts.ordered_fold as core_impl

        self.assertNotEqual(package.__file__, core_impl.__file__)
        self.assertNotIn('trusts_ordered_fold', core_impl.__file__)
"""

IMPORT_ROOT_NEW = """\
    def test_import_root_is_not_trusts_ordered_fold_submodule(self):
        with self.assertRaises(ModuleNotFoundError):
            __import__('trusts.ordered_fold')
        self.assertEqual(package.__name__, 'trusts_ordered_fold')
        self.assertNotIn('/trusts/ordered_fold.py', package.__file__)
"""

CORE_HANDLE_OLD = """\
        self.assertEqual(core_handle.registry.strategies, ())
"""

CORE_HANDLE_NEW = """\
        self.assertFalse(hasattr(core_handle.registry, 'strategies'))
        self.assertFalse(hasattr(core_handle, 'register_ordered_fold'))
"""

REPLACEMENTS = (
    ('tests/test_facade.py', DECLARATION_OLD, DECLARATION_NEW),
    ('tests/test_facade.py', IMPORT_ROOT_OLD, IMPORT_ROOT_NEW),
    ('tests/test_register.py', CORE_HANDLE_OLD, CORE_HANDLE_NEW),
)


def _already_adapted(text: str, new: str, old: str) -> bool:
    return new in text and old not in text


def adapt(checkout: Path) -> None:
    for rel, old, new in REPLACEMENTS:
        path = checkout / rel
        if not path.is_file():
            raise SystemExit('missing %s in %s' % (rel, checkout))
        text = path.read_text(encoding='utf-8')
        if _already_adapted(text, new, old):
            continue
        if old not in text:
            raise SystemExit(
                '%s does not contain the P2 %s coexistence block' % (rel, P2_SHA)
            )
        path.write_text(text.replace(old, new, 1), encoding='utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'checkout',
        type=Path,
        help='django-trusts-ordered-fold checkout at the P2 squash',
    )
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    adapt(checkout)
    print('adapted OrderedFold P2 coexistence tests for C2 at %s' % checkout)


if __name__ == '__main__':
    main()
