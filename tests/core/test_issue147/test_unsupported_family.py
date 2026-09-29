"""Unsupported-family fail-closed boundary for Core lockfile v1.

A configured handle whose family is not relationship fails the
whole snapshot. The relationship handle beside it is not emitted
and is not a reason to continue.
"""

from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.core import (
    TrustsConfigurationError,
    TrustsRegistry,
)
from trusts.policy_lock import build_policy_manifest

from tests.core.test_issue147.support import (
    _direct,
    _handle,
    _installed_owner,
    _policy_models,
)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class UnsupportedFamilyFailClosedTest(SimpleTestCase):
    """Configured non-relationship family fails the whole snapshot closed."""

    def test_unsupported_family_fails_closed_for_the_whole_snapshot(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        kept = TrustsRegistry()
        _direct(kept, Grant)
        good = _handle(kept, 'tests.policy.good')
        bad_registry = TrustsRegistry()
        bad = _handle(bad_registry, 'tests.policy.fold')

        with _installed_owner('tests.policy.good', 'relationship'), \
                _installed_owner('tests.policy.fold', 'ordered_fold'):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([good, bad])
        message = str(ctx.exception)
        self.assertIn('tests.policy.fold', message)
        self.assertIn('ordered_fold', message)
        self.assertIn('relationship', message)
        self.assertNotIn('tests.policy.good', message)

