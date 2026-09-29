"""Lockfile regressions for issue #147, arranged for audit.

The kernel and pair suites load this package. ``load_tests`` pulls in
one module per accepted slice, plus the unsupported-family boundary:

- ``test_c1_snapshot`` — projection, fingerprints, labels, renderer profile
- ``test_unsupported_family`` — non-relationship family fails the snapshot closed
- ``test_c2_canonical`` — quiet bytes and the strict reader
- ``test_c3_commands`` — generate, check, presence, and the human diff
- ``test_c4a_runtime`` — sticky runtime verification before every result
- ``test_c4b_isolation`` — late registration and fresh-process sticky state
- ``test_suite_wiring`` — suite labels and the single authorization gate

``PortableOtherCompiler`` stays on this module so its import identity
remains ``tests.core.test_issue147.PortableOtherCompiler``.
"""

from trusts.core import PlanQueryCompiler

SLICE_MODULES = (
    'tests.core.test_issue147.test_c1_snapshot',
    'tests.core.test_issue147.test_unsupported_family',
    'tests.core.test_issue147.test_c2_canonical',
    'tests.core.test_issue147.test_c3_commands',
    'tests.core.test_issue147.test_c4a_runtime',
    'tests.core.test_issue147.test_c4b_isolation',
    'tests.core.test_issue147.test_suite_wiring',
)


class PortableOtherCompiler(PlanQueryCompiler):
    """Module-level compiler so its identity round-trips through import."""


def load_tests(loader, tests, pattern):
    """Load the audit slices. ``pattern`` is the unittest hook argument."""
    del pattern
    for name in SLICE_MODULES:
        tests.addTests(loader.loadTestsFromName(name))
    return tests
