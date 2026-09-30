"""Lockfile regressions for the SQL-first policy export.

The kernel and pair suites load this package. ``load_tests`` pulls in
the SQL export slice and the suite-wiring check.
"""

SLICE_MODULES = (
    'tests.core.test_issue147.test_sql_export',
    'tests.core.test_issue147.test_suite_wiring',
    'tests.core.test_issue147.test_yaml_lock',
)


def load_tests(loader, tests, pattern):
    """Load the audit slices. ``pattern`` is the unittest hook argument."""
    del pattern
    for name in SLICE_MODULES:
        tests.addTests(loader.loadTestsFromName(name))
    return tests
