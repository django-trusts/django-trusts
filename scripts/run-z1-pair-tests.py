#!/usr/bin/env python3
"""Run Zero's complete top-level suite from the Zero checkout.

Historical Trust/Content/Junction coverage lives in Zero
``tests/legacy/`` after #37 STAGE 1. Do not import those modules from
core package paths.

Pinned Zero ``18e87a63ff5079298e1ee330b888b4ff86551e1f`` still asserts
that a new ``TrustsRegistry`` is unbound. C1 self-binds at construct.
Override/unbind Zero tests stay. Drop the omit when C2 retargets the
companion pin.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
zero = Path(os.environ.get('ZERO_CHECKOUT', ROOT / '.deps' / 'django-trusts-zero')).resolve()
kernel = Path(os.environ.get('KERNEL_CHECKOUT', ROOT)).resolve()

# Pinned Zero 18e87a63ff5079298e1ee330b888b4ff86551e1f asserts the
# pre-C1 unbound default. Z2 updates that test; C2 drops this omit.
OMIT_ZERO_UNBOUND_DEFAULT = (
    'tests.legacy.test_issue54.ConditionLookupBindTest.'
    'test_unbound_is_none_and_bind_is_zero_sql',
)

DRIVER = r'''
import os
import sys
import unittest

import django
from django.conf import settings
from django.test.utils import get_runner

from tests.runtests import NORMAL_SUITE

OMIT = set(%r)

django.setup()
TestRunner = get_runner(settings)
runner = TestRunner(verbosity=1, interactive=False)
loader = runner.test_loader
labels = []
for label in NORMAL_SUITE:
    if label != 'tests.legacy.test_issue54':
        labels.append(label)
        continue
    for test in loader.loadTestsFromName(label):
        stack = [test]
        while stack:
            item = stack.pop()
            if isinstance(item, unittest.TestSuite):
                stack.extend(item)
                continue
            name = item.id()
            if name not in OMIT:
                labels.append(name)
failures = runner.run_tests(labels)
sys.exit(bool(failures))
''' % (OMIT_ZERO_UNBOUND_DEFAULT,)


if not (zero / 'tests' / 'runtests.py').is_file():
    raise SystemExit('ZERO_CHECKOUT missing tests/runtests.py at %s' % zero)
if not (zero / 'tests' / 'legacy' / 'test_historical.py').is_file():
    raise SystemExit(
        'ZERO_CHECKOUT missing tests/legacy/ (need #37 STAGE 1) at %s' % zero
    )

env = os.environ.copy()
env['KERNEL_CHECKOUT'] = str(kernel)
env.pop('DJANGO_SETTINGS_MODULE', None)
result = subprocess.run(
    [sys.executable, '-c', DRIVER],
    cwd=str(zero),
    env=env,
)
raise SystemExit(result.returncode)
