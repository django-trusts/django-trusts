#!/usr/bin/env python3
"""Run Zero Z1 tests that are valid against real C2.

Invokes Zero's runner from the Zero checkout so ``tests`` is Zero's
package. Skips ``tests.test_duplicate_label`` (Neg-Z1-C1 gate).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
zero = Path(os.environ.get('ZERO_CHECKOUT', ROOT / '.deps' / 'django-trusts-zero')).resolve()
kernel = Path(os.environ.get('KERNEL_CHECKOUT', ROOT)).resolve()

if not (zero / 'tests' / 'runtests.py').is_file():
    raise SystemExit('ZERO_CHECKOUT missing tests/runtests.py at %s' % zero)

PROBE = r'''
import tests.runtests as rt
rt.NORMAL_SUITE = [
    "tests.test_appconfig",
    "tests.test_migrations",
    "tests.test_packaging",
    "tests.test_codec",
    "tests.test_smoke",
]
rt.runtests()
'''

env = os.environ.copy()
env['KERNEL_CHECKOUT'] = str(kernel)
env['TRUSTS_ZERO_SKIP_C2_SHAPE'] = '1'
env.pop('DJANGO_SETTINGS_MODULE', None)
result = subprocess.run(
    [sys.executable, '-c', PROBE],
    cwd=str(zero),
    env=env,
)
raise SystemExit(result.returncode)
