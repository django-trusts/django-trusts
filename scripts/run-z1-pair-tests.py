#!/usr/bin/env python3
"""Run Zero's complete top-level suite from the Zero checkout.

Historical Trust/Content/Junction coverage lives in Zero
``tests/legacy/`` after #37 STAGE 1. Do not import those modules from
core package paths.
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
if not (zero / 'tests' / 'legacy' / 'test_historical.py').is_file():
    raise SystemExit(
        'ZERO_CHECKOUT missing tests/legacy/ (need #37 STAGE 1) at %s' % zero
    )

env = os.environ.copy()
env['KERNEL_CHECKOUT'] = str(kernel)
env.pop('DJANGO_SETTINGS_MODULE', None)
result = subprocess.run(
    [sys.executable, '-m', 'tests.runtests'],
    cwd=str(zero),
    env=env,
)
raise SystemExit(result.returncode)
