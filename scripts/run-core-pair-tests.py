#!/usr/bin/env python3
"""Run the complete applicable legacy core suite against core + Zero IIa.

Uses ``tests.pair_settings`` (ZeroConfig only; no library ``'trusts'``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
kernel = Path(os.environ.get('KERNEL_CHECKOUT', ROOT)).resolve()
zero = Path(os.environ.get('ZERO_CHECKOUT', ROOT / '.deps' / 'django-trusts-zero')).resolve()

if not (zero / 'trusts' / 'zero' / 'apps.py').is_file():
    raise SystemExit('ZERO_CHECKOUT missing trusts.zero at %s' % zero)

cleaned = []
for p in sys.path:
    if '__editable__.django_trusts' in str(p):
        continue
    abs_p = Path(p or os.getcwd()).resolve()
    if abs_p in {ROOT.resolve(), kernel, zero}:
        continue
    if (abs_p / 'trusts' / '__init__.py').is_file() and abs_p != kernel:
        continue
    cleaned.append(p)
sys.path[:] = cleaned
sys.path.insert(0, str(kernel))
sys.path.append(str(zero))

os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.pair_settings'
os.environ.pop('TRUSTS_ZERO_SKIP_C2_SHAPE', None)
os.chdir(str(kernel))

import tests.runtests as rt
rt.runtests(rt.PAIR_LEGACY_SUITE)
