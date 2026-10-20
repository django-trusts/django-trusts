#!/usr/bin/env python3
"""Installed-wheel Pyright proof for recorder ``register`` inference.

Must run from outside the checkout after installing the built wheel.
A valid consumer must be clean; ``t.not_a_field`` must be a diagnostic.
The consumer registers on ``TrustsConfigMixin.recorder`` and does not
import or annotate ``BackendHandle``.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


OK_SOURCE = '''\
from django.db import models

from trusts.apps import TrustsConfigMixin


class AnnotatedGrant(models.Model):
    user: object
    permission: object
    document: object
    team: object

    class Meta:
        app_label = "pyright_proof"


class DocumentsConfig(TrustsConfigMixin):
    name = "pyright_proof"
    label = "pyright_proof"

    def ready(self):
        self.recorder.register(
            trust=AnnotatedGrant,
            user=lambda t: t.user,
            permission=lambda t: t.permission,
            content=lambda t: t.document,
            condition=lambda t: t.team == t.document,
        )
        super().ready()
'''

MISSING_SOURCE = '''\
from django.db import models

from trusts.apps import TrustsConfigMixin


class AnnotatedGrant(models.Model):
    user: object
    permission: object
    document: object
    team: object

    class Meta:
        app_label = "pyright_proof"


class DocumentsConfig(TrustsConfigMixin):
    name = "pyright_proof"
    label = "pyright_proof"

    def ready(self):
        self.recorder.register(
            trust=AnnotatedGrant,
            user=lambda t: t.user,
            permission=lambda t: t.permission,
            content=lambda t: t.document,
            condition=lambda t: t.not_a_field == t.document,
        )
        super().ready()
'''

# Host app the consumer imports. It is not part of the consumer.
FIXTURE_BACKEND = '''\
from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackendMixin


class DocumentBackend(TrustModelBackendMixin, ModelBackend):
    pass
'''

CONFIG = '''\
{
  "typeCheckingMode": "basic",
  "pythonVersion": "3.12",
  "reportMissingImports": "warning",
  "extraPaths": ["fixture"],
  "executionEnvironments": [
    {"root": ".", "extraPaths": ["fixture"]}
  ]
}
'''


def _reject_handle_annotation(source: str, label: str) -> None:
    if 'BackendHandle' in source:
        raise SystemExit(
            '%s consumer must not import or annotate BackendHandle' % label
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', required=True)
    args = parser.parse_args()
    checkout = Path(args.checkout).resolve()
    cwd = Path.cwd().resolve()
    if cwd == checkout or checkout in cwd.parents:
        raise SystemExit(
            'Refuse to run from the checkout (%s). cd to a temporary directory.'
            % cwd
        )

    _reject_handle_annotation(OK_SOURCE, 'valid')
    _reject_handle_annotation(MISSING_SOURCE, 'missing-attribute')

    ok = Path('register_ok.py')
    missing = Path('register_missing.py')
    ok.write_text(OK_SOURCE)
    missing.write_text(MISSING_SOURCE)
    fixture = Path('fixture') / 'documents'
    fixture.mkdir(parents=True)
    (fixture / '__init__.py').write_text('')
    (fixture / 'backends.py').write_text(FIXTURE_BACKEND)
    Path('pyrightconfig.json').write_text(CONFIG)

    pyright = shutil.which('pyright')
    if pyright is None:
        raise SystemExit('pyright is not installed')

    env = dict(os.environ)
    env['PYTHONPATH'] = ''

    ok_run = subprocess.run(
        [pyright, '--outputjson', str(ok)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    ok_diagnostics = _diagnostics(ok_run)
    if ok_run.returncode != 0 or ok_diagnostics:
        raise SystemExit(
            'valid consumer failed Pyright:\n%s\n%s'
            % (ok_run.stdout, ok_run.stderr)
        )

    miss_run = subprocess.run(
        [pyright, '--outputjson', str(missing)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    diagnostics = _diagnostics(miss_run)
    if len(diagnostics) != 1 or 'not_a_field' not in diagnostics[0].get('message', ''):
        raise SystemExit(
            'missing-attribute consumer diagnostics: %r'
            % diagnostics
        )
    print('pyright valid consumer clean')
    print('pyright missing attribute diagnostic')
    return 0


def _diagnostics(run: subprocess.CompletedProcess[str]) -> list:
    payload = json.loads(run.stdout or '{}')
    return list(payload.get('generalDiagnostics') or [])


if __name__ == '__main__':
    sys.exit(main())
