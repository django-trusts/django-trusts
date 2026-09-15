#!/usr/bin/env python3
"""Installed-wheel Pyright proof for public ``configured_backend()`` inference.

Must run from outside the checkout after installing the built wheel.
A valid consumer must be clean; ``t.not_a_field`` must be a diagnostic.
The consumer uses the documented ``TrustsImplementationConfig`` path and
does not import or annotate ``BackendHandle``.
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

from trusts.apps import TrustsImplementationConfig


class AnnotatedGrant(models.Model):
    user: object
    permission: object
    document: object
    team: object

    class Meta:
        app_label = "pyright_proof"


class DocumentsConfig(TrustsImplementationConfig):
    name = "pyright_proof"
    trusts_backend_paths = (
        "documents.backends.DocumentBackend",
    )

    def ready(self):
        super().ready()
        backend = self.configured_backend()
        backend.register(
            trust=AnnotatedGrant,
            user=lambda t: t.user,
            permission=lambda t: t.permission,
            content=lambda t: t.document,
            condition=lambda t: t.team == t.document,
        )
'''

MISSING_SOURCE = '''\
from django.db import models

from trusts.apps import TrustsImplementationConfig


class AnnotatedGrant(models.Model):
    user: object
    permission: object
    document: object
    team: object

    class Meta:
        app_label = "pyright_proof"


class DocumentsConfig(TrustsImplementationConfig):
    name = "pyright_proof"
    trusts_backend_paths = (
        "documents.backends.DocumentBackend",
    )

    def ready(self):
        super().ready()
        backend = self.configured_backend()
        backend.register(
            trust=AnnotatedGrant,
            user=lambda t: t.user,
            permission=lambda t: t.permission,
            content=lambda t: t.document,
            condition=lambda t: t.not_a_field == t.document,
        )
'''

CONFIG = '''\
{
  "typeCheckingMode": "basic",
  "pythonVersion": "3.12",
  "reportMissingImports": "warning"
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
    if ok_run.returncode != 0:
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
    payload = json.loads(miss_run.stdout or '{}')
    diagnostics = payload.get('generalDiagnostics') or []
    texts = [
        '%s %s' % (item.get('message', ''), item.get('rule', ''))
        for item in diagnostics
    ]
    joined = '\n'.join(texts)
    if miss_run.returncode == 0:
        raise SystemExit(
            'missing-attribute consumer was clean; expected a diagnostic'
        )
    if 'not_a_field' not in joined and not any(
        'not_a_field' in (item.get('file', '') + item.get('message', ''))
        for item in diagnostics
    ):
        raw_messages = [item.get('message', '') for item in diagnostics]
        if not any('not_a_field' in msg for msg in raw_messages):
            raise SystemExit(
                'missing-attribute consumer failed, but not for not_a_field: %r'
                % raw_messages
            )
    print('pyright valid consumer clean')
    print('pyright missing attribute diagnostic')
    return 0


if __name__ == '__main__':
    sys.exit(main())
