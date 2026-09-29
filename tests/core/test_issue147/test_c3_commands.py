"""C3. Generate, check, presence, and the fingerprint-first diff."""

import copy
import json
import os
import subprocess
import sys
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.core.management import (
    call_command,
    get_commands,
    load_command_class,
)
from django.core.management.base import CommandError
from django.test import (
    SimpleTestCase,
    override_settings,
)

from trusts.core import TrustsConfigurationError
from trusts.policy_lock import (
    ALONG_UNSUPPORTED,
    CONVENTIONAL_LOCKFILE_NAME,
    GENERIC_UNSUPPORTED_ALONG_PROFILE,
    build_policy_manifest,
    canonicalize,
    check_policy_lockfile,
    format_policy_diff,
    generate_policy_lockfile,
    resolve_lockfile_path,
)

from tests.core.test_issue147.support import (
    REPO_ROOT,
    _eq_expr,
    _forbid_sql,
    _lock_document,
    _minimal_along,
    _sha,
    _stamp_registration,
)


class PolicyLockCommandTest(SimpleTestCase):
    """C3 path, presence, generate, check, and semantic diff."""

    def test_commands_register_without_a_management_package(self):
        import trusts.policy_commands as policy_commands
        import trusts.policy_lock as policy_lock

        root = REPO_ROOT
        self.assertFalse((root / 'trusts' / 'management').exists())
        self.assertTrue(hasattr(policy_lock, 'ensure_policy_lockfile_verified'))
        source = Path(policy_commands.__file__).read_text(encoding='utf-8')
        self.assertNotIn('ensure_policy_lockfile_verified(', source)
        commands = get_commands()
        self.assertEqual(
            commands['trusts_policy_generate'], 'trusts.policy_commands',
        )
        self.assertEqual(
            commands['trusts_policy_check'], 'trusts.policy_commands',
        )
        generate = load_command_class(
            'trusts.policy_commands', 'trusts_policy_generate',
        )
        check = load_command_class(
            'trusts.policy_commands', 'trusts_policy_check',
        )
        self.assertEqual(type(generate).__name__, 'GenerateCommand')
        self.assertEqual(type(check).__name__, 'CheckCommand')

    def test_unusable_base_dir_and_relative_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as cwd_s:
            cwd = Path(cwd_s)
            decoy = cwd / 'rel.lock.json'
            decoy.write_text('from-cwd')
            previous = os.getcwd()
            os.chdir(cwd)
            try:
                with override_settings(BASE_DIR=None, TRUSTS_POLICY_LOCKFILE=None):
                    with patch('os.getcwd', side_effect=AssertionError('cwd')):
                        with patch(
                            'pathlib.Path.resolve',
                            side_effect=AssertionError('resolve'),
                        ):
                            with self.assertRaises(TrustsConfigurationError) as ctx:
                                resolve_lockfile_path()
                    self.assertIn('BASE_DIR', str(ctx.exception))
                    self.assertIn('working directory', str(ctx.exception))
                with override_settings(BASE_DIR='relative-base', TRUSTS_POLICY_LOCKFILE=None):
                    with self.assertRaises(TrustsConfigurationError) as ctx:
                        resolve_lockfile_path()
                    self.assertIn('BASE_DIR', str(ctx.exception))
                with override_settings(TRUSTS_POLICY_LOCKFILE=''):
                    with self.assertRaises(TrustsConfigurationError) as ctx:
                        resolve_lockfile_path()
                    self.assertIn('absolute', str(ctx.exception))
                    self.assertIn("''", str(ctx.exception))
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    check_policy_lockfile(override='rel.lock.json')
                self.assertIn('working directory', str(ctx.exception))
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    generate_policy_lockfile(override='rel.lock.json')
                self.assertIn('working directory', str(ctx.exception))
            finally:
                os.chdir(previous)
            self.assertEqual(decoy.read_text(), 'from-cwd')
            self.assertFalse((cwd / CONVENTIONAL_LOCKFILE_NAME).exists())

    def test_conventional_absence_ignores_cwd_and_parent_lockfiles(self):
        with tempfile.TemporaryDirectory() as base_s, tempfile.TemporaryDirectory() as cwd_s:
            base = Path(base_s)
            project = base / 'project'
            project.mkdir()
            cwd = Path(cwd_s)
            (cwd / CONVENTIONAL_LOCKFILE_NAME).write_text('from-cwd')
            (base / CONVENTIONAL_LOCKFILE_NAME).write_text('from-parent')
            previous = os.getcwd()
            os.chdir(cwd)
            try:
                with override_settings(
                    BASE_DIR=str(project), TRUSTS_POLICY_LOCKFILE=None,
                ):
                    with patch('os.getcwd', side_effect=AssertionError('cwd')):
                        location = resolve_lockfile_path()
                        with patch(
                            'trusts.policy_lock.build_policy_manifest',
                            side_effect=AssertionError('built'),
                        ):
                            inactive = check_policy_lockfile()
                    self.assertFalse(location.explicit)
                    self.assertEqual(location.state, 'absent')
                    self.assertEqual(
                        location.path, project / CONVENTIONAL_LOCKFILE_NAME,
                    )
                    self.assertEqual(inactive.status, 'inactive')
                    self.assertFalse(location.path.exists())
                    stdout = StringIO()
                    call_command('trusts_policy_check', stdout=stdout)
                    self.assertIn(
                        'policy lock inactive: %s' % location.path,
                        stdout.getvalue(),
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(
                (cwd / CONVENTIONAL_LOCKFILE_NAME).read_text(), 'from-cwd',
            )
            self.assertEqual(
                (base / CONVENTIONAL_LOCKFILE_NAME).read_text(), 'from-parent',
            )

    def test_generate_and_check_round_trip_without_sql(self):
        with tempfile.TemporaryDirectory() as base_s, tempfile.TemporaryDirectory() as cwd_s:
            project = Path(base_s) / 'project'
            project.mkdir()
            cwd = Path(cwd_s)
            (cwd / CONVENTIONAL_LOCKFILE_NAME).write_text('from-cwd')
            previous = os.getcwd()
            os.chdir(cwd)
            try:
                with override_settings(
                    BASE_DIR=str(project), TRUSTS_POLICY_LOCKFILE=None,
                ):
                    with _forbid_sql():
                        with patch(
                            'trusts.policy_lock.check_policy_lockfile',
                            side_effect=AssertionError('checked'),
                        ):
                            written = generate_policy_lockfile()
                    expected = canonicalize(build_policy_manifest())
                    self.assertEqual(written, project / CONVENTIONAL_LOCKFILE_NAME)
                    self.assertEqual(written.read_bytes(), expected)
                    self.assertTrue(expected.endswith(b'\n'))
                    self.assertNotIn(b'\r', expected)
                    self.assertNotIn(b'diagnostics', expected)
                    names = sorted(path.name for path in project.iterdir())
                    self.assertEqual(names, [CONVENTIONAL_LOCKFILE_NAME])
                    with _forbid_sql():
                        match = check_policy_lockfile()
                    self.assertEqual(match.status, 'match')
                    stdout = StringIO()
                    call_command('trusts_policy_check', stdout=stdout)
                    self.assertIn('policy lock ok: %s' % written, stdout.getvalue())
            finally:
                os.chdir(previous)
            self.assertEqual(
                (cwd / CONVENTIONAL_LOCKFILE_NAME).read_text(), 'from-cwd',
            )

    def test_explicit_path_create_replace_and_setting_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chosen = root / 'chosen.lock.json'
            other = root / 'other.lock.json'
            conventional = root / CONVENTIONAL_LOCKFILE_NAME
            with override_settings(
                BASE_DIR=str(root), TRUSTS_POLICY_LOCKFILE=str(other),
            ):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    check_policy_lockfile()
                self.assertIn('file is missing', str(ctx.exception))
                self.assertIn(str(other), str(ctx.exception))
                self.assertFalse(other.exists())
                with patch(
                    'trusts.policy_lock.build_policy_manifest',
                    side_effect=AssertionError('built'),
                ):
                    with self.assertRaises(TrustsConfigurationError):
                        check_policy_lockfile()
                self.assertFalse(other.exists())
                stdout = StringIO()
                with _forbid_sql():
                    call_command(
                        'trusts_policy_generate', lockfile=str(chosen),
                        stdout=stdout,
                    )
                self.assertIn('wrote %s' % chosen, stdout.getvalue())
                self.assertTrue(chosen.is_file())
                self.assertFalse(other.exists())
                self.assertFalse(conventional.exists())
                chosen.write_bytes(b'not-json')
                replaced = generate_policy_lockfile()
                self.assertEqual(replaced, other)
                self.assertEqual(
                    other.read_bytes(), canonicalize(build_policy_manifest()),
                )
                self.assertEqual(chosen.read_bytes(), b'not-json')

    def test_missing_parent_permission_and_directory_are_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / 'missing-parent' / 'trusts-policy.lock.json'
            with self.assertRaises(TrustsConfigurationError) as ctx:
                generate_policy_lockfile(override=str(missing))
            self.assertIn(
                'parent directory is missing: %s' % missing.parent,
                str(ctx.exception),
            )
            self.assertNotIn('file is missing', str(ctx.exception))
            self.assertFalse(missing.parent.exists())
            with self.assertRaises(TrustsConfigurationError) as ctx:
                check_policy_lockfile(override=str(missing))
            self.assertIn('parent directory is missing', str(ctx.exception))
            self.assertNotIn('permission denied', str(ctx.exception))

            parent_file = root / 'not-a-dir'
            parent_file.write_text('x')
            nested = parent_file / 'trusts-policy.lock.json'
            with self.assertRaises(TrustsConfigurationError) as ctx:
                check_policy_lockfile(override=str(nested))
            self.assertIn('not a directory', str(ctx.exception))
            with self.assertRaises(TrustsConfigurationError) as ctx:
                generate_policy_lockfile(override=str(nested))
            self.assertIn(
                'parent is not a directory: %s' % parent_file,
                str(ctx.exception),
            )
            self.assertTrue(parent_file.is_file())

            ghost = root / 'ghost-base'
            with override_settings(BASE_DIR=str(ghost), TRUSTS_POLICY_LOCKFILE=None):
                inactive = check_policy_lockfile()
                self.assertEqual(inactive.status, 'inactive')
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    generate_policy_lockfile()
            self.assertIn('parent directory is missing', str(ctx.exception))
            self.assertFalse(ghost.exists())

            target = root / 'locked.json'
            target.write_bytes(b'{}')
            with patch(
                'trusts.policy_lock.os.stat',
                side_effect=PermissionError('denied'),
            ):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    check_policy_lockfile(override=str(target))
            self.assertIn('permission denied: %s' % target, str(ctx.exception))
            self.assertNotIn('parent directory is missing', str(ctx.exception))
            self.assertNotIn('file is missing', str(ctx.exception))
            with patch(
                'trusts.policy_lock.tempfile.mkstemp',
                side_effect=PermissionError('denied'),
            ):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    generate_policy_lockfile(override=str(root / 'new.lock.json'))
            self.assertIn('permission denied', str(ctx.exception))
            self.assertFalse((root / 'new.lock.json').exists())

            directory = root / 'dir.lock.json'
            directory.mkdir()
            with self.assertRaises(TrustsConfigurationError) as ctx:
                generate_policy_lockfile(override=str(directory))
            self.assertIn('is a directory', str(ctx.exception))
            self.assertTrue(directory.is_dir())
            with self.assertRaises(TrustsConfigurationError) as ctx:
                check_policy_lockfile(override=str(directory))
            self.assertIn('is a directory', str(ctx.exception))

            present = root / 'present.lock.json'
            present.write_bytes(b'{}')
            with patch.object(
                Path, 'read_bytes', side_effect=PermissionError('denied'),
            ):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    check_policy_lockfile(override=str(present))
            self.assertIn('permission denied: %s' % present, str(ctx.exception))
            self.assertNotIn('file is missing', str(ctx.exception))
            self.assertEqual(present.read_bytes(), b'{}')

    def test_malformed_documents_fail_closed_without_rewriting(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trusts-policy.lock.json'
            original = canonicalize(build_policy_manifest())
            target.write_bytes(b'{')
            with _forbid_sql():
                with patch(
                    'trusts.policy_lock.build_policy_manifest',
                    side_effect=AssertionError('built'),
                ):
                    with self.assertRaises(TrustsConfigurationError) as ctx:
                        check_policy_lockfile(override=str(target))
            self.assertIn('JSON', str(ctx.exception))
            self.assertEqual(target.read_bytes(), b'{')

            document = json.loads(original)
            document['schema_version'] = 2
            target.write_text(json.dumps(document), encoding='utf-8')
            with self.assertRaises(TrustsConfigurationError) as ctx:
                check_policy_lockfile(override=str(target))
            self.assertIn('schema_version', str(ctx.exception))

            document['schema_version'] = 1
            document['compiler_version'] = 9
            target.write_text(json.dumps(document), encoding='utf-8')
            with self.assertRaises(TrustsConfigurationError) as ctx:
                check_policy_lockfile(override=str(target))
            self.assertIn('compiler_version', str(ctx.exception))

            document['compiler_version'] = 1
            document['extra'] = True
            target.write_text(json.dumps(document), encoding='utf-8')
            with self.assertRaises(TrustsConfigurationError) as ctx:
                check_policy_lockfile(override=str(target))
            self.assertIn('extra', str(ctx.exception))
            self.assertTrue(target.read_text(encoding='utf-8').find('extra') >= 0)

            spaced = original.replace(b': ', b':  ')
            target.write_bytes(spaced)
            self.assertNotEqual(target.read_bytes(), original)
            match = check_policy_lockfile(override=str(target))
            self.assertEqual(match.status, 'match')
            self.assertEqual(target.read_bytes(), spaced)

            loaded = json.loads(original)
            loaded['diagnostics'] = {'note': 'hand edit'}
            target.write_text(json.dumps(loaded), encoding='utf-8')
            match = check_policy_lockfile(override=str(target))
            self.assertEqual(match.status, 'match')
            self.assertIn('diagnostics', target.read_text(encoding='utf-8'))
            generate_policy_lockfile(override=str(target))
            self.assertEqual(target.read_bytes(), original)
            self.assertNotIn(b'diagnostics', target.read_bytes())
            target.write_bytes(b'not-json')
            generate_policy_lockfile(override=str(target))
            self.assertEqual(target.read_bytes(), original)

    def test_build_failure_does_not_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trusts-policy.lock.json'
            with patch(
                'trusts.policy_lock.build_policy_manifest',
                side_effect=TrustsConfigurationError('unsupported family'),
            ):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    generate_policy_lockfile(override=str(target))
            self.assertIn('unsupported family', str(ctx.exception))
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_atomic_write_stays_in_the_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trusts-policy.lock.json'
            seen = {}
            real = tempfile.mkstemp

            def spy(*args, **kwargs):
                seen['dir'] = kwargs.get('dir')
                return real(*args, **kwargs)

            with patch('trusts.policy_lock.tempfile.mkstemp', spy):
                generate_policy_lockfile(override=str(target))
            self.assertEqual(Path(seen['dir']), Path(tmp))
            self.assertEqual(
                [path.name for path in Path(tmp).iterdir()],
                ['trusts-policy.lock.json'],
            )

    def test_diff_is_fingerprint_first_at_each_authorization_level(self):
        base = _lock_document()
        self.assertEqual(format_policy_diff(base, copy.deepcopy(base)), '')

        changed = copy.deepcopy(base)
        row = changed['handles'][0]['registrations'][0]
        row['user'] = ['other']
        _stamp_registration(row)
        diff = format_policy_diff(base, changed)
        self.assertIn('registration changed: app.Grant:document', diff)
        self.assertIn('likely change: label stable, fingerprint moved', diff)
        self.assertIn('path user: ["user"] -> ["other"]', diff)
        self.assertIn(base['handles'][0]['registrations'][0]['fingerprint'], diff)
        self.assertIn(row['fingerprint'], diff)
        self.assertNotIn('registration added:', diff)
        self.assertNotIn('registration removed:', diff)

        labeled = copy.deepcopy(base)
        labeled['handles'][0]['registrations'][0]['label'] = 'renamed'
        diff = format_policy_diff(base, labeled)
        self.assertIn(
            'label: app.Grant:document -> renamed', diff,
        )
        self.assertNotIn('likely change', diff)

        left = copy.deepcopy(base)
        right = copy.deepcopy(base)
        for document, condition in (
            (left, {
                'op': 'equal', 'left': ['team'], 'right': ['document'],
            }),
            (right, {
                'op': 'equal', 'left': ['team'], 'right': ['other'],
            }),
        ):
            row = document['handles'][0]['registrations'][0]
            row['condition'] = condition
            row['label'] = 'app.Grant:document+cond'
            _stamp_registration(row)
        diff = format_policy_diff(left, right)
        self.assertIn('condition:', diff)
        self.assertIn('likely change:', diff)

        left = copy.deepcopy(base)
        right = copy.deepcopy(base)
        for document, walk in ((left, ['node']), (right, ['other'])):
            row = document['handles'][0]['registrations'][0]
            row['along'] = _minimal_along()
            row['along']['walk_path'] = walk
            row['label'] = 'app.Grant:document+along:S:3'
            _stamp_registration(row)
        diff = format_policy_diff(left, right)
        self.assertIn('strategy along.walk_path:', diff)
        self.assertIn('["node"] -> ["other"]', diff)

        kind = copy.deepcopy(base)
        kind_row = kind['handles'][0]['registrations'][0]
        kind_row['kind'] = 'scoped'
        kind_row['fingerprint'] = _sha('cd')
        diff = format_policy_diff(base, kind)
        self.assertIn('strategy kind: any_path -> scoped', diff)

        crowded_left = copy.deepcopy(base)
        crowded_right = copy.deepcopy(base)
        seed = base['handles'][0]['registrations'][0]
        left_rows = []
        right_rows = []
        for user in ('aa', 'bb'):
            row = copy.deepcopy(seed)
            row['user'] = [user]
            row['label'] = 'app.Grant:document'
            _stamp_registration(row)
            left_rows.append(row)
        for user in ('cc', 'dd'):
            row = copy.deepcopy(seed)
            row['user'] = [user]
            row['label'] = 'app.Grant:document'
            _stamp_registration(row)
            right_rows.append(row)
        crowded_left['handles'][0]['registrations'] = left_rows
        crowded_right['handles'][0]['registrations'] = right_rows
        diff = format_policy_diff(crowded_left, crowded_right)
        self.assertNotIn('likely change', diff)
        self.assertEqual(diff.count('registration removed:'), 2)
        self.assertEqual(diff.count('registration added:'), 2)

        removed = copy.deepcopy(base)
        removed['handles'][0]['path'] = 'tests.policy.other'
        diff = format_policy_diff(base, removed)
        self.assertIn('handle removed: tests.policy.reader', diff)
        self.assertIn('handle added: tests.policy.other', diff)
        self.assertIn('registration removed:', diff)
        self.assertIn('registration added:', diff)

        compiler = copy.deepcopy(base)
        compiler['handles'][0]['compiler'] = 'trusts.core.OtherCompiler'
        compiler['handles'][0]['renderer']['along'] = ALONG_UNSUPPORTED
        compiler['handles'][0]['renderer']['profile'] = (
            GENERIC_UNSUPPORTED_ALONG_PROFILE
        )
        diff = format_policy_diff(base, compiler)
        self.assertIn(
            'compiler: trusts.core.PlanQueryCompiler -> trusts.core.OtherCompiler',
            diff,
        )
        self.assertIn('renderer.along: supported -> unsupported', diff)
        self.assertIn('renderer.profile:', diff)

        named_left = _lock_document(_eq_expr('rank', {'type': 'int', 'value': 1}))
        named_right = copy.deepcopy(named_left)
        named_right['handles'][0]['named_filters'][0]['expr'] = _eq_expr(
            'rank', {'type': 'int', 'value': 2},
        )
        named_right['handles'][0]['named_filters'][0]['fingerprint'] = _sha('ef')
        diff = format_policy_diff(named_left, named_right)
        self.assertIn('named filter changed: app.Doc:ranked', diff)
        self.assertIn('expr:', diff)
        added = copy.deepcopy(named_left)
        added['handles'][0]['named_filters'] = []
        diff = format_policy_diff(added, named_left)
        self.assertIn('named filter added: app.Doc:ranked', diff)
        diff = format_policy_diff(named_left, added)
        self.assertIn('named filter removed: app.Doc:ranked', diff)

        diff = format_policy_diff(
            {'schema_version': 1, 'compiler_version': 1, 'handles': []},
            {'schema_version': 2, 'compiler_version': 3, 'handles': []},
        )
        self.assertIn('schema_version: 1 -> 2', diff)
        self.assertIn('compiler_version: 1 -> 3', diff)

    def test_check_command_prints_human_diff_and_optional_raw_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trusts-policy.lock.json'
            generate_policy_lockfile(override=str(target))
            document = json.loads(target.read_text(encoding='utf-8'))
            handle = next(
                item for item in document['handles'] if item['registrations']
            )
            row = handle['registrations'][0]
            original_fingerprint = row['fingerprint']
            label = row['label']
            row['user'] = ['drift_user']
            _stamp_registration(row)
            self.assertEqual(row['label'], label)
            self.assertNotEqual(row['fingerprint'], original_fingerprint)
            target.write_text(json.dumps(document), encoding='utf-8')
            stdout = StringIO()
            with _forbid_sql():
                with self.assertRaises(CommandError) as ctx:
                    call_command(
                        'trusts_policy_check', lockfile=str(target),
                        stdout=stdout,
                    )
            text = stdout.getvalue()
            self.assertIn('registration changed: %s' % label, text)
            self.assertIn('likely change: label stable, fingerprint moved', text)
            self.assertIn('path user:', text)
            self.assertIn(original_fingerprint, text)
            self.assertIn(row['fingerprint'], text)
            self.assertNotIn('+++ live', text)
            self.assertIn('Policy lock drift: %s' % target, str(ctx.exception))

            verbose = StringIO()
            with self.assertRaises(CommandError):
                call_command(
                    'trusts_policy_check', lockfile=str(target),
                    verbosity=2, stdout=verbose,
                )
            raw = verbose.getvalue()
            self.assertIn('registration changed:', raw)
            self.assertIn('+++ live', raw)
            self.assertIn('--- recorded', raw)

            document = json.loads(
                canonicalize(build_policy_manifest()).decode('utf-8'),
            )
            for item in document['handles']:
                if item['registrations']:
                    item['registrations'].pop(0)
                    break
            target.write_text(json.dumps(document), encoding='utf-8')
            stdout = StringIO()
            with self.assertRaises(CommandError):
                call_command(
                    'trusts_policy_check', lockfile=str(target), stdout=stdout,
                )
            self.assertIn('registration added:', stdout.getvalue())

    def test_subprocess_check_command_fails_closed_when_explicit_file_is_missing(self):
        root = REPO_ROOT
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / 'trusts-policy.lock.json'
            env = os.environ.copy()
            env['PYTHONPATH'] = str(root) + os.pathsep + env.get('PYTHONPATH', '')
            env['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
            proc = subprocess.run(
                [
                    sys.executable, '-m', 'django', 'trusts_policy_check',
                    '--lockfile', str(missing),
                ],
                cwd=str(root),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertNotIn('Unknown command', proc.stderr)
            self.assertIn('Policy lock file is missing', proc.stderr)
            self.assertFalse(missing.exists())
