"""#195 C2: Core is relationship-only after OrderedFold deletion."""

import ast
from pathlib import Path

from django.test import SimpleTestCase

import trusts
import trusts.checks
import trusts.core as core
from tests.myapp.models import Document
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    QueryCompiler,
    RelationPlan,
    TrustsRegistry,
    _compiler_applies,
    any_plan_records,
)


ROOT = Path(__file__).resolve().parents[2]
FOLD_NAMES = (
    'OrderedFold',
    'PermissionMaskDomain',
    'MaskEntry',
    'PolarityMap',
    'FlatToken',
)


_FOLD_IMPORT_ROOTS = (
    'trusts.ordered_fold',
    'trusts_ordered_fold',
)


def _suite_sources(tests_root, module):
    """Return the Python sources a suite label loads.

    A label is either ``tests/core/<name>.py`` or a package directory
    of the same name. The ordered-fold import audit has to see both.
    """
    name = module.rsplit('.', 1)[-1]
    file_path = tests_root / ('%s.py' % name)
    if file_path.is_file():
        return [file_path]
    package_path = tests_root / name
    if (package_path / '__init__.py').is_file():
        return sorted(
            path for path in package_path.rglob('*.py')
            if path.is_file() and '__pycache__' not in path.parts
        )
    return []


def _is_deleted_fold_import(name):
    return any(
        name == root or name.startswith(root + '.')
        for root in _FOLD_IMPORT_ROOTS
    )


class CoreOrderedFoldDeletedTest(SimpleTestCase):
    def test_engine_module_is_gone(self):
        with self.assertRaises(ModuleNotFoundError):
            __import__('trusts.ordered_fold')
        self.assertFalse((ROOT / 'trusts' / 'ordered_fold.py').exists())

    def test_declaration_reexports_and_register_are_gone(self):
        for name in FOLD_NAMES:
            self.assertFalse(hasattr(core, name))
            self.assertNotIn(name, dir(core))
        self.assertFalse(hasattr(BackendHandle, 'register_ordered_fold'))
        self.assertFalse(hasattr(TrustsRegistry, 'register_strategy'))
        self.assertFalse(hasattr(TrustsRegistry, 'strategies'))
        fields = getattr(RelationPlan, '__dataclass_fields__', {})
        self.assertNotIn('strategy', fields)

    def test_core_does_not_import_or_discover_the_extension(self):
        package_dir = Path(trusts.__file__).resolve().parent
        forbidden_roots = (
            'trusts.ordered_fold',
            'trusts_ordered_fold',
            'django_trusts_ordered_fold',
        )
        for path in package_dir.rglob('*.py'):
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or '']
                for name in names:
                    for root in forbidden_roots:
                        self.assertFalse(
                            name == root or name.startswith(root + '.'),
                            msg='%s imports %s' % (path.name, name),
                        )

    def test_e006_and_renderer_check_are_retired(self):
        self.assertFalse(hasattr(trusts.checks, 'CHECK_ID_ORDERED_FOLD_RENDERER'))
        self.assertFalse(hasattr(trusts.checks, 'check_ordered_fold_renderer'))
        source = (ROOT / 'trusts' / 'checks.py').read_text()
        self.assertIn("``trusts.E006``", source)
        self.assertIn('trusts_ordered_fold.E001', source)
        self.assertNotIn("CHECK_ID_ORDERED_FOLD_RENDERER = 'trusts.E006'", source)


class RelationshipOnlyCompilerTest(SimpleTestCase):
    def test_applies_and_any_plan_records_ignore_strategy(self):
        compiler = PlanQueryCompiler()
        protocol = QueryCompiler()
        empty = type('Plan', (), {'records': (), 'strategy': object()})()
        filled = type('Plan', (), {'records': (object(),)})()
        self.assertFalse(compiler.applies(empty))
        self.assertFalse(protocol.applies(empty))
        self.assertFalse(_compiler_applies(compiler, empty))
        self.assertFalse(_compiler_applies(object(), empty))
        self.assertTrue(compiler.applies(filled))
        self.assertTrue(_compiler_applies(compiler, filled))

        empty_handle = BackendHandle(
            path='tests.core.195-empty',
            registry=TrustsRegistry(),
            compiler=compiler,
        )
        self.assertFalse(any_plan_records((empty_handle,), Document))

    def test_complete_exists_is_records_only(self):
        compiler = PlanQueryCompiler()
        plan = RelationPlan(records=())
        self.assertIsNone(compiler.complete_exists(plan, None, None, None))
        self.assertFalse(hasattr(plan, 'strategy'))


class PairSuiteDoesNotImportDeletedEngineTest(SimpleTestCase):
    def test_pair_and_kernel_suites_omit_deleted_fold_modules(self):
        self.assertNotIn('tests.core.test_issue100', KERNEL_SUITE)
        self.assertNotIn('tests.core.test_issue187', KERNEL_SUITE)
        self.assertNotIn('tests.core.test_ordered_fold_provisional', KERNEL_SUITE)
        self.assertNotIn('tests.core.test_issue100', PAIR_KERNEL_SUITE)
        self.assertIn('tests.core.test_issue195', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue195', PAIR_KERNEL_SUITE)

    def test_pair_suite_modules_do_not_import_trusts_ordered_fold(self):
        from tests.core.test_issue147 import SLICE_MODULES

        tests_root = ROOT / 'tests' / 'core'
        for module in PAIR_KERNEL_SUITE:
            sources = _suite_sources(tests_root, module)
            self.assertTrue(sources, msg=module)
            if module == 'tests.core.test_issue147':
                scanned = {path.resolve() for path in sources}
                for slice_module in SLICE_MODULES:
                    relative = slice_module[len('tests.core.'):]
                    slice_path = (
                        tests_root / (relative.replace('.', '/') + '.py')
                    ).resolve()
                    self.assertIn(slice_path, scanned, msg=slice_module)
            for path in sources:
                tree = ast.parse(path.read_text(), filename=str(path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertFalse(
                                _is_deleted_fold_import(alias.name),
                                msg=path,
                            )
                    elif isinstance(node, ast.ImportFrom):
                        module_name = node.module or ''
                        self.assertFalse(
                            _is_deleted_fold_import(module_name),
                            msg=path,
                        )
                        if module_name == 'trusts.core':
                            imported = {alias.name for alias in node.names}
                            self.assertFalse(
                                imported & set(FOLD_NAMES), msg=path,
                            )
