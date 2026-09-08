"""Regression for wheel absence checks that must not execute candidate modules."""

import importlib
import importlib.util
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase


def _load_verifier():
    path = Path(__file__).resolve().parents[2] / 'scripts' / 'verify-wheel-install.py'
    spec = importlib.util.spec_from_file_location('verify_wheel_install', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WheelInstallAbsenceCheckTest(SimpleTestCase):
    def test_present_module_that_raises_importerror_is_still_detected(self):
        """A leaked trusts.tests would import tests.models and raise ImportError.

        Executing the module and treating ImportError as absence would hide
        that file in the wheel. find_spec must still report it as shipped.
        """
        verifier = _load_verifier()
        with TemporaryDirectory() as tmp:
            pkg = Path(tmp) / 'leakedpkg'
            pkg.mkdir()
            (pkg / '__init__.py').write_text('')
            # Same failure mode as a leaked trusts.tests importing
            # tests.models outside the checkout. Raise it directly so this
            # check does not depend on the top-level tests package.
            (pkg / 'tests.py').write_text(
                "raise ImportError(\"No module named 'tests.models'\")\n"
            )
            sys.path.insert(0, tmp)
            try:
                with self.assertRaises(ImportError):
                    importlib.import_module('leakedpkg.tests')
                self.assertEqual(
                    verifier.find_shipped_modules([
                        'leakedpkg.tests',
                        'leakedpkg.missing',
                    ]),
                    ['leakedpkg.tests'],
                )
            finally:
                sys.path.remove(tmp)
                sys.modules.pop('leakedpkg.tests', None)
                sys.modules.pop('leakedpkg', None)

    def test_uninstalled_trusts_test_modules_have_no_spec(self):
        verifier = _load_verifier()
        self.assertEqual(verifier.find_shipped_modules(verifier.ABSENT_TEST_MODULES), [])
