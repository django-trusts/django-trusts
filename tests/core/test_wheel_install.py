"""Regression for wheel absence checks that must not execute candidate modules."""

import importlib
import importlib.util
from pathlib import Path

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
        with self.assertRaises(ImportError):
            importlib.import_module('tests.core.importerror_body')
        self.assertEqual(
            verifier.find_shipped_modules([
                'tests.core.importerror_body',
                'tests.core.missing',
            ]),
            ['tests.core.importerror_body'],
        )

    def test_uninstalled_trusts_test_modules_have_no_spec(self):
        verifier = _load_verifier()
        self.assertEqual(verifier.find_shipped_modules(verifier.ABSENT_TEST_MODULES), [])
