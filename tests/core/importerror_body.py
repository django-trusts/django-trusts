"""Present module whose body raises ImportError.

Used by WheelInstallAbsenceCheckTest. Not a test module (name does not
match test*.py). Mirrors a leaked trusts.tests that imports tests.models
when the top-level tests package is not on the path.
"""

raise ImportError("No module named 'tests.models'")
