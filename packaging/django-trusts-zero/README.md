# django-trusts-zero (packaging template)

This directory is the **distribution recipe** the companion
[`django-trusts-zero`](https://github.com/django-trusts/django-trusts-zero)
repository should publish. It is not itself an installable checkout: the
Python tree lives at `trusts/zero/` in `django-trusts` until the Zero
package PR copies it.

Unrelated to Zero Trust network architecture.

## What Zero must ship

Only `trusts/zero/**`, including `trusts/zero/__init__.py`. **Do not**
ship `trusts/__init__.py`, `trusts/context.py`, `trusts/trustee.py`,
`trusts/path.py`, `trusts/conditions.py`, `trusts/utils.py`,
`trusts/apps.py`, or `trusts/checks.py`.

Copy from this repository:

```
trusts/zero/
packaging/django-trusts-zero/pyproject.toml  (this file's sibling)
```

Stage as:

```
django-trusts-zero/
  pyproject.toml
  README.md
  trusts/
    zero/          # no parent trusts/__init__.py
```

`django-trusts-zero` depends on `django-trusts`. Explicit
`INSTALLED_APPS` after the split:

```python
INSTALLED_APPS = [
    'trusts.apps.KernelConfig',     # name='trusts', label='trusts_kernel'
    'trusts.zero.apps.ZeroConfig',  # name='trusts.zero', label='trusts'
]
```

Bare `'trusts'` and `'trusts.zero'` are invalid. Migration identity stays
`('trusts', '0001_initial')` / `('trusts', '0002_trustgroup')`.

Editable installs of this package next to the kernel must use setuptools
compat mode so kernel `trusts/__init__.py` (`pkgutil.extend_path`) stays
the package owner:

```
pip install -e ../django-trusts --config-settings editable_mode=compat
pip install -e . --no-deps --config-settings editable_mode=compat
```

Default strict editable mode turns `trusts` into a PEP 420 namespace
(`trusts.__file__ is None`) and hides the kernel `__init__.py`. Wheel+wheel
into the same `site-packages/trusts/` tree does not need this flag.
