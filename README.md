# django-trusts

`django-trusts` is a **non-standalone Python dependency** for applications
and packages that define their own declarative Django authorization
implementation.

Core supplies no concrete permission schema, no Trust / Content / Group /
ACL / organization / role models, no generic grant editor, and no Django
`AppConfig`. Do **not** list `'trusts'` in `INSTALLED_APPS`. The consumer
implementation owns its `TrustsImplementationConfig`, backend path,
models, and persisted policy facts.

## Which package?

- Seeking or upgrading from django-trusts 0.x concrete Trust/Content
  behavior → [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero)
- Studying persisted organization / team / repository relationships →
  [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions)
- Building a new permission implementation → continue here

A forthcoming Windows ordered-policy example will show explicit
allow/deny rows. That reference implementation is not complete on the
final core API yet.

## Principles

- **Minimal** — ordinary Django models plus compact declarations
- **Declarative** — relationship paths name where user, permission, and
  protected content meet
- **Persisted truth** — authorization derives from stored relational
  state, not transient application guesses
- **Database-first** — object decisions and authorized querysets share
  compiled policy; supported work is pushed into one SQL query before
  pagination
- **Fail closed** — malformed, unsupported, or missing policy cannot
  become a grant
- **Implementation-neutral** — core does not impose one permission schema

This is not an object-permission store. A grant may be implied by
persisted organization relationships rather than requiring one
permission row per user/object, or it may come from explicit policy
rows that an implementation defines.

## Install

```bash
pip install django-trusts
```

This is a development release of the 1.x line, not a declared stable
1.0, and not a published PyPI release. Install from a local checkout
or a built sdist/wheel until a stable tag exists.

Requires **Python 3.12–3.14** and **Django 6.1**. See
[docs/support-matrix.md](docs/support-matrix.md).

## Configure

These imports and settings match the project's verified test
configuration. A real implementation substitutes its own app module,
`TrustsImplementationConfig` subclass, and mixin backend path.

```python
from django.contrib.auth.backends import ModelBackend

from trusts.apps import TrustsImplementationConfig
from trusts.backends import TrustModelBackendMixin

HOST_BACKEND = 'tests.backends.HostTrustModelBackend'

class HostTrustModelBackend(TrustModelBackendMixin, ModelBackend):
    pass

class KernelHostConfig(TrustsImplementationConfig):
    name = 'tests.kernel_host'
    label = 'trusts_kernel_host'
    trusts_backend_paths = (HOST_BACKEND,)

INSTALLED_APPS = (
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'tests.kernel_host.apps.KernelHostConfig',
)
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'tests.backends.HostTrustModelBackend',
)
```

Do not add `'trusts'` to `INSTALLED_APPS`.

## Declare and authorize

Ordinary application-owned models plus one `Ref` registration. Grant
mutation happens through those models; core has no generic grant/revoke
workflow.

```python
from django.contrib.auth.models import Permission
from django.db import models

from trusts.core import Ref
from trusts.decorators import permission_required
from trusts.query import AuthorizedManager

class Document(models.Model):
    title = models.CharField(max_length=200)
    objects = AuthorizedManager()

    class Meta:
        app_label = 'trusts_tests'

class DocumentGrant(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'trusts_tests'

j = Ref(DocumentGrant)
registry.register(
    content=j.document,
    user=j.user,
    permission=j.permission,
)
DocumentGrant.objects.create(
    document=document, user=user, permission=change_permission,
)
user.has_perm('trusts_tests.change_document', document)
Document.objects.authorized(user, change_permission)
```

View guard from the same passing test:

```python
@permission_required(
    'trusts_tests.change_document',
    fieldlookups_kwargs={'pk': 'pk'},
)
def edit_document(request, pk):
    ...
```

## Documentation

- [migrates.md](migrates.md) — core API migration guide
- [docs/source/index.rst](docs/source/index.rst) — full docs
- [docs/support-matrix.md](docs/support-matrix.md) — Python / Django matrix
- [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero) — 0.x continuation
- [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions) — organization/team/repository example
- [Issues](https://github.com/django-trusts/django-trusts/issues)

Contributor and build history lives in [DEV.md](DEV.md).

Licensed under the BSD 2-Clause License. Copyright BeeDesk, Inc.
