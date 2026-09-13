# django-trusts

[![Coverage](https://coveralls.io/repos/github/django-trusts/django-trusts/badge.svg?branch=dev)](https://coveralls.io/github/django-trusts/django-trusts?branch=dev)

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

This is a development release of the 1.x line, not a declared stable
1.0, and not a published PyPI release. Install from a local checkout
or a built sdist/wheel:

```
python -m pip install "Django>=6.1,<6.2"
python -m pip install .
```

Requires **Python 3.12–3.14** and **Django 6.1**. See
[docs/support-matrix.md](docs/support-matrix.md).

## Configure

The worked example is the `tests.myapp` consumer in this tree. Every
import and settings path below is that module.

```python
from django.contrib.auth.backends import ModelBackend

from trusts.apps import TrustsImplementationConfig
from trusts.backends import TrustModelBackendMixin
from trusts.core import Ref

DOCUMENT_BACKEND = 'tests.myapp.backends.DocumentBackend'

class DocumentBackend(TrustModelBackendMixin, ModelBackend):
    pass

class DocumentConfig(TrustsImplementationConfig):
    name = 'tests.myapp'
    label = 'myapp'
    trusts_backend_paths = (DOCUMENT_BACKEND,)

    def ready(self):
        super().ready()
        from tests.myapp.models import Document, DocumentGrant

        handle = self.configured_backend()
        registry = handle.registry
        j = Ref(DocumentGrant)
        registry.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )
        handle.register_permission_condition(
            Document,
            'non_confidential',
            lambda u, p, o: o.confidential != True,
        )

INSTALLED_APPS = (
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'tests.myapp.apps.DocumentConfig',
)
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'tests.myapp.backends.DocumentBackend',
)
```

Do not add `'trusts'` to `INSTALLED_APPS`.

## Declare and authorize

Ordinary application-owned models plus the `Ref` registration above.
Grant mutation happens through those models; core has no generic
grant/revoke workflow.

```python
from django.contrib.auth.models import Permission
from django.db import models

from trusts.query import AuthorizedManager

class Document(models.Model):
    title = models.CharField(max_length=200)
    confidential = models.BooleanField(default=False)
    objects = AuthorizedManager()

    class Meta:
        app_label = 'myapp'

class DocumentGrant(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'myapp'

DocumentGrant.objects.create(
    document=document, user=user, permission=change_permission,
)
user.has_perm('myapp.change_document', document)
Document.objects.authorized(user, change_permission)
```

View guard for the same permission:

```python
from trusts.decorators import permission_required

@permission_required('myapp.change_document', fieldlookups_kwargs={'pk': 'pk'})
def edit_document(request, pk):
    return 'ok'
```

Named queryable conditions are registration-time builders. The
`DocumentConfig.ready()` example above registers `non_confidential`
against `Document.confidential`. Core invokes that callable once with
symbolic refs, stores only the normalized predicate, and never runs it
during `has_perm` or queryset filtering. Write builders like
migrations: no queries, no I/O, no request state. A lambda and an
equivalent named function are accepted identically.

```python
user.has_perm('myapp.change_document:non_confidential', document)
```

`TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS` does not restore runtime
callbacks; if it is still `True`, Django system checks report
`trusts.E007`.

## Documentation

- [migrates.md](migrates.md) — 1.x migration router
- [docs/source/index.rst](docs/source/index.rst) — full docs
- [docs/support-matrix.md](docs/support-matrix.md) — Python / Django matrix
- [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero) — 0.x continuation
- [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions) — organization/team/repository example
- [Issues](https://github.com/django-trusts/django-trusts/issues)

Contributor and build history lives in [DEV.md](DEV.md).

Copyright BeeDesk, Inc., 2015–2026 (BSD-2-Clause).
