# django-trusts

`django-trusts` is a **non-standalone Python dependency** for
applications and packages that define their own declarative Django
authorization implementation.

Core supplies no concrete permission schema, no Trust / Content /
Group / ACL / organization / role models, no generic grant editor, and
no Django `AppConfig`. Do **not** list `'trusts'` in `INSTALLED_APPS`.
The consumer owns its `TrustsImplementationConfig`, backend path,
models, and persisted policy facts.

## Which package do you want?

- Seeking or upgrading from django-trusts 0.x Trust / Content
  behavior → [`django-trusts-zero`](https://github.com/django-trusts/django-trusts-zero)
- Studying persisted organization / team / repository relationships →
  [`django-trusts-gh-permissions`](https://github.com/django-trusts/django-trusts-gh-permissions)
- Building a new permission implementation → continue with this
  library
- An explicit ordered-policy example is forthcoming as the Windows
  reference implementation; it is not complete on this tree

## Principles

- Minimal ordinary Django models plus compact declarations
- Declarative relationship paths
- Authorization derives from persisted relational state
- Object decisions and authorized querysets share compiled policy;
  supported work is pushed into one SQL query before pagination
- Malformed, unsupported, or missing policy fails closed
- Implementation-neutral core rather than one imposed permission
  schema

This is not an object-permission store that requires one grant row per
user and object. A grant may be implied by persisted organization
relationships, or it may come from explicit policy rows that the
implementation defines. Grant mutation is ordinary ORM work on those
consumer models. Core has no generic grant / revoke workflow.

## Install

```bash
pip install django-trusts
```

This is a development release, not a published PyPI 1.0. Install from
a local checkout or an sdist / wheel built from this tree until a
stable release exists.

```bash
python -m pip install "Django>=6.1,<6.2"
python -m pip install .
```

## Configure

The implementation app is installed. Core is not:

```python
INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'myapp.apps.FolderAuthConfig',
]
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'myapp.backends.FolderBackend',
)
```

`ModelBackend` is listed only when the host also wants ordinary global
Django permissions. Trusts answers object and queryset checks and
contributes `False` / empty results when `obj is None`.

## Example

The following is the smallest runnable consumer shape. The same
models, mixin backend, implementation config, `Ref` registration,
`has_perm`, authorized queryset, and view decorator are exercised by
`trusts.test_issue115`.

```python
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.db import models

from trusts.apps import TrustsImplementationConfig
from trusts.backends import TrustModelBackendMixin
from trusts.core import Ref
from trusts.decorators import permission_required
from trusts.query import AuthorizedManager, AuthorizedQuerySet


class Folder(models.Model):
    title = models.CharField(max_length=40)
    objects = AuthorizedManager()


class FolderGrant(models.Model):
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)


class FolderBackend(TrustModelBackendMixin, ModelBackend):
    pass


class FolderAuthConfig(TrustsImplementationConfig):
    name = 'myapp'
    trusts_backend_paths = ('myapp.backends.FolderBackend',)

    def ready(self):
        super().ready()
        grant = Ref(FolderGrant)
        self.registry.register(
            content=grant.folder,
            user=grant.user,
            permission=grant.permission,
        )
```

Create or delete grant rows with the consumer ORM:

```python
FolderGrant.objects.create(folder=folder, user=user, permission=perm)
```

Object decision and authorized queryset (one compiled policy):

```python
user.has_perm('myapp.change_folder', folder)
AuthorizedQuerySet(Folder).authorized(user, perm)
```

View decorator / guard:

```python
@permission_required(
    'myapp.change_folder',
    fieldlookups_kwargs={'pk': 'folder_id'},
)
def edit_folder(request, folder_id):
    return folder_id
```

## Supported versions

- Python 3.12, 3.13, and 3.14
- Django 6.1

See [docs/support-matrix.md](docs/support-matrix.md). This line is a
development release, not a declared stable 1.0.

## License

BSD 2-Clause Simplified. Copyright BeeDesk, Inc., 2015-2026.

## Further reading

- [migrates.md](migrates.md) — core API migration guide
- [docs](http://django-trusts.readthedocs.org/en/latest/)
- [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero)
- [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions)
- [docs/support-matrix.md](docs/support-matrix.md)
- [Issues](https://github.com/django-trusts/django-trusts/issues)

Contributor and build history lives in [DEV.md](DEV.md).
