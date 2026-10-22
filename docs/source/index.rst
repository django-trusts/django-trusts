django-trusts
=============

.. image:: _static/django-trusts-mascot.png
   :alt: django-trusts badger mascot holding a green key
   :align: center
   :width: 220px

Declarative object permissions for Django
-----------------------------------------

``django-trusts`` is object permissions for Django. You keep using
``user.has_perm(permission, object)`` and define the policy with ordinary
models. A **trust model** is the model those paths start from. A matching
row is a grant.

The same registration answers object checks, permitted querysets,
``filter_by_permitted_content``, permission lists, and view guards. The
`security audit guide
<https://github.com/django-trusts/django-trusts/blob/dev/docs/source/security-audit.md>`_
is the boundary those APIs keep.

How permissions are represented
--------------------------------

A registration names:

* **user** -- who is asking;
* **permission** -- a path to Django permission rows; or
* **group** -- a path to ``auth.Group``, whose permissions apply; and
* **content** -- the protected object.

Use ``permission=`` or ``group=``, not both. Every path starts on the
trust model.

Installation
------------

django-trusts requires Python 3.12--3.14 and Django 6.1.

.. code-block:: console

   python -m pip install "Django>=6.1,<6.2"
   python -m pip install "django-trusts @ git+https://github.com/django-trusts/django-trusts@dev"

Extend ``TrustsConfigMixin`` on the ``AppConfig`` of every app that
registers trusts or hosts a Trusts backend.

Define the models
-----------------

.. code-block:: python

   # documents/models.py

   from django.conf import settings
   from django.contrib.auth.models import Group, Permission
   from django.db import models

   from trusts.models import PermittedQuerySetMixin, PermittedUsersMixin


   class DocumentQuerySet(PermittedQuerySetMixin, models.QuerySet):
       pass


   class Document(PermittedUsersMixin, models.Model):
       title = models.CharField(max_length=200)
       confidential = models.BooleanField(default=False)

       objects = DocumentQuerySet.as_manager()


   class DocumentPermission(models.Model):
       user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
       permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
       document = models.ForeignKey(Document, on_delete=models.CASCADE)


   class GroupDocumentPermission(models.Model):
       group = models.ForeignKey(Group, on_delete=models.CASCADE)
       document = models.ForeignKey(Document, on_delete=models.CASCADE)


   class DocumentDelegation(models.Model):
       delegate = models.ForeignKey(
           settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
           related_name="received_document_delegations",
       )
       sponsor = models.ForeignKey(
           settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
           related_name="sponsored_document_delegations",
       )
       document = models.ForeignKey(Document, on_delete=models.CASCADE)
       permissions = models.ManyToManyField(Permission)

``Document.objects.permitted(permission, user)`` lists documents that
user may access. ``document.get_permitted_users(permission)`` lists the
users. ``user.has_perm(permission, document)`` does not need either mixin.
If you already have a manager, use
``Manager.from_queryset(DocumentQuerySet)``. ``PermittedQuerySet`` and
``PermittedManager`` are the ready-made forms.
``.authorized(user, permission)`` takes a saved permission row, not a
permission string, and does not take named conditions.

Create and delete grants as ordinary rows:

.. code-block:: python

   DocumentPermission.objects.create(
       user=user, permission=change_document, document=document,
   )

Define the backend
------------------

Put the backend in the same app.

.. code-block:: python

   # documents/backends.py

   from django.contrib.auth.backends import ModelBackend

   from trusts.backends import TrustModelBackendMixin


   class DocumentBackend(TrustModelBackendMixin, ModelBackend):
       pass

Register the trust
------------------

Call ``self.recorder`` in ``ready()``, then ``super().ready()``.

.. code-block:: python

   # documents/apps.py

   from django.apps import AppConfig

   from trusts.apps import TrustsConfigMixin


   class DocumentsConfig(TrustsConfigMixin, AppConfig):
       name = "documents"

       def ready(self):
           from .models import (
               Document, DocumentDelegation, DocumentPermission,
               GroupDocumentPermission,
           )

           self.recorder.register(
               trust=DocumentPermission,
               user="user",              # or lambda t: t.user
               permission="permission",
               content="document",
           )
           self.recorder.register(
               trust=GroupDocumentPermission,
               user=lambda t: t.group.user,
               group="group",
               content="document",
           )
           self.recorder.register(
               trust=DocumentDelegation,
               delegate="delegate",
               sponsor="sponsor",
               content="document",
               condition=lambda d, p: d.permissions.contains(p),
           )
           self.recorder.add_named_filter(
               Document, "non_confidential",
               lambda u, p, o: o.confidential != True,
           )
           super().ready()

Paths are a ``__`` string or a one-argument lambda. A ``permission=``
path may end on one forward many-to-many of ``auth.Permission``. Only an
explicit ``group=`` registration is listed by ``get_group_permissions()``.

Delegate live authority
-----------------------

``delegate=`` and ``sponsor=`` replace ``user=`` plus ``permission=`` or
``group=``. The delegate may use the sponsor's grants on that content,
from that backend's catalog. Write the row yourself:

.. code-block:: python

   delegation = DocumentDelegation.objects.create(
       delegate=automation_user, sponsor=owner, document=document,
   )
   delegation.permissions.add(change_document)

``content=`` may be a foreign key, or reverse one-to-one steps followed
by one reverse one-to-many. ``along=`` on the delegation and on the
sponsor's grant must both reach the object. A delegation cannot sponsor
another delegation. Sponsor checks are described in
:ref:`user conditions and overrides <user-conditions-and-overrides>`.

Configure Django
----------------

.. code-block:: python

   # settings.py

   INSTALLED_APPS = [
       "django.contrib.contenttypes",
       "django.contrib.auth",
       "documents.apps.DocumentsConfig",
   ]

   AUTHENTICATION_BACKENDS = [
       "django.contrib.auth.backends.ModelBackend",
       "documents.backends.DocumentBackend",
   ]

``ModelBackend`` still answers global permissions. Django calls
``has_perm`` on each listed backend. Each Trusts backend answers from
its own catalog.

Ask permission questions
------------------------

.. code-block:: python

   user.has_perm("documents.change_document", document)
   user.get_all_permissions(document)
   user.get_group_permissions(document)

   documents = Document.objects.permitted("documents.change_document", user)
   documents = Document.objects.permitted(
       "documents.change_document", user, conditions=("non_confidential",),
   )

   permitted_users = document.get_permitted_users("documents.change_document")

To list users from your user manager, mix in
``PermittedUsersManagerMixin`` from ``trusts.models``. Stock
``auth.User`` does not gain ``permitted``.

.. code-block:: python

   from trusts.models import PermittedUsersManagerMixin

   class UserManager(PermittedUsersManagerMixin, ExistingUserManager):
       pass

   User.objects.permitted(document, change_document)

An ``auth.Permission`` matches an object only when its content type is
that object's. A string passed to ``.permitted()`` is the codename for
the queryset's model. ``has_perm`` still guesses the model from the
codename suffix
(`issue #268 <https://github.com/django-trusts/django-trusts/issues/268>`_).

Each Trusts backend answers from its own catalog. Pass ``backend=``, a
dotted ``AUTHENTICATION_BACKENDS`` path, when more than one Trusts
backend registers that model; otherwise the call raises. The same rule
applies to ``.authorized()``, ``filter_by_permitted_content``,
``get_permitted_users``, ``User.objects.permitted``, and
``authorization_required``.

Filter by permitted content
~~~~~~~~~~~~~~~~~~~~~~~~~~~

``filter_by_permitted_content`` keeps rows that have permitted content
under them. ``permission`` is a saved permission row. Pass ``backend=``
when two Trusts backends register that model.

.. code-block:: python

   from trusts.decorators import filter_by_permitted_content

   cabinets = filter_by_permitted_content(
       Cabinet.objects.all(), user, read_sheet, content=Sheet,
   )

.. _user-is-active-checks:

.. _user-conditions-and-overrides:

User conditions and overrides
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A user condition must hold for a grant. A user override grants without
an ordinary row. The default condition is ``is_active``, when that field
exists. No override is installed.

Set them on ``self.recorder`` before any ``register()``, and before
``super().ready()``. The same name replaces a condition. ``None`` removes
it. ``skip_<name>=True`` skips one condition for that call.

.. code-block:: python

   self.recorder.set_user_condition("is_active", lambda u: u.is_active)
   self.recorder.set_user_override(
       "superuser", lambda u: u.is_active & u.is_superuser,
   )

   Document.objects.permitted(
       "documents.change_document", user, skip_is_active=True,
   )

Django allows an active superuser before it asks backends. See the
`security audit <https://github.com/django-trusts/django-trusts/blob/dev/docs/source/security-audit.md#django-auths-checks-before-calling-backends>`_.

.. _protect-a-view:

Protect a view with ``authorization_required``. It binds the URL argument
``pk``. A missing row is 404. An unauthorized row is 403. Pass
``backend=`` when two Trusts backends register the model.

.. code-block:: python

   from django.http import HttpResponse

   from trusts.decorators import authorization_required

   @authorization_required(
       Document, "documents.change_document", ("non_confidential",),
   )
   def edit_document(request, pk):
       return HttpResponse("Authorized")

``skip_<name>`` on the decorator is fixed there. It is not read from the
request.

Named filters
-------------

A named filter narrows a grant. It does not create one. Register it with
``self.recorder.add_named_filter(model, name, function)`` before
``super().ready()``. The function takes the user, the permission, and the
object. Select it with a ``:name`` suffix, or pass a tuple of names to
``authorization_required``.

.. code-block:: python

   user.has_perm("documents.change_document:non_confidential", document)

``trusts.utils.parse_perm_code(permission)`` returns ``(app label, model
name, action, condition)``. The condition is ``''`` when there is no
suffix.

More expressive permission policies
-----------------------------------

Point ``user=``, ``permission=``, and ``content=`` through relations.
``condition=`` is a function. A delegation may take the requested
permission as a second argument. Use ``==``, ``!=``, ``&``, ``|``,
``~`` on a boolean, and ``.contains()``. Parenthesize a comparison joined
with ``&``. Pass the function, not a prebuilt condition.

.. code-block:: python

   self.recorder.register(
       trust=TeamDocumentPermission,
       user="team__members",
       permission="permission",
       content="document",
       condition=lambda t: (
           t.team.allowed_operations.contains(t.permission)
           & (t.team.organization == t.document.organization)
       ),
   )

A condition narrows its own registration. A named filter is selected by
the caller. Neither grants on its own.

Inherited relationships
~~~~~~~~~~~~~~~~~~~~~~~

``along=("parent", 8)`` on ``register`` walks that relation up to the
bound, for object checks, querysets, permission lists, users, and the
policy output. See the `bounded-reach security audit
<https://github.com/django-trusts/django-trusts/blob/dev/docs/source/security-audit.md#bounded-inherited-relationships>`_.

Ordered allow and deny
~~~~~~~~~~~~~~~~~~~~~~

`django-trusts-ordered-fold
<https://github.com/django-trusts/django-trusts-ordered-fold>`_ is a
provisional extension for ordered allow and deny.
`django-trusts-windows-acl
<https://github.com/django-trusts/django-trusts-windows-acl>`_ is an
example.

Permission policy in SQL
------------------------

Render the registered policy for review. It is not an input format.

.. code-block:: console

   python manage.py trusts_policy_sql
   python manage.py trusts_policy_sql --lock

Opt in with ``management/commands/trusts_policy_sql.py``:

.. code-block:: python

   from trusts.inspect.commands import PolicySqlCommand as Command

``trusts.backends.policy_document()`` returns that document for every
installed Trusts backend. ``DocumentBackend().policy_document()`` returns
that backend only. Pass ``backend=`` as a dotted path to select one.
``alias=`` selects the database, as ``--database`` does. Each entry is
that catalog's own registrations. A chain of ``and``, or a chain of
``or``, prints flat. Companions call ``policy_document`` and
``trusts.utils.parse_perm_code``.

``python manage.py check`` compares a committed lockfile when the usual
file is present or ``TRUSTS_POLICY_LOCKFILE`` is an absolute path.
``TRUSTS_SQL_BIND_ONCE`` defaults to true. Set it to false only if that
SQL misbehaves.

Reference implementations
-------------------------

`django-trusts-gh-permissions
<https://github.com/django-trusts/django-trusts-gh-permissions>`_ is an
organization, team, and repository example.
`django-trusts-windows-acl
<https://github.com/django-trusts/django-trusts-windows-acl>`_ is an
ordered allow-and-deny example built with ``django-trusts-ordered-fold``.

Migrating from django-trusts 0.x
--------------------------------

The old ``Trust`` and ``Content`` schema lives in `django-trusts-zero
<https://github.com/django-trusts/django-trusts-zero>`_. Imports move to
``trusts.zero``, as its `migration guide
<https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md>`_
describes. This package's boundary notes are in `migrates.md
<https://github.com/django-trusts/django-trusts/blob/dev/docs/source/migrates.md>`_.
A sample app is `django-trusts-zero-example
<https://github.com/django-trusts/django-trusts-zero-example/tree/dev>`_.

Validation and support
----------------------

.. code-block:: console

   python manage.py check

Invalid registrations fail at startup. Supported Python, Django, and
databases are in the `support matrix
<https://github.com/django-trusts/django-trusts/blob/dev/docs/dev/support-matrix.md>`_.

Copyright BeeDesk, Inc., 2015--2026. Released under the BSD 2-Clause License.
