django-trusts
=============

.. image:: _static/django-trusts-mascot.png
   :alt: django-trusts badger mascot holding a green key
   :align: center
   :width: 220px

Declarative object permissions for Django
-----------------------------------------

``django-trusts`` is a Django permission system for object-level
authorization. It integrates with Django's authentication backend interface,
allowing applications to use familiar checks such as
``user.has_perm(permission, object)`` while defining authorization policies
with ordinary Django models.

At its simplest, a permission is a persisted relationship among a user, an
operation, and protected content. The application model from which those paths
begin is the **trust model**. A matching trust record is a candidate grant. A
trust model may be an explicit many-to-many relation model, a direct grant
model, or another relational structure owned by the application.

``django-trusts`` compiles these declarations into database queries via
QuerySet, keeping permission decisions based on persisted truth. The same
declarations support
object checks, authorized querysets, permission enumeration, and decorators
for protecting views. The separate `security audit guide
<https://github.com/django-trusts/django-trusts/blob/dev/SECURITY_AUDIT.md>`_
defines the boundary these APIs enforce and the responsibilities that remain
with the application.

How permissions are represented
--------------------------------

A registered trust connects three paths:

* **user** -- who is requesting access;
* **permission** -- the operation being requested; and
* **content** -- the object being protected.

All three paths begin from the same trust model. In the simplest case, that
model has foreign keys to a user, a Django permission, and a protected object.

Multiple registered trusts may authorize the same kind of content. Each
complete trust is an independent way to receive permission.

Installation
------------

The current development version requires Python 3.12--3.14 and Django 6.1.

.. code-block:: console

   python -m pip install "Django>=6.1,<6.2"
   python -m pip install "django-trusts @ git+https://github.com/django-trusts/django-trusts@dev"

Define the models
-----------------

The application owns its protected content and trust models.

.. code-block:: python

   # documents/models.py

   from django.conf import settings
   from django.contrib.auth.models import Permission
   from django.db import models

   from trusts.query import AuthorizedManager


   class Document(models.Model):
       title = models.CharField(max_length=200)
       confidential = models.BooleanField(default=False)

       # Adds Document.objects.authorized(user, permission).
       objects = AuthorizedManager()


   class DocumentPermission(models.Model):
       user = models.ForeignKey(
           settings.AUTH_USER_MODEL,
           on_delete=models.CASCADE,
       )
       permission = models.ForeignKey(
           Permission,
           on_delete=models.CASCADE,
       )
       document = models.ForeignKey(
           Document,
           on_delete=models.CASCADE,
       )

``DocumentPermission`` is the trust model. Each trust record connects one
user and one permission to one document.

``AuthorizedManager`` is needed only when the protected model should expose
``Document.objects.authorized(user, permission)`` for queryset filtering.
Plain ``user.has_perm(permission, document)`` object checks do not require it.

Granting and revoking permission are ordinary changes to persisted application
data:

.. code-block:: python

   DocumentPermission.objects.create(
       user=user,
       permission=change_document,
       document=document,
   )

   DocumentPermission.objects.filter(
       user=user,
       permission=change_document,
       document=document,
   ).delete()

An application may instead change a team membership, organizational
relationship, ACL entry, or another persisted fact. ``django-trusts`` does
not impose one grant-management workflow.

Define the backend
------------------

The application provides a Django authentication backend using
``TrustModelBackendMixin``.

.. code-block:: python

   # documents/backends.py

   from django.contrib.auth.backends import ModelBackend

   from trusts.backends import TrustModelBackendMixin


   class DocumentBackend(TrustModelBackendMixin, ModelBackend):
       pass

Register the trust
------------------

Register the model paths when the application starts:

.. code-block:: python

   # documents/apps.py

   from trusts.apps import TrustsImplementationConfig


   class DocumentsConfig(TrustsImplementationConfig):
       name = "documents"
       trusts_backend_paths = (
           "documents.backends.DocumentBackend",
       )

       def ready(self):
           super().ready()

           from .models import Document, DocumentPermission

           backend = self.configured_backend()
           backend.register(
               trust=DocumentPermission,
               user=lambda t: t.user,
               permission=lambda t: t.permission,
               content=lambda t: t.document,
           )
           backend.add_named_filter(
               Document,
               "non_confidential",
               predicate=lambda u, p, o: o.confidential != True,
           )

``DocumentPermission`` is the trust model. The three paths identify the user,
permission, and protected content associated with each trust record.

``user``, ``permission``, and ``content`` each accept either a one-argument
path lambda (the form in ``ready()`` above) or a Django ``__``
path string. Both forms of the same registration are valid; the string
equivalent is:

.. code-block:: python

   backend.register(
       trust=DocumentPermission,
       user="user",
       permission="permission",
       content="document",
   )


Configure Django
----------------

Install the application that owns the permission implementation and add its
backend:

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

Django's ``ModelBackend`` remains available for ordinary global permissions.
``DocumentBackend`` answers object-level permission questions declared
through ``django-trusts``.

Ask permission questions
------------------------

Use Django's familiar object-permission API:

.. code-block:: python

   user.has_perm(
       "documents.change_document",
       document,
   )

List the user's permissions on an object:

.. code-block:: python

   user.get_all_permissions(document)
   # {"documents.change_document"}

Filter a queryset to the objects authorized for a particular permission:

.. code-block:: python

   change_document = Permission.objects.get(
       content_type__app_label="documents",
       codename="change_document",
   )

   documents = Document.objects.authorized(
       user,
       change_document,
   )

Protect a view with the Trusts-only primary-key guard:

.. code-block:: python

   # documents/views.py

   from django.http import HttpResponse

   from trusts.decorators import authorization_required

   from .models import Document


   @authorization_required(
       Document,
       "documents.change_document",
       ("non_confidential",),
   )
   def edit_document(request, pk):
       return HttpResponse("Authorized")

The guard binds only the URL keyword argument named ``pk`` to the model's
primary-key field. It performs configuration preflight before candidate lookup;
a missing object produces 404 and an existing unauthorized object produces
403.

Object checks, permission enumeration, queryset filtering, and view protection
consume the same normalized registrations.

Named filters
-------------

A named filter further constrains an existing permission; it cannot grant
permission by itself. Register it against the protected model during
``AppConfig.ready()`` with ``backend.add_named_filter(...)``.

Its predicate is a three-argument lambda or function: ``u`` is the requesting
user, ``p`` is the requested permission, and ``o`` is the protected object. It
must return a supported boolean expression that django-trusts can translate
into the Django QuerySet used for authorization. The example above registers
``non_confidential`` against ``Document.confidential``. Object checks select
one named filter with the ``:name`` suffix; ``authorization_required`` accepts
a tuple of names. Unsupported expressions fail registration.

.. code-block:: python

   user.has_perm("documents.change_document:non_confidential", document)

More expressive permission policies
-----------------------------------

The ``DocumentPermission`` example uses the shortest useful trust: one record
directly connects a user, a permission, and a document. The same registration
API also supports paths through multiple relationships:

.. code-block:: python

   backend.register(
       trust=TeamDocumentPermission,
       user=lambda t: t.team.members,  # or "team__members"
       permission=lambda t: t.permission,  # or "permission"
       content=lambda t: t.document,  # or "document"
   )

The ``condition=`` argument on ``register`` can further constrain
that relationship branch. It may require the user and content to belong to the
same organization, or require a requested operation to appear in a team's
allowed operations. A relationship condition is always applied to its branch;
a named filter is selected by an authorization caller. Neither can create
permission by itself.

Applications may register more than one valid path to the same content. A
direct user grant and a team-derived grant can coexist, with either complete
path providing permission.

Inherited relationships
~~~~~~~~~~~~~~~~~~~~~~~

Inherited relationships are provisional. A bounded hierarchical walk may be
declared with ``along=("parent", 8)`` on ``backend.register``.
django-trusts evaluates the walk with a recursive common table expression
rather than traversing the hierarchy in Python. Its currently verified database
support is recorded in the `support matrix
<https://github.com/django-trusts/django-trusts/blob/dev/docs/support-matrix.md>`_.

Ordered allow and deny
~~~~~~~~~~~~~~~~~~~~~~

`django-trusts-ordered-fold
<https://github.com/django-trusts/django-trusts-ordered-fold>`_ is a
provisional extension of django-trusts for ordered allow and deny policies.
An example Windows declaration lives in
`django-trusts-windows-acl
<https://github.com/django-trusts/django-trusts-windows-acl>`_.

Reference implementations
-------------------------

Two reference implementations demonstrate how different permission systems
can be built with ``django-trusts``.

Organization and team permissions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`django-trusts-gh-permissions
<https://github.com/django-trusts/django-trusts-gh-permissions>`_ models
permissions implied by organization, team, repository, and membership
relationships.

It demonstrates:

* direct and team-derived permission paths;
* many-to-many team membership;
* operation ceilings;
* organization-alignment conditions; and
* multiple valid paths to the same protected content.

It is a focused example of a GitHub-shaped permission model, not a complete
reimplementation of GitHub.

Ordered access-control entries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`django-trusts-windows-acl
<https://github.com/django-trusts/django-trusts-windows-acl>`_ models
permissions using persisted access-control entries with ordering, allow and
deny effects, permission masks, and inheritance.

It demonstrates an ACL-style permission system built with
``django-trusts-ordered-fold``, a provisional extension of ``django-trusts``,
while
retaining the same Django-facing permission APIs. It is not intended to
reproduce every feature or security behavior of Windows ACLs.

Users of django-trusts 0.x
--------------------------

Earlier versions of ``django-trusts`` included a concrete permission system
based on ``Trust``, ``Content``, groups, roles, and their associated
migrations.

That implementation now continues as `django-trusts-zero
<https://github.com/django-trusts/django-trusts-zero>`_. Applications
upgrading from 0.x, or applications that specifically want that model, should
use ``django-trusts-zero``.

Its Django application label, database tables, content types, permissions, and
migration identities are preserved. Python imports and Django settings move to
the explicit ``trusts.zero`` paths described in the `Zero migration guide
<https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md>`_.

The migration guide is `migrates.md
<https://github.com/django-trusts/django-trusts/blob/dev/migrates.md>`_.

A runnable application using that implementation is available in
`django-trusts-zero-example
<https://github.com/django-trusts/django-trusts-zero-example/tree/dev>`_.

Validation and support
----------------------

Run Django's system checks during development and deployment:

.. code-block:: console

   python manage.py check

Invalid declarations are rejected during application setup. Missing
registrations and unsupported permission paths fail closed.

Current Python, Django, database, and evaluation-strategy support is recorded
in the `support matrix
<https://github.com/django-trusts/django-trusts/blob/dev/docs/support-matrix.md>`_.

Copyright BeeDesk, Inc., 2015--2026. Released under the BSD 2-Clause License.
