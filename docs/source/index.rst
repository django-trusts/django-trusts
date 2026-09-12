django-trusts
=============

Declarative object permissions for Django
-----------------------------------------

``django-trusts`` is a Django permission system for object-level
authorization. It integrates with Django's authentication backend interface,
allowing applications to use familiar checks such as
``user.has_perm(permission, object)`` while defining authorization policies
with ordinary Django models.

At its simplest, a permission is a persisted relationship among a user, an
operation, and protected content. An application declares the model paths
connecting them. A permission may come from a direct grant row, team
membership, an organizational relationship, an inherited access-control
entry, or another relational structure owned by the application.

``django-trusts`` compiles these declarations into database queries, keeping
permission decisions based on persisted truth. The same declarations support
object checks, authorized querysets, permission enumeration, and decorators
for protecting views.

How permissions are represented
--------------------------------

A registered permission relationship connects three paths:

* **user** -- who is requesting access;
* **permission** -- the operation being requested; and
* **content** -- the object being protected.

The paths begin from the same permission-bearing relation. In the simplest
case, that relation is a table with foreign keys to a user, a Django
permission, and a protected object.

Multiple registered relationships may authorize the same kind of content.
Each complete relationship is an independent way to receive permission.

Installation
------------

The current development version requires Python 3.12--3.14 and Django 6.1.

.. code-block:: console

   python -m pip install "Django>=6.1,<6.2"
   python -m pip install "django-trusts @ git+https://github.com/django-trusts/django-trusts@dev"

Define the models
-----------------

The application owns its protected content and permission relationships.

.. code-block:: python

   # documents/models.py

   from django.conf import settings
   from django.contrib.auth.models import Permission
   from django.db import models

   from trusts.query import AuthorizedManager


   class Document(models.Model):
       title = models.CharField(max_length=200)

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

``DocumentPermission`` is the permission-bearing relation. Each row connects
one user and one permission to one document.

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

Register the permission relationship
------------------------------------

Register the model paths when the application starts:

.. code-block:: python

   # documents/apps.py

   from trusts.apps import TrustsImplementationConfig
   from trusts.core import Ref


   class DocumentsConfig(TrustsImplementationConfig):
       name = "documents"
       trusts_backend_paths = (
           "documents.backends.DocumentBackend",
       )

       def ready(self):
           super().ready()

           from .models import DocumentPermission

           relation = Ref(DocumentPermission)

           self.configured_backend().registry.register(
               user=relation.user,
               permission=relation.permission,
               content=relation.document,
           )

``Ref(DocumentPermission)`` begins a declaration from the permission-bearing
model. The three paths identify the user, permission, and protected content
associated with each row.

The declaration is validated when it is registered. Invalid or unsupported
paths raise a configuration error instead of becoming an authorization rule.

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

Protect a view with the same permission:

.. code-block:: python

   # documents/views.py

   from django.http import HttpResponse

   from trusts.decorators import permission_required


   @permission_required(
       "documents.change_document",
       fieldlookups_kwargs={"pk": "pk"},
   )
   def edit_document(request, pk):
       return HttpResponse("Authorized")

Object checks, permission enumeration, queryset filtering, and view protection
all use the registered permission relationship.

More expressive permission policies
-----------------------------------

The ``DocumentPermission`` example uses the shortest useful path: one row
directly connects a user, a permission, and a document. The same registration
API also supports paths through multiple relationships.

For example, a user may receive permission through membership in a team, while
the team receives access to content through another model. The registered user
path can traverse those relationships without copying the resulting
permissions into a separate user-object table.

Conditions can further constrain a permission path. A condition may require
the user and content to belong to the same organization, or require a
requested operation to appear in a team's allowed operations. Conditions
narrow an existing permission relationship; they cannot create permission by
themselves.

Applications may register more than one valid path to the same content. A
direct user grant and a team-derived grant can coexist, with either complete
path providing permission.

Inherited relationships
~~~~~~~~~~~~~~~~~~~~~~~

Permissions may also be inherited through hierarchical relationships. The
``Along`` strategy walks a bounded hierarchy with a recursive common table
expression, allowing a permission attached to one node to apply to related
ancestors or descendants without traversing the hierarchy in Python.

Policies that require ordered allow and deny entries can use the
``OrderedFold`` strategy. It evaluates persisted entries in order while
tracking which requested permission bits remain undecided.

Evaluation strategies use the same object-check, permission-enumeration, and
queryset interfaces as direct permission paths. Database support varies by
strategy; see the support matrix for the currently verified combinations.

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

It demonstrates how an ACL-style permission system can select an ordered
evaluation strategy while retaining the same Django-facing permission APIs.

The project is intended to prove that this class of permission system can be
implemented with ``django-trusts``. It is not intended to reproduce every
feature or security guarantee of Windows ACLs.

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

A runnable application using that implementation is available in
`django-trusts-zero-example
<https://github.com/django-trusts/django-trusts-zero-example>`_.

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
