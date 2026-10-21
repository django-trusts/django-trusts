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
declarations support object checks, permitted querysets,
``filter_by_permitted_content``, permission enumeration, and decorators
for protecting views. The separate `security audit guide
<https://github.com/django-trusts/django-trusts/blob/dev/docs/source/security-audit.md>`_
defines the boundary these APIs enforce and the responsibilities that remain
with the application.

How permissions are represented
--------------------------------

A registered trust connects a user, protected content, and a permission
source:

* **user** -- who is requesting access;
* **permission** -- a path that reaches Django permission objects directly; or
* **group** -- a path that reaches Django ``auth.Group`` objects, whose
  permissions are used indirectly; and
* **content** -- the object being protected.

``permission`` and ``group`` are mutually exclusive. All paths begin from the
same trust model. In the simplest cases, that model connects the protected
object to either a user and Django permission or a Django group.

Multiple registered trusts may authorize the same kind of content. Each
trust is an independent way to receive permission.

Installation
------------

django-trusts requires Python 3.12--3.14 and Django 6.1.

.. code-block:: console

   python -m pip install "Django>=6.1,<6.2"
   python -m pip install "django-trusts @ git+https://github.com/django-trusts/django-trusts@dev"

Every app that hosts Trusts registrations or a Trusts backend must extend
``TrustsConfigMixin`` on its Django ``AppConfig``, so the app owns its catalog.

.. code-block:: python

   class ProjectsConfig(TrustsConfigMixin, AppConfig):

Define the models
-----------------

The application owns its protected content and trust models.

.. code-block:: python

   # documents/models.py

   from django.conf import settings
   from django.contrib.auth.models import Group, Permission
   from django.db import models

   from trusts.query import PermittedQuerySetMixin, PermittedUsersMixin


   class DocumentQuerySet(PermittedQuerySetMixin, models.QuerySet):
       pass


   class Document(PermittedUsersMixin, models.Model):
       title = models.CharField(max_length=200)
       confidential = models.BooleanField(default=False)

       # Document.objects.filter(...).permitted(permission, user) chains.
       objects = DocumentQuerySet.as_manager()


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


   class GroupDocumentPermission(models.Model):
       group = models.ForeignKey(
           Group,
           on_delete=models.CASCADE,
       )
       document = models.ForeignKey(
           Document,
           on_delete=models.CASCADE,
       )


   class DocumentDelegation(models.Model):
       delegate = models.ForeignKey(
           settings.AUTH_USER_MODEL,
           on_delete=models.CASCADE,
           related_name="received_document_delegations",
       )
       sponsor = models.ForeignKey(
           settings.AUTH_USER_MODEL,
           on_delete=models.CASCADE,
           related_name="sponsored_document_delegations",
       )
       document = models.ForeignKey(
           Document,
           on_delete=models.CASCADE,
       )
       permissions = models.ManyToManyField(Permission)

``DocumentPermission`` connects one user and one permission to one document.
``GroupDocumentPermission`` connects a Django group to one document; users
receive the group's permissions through group membership.
``DocumentDelegation`` lets its delegate act within its sponsor's current
permissions on one document, limited to the relationship's approved
operations.

``PermittedQuerySetMixin`` adds
``permitted(permission, user, conditions=())`` to the application's
queryset. ``as_manager()`` is enough when the application does not need
its own manager class. An application that already owns a manager supplies
the same queryset with ``from_queryset``:

.. code-block:: python

   class DocumentQuerySet(PermittedQuerySetMixin, models.QuerySet):
       def published(self):
           return self.filter(confidential=False)


   class DocumentManager(models.Manager.from_queryset(DocumentQuerySet)):
       pass


   class Document(models.Model):
       objects = DocumentManager()

``PermittedQuerySet`` and
``PermittedManager = Manager.from_queryset(PermittedQuerySet)`` are the
concrete forms when no custom queryset is required. Plain
``user.has_perm(permission, document)`` object checks do not require
either one. ``.authorized(user, permission, extra_q=None)`` remains the lower-level instance
projection. It accepts a saved permission instance rather than a permission
string and does not select named conditions. ``.permitted(permission, user,
conditions=())`` is the public content-list inquiry and keeps the same
registered user conditions, overrides, and relationship grants as the object
check.

``PermittedUsersMixin`` adds
``document.get_permitted_users(permission)``, which returns the users whose
object check succeeds for one saved document and permission. The optional
``User.objects.permitted(document, permission)`` manager adapter asks the same
question. Neither changes ``Document.objects``.

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
``TrustModelBackendMixin``. Every app that hosts that backend must extend
``TrustsConfigMixin`` on its Django ``AppConfig``, so the app owns its catalog.

.. code-block:: python

   # documents/backends.py

   from django.contrib.auth.backends import ModelBackend

   from trusts.backends import TrustModelBackendMixin


   class DocumentBackend(TrustModelBackendMixin, ModelBackend):
       pass

Register the trust
------------------

Register the model paths when the application starts.
Every app that hosts Trusts registrations must extend ``TrustsConfigMixin``
on its Django ``AppConfig``, so the app owns its catalog.

.. code-block:: python

   # documents/apps.py

   from django.apps import AppConfig

   from trusts.apps import TrustsConfigMixin


   class DocumentsConfig(TrustsConfigMixin, AppConfig):
       name = "documents"
       trusts_backend_paths = (
           "documents.backends.DocumentBackend",
       )

       def ready(self):
           super().ready()

           from .models import (
               Document,
               DocumentDelegation,
               DocumentPermission,
               GroupDocumentPermission,
           )

           registry = DocumentBackend().get_registry()
           registry.register(
               trust=DocumentPermission,
               user=lambda t: t.user,
               permission=lambda t: t.permission,
               content=lambda t: t.document,
           )
           registry.register(
               trust=GroupDocumentPermission,
               user=lambda t: t.group.user,
               group=lambda t: t.group,
               content=lambda t: t.document,
           )
           registry.register(
               trust=DocumentDelegation,
               delegate=lambda d: d.delegate,
               sponsor=lambda d: d.sponsor,
               content=lambda d: d.document,
               condition=lambda d, p: d.permissions.contains(p),
           )
           registry.add_named_filter(
               Document,
               "non_confidential",
               predicate=lambda u, p, o: o.confidential != True,
           )

The first registration reaches permission objects directly. The second reaches
Django ``auth.Group`` objects; ``django-trusts`` follows each group's
permissions. Applications do not append ``permissions`` to the ``group`` path.
Each registration supplies either ``permission=`` or ``group=``, never both.

A ``permission=`` path may also end on one forward to-many collection of
``auth.Permission``. Zero or more forward to-one steps may precede that
terminal step (``permissions`` or ``team__permissions``). To-one means a
foreign key or one-to-one; to-many means a many-to-many. That is the
relation shape, not a count of permission rows. A reverse many-to-many, or
a collection that does not end on ``auth.Permission``, is rejected when the
relationship is registered. An intermediate many-to-many is still rejected
at registration; support for that shape is deferred and is not a design
rejection. The collection still does not contribute to
``get_group_permissions()``; only an explicit ``group=`` registration does.

``user``, ``permission``, ``group``, and ``content`` each accept either a
one-argument path lambda (the form in ``ready()`` above) or a Django ``__``
path string. Both forms of the same registration are valid; the string
equivalent of the first registration is:

.. code-block:: python

   registry.register(
       trust=DocumentPermission,
       user="user",
       permission="permission",
       content="document",
   )


Delegate live authority
-----------------------

A delegation lets a **delegate** act with a **sponsor**'s live ordinary
permissions on the protected content. For a requested permission,
django-trusts requires the same delegation row, its selected content and
condition, and sponsor authority on that content. Conditions that apply to
the sponsor are described in :ref:`user conditions and overrides
<user-conditions-and-overrides>`. The actor's own ordinary grants remain
available as independent alternatives.

The delegated ``condition=`` builder receives the relationship as a symbolic
value and may receive the requested permission as a second symbolic value.
The one-argument form applies row-only restrictions. The two-argument form in
the example checks the requested permission against ``permissions``.
Create the relationship and its scope with ordinary application data writes:

.. code-block:: python

   delegation = DocumentDelegation.objects.create(
       delegate=automation_user,
       sponsor=owner,
       document=document,
   )
   delegation.permissions.add(change_document)

Permission checks keep the familiar Django spelling:

.. code-block:: python

   automation_user.has_perm(
       "documents.change_document",
       document,
   )

The same correlated policy drives object checks, permission enumeration,
``QuerySet.permitted()``, users from content, and authorization
policy SQL. The sponsor's authority limits all of those inquiries.

Several delegated relationship models may target the same content model. Each
relationship provides another way to receive permission: its own delegate,
content, condition, and sponsor authority are ANDed before that branch is
ORed with the others. A branch cannot borrow another relationship's approval
or sponsor.

For ordinary and delegated registrations, ``content=`` may also reach a bounded content
set rather than a foreign key on the relationship row. For example,
``sponsor__personal_organization__repositories`` crosses a reverse one-to-one
personal organization and then the one reverse one-to-many repository gateway.
One or more reverse one-to-one relations may be chained as single-valued
prefix hops before that gateway. A reverse one-to-one is not itself a
supported content terminal or gateway.

A sponsor's ordinary grant may use ``along=``. That bounded walk is part of
the sponsor's live authority on every object it reaches, including when the
check is a delegation. A delegated registration may use ``along=`` on the
same call. The delegate is allowed on an object only when the delegation walk
and the sponsor's ordinary grant both reach that object. Each contributing
ordinary sponsor grant's ``along=`` walk or exact match must reach the object.
A delegate cannot sponsor a further delegation.


Configure Django
----------------

Install the application that owns the permission implementation and add its
backend. Every app that hosts Trusts registrations or a Trusts backend must
extend ``TrustsConfigMixin`` on its Django ``AppConfig``, so the app owns its
catalog.

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

An ``auth.Permission`` matches an object only when ``Permission.content_type``
is that object's content type. Asking a repository permission about an
organization is a denial (``False``, and the codename is absent from
``get_all_permissions`` and ``.permitted()``), including when one group
holds both permissions and a registration reaches both models. A proxy
model keeps its own content type. Any other permission terminal, including
a custom model with a ``content_type`` foreign key, is still matched by
primary key.

List the user's permissions on an object:

.. code-block:: python

   user.get_all_permissions(document)
   # {"documents.change_document"}

List only the permissions obtained through registered Django groups:

.. code-block:: python

   user.get_group_permissions(document)
   # {"documents.change_document"}

A ``group=`` registration participates in the same object checks, permission
enumeration, and queryset filtering as a ``permission=`` registration. Its
explicit group classification also lets ``get_group_permissions()`` select the
group-derived subset.

A ``permission=`` registration is not treated as group-derived merely because its
``user=`` path crosses ``auth.Group``; only explicit ``group=`` registrations
contribute to ``get_group_permissions()``.

Filter a queryset to the objects permitted for a particular permission:

.. code-block:: python

   documents = Document.objects.permitted(
       "documents.change_document",
       user,
   )

The permission may instead be the corresponding saved ``auth.Permission``
instance. The queryset supplies the protected content model. A string is
the exact ``app_label.codename`` bound to that model's content type; the
codename is not parsed to guess a model. This is the same kind of question
as ``user.has_perm(permission, document)``, not the same string codec.
``has_perm`` still infers a model from the codename suffix
(`issue #268 <https://github.com/django-trusts/django-trusts/issues/268>`_).

A relationship-family backend participates only when it has an applicable
``auth.Permission`` plan for the queryset model and owns every selected
name as a queryable condition. Other backends contribute nothing. If none
own the full set, the call raises ``TrustsConfigurationError`` before SQL.
``trusts.E008`` reports that configuration for ``authorization_required``
declarations only. A runtime ``.permitted()`` call is not one of those
declarations; it still validates and raises on first use.

Malformed permissions and conditions raise before SQL. A well-formed
permission for another content type produces an empty queryset. Named conditions remain explicit:

.. code-block:: python

   documents = Document.objects.permitted(
       "documents.change_document",
       user,
       conditions=("non_confidential",),
   )

Filter by permitted content
~~~~~~~~~~~~~~~~~~~~~~~~~~~

``filter_by_permitted_content`` keeps rows of the queryset you pass when
permitted content sits under those rows. The result is a lazy queryset of
the same model.

``permission`` is a saved permission row. ``content`` is the protected
model. ``handles`` is optional and defaults to the installed relationship
backends.

A cabinet holds sheets. This call keeps the cabinets that have a sheet
the user may read:

.. code-block:: python

   from trusts.core import filter_by_permitted_content

   cabinets = filter_by_permitted_content(
       Cabinet.objects.all(),
       user,
       read_sheet,
       content=Sheet,
   )

``filter_by_permitted_content`` follows ``along=`` walks and one-level
delegation.

List the users who may perform one permission on one saved object:

.. code-block:: python

   permitted_users = document.get_permitted_users(change_document)

The permission may also use Django's string form:

.. code-block:: python

   permitted_users = document.get_permitted_users(
       "documents.change_document",
   )

The result is a lazy queryset of the configured user model. Normal queryset
operations remain available.

Applications that own their user model may expose the same inquiry on their
existing user manager:

.. code-block:: python

   from trusts.query import PermittedUsersManagerMixin


   class UserManager(PermittedUsersManagerMixin, ExistingUserManager):
       pass

After installing that manager on the application's user model, the equivalent
user-side spelling is:

.. code-block:: python

   from django.contrib.auth import get_user_model


   User = get_user_model()
   permitted_users = User.objects.permitted(document, change_document)

The manager method is spelled ``permitted`` because the manager already
identifies the user model, and Django's ``get`` convention implies one row.
This method returns a lazy queryset. Both spellings return the same rows.
The user-manager mixin is optional; an application that cannot change its
user manager uses ``content.get_permitted_users(perm)``. Stock ``auth.User``
does not grow ``permitted``.

.. _user-is-active-checks:

.. _user-conditions-and-overrides:

User conditions and overrides
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A user condition must hold for every grant. A user override grants the
checked user without an ordinary grant.

The only default condition is ``is_active``, if the field exists.
No user override is registered by default.

Set user conditions and overrides in the ``ready()`` of an app config that
extends ``TrustsConfigMixin``, so the app owns its catalog, before
registering permissions or delegations. For example, replace the activity
condition:

.. code-block:: python

   registry = backend.registry
   registry.set_user_condition("is_active", lambda u: u.is_active)

Setting the same name replaces that condition. Pass ``None`` to remove it:

.. code-block:: python

   registry.set_user_condition("is_active", None)

Use ``skip_<name>=True`` to skip a condition for one Trusts inquiry. For
example, inspect an inactive user's grants:

.. code-block:: python

   documents = Document.objects.permitted(
       "documents.change_document", user, skip_is_active=True,
   )
   users = document.get_permitted_users(
       "documents.change_document", skip_is_active=True,
   )

Condition names must be Python identifiers with no name conflict; their
lambdas must return Boolean expressions.

Use ``set_user_override()`` to set the single override; setting another
replaces it. Pass its current name with ``None`` to remove it.

Django allows active superusers before asking backends; see the `security audit <https://github.com/django-trusts/django-trusts/blob/dev/docs/source/security-audit.md#django-auths-checks-before-calling-backends>`_.

.. _protect-a-view:

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
403. Named ``skip_<name>`` values may be passed after ``conditions`` when a
view deliberately needs one, for example
``authorization_required(Document, permission, (), skip_is_active=True)``.
Those values are fixed when the decorator is created and forwarded to the
Trusts inquiry; they are not selected from request data.

Object checks, permission enumeration, queryset filtering, and view protection
consume the same normalized registrations.

Named filters
-------------

A named filter further constrains an existing permission; it cannot grant
permission by itself. Register it against the protected model during the ``ready()`` of an app
config that extends ``TrustsConfigMixin``, so the app owns its catalog, with
``registry.add_named_filter(...)``.

Its condition is a three-argument lambda or function: ``u`` is the requesting
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

   registry.register(
       trust=TeamDocumentPermission,
       user=lambda t: t.team.members,  # or "team__members"
       permission=lambda t: t.permission,  # or "permission"
       content=lambda t: t.document,  # or "document"
   )

For an ordinary registration, the ``condition=`` argument is a one-argument
symbolic condition rooted at the trust model. A delegated registration may
use the same one-argument form for row-only restrictions or the two-argument
form shown above when its relationship scope must compare with the requested
permission. django-trusts invokes either builder once during registration and
stores no callable. The condition grammar is path equality
(``==``), collection-rooted membership (``.contains(member)``), and
conjunction (``&``). Parenthesize ``==`` when combining it with ``&``.
Python ``in``, ``and`` / ``or`` / ``not``, and prebuilt ``All`` /
``Equal`` / ``permission_in`` values are not accepted. ``.contains`` is a
reserved method on the condition proxy; a model field actually named
``contains`` cannot be walked there. ``predicate=`` is reserved and
unsupported in 1.0.

.. code-block:: python

   backend.register(
       trust=TeamDocumentPermission,
       user=lambda t: t.team.members,
       permission=lambda t: t.permission,
       content=lambda t: t.document,
       condition=lambda t: (
           t.team.allowed_operations.contains(t.permission)
           & (t.team.organization == t.document.organization)
       ),
   )

A relationship condition is always applied to its branch; a named filter is
selected by an authorization caller. Neither can create permission by itself.

Applications may register more than one valid path to the same content. A
direct user grant and a team-derived grant can coexist, with either
path providing permission.

Inherited relationships
~~~~~~~~~~~~~~~~~~~~~~~

``along=`` declares bounded hierarchical reachability and also works with
delegated registrations. For example, ``along=("parent", 8)`` on
``registry.register`` applies the same bounded walk to object checks,
permitted-content querysets, permission enumeration, users from content, and
authorization-policy output. See the `bounded-reach security audit
<https://github.com/django-trusts/django-trusts/blob/dev/docs/source/security-audit.md#bounded-inherited-relationships>`_
for the recursive-query and database boundaries.

Ordered allow and deny
~~~~~~~~~~~~~~~~~~~~~~

`django-trusts-ordered-fold
<https://github.com/django-trusts/django-trusts-ordered-fold>`_ is a
provisional extension of django-trusts for ordered allow and deny policies.
An example Windows declaration lives in
`django-trusts-windows-acl
<https://github.com/django-trusts/django-trusts-windows-acl>`_.

Permission policy in SQL
------------------------

django-trusts can render its registered authorization policy as reviewable
output containing generated parameterized SQL:

.. code-block:: console

   python manage.py trusts_policy_sql

This output is for examining the queries and noticing changes. It is not a
public file format or an input API. Write the current output to a lockfile
after registration is complete:

.. code-block:: console

   python manage.py trusts_policy_sql --lock

The Django model check ``trusts.E009`` compares the generated bytes with the
committed lockfile when the conventional file exists or
``TRUSTS_POLICY_LOCKFILE`` selects an explicit absolute path. Run
``python manage.py check`` in CI and before deployment.

.. note::

   Example SQLite output for the direct ``DocumentPermission`` registration
   above; the layout is not a stable format. The `historical policy-output record
   <https://github.com/django-trusts/django-trusts/blob/dev/docs/dev/permission-policy-sql.rst>`_
   retains the wider example and implementation details.

.. code-block:: yaml

   get_permitted_users:
     params: ["$permission.id", "$content.id", "user.is_active=True", "$content.app_label=\"documents\"", "$content.model=\"document\"", "skip_is_active=False"]
     sql: |-
       SELECT DISTINCT "auth_user"."id", "auth_user"."password", "auth_user"."last_login", "auth_user"."is_superuser", "auth_user"."username", "auth_user"."first_name", "auth_user"."last_name", "auth_user"."email", "auth_user"."is_staff", "auth_user"."is_active", "auth_user"."date_joined"
       FROM "auth_user"
       CROSS JOIN (
         SELECT %s AS "permission_id", %s AS "content_id", %s AS "is_active", %s AS "app_label", %s AS "model"
       ) "trusts_bind"
       WHERE (((%s)
             OR "auth_user"."is_active" = ("trusts_bind"."is_active")
         )
         AND EXISTS (
           SELECT 1 AS "a"
           FROM "documents_documentpermission" "U0"
           INNER JOIN "auth_permission" "U2" ON ("U0"."permission_id" = "U2"."id")
           INNER JOIN "django_content_type" "U3" ON ("U2"."content_type_id" = "U3"."id")
           WHERE ("U0"."document_id" = ("trusts_bind"."content_id")
               AND "U0"."permission_id" = ("trusts_bind"."permission_id")
               AND "U3"."app_label" = ("trusts_bind"."app_label")
               AND "U3"."model" = ("trusts_bind"."model")
               AND "U0"."user_id" = ("auth_user"."id")
           )
           LIMIT 1
         ) )

``TRUSTS_SQL_BIND_ONCE`` defaults to true and enables the one-row bind-table
rewrite. Leave it enabled. Set it to false only if that SQL misbehaves;
django-trusts then uses the plain queryset SQL. If the queryset does not have
the Django query structure required by the rewrite, django-trusts keeps the
plain SQL and logs a warning.

See the `lockfile security audit guide
<https://github.com/django-trusts/django-trusts/blob/dev/docs/source/security-audit.md#authorization-policy-sql-and-lockfile>`_ for the
renderer, dependency, connection, and enforcement boundaries.

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

Migrating from django-trusts 0.x
--------------------------------

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

django-trusts keeps a terse migration-boundary record in `migrates.md
<https://github.com/django-trusts/django-trusts/blob/dev/docs/source/migrates.md>`_,
while the supported 0.x migration guide is Zero's ``migrates.md``
(linked above).

A runnable application using that implementation is available in
`django-trusts-zero-example
<https://github.com/django-trusts/django-trusts-zero-example/tree/dev>`_.

Validation and support
----------------------

Run Django's system checks during development and deployment:

.. code-block:: console

   python manage.py check

django-trusts is designed to reject invalid declarations during application
setup. Missing registrations and unsupported permission paths are intended to
fail closed.

Current Python, Django, database, and evaluation-strategy support is recorded
in the `support matrix
<https://github.com/django-trusts/django-trusts/blob/dev/docs/dev/support-matrix.md>`_.

Copyright BeeDesk, Inc., 2015--2026. Released under the BSD 2-Clause License.
