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
object checks, permitted querysets, permission enumeration, and decorators
for protecting views. The separate `security audit guide
<https://github.com/django-trusts/django-trusts/blob/dev/SECURITY_AUDIT.md>`_
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
complete trust is an independent way to receive permission.

A delegated trust connects a **delegate** who is acting, a **sponsor** whose
live ordinary authority supplies the ceiling, and the protected content. Its
condition may narrow that authority to relationship-owned scope such as
approved operations or selected repositories.

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
       allowed_permissions = models.ManyToManyField(Permission)

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
either one. ``.authorized()`` remains the lower-level instance
projection. The `permitted queryset inquiry contract
<https://github.com/django-trusts/django-trusts/blob/dev/docs/permitted-queryset-inquiry.md>`_
records that split.

``PermittedUsersMixin`` adds
``document.get_permitted_users(permission)``, the reverse inquiry that
returns the users permitted on one saved document. It does not replace or
change ``Document.objects``.

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

           from .models import (
               Document,
               DocumentDelegation,
               DocumentPermission,
               GroupDocumentPermission,
           )

           backend = self.configured_backend()
           backend.register(
               trust=DocumentPermission,
               user=lambda t: t.user,
               permission=lambda t: t.permission,
               content=lambda t: t.document,
           )
           backend.register(
               trust=GroupDocumentPermission,
               user=lambda t: t.group.user,
               group=lambda t: t.group,
               content=lambda t: t.document,
           )
           backend.register(
               trust=DocumentDelegation,
               delegate=lambda d: d.delegate,
               sponsor=lambda d: d.sponsor,
               content=lambda d: d.document,
               condition=lambda d, p: d.allowed_permissions.contains(p),
           )
           backend.add_named_filter(
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

   backend.register(
       trust=DocumentPermission,
       user="user",
       permission="permission",
       content="document",
   )


Delegate live authority
-----------------------

The delegated registration makes ``delegate`` the current actor and
``sponsor`` the source of live ordinary authority. For a requested permission,
django-trusts requires the same delegation row, its selected content and
condition, and an ordinary sponsor grant on that content. The actor's own
ordinary grants remain available as independent alternatives.

The delegated ``condition=`` builder receives the relationship as a symbolic
value and may receive the requested permission as a second symbolic value.
The one-argument form applies row-only restrictions. The two-argument form in
the example checks the requested permission against ``allowed_permissions``.
Create the relationship and its scope with ordinary application data writes:

.. code-block:: python

   delegation = DocumentDelegation.objects.create(
       delegate=automation_user,
       sponsor=owner,
       document=document,
   )
   delegation.allowed_permissions.add(change_document)

Permission checks keep the familiar Django spelling:

.. code-block:: python

   automation_user.has_perm(
       "documents.change_document",
       document,
   )

The same correlated policy drives object checks, permission enumeration,
``QuerySet.permitted()``, reverse permitted-user inquiry, and authorization
policy SQL. The 1.1 feature supports one level of delegation: sponsor authority
comes from ordinary registrations. Multi-level delegation is outside this
feature's scope.


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

An ``auth.Permission`` matches an object only when ``Permission.content_type``
is that object's content type. Asking a repository permission about an
organization is a denial (``False``, and the codename is absent from
``get_all_permissions`` and ``.permitted()``), including when one group
holds both permissions and a registration reaches both models. A proxy
model keeps its own content type. Any other permission terminal, including
a custom model with a ``content_type`` foreign key, is still matched by
primary key. Django's active-superuser shortcut can still make
``user.has_perm`` return ``True`` before this check runs.
``.permitted()``, enumeration, and the reverse user inquiry do not copy
that shortcut.

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

Malformed permissions and conditions raise before SQL, including when the
principal is anonymous. Anonymous and inactive principals, and a
well-formed permission for another content type, produce an empty
queryset. There is no active-superuser shortcut. Named conditions remain
explicit:

.. code-block:: python

   documents = Document.objects.permitted(
       "documents.change_document",
       user,
       conditions=("non_confidential",),
   )

List the users who may perform one permission on one saved object:

.. code-block:: python

   permitted_users = document.get_permitted_users(change_document)

The permission may also use Django's string form:

.. code-block:: python

   permitted_users = document.get_permitted_users(
       "documents.change_document",
   )

The result is a lazy queryset of the configured user model. Normal queryset
operations remain available, for example
``document.get_permitted_users(change_document).filter(is_active=True)``.

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

For an ordinary registration, the ``condition=`` argument is a one-argument
symbolic predicate rooted at the trust model. A delegated registration may
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
direct user grant and a team-derived grant can coexist, with either complete
path providing permission.

Inherited relationships
~~~~~~~~~~~~~~~~~~~~~~~

Inherited relationships are provisional. A bounded hierarchical walk may be
declared with ``along=("parent", 8)`` on ``backend.register``.
django-trusts evaluates the walk with a recursive common table expression
rather than traversing the hierarchy in Python. The database combinations
currently exercised by CI are recorded in the `support matrix
<https://github.com/django-trusts/django-trusts/blob/dev/docs/support-matrix.md>`_.

Ordered allow and deny
~~~~~~~~~~~~~~~~~~~~~~

`django-trusts-ordered-fold
<https://github.com/django-trusts/django-trusts-ordered-fold>`_ is a
provisional extension of django-trusts for ordered allow and deny policies.
An example Windows declaration lives in
`django-trusts-windows-acl
<https://github.com/django-trusts/django-trusts-windows-acl>`_.

Authorization policy in SQL
---------------------------

django-trusts can render the registered authorization policy as deterministic
YAML containing parameterized compiler SQL:

.. code-block:: console

   python manage.py trusts_policy_sql

The command uses ``TRUSTS_POLICY_DATABASE``, or Django's ``default`` alias when
unset. ``--database`` selects another configured alias for one invocation.

The artifact is organized by backend and protected content model. A content
with trusts lists its relationships and SQL for ``permitted``, ``has_perm``,
``get_all_permissions``, and ``get_permitted_users``. The locked
``get_permitted_users`` statement is that backend's reverse predicate
(eligibility and complete grants), not Django's outer superuser rule and
not other backends. A content with named filters lists those queries.
Empty relationship backends remain visible as ``contents: []``.

``content.get_permitted_users(perm)`` and
``User.objects.permitted(content, perm)`` call the same compiler, so the
artifact contains one reverse-user query rather than duplicate entries. The
lockfile key remains ``get_permitted_users``. For the direct
``DocumentPermission`` example on SQLite, that entry is:

.. code-block:: yaml

   get_permitted_users:
     params: [{const: true}, {const: 1}, {bind: "content.id"}, {bind: "permission.id"}, {const: "documents"}, {const: "document"}]
     sql: |-
       SELECT DISTINCT "auth_user"."id", "auth_user"."password", "auth_user"."last_login", "auth_user"."is_superuser", "auth_user"."username", "auth_user"."first_name", "auth_user"."last_name", "auth_user"."email", "auth_user"."is_staff", "auth_user"."is_active", "auth_user"."date_joined" FROM "auth_user" WHERE ("auth_user"."is_active" = %s AND EXISTS(SELECT %s AS "a" FROM "documents_documentpermission" "U0" INNER JOIN "auth_permission" "U2" ON ("U0"."permission_id" = "U2"."id") INNER JOIN "django_content_type" "U3" ON ("U2"."content_type_id" = "U3"."id") WHERE ("U0"."document_id" = %s AND "U0"."permission_id" = %s AND "U3"."app_label" = %s AND "U3"."model" = %s AND "U0"."user_id" = ("auth_user"."id")) LIMIT 1))

Several trusts for the same content within one backend are OR alternatives.
django-trusts issues one SQL statement for each permission inquiry and combines
those trusts with OR. Different backends remain separate.

Authorization policy lockfile
-----------------------------

Write the same bytes to a lockfile after registration is complete:

.. code-block:: console

   python manage.py trusts_policy_sql --lock

``TRUSTS_POLICY_LOCKFILE`` selects an explicit absolute path. Relative explicit
paths are errors and are not resolved against ``BASE_DIR`` or the working
directory. Otherwise django-trusts uses
``BASE_DIR / "trusts-policy.lock.yaml"`` when ``BASE_DIR`` is absolute.

The Django model check ``trusts.E009`` enforces the lockfile when the
conventional file exists or ``TRUSTS_POLICY_LOCKFILE`` is configured. When the
conventional file does not exist and the setting is not configured, the check
returns no error and does not resolve the renderer. A missing explicit file is
an error.

A lockfile belongs to one database renderer. Multi-engine CI may keep runtime
databases different while pinning one ``TRUSTS_POLICY_DATABASE`` inspection
alias consistently in settings and every render or E009 job. For example,
MySQL ``default`` plus SQLite ``policy`` reviews one SQLite lockfile; E009
follows ``policy``. Run ``python manage.py check`` in CI and before deployment.

See the :doc:`authorization policy SQL guide <authorization-policy-sql>` for
the schema, identifiers, renderer selection, and review workflow. See the
`lockfile security audit guide
<../../SECURITY_AUDIT.md#authorization-policy-sql-and-lockfile>`_ for the
connection and enforcement boundaries.

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
<https://github.com/django-trusts/django-trusts/blob/dev/migrates.md>`_,
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
<https://github.com/django-trusts/django-trusts/blob/dev/docs/support-matrix.md>`_.

.. toctree::
   :hidden:

   authorization-policy-sql

Copyright BeeDesk, Inc., 2015--2026. Released under the BSD 2-Clause License.
