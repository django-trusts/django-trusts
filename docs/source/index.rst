django-trusts
=============

Declarative authorization for Django applications that own their policy model.

``django-trusts`` is a **non-standalone Python dependency** for applications
and packages that want authorization to follow ordinary persisted Django
relationships. The application describes the path from a user to a permission
and protected content; core compiles that declaration for object checks and
authorized querysets.

Core supplies no concrete permission schema, no Trust, Content, Group, ACL,
organization, or role models, no generic grant editor, and no Django
``AppConfig``. Do **not** list ``'trusts'`` in ``INSTALLED_APPS``. The consumer
owns its implementation ``AppConfig``, backend, models, and editing workflow.

Choose the right package
------------------------

* Upgrading from or seeking the concrete django-trusts 0.x Trust/Content
  behavior: `django-trusts-zero
  <https://github.com/django-trusts/django-trusts-zero>`_.
* Learning from persisted organization, team, and repository relationships:
  `django-trusts-gh-permissions
  <https://github.com/django-trusts/django-trusts-gh-permissions>`_.
* Learning from explicit ordered allow/deny rows:
  `django-trusts-windows-acl
  <https://github.com/django-trusts/django-trusts-windows-acl>`_.
* Designing a new implementation-neutral permission layer: continue here.

The reference implementations validate bounded real-world shapes. They are not
complete clones of GitHub or Windows, and application-level validation remains
necessary.

Why use it?
-----------

``django-trusts`` keeps authorization:

* **minimal** -- ordinary Django models plus compact declarations;
* **declarative** -- relationship paths identify where user, permission, and
  protected content meet;
* **persisted** -- authorization derives from stored relational state rather
  than transient application guesses;
* **database-first** -- object decisions and authorized querysets share a
  compiled policy, with supported filtering performed in SQL before
  pagination;
* **fail-closed** -- missing, malformed, or unsupported policy cannot become a
  grant; and
* **implementation-neutral** -- core does not impose one domain schema.

This differs from an object-permission store that needs a permission row for
every user/object pair. An implementation may infer a permission from existing
organization relationships, or represent it with explicit policy rows. In
both cases, the database remains the authorization truth.

Install
-------

This is a development release of the 1.x line, not a declared stable 1.0 and
not a published PyPI release. Install from a local checkout or built artifact::

   python -m pip install "Django>=6.1,<6.2"
   python -m pip install .

The supported matrix is Python 3.12--3.14 and Django 6.1. See the
`support matrix
<https://github.com/django-trusts/django-trusts/blob/dev/docs/support-matrix.md>`_.

Configure a consumer
--------------------

The example below is copied from the passing ``tests.myapp`` consumer in this
repository. The implementation owns both the backend and the registry.

.. code-block:: python

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
           from tests.myapp.models import DocumentGrant

           handle = self.configured_backend()
           registry = handle.registry
           j = Ref(DocumentGrant)
           registry.register(
               content=j.document,
               user=j.user,
               permission=j.permission,
           )

Configure Django with the consumer application and backend, not core itself:

.. code-block:: python

   INSTALLED_APPS = (
       'django.contrib.contenttypes',
       'django.contrib.auth',
       'tests.myapp.apps.DocumentConfig',
   )
   AUTHENTICATION_BACKENDS = (
       'django.contrib.auth.backends.ModelBackend',
       'tests.myapp.backends.DocumentBackend',
   )

``ModelBackend`` is optional if the host does not need Django's global
permissions. A Trusts backend contributes ``False`` or an empty set when no
object is supplied; it does not silently become a global-permission backend.

Declare and authorize
---------------------

Application-owned models hold the facts. Core intentionally has no generic
grant or revoke method.

.. code-block:: python

   from django.contrib.auth.models import Permission
   from django.db import models

   from trusts.query import AuthorizedManager

   class Document(models.Model):
       title = models.CharField(max_length=200)
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

The object decision and queryset use the same registered policy.
``AuthorizedQuerySet.authorized(user, permission, extra_q=None)`` requires a
permission model instance. Unsupported inputs fail closed rather than falling
back to a broader rule.

Guard a view with the same Django permission name:

.. code-block:: python

   from trusts.decorators import permission_required

   @permission_required(
       'myapp.change_document',
       fieldlookups_kwargs={'pk': 'pk'},
   )
   def edit_document(request, pk):
       return 'ok'

Registration model
------------------

``Ref(Model)`` starts a typed, root-relative declaration. A registration names
the content, requester, and permission paths contributed by one persisted row.
Multiple complete registrations for the same content combine with OR; fields
inside one registration remain correlated to that same row.

Core validates declarations without querying the database. Unsupported
relationship shapes, ambiguous registrations, incompatible comparison fields,
and missing terminals raise ``TrustsConfigurationError``. Runtime failures do
not widen access.

Conditions constrain existing paths
------------------------------------

Closed predicates such as ``All``, ``Equal``, and ``permission_in`` can add
declarative constraints to a registered path. They never create a grant on
their own. Object authorization, permission enumeration, and queryset
filtering consume the same compiled plan.

For example, a team-derived repository permission can require both a bundled
operation and organization alignment:

.. code-block:: python

   from trusts.core import All, Equal, Ref, permission_in

   grant = Ref(TeamRepositoryGrant)
   registry.register(
       content=grant.repository,
       user=grant.team.members,
       permission=grant.operation,
       condition=All(
           permission_in(grant.team.permission_bundles.operations),
           Equal(grant.team.organization, grant.repository.organization),
       ),
   )

Application-specific condition adapters may bind through
``TrustsRegistry.set_condition_lookup``. Arbitrary callbacks are not queryset
policy and must not be used as a fallback grant.

Create-under-scope filtering
----------------------------

``filter_authorized_scopes`` filters an intermediate model that is a proper
prefix of a registered content path:

.. code-block:: python

   from trusts.core import filter_authorized_scopes

   filter_authorized_scopes(
       Scope.objects.all(),
       user,
       permission_instance,
       content=Payload,
   )

Unknown terminals, empty registries, invalid prefixes, and the content
terminal itself return an empty queryset. Use ``.authorized()`` for the
content terminal.

Operational guarantees
----------------------

* Register policy from the consumer ``AppConfig.ready()`` and call
  ``super().ready()``.
* Run ``python manage.py check`` in CI and before deployment.
* Filter authorized querysets before slicing or pagination.
* Keep grant mutation in explicit application-owned ORM workflows.
* Treat reference implementations as evidence for bounded shapes, not as a
  substitute for validation in the host application.
* NIST material is research context, not an adopted architecture.

Migration and support
---------------------

* `Core migration guide
  <https://github.com/django-trusts/django-trusts/blob/dev/migrates.md>`_
* `Support matrix
  <https://github.com/django-trusts/django-trusts/blob/dev/docs/support-matrix.md>`_
* `Legacy baseline
  <https://github.com/django-trusts/django-trusts/blob/dev/docs/legacy-baseline.md>`_
* `Contributor and build history
  <https://github.com/django-trusts/django-trusts/blob/dev/DEV.md>`_

Copyright BeeDesk, Inc., 2015--2026. BSD-2-Clause.
