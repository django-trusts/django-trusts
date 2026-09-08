.. django-trusts documentation master file, created by
   sphinx-quickstart on Fri Jan 29 22:11:11 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to django-trusts's documentation!
=========================================

Django authorization add-on for multiple organizations and object-level permission settings

How to read this guide
----------------------

This page is a hand-drawn map of the system, not a generated API reference.
It keeps the original conceptual character: one added idea, ``trust``,
drawn against Django's built-in authorization. The map is now aligned with
the ``1.0.0.dev0`` development line. Passages are marked so you can tell
what is road, what is fence, and what is still a sketch:

* **Verified** — behavior covered by current code and tests
  (`#23 <https://github.com/django-trusts/django-trusts/issues/23>`_ /
  `PR #24 <https://github.com/django-trusts/django-trusts/pull/24>`_,
  `#4 <https://github.com/django-trusts/django-trusts/issues/4>`_ /
  `PR #28 <https://github.com/django-trusts/django-trusts/pull/28>`_,
  `#29 <https://github.com/django-trusts/django-trusts/issues/29>`_ /
  `PR #30 <https://github.com/django-trusts/django-trusts/pull/30>`_,
  `#25 <https://github.com/django-trusts/django-trusts/issues/25>`_ /
  `PR #31 <https://github.com/django-trusts/django-trusts/pull/31>`_,
  `#26 <https://github.com/django-trusts/django-trusts/issues/26>`_ /
  `PR #32 <https://github.com/django-trusts/django-trusts/pull/32>`_,
  `#33 <https://github.com/django-trusts/django-trusts/issues/33>`_ /
  `PR #36 <https://github.com/django-trusts/django-trusts/pull/36>`_).
* **Bounded / legacy** — a deliberately limited facility, an opt-in
  escape hatch, or a setting that exists but is not a swap point.
* **Future** — direction that remains aspirational. Do not implement
  against it.

The runnable picture is
`django-trusts-example <https://github.com/django-trusts/django-trusts-example>`_.
API and authorization changes live in the
`migration record <https://github.com/django-trusts/django-trusts/blob/master/migrates.md>`_.
Python and Django versions are in the
`support matrix <https://github.com/django-trusts/django-trusts/blob/master/docs/support-matrix.md>`_.

The map
-------

``django-trusts`` is an add-on to Django's built-in [1]_ authorization. It
strives to be a **minimal** implementation, adding only a single concept,
``trust``, so a project can host users from multiple organizations [2]_ in
one user namespace and still keep per-object permission settings
maintainable.

A ``trust`` is the authorization context for one or more content objects.
It records a ``settlor`` (the entity under whose trust the content is held)
and grants access to specific users (``trustees``) or to Django groups
through a ``TrustGroup`` association. django-trusts does not require the
settlor to be the content's creator and does not automatically grant the
settlor permissions. Content is a ``Content`` subclass (it carries a
``trust`` foreign key), an existing model reached through a ``Junction``,
or a registered dependent model that reuses a related ``Content``
object's Trust without its own ``trust`` field or Junction (see
Dependent content).

.. admonition:: Verified — the Trust-scoped group invariant

   A group permission applies to Trust-controlled content only when **all**
   of these facts exist:

   .. code-block:: text

      membership ∧ TrustGroup association ∧ local permission ∧ global ceiling

   In other words: the user is in the group, the group is associated with
   that Trust, the permission is enabled locally on that ``TrustGroup``,
   and the permission is in the group's global ceiling
   (``Group.permissions`` or a ``Role`` assigned to the group). Missing
   any one of those four denies access. Direct ``TrustUserPermission``
   trustee grants are a parallel path; they do not go through this
   intersection.

   A Trust can authorize **multiple** content objects. Local group changes
   (associate, grant, revoke, set) apply to **every** object that uses
   that Trust. Roles contribute to the **global group ceiling**. They are
   not local grants and are not assigned per Trust. Trust-scoped Role
   assignment is a later design question
   (`#34 <https://github.com/django-trusts/django-trusts/issues/34>`_).

Association without a local grant grants nothing. ``trust.groups.add(group)``
creates the ``TrustGroup`` row and stops there.

Trust and grant resolution is designed to run as database queries rather
than per-object Python loops. That is the sense in which this line aims
to be scalable. It is **design intent**, not a measured performance claim.

.. warning::

   The per-trust permission cache is not automatically invalidated when
   grants, group membership, local TrustGroup permissions, or roles change.
   Reload the user object, or explicitly remove its ``_trust_perm_cache``
   attribute, before making further permission checks with the same user
   instance.

``django-trusts`` supports Django's built-in user permission methods,
``has_perm()`` and ``has_perms()``. Without an object, those methods stay
on Django's ordinary ``ModelBackend`` path (global ``auth.Permission``).
Object-level Trust evaluation is a separate path on
``trusts.backends.TrustModelBackend``.

.. [1]  See: `Django Object Permissions <https://github.com/djangoadvent/djangoadvent-articles/blob/master/1.2/06_object-permissions.rst>`_.
.. [2]  Although ``django-trusts`` was created to support multiple organizations in one project, it does not define or restrict the organization model. One approach is to model an organization as a special user that can be the settlor of trusts. Another is to create a separate organization model. In that arrangement, a trust's settlor may be the creating user, who may or may not have every permission on the organization's content.

Installation
------------

.. admonition:: Bounded / legacy — two install lines

   ``pip install django-trusts`` selects the **historical** PyPI release
   (**0.10.3**, Python 2.7 / Django 1.8). It is not this unpublished
   ``1.0.0.dev0`` development line (Python 3.12–3.14, Django 6.1).

Install the development line from a checkout or from an sdist/wheel built
from this tree:

.. code-block:: console

   python -m pip install "Django>=6.1,<6.2"
   python -m pip install .

Then:

1. Set ``AUTHENTICATION_BACKENDS`` in ``settings.py``:

   .. code-block:: python

      AUTHENTICATION_BACKENDS = (
          'trusts.backends.TrustModelBackend',
      )

2. Add ``trusts`` to ``INSTALLED_APPS`` in ``settings.py``.

3. Apply migrations:

   .. code-block:: console

      python manage.py migrate

4. Run Django system checks in CI and before deploy:

   .. code-block:: console

      python manage.py check

Content and Junction
--------------------

Alternative 1: subclass ``Content``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A ``Content`` subclass carries the ``trust`` foreign key. ``Content`` is
already an abstract ``Model``; you do not also inherit ``models.Model``.

.. code-block:: python

   # app/models.py

   from django.conf import settings
   from django.db import models
   from trusts.models import Content


   class Receipt(Content):
       title = models.CharField(max_length=40)
       owner = models.ForeignKey(
           settings.AUTH_USER_MODEL,
           null=True,
           on_delete=models.CASCADE,
           related_name='receipts',
       )

Alternative 2: wrap an existing model with ``Junction``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``Junction`` when the model is not yours to subclass. The junction
field **must** be named ``content``, and it must be unique, non-null, and
required.

.. code-block:: python

   # app/models.py

   from django.db import models
   from django.contrib.auth.models import Group
   from trusts.models import Junction


   class GroupJunction(Junction):
       content = models.ForeignKey(
           Group,
           unique=True,
           null=False,
           blank=False,
           on_delete=models.CASCADE,
       )

Trustees, teams, and local grants
---------------------------------

Two writing surfaces
~~~~~~~~~~~~~~~~~~~~

**Trusted setup** (management commands, tests, seed data) may call the
unchecked model methods: ``Content.grant`` / ``Content.revoke``,
``Trust.groups.add`` / ``Trust.associate_group``,
``Trust.grant_group_permission`` / ``revoke_group_permission`` /
``set_group_permissions``. Those methods do **not** check the actor.
``Trust.grant_group_permission`` accepts an ``auth.Permission`` instance
or integer PK, not an action or codename string. Resolve the permission
through the content manager first
(``Receipt.objects.get_permission('read')``). The actor-gated helper
``grant_trust_group_permission`` *does* accept that content-relative
string.

**Request-driven writes** (views, forms) must go through
``trusts.authorization``. Those helpers require administrative ``change``
on the content (or, for membership, ``change`` on every Trust that uses
the group). Ordinary ``read`` and mere group membership are not enough.
Unknown submitted IDs raise ``AuthorizationDenied`` and write nothing.

.. admonition:: Verified — association without grant, then an explicit local grant

   Associating a group creates a ``TrustGroup`` row with an empty local
   set. Enable a subset of the group's ceiling afterwards. A rejected
   grant or set does not create a ``TrustGroup`` row for a previously
   unassociated group.

Trusted setup (no actor check):

.. code-block:: python

   from django.contrib.auth import get_user_model
   from django.contrib.auth.models import Group
   from trusts.models import Trust
   from app.models import Receipt

   User = get_user_model()
   settlor = User.objects.get(username='alice')
   trustee = User.objects.get(username='bob')
   accountants = Group.objects.get(name='accountants')

   trust, _created = Trust.objects.get_or_create_settlor_default(settlor=settlor)
   receipt = Receipt(trust=trust, title='Q3 close')
   receipt.save()

   receipt.grant('change', settlor)
   receipt.grant('read', trustee)

   trust.groups.add(accountants)
   trust.grant_group_permission(
       accountants, Receipt.objects.get_permission('read'),
   )

   settlor.has_perm('app.change_receipt', receipt)
   trustee.has_perm('app.read_receipt', receipt)
   # A member of accountants still needs membership + this local read
   # + read in the group's ceiling before has_perm is True.

The same operations from a request, actor-gated:

.. code-block:: python

   from trusts.authorization import (
       associate_group_with_trust,
       grant_trustee,
       grant_trust_group_permission,
   )

   grant_trustee(request.user, receipt, trustee, 'read')
   associate_group_with_trust(request.user, receipt, accountants)
   grant_trust_group_permission(request.user, receipt, accountants, 'read')

``associate_group_with_trust(..., permissions=['read'])`` associates and
enables those local grants in one call, still ceiling-enforced. Omitting
``permissions`` associates and grants nothing.

Related helpers: ``revoke_trustee``, ``disassociate_group_from_trust``,
``revoke_trust_group_permission``, ``set_trust_group_permissions``,
``add_group_member``, ``remove_group_member``, ``create_team``.
``refuse_group_permission_write()`` always raises: ``Group.permissions``
is the global ceiling, not a per-trust setting.

A later add to ``Group.permissions`` (or a role) raises the ceiling only.
It does not enable that permission on existing Trusts until a local grant
is created. ``Group.user_set`` is also global: adding a member to a group
that two Trusts share grants that group's *effective* rights in both
(still subject to each Trust's local grants). Membership changes therefore
require administrative ``change`` on every Trust that uses the group.

.. admonition:: Bounded / legacy — restoring pre-#23 implicit group access

   After ``trusts.0002_trustgroup``, existing ``Trust.groups`` associations
   are kept and grant nothing. Operators who deliberately want the old
   implicit ``Group.permissions`` ∩ association behavior can review
   ``manage.py grandfather_trust_group_permissions --dry-run`` and then
   ``--apply``. That command is not run from the schema migration.

Roles
-----

``Role`` is a reusable permission bundle declared on a ``Content`` model's
``Meta``. ``python manage.py update_roles_permissions`` writes the
corresponding ``Role`` / ``RolePermission`` rows. Roles declared on
different models with the same name are merged.

.. code-block:: python

   from django.db import models
   from trusts.models import Content


   class Receipt(Content):
       title = models.CharField(max_length=40, null=False, blank=False)

       class Meta:
           default_permissions = ('add', 'read', 'change', 'delete')
           permissions = (
               ('ask_question_about_receipt', 'Ask question about a receipt'),
           )
           roles = (
               ('user', ('read_receipt', 'ask_question_about_receipt')),
               ('manager', ('read_receipt', 'change_receipt',
                            'ask_question_about_receipt')),
               ('accounting', ('read_receipt', 'add_receipt', 'change_receipt',
                               'ask_question_about_receipt')),
           )

After the management command, those role permissions become part of a
group's **global capability ceiling** when the role is assigned to the
group. They are not local Trust grants.

Trusted setup: assign the role, associate, then enable a local subset.

.. code-block:: python

   from django.contrib.auth.models import Group
   from trusts.models import Role, Trust
   from app.models import Receipt

   trust = Trust.objects.get(title='acme')
   accountants = Group.objects.get(name='accountants')
   accountants.roles.add(Role.objects.get(name='accounting'))

   trust.groups.add(accountants)
   trust.grant_group_permission(
       accountants, Receipt.objects.get_permission('change'),
   )

   receipt = Receipt(trust=trust, title='Q3 close')
   receipt.save()

The same local grant from a request uses
``grant_trust_group_permission(actor, receipt, accountants, 'change')``.

.. admonition:: Future — Trust-scoped Role assignment

   Role is currently related to ``Group`` globally. A durable model where
   a Role is assigned to a Group **within a Trust** is
   `#34 <https://github.com/django-trusts/django-trusts/issues/34>`_.
   That issue is a design hypothesis, not an adopted schema.

Dependent content
-----------------

A model that does not subclass ``Content`` (and does not have its own
``trust`` field) can still be checked against the Trust of a related
``Content`` object. Register each dependent hop with the ORM path from
``Trust`` to that model.

``Content.get_content_fieldlookup(klass)`` returns that path as a string
for a registered model, or ``None`` if the model is not registered. A
direct ``Content`` subclass resolves to the reverse of ``Content.trust``
(``app_label_model_content``), never ``None``. Compose the next hop with
``Content.compose_content_fieldlookup(parent, related_name)`` so a missing
parent cannot become ``None__image``.

``related_name`` is the reverse query name on the parent model (one hop
per call). This reuses one Trust through related rows. It does **not**
implement parent/child permission ceilings, explicit deny, or ACL
inheritance. Each model still needs its own granted permission codename:
``change_receipt`` does not grant ``change_receiptimage``.

.. code-block:: python

   from django.db import models
   from trusts.models import Content


   class Receipt(Content):
       title = models.CharField(max_length=40)


   class ReceiptImage(models.Model):
       receipt = models.ForeignKey(
           Receipt, related_name='image', on_delete=models.CASCADE,
       )


   class ReceiptImageMeta(models.Model):
       image = models.ForeignKey(
           ReceiptImage, related_name='meta', on_delete=models.CASCADE,
       )


   Content.register_content(
       ReceiptImage,
       Content.compose_content_fieldlookup(Receipt, 'image'),
   )
   Content.register_content(
       ReceiptImageMeta,
       Content.compose_content_fieldlookup(ReceiptImage, 'meta'),
   )

   # Equivalent interpolation, only because get_content_fieldlookup(Receipt)
   # returns the resolved path (for example 'app_receipt_content'):
   # Content.register_content(
   #     ReceiptImage,
   #     '%s__image' % Content.get_content_fieldlookup(Receipt),
   # )

An unregistered dependent model is not Trust content: ``has_perm`` denies
and ``Trust.objects.filter_by_content`` is empty. Registering a lookup
composed from ``None`` (or an empty path) raises ``InvalidContentFieldlookup``.
``compose_content_fieldlookup`` raises ``AttributeError`` if the parent
is not registered, and ``InvalidContentFieldlookup`` if ``related_name``
is a scalar field (for example ``Receipt.title``) rather than a relation.
The registered path must be a Trust-origin relation chain whose terminal
model is the registered class. If reverse relations cannot be checked
during model import, validation is deferred until the app registry is
ready; ``filter_by_content`` / ``has_perm`` still raise on an invalid
registration rather than querying it. A lookup that does not resolve, or
that would compare a scalar field to the dependent instance, never
grants access.

.. admonition:: Bounded — dependents are not list-filtered by ``.permitted()``

   Non-Content dependents have no ``trust`` foreign key.
   ``ContentQuerySet.permitted()`` is not defined on those managers.
   Check a dependent instance with ``has_perm``, or filter from the
   ``Content`` parent.

Checking permissions
--------------------

Object checks use Django's built-in API:

.. code-block:: python

   def check_permission_to_a_specific_receipt(request, receipt_id):
       return request.user.has_perm(
           'app.change_receipt',
           Receipt.objects.get(id=receipt_id),
       )


   def check_permission_to_a_specific_group(request, group_id):
       return request.user.has_perm(
           'auth.change_group',
           Group.objects.get(id=group_id),
       )

``has_perm(..., queryset)`` is **all-must-match**: it is true only when
every object in the ``QuerySet`` is allowed. A mixed set that includes
one denied row is false. That is a yes/no check, not a list filter.

``ContentQuerySet.permitted(perm, user)`` is the **database-side list
filter**. It returns the rows the user may access (trustee **or** the
TrustGroup intersection) as a ``QuerySet``. Paginate that queryset; do
not load every row and call ``has_perm`` in Python. Inactive and
anonymous principals yield an empty queryset. Superuser short-circuit is
**not** duplicated here (that remains Django ``ModelBackend`` on
``has_perm``).

.. code-block:: python

   page = Receipt.objects.permitted('app.read_receipt', request.user)
   # Paginate `page`. Do not confuse this with:
   # request.user.has_perm('app.read_receipt', Receipt.objects.all())
   # which is true only if the user may read every receipt.

``Trust.objects.filter_by_user_content_perm(user, Receipt, 'add')``
selects Trust rows under which the user may create that content (create-
under-trust). It does not follow parent Trusts and does not treat settlor
identity as a grant. ``Trust.objects.filter_by_user_perm(user)`` is the
older attachment listing (trustee or group membership, no permission
name).

Without an object, ``has_perm('app.change_receipt')`` is ordinary Django
``ModelBackend`` evaluation against global ``auth.Permission``. That path
is not Trust-scoped.

Decorators
----------

``trusts.decorators.permission_required`` checks the object-level
permission before the view runs. **By default** (``raise_exception=True``)
a failed check raises ``django.core.exceptions.PermissionDenied``, which
Django renders as **HTTP 403**. Set ``raise_exception=False`` to redirect
to the login page instead.

.. code-block:: python

   from trusts.decorators import permission_required
   from app.models import Receipt


   @permission_required('app.change_receipt', fieldlookups_kwargs={'pk': 'receipt_id'})
   def edit_receipt_view(request, receipt_id):
       pass

``fieldlookups_kwargs`` maps a field on the permissible object to a view
keyword argument. The decorator loads that object and calls ``has_perms``.

K(), G(), O() lookups
~~~~~~~~~~~~~~~~~~~~~

The same mapping can be written with ``K()`` (view kwargs), ``G()``
(``request.GET``), or ``O()`` (``request.POST``):

.. code-block:: python

   from trusts.decorators import permission_required, K, G, O
   from app.models import Receipt


   @permission_required('app.change_receipt', pk=K('receipt_id'))
   def edit_receipt_view(request, receipt_id):
       pass

P() expressions
~~~~~~~~~~~~~~~

``P()`` builds a compound permission with ``|`` (OR) and ``&`` (AND).
Django's decorator cannot express OR on its own:

.. code-block:: python

   from trusts.decorators import permission_required, P, K, O
   from app.models import Receipt


   @permission_required(
       P('app.change_project:own', pk=K('project_id'))
       | P('app.move_receipt', pk=O('receipt_id'))
   )
   def move_receipt_to_project_view(request, project_id):
       pass

Permission conditions
---------------------

A ``:condition`` suffix **constrains an existing grant**. It never grants
the underlying permission by itself. ``change_receipt:own`` requires both
``change_receipt`` and a successful ``own`` condition.

.. warning::

   A condition is an additional constraint, not a grant. Registering
   ``own`` does not give anyone ``change_receipt``.

V1 declarative conditions are **registered expression objects** (``==``,
``!=``, ``&``, ``|`` over principal and object fields), not probed
lambdas. ``has_perm`` and ``.permitted()`` consume the same tree: object
checks evaluate it in Python, and queryset filtering is
``base relational grant AND compiled condition`` before pagination.

Build an ``Expr`` from symbolic ``u``, ``p``, ``o`` and register that
tree. Django ``Q`` is a compiler target, not the canonical form. Dispatch
is by type: an ``Expr`` is queryable policy data; a callable is never
probed.

.. code-block:: python

   from django.conf import settings
   from django.db import models
   from trusts.conditions import condition_refs
   from trusts.models import Content


   class Organization(models.Model):
       manager = models.ForeignKey(
           settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
       )


   class Receipt(Content):
       owner = models.ForeignKey(
           settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
       )
       organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
       status = models.CharField(max_length=20)


   u, p, o = condition_refs()
   Content.register_permission_condition(
       Receipt, 'editable',
       (u == o.owner) |
       ((u == o.organization.manager) & (o.status != "locked")),
   )

   request.user.has_perm('app.change_receipt:editable', receipt)
   Receipt.objects.permitted('app.change_receipt:editable', request.user)

``Trust``'s built-in ``:own`` is the expression ``u == o.settlor``.

``django_trusts.Query`` / ``TQ`` is the reserved namespace for later
Django-style lookups (not a ``QuerySet``). V1 does not implement extra
lookups; equality uses ``==`` / ``!=`` on the refs.

Supported in this experiment:

* Principal and object field references, including ``ForeignKey`` /
  ``OneToOneField`` traversal (``o.organization.manager``)
* Literal constants (``None``, booleans, numbers, strings) whose Python
  type matches the field; relations compare to model instances, not raw
  primary keys
* ``==`` and ``!=``
* Nested ``&`` and ``|`` (grouping is preserved)

Unsupported (fail closed; do not drop the condition):

* Python ``and`` / ``or`` / ``not`` (they cannot be overloaded). Symbolic
  truth testing raises ``PermissionConditionBooleanError`` directing
  callers to ``&`` / ``|``.
* Chained comparisons such as ``0 < o.amount < 100`` (they truth-test the
  first comparison). Ordering comparisons are not in V1.
* Function or method calls, loops, indexing, I/O, arithmetic, assignment
  to symbolic fields
* Source or bytecode inspection; automatic probing of callables
* Permission attribute traversal (``p.codename``); ``p`` is unused in V1
  except as a ref
* Terminal ``ManyToManyField`` and reverse one-to-many refs
  (``o.owner.groups``) until membership is defined
* Django field coercion (``Q(status=1)`` becoming ``"1"`` on a
  ``CharField``, or a ``ForeignKey`` accepting a raw PK). Incompatible
  ``Eq`` / ``Ne`` operands raise ``PermissionConditionError`` on both
  ``has_perm`` and ``.permitted()``.

Object and principal field paths are resolved against the target model and
``TRUSTS_ENTITY_MODEL`` / ``AUTH_USER_MODEL`` respectively (``_meta``
fields and ``ForeignKey`` / ``OneToOneField`` traversal). Unknown or
misspelled names raise ``PermissionConditionError`` on both ``has_perm``
and ``.permitted()``; they are not treated as SQL/Python ``NULL``.
Legitimate nullable relations may still compare as ``None``. Python
``@property`` values are not V1 field paths. Operand types are checked
without Django ``get_prep_value`` coercion: ``o.status == 1`` and
``o.owner == "1"`` raise ``PermissionConditionError`` on both paths.
``filter_by_user_content_perm`` still rejects every ``:condition`` suffix:
that API filters Trust rows, not the content model the condition is
registered on.

.. admonition:: Bounded / legacy — callable conditions

   A callable stays object-only (``has_perm``) and is never invoked with
   symbolic references. It requires
   ``TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS = True``. Without that flag,
   registration is ``trusts.E002`` and runtime raises
   ``PermissionConditionError`` without calling the function.

   ``ContentQuerySet.permitted`` and ``filter_by_user_content_perm`` raise
   ``PermissionConditionNotQueryable`` for those callbacks so they cannot
   silently return the underlying grant.

   .. code-block:: python

      from trusts.models import Content
      from app.models import Receipt

      Content.register_permission_condition(
          Receipt, 'own', lambda u, p, o: u == o.owner,
      )

Run ``python manage.py check`` in CI and before deploy so invalid ``Expr``
registrations (``trusts.E001``) are reported before requests are served.
Silencing a check ID does not make the policy executable: ``has_perm`` and
``.permitted()`` still validate and fail closed.

.. admonition:: Future — the rest of #4

   Arbitrary Python callbacks, cross-language serialization, a policy
   service, ``TQ`` lookups, and ordering comparisons remain open on
   `#4 <https://github.com/django-trusts/django-trusts/issues/4>`_. V1 is a
   bounded experiment. It does not close that issue.

Customization
-------------

.. warning::

   Set ``TRUSTS_ENTITY_MODEL``, ``TRUSTS_ALLOW_NULL_SETTLOR``, and
   ``TRUSTS_DEFAULT_SETTLOR`` before creating migrations or running
   ``manage.py migrate`` for the first time. These settings affect model
   fields and relationships. Changing them after tables exist is not
   handled automatically by ``makemigrations`` and requires an explicit
   schema and data migration.

   Do **not** set ``TRUSTS_GROUP_MODEL`` or ``TRUSTS_PERMISSION_MODEL``.
   Those settings are deprecated in 1.0 and removed in 1.1.0. They do not
   change field targets. Runtime Group and Permission stay
   ``auth.Group`` / ``auth.Permission``.

   The root settings control initial root creation. Changing
   ``TRUSTS_CREATE_ROOT``, ``TRUSTS_ROOT_PK``, ``TRUSTS_ROOT_SETTLOR``, or
   ``TRUSTS_ROOT_TITLE`` after the root exists does not update that row
   automatically. In particular, changing ``TRUSTS_ROOT_PK`` can
   invalidate existing references and defaults and requires a deliberate
   data migration.

* TRUSTS_ENTITY_MODEL -- Settlor and trustee model, in ``app_label.Model``
  form. **Must be the same model as** ``AUTH_USER_MODEL`` (default:
  ``settings.AUTH_USER_MODEL``). A custom user is the supported entity
  swap. A separate non-user model is not a Django permission principal
  (``has_perm``, ``is_active``, ``is_anonymous``). ``trusts.E003`` is the
  deployment diagnostic; silencing it does not authorize a non-user
  entity. Runtime grants and authorization queries fail closed
  independently of the check, including group-derived object-level
  evaluation (membership + TrustGroup + local grant + ceiling).
* TRUSTS_GROUP_MODEL -- **Deprecated in 1.0; removed in 1.1.0.** Leave
  this setting unset. Runtime Group is always ``auth.Group``. Django does
  **not** swap ``auth.Group`` (ticket
  `#29748 <https://code.djangoproject.com/ticket/29748>`_ closed
  ``wontfix``). An explicit value of ``auth.Group`` is ``trusts.W002``.
  Any other value is ``trusts.E004``. Silencing those IDs does not route
  grants or ``group__user`` queries through another model.
* TRUSTS_PERMISSION_MODEL -- **Deprecated in 1.0; removed in 1.1.0.**
  Leave this setting unset. Runtime Permission is always
  ``auth.Permission``. Django does **not** swap ``auth.Permission``.
  ``User.has_perm`` without an object uses Django's ``ModelBackend`` /
  ``auth.Permission``. An explicit value of ``auth.Permission`` is
  ``trusts.W003``. Any other value is ``trusts.E005``. Silencing those
  IDs does not resolve or grant through another model.
* TRUSTS_CREATE_ROOT -- A boolean set to True indicates root Trust model
  object to be created during the initial migration. (default: True)
* TRUSTS_ROOT_PK -- The `pk` of the root trust model object. (default: 1)
* TRUSTS_ROOT_SETTLOR -- The `pk` of settlor of the root trust object.
  (default: None)
* TRUSTS_ALLOW_NULL_SETTLOR -- A boolean set to True indicates
  Trust.settlor field can be null. (default: TRUSTS_DEFAULT_SETTLOR ==
  None)
* TRUSTS_DEFAULT_SETTLOR -- The default value for `settlor` field on Trust
  model. (default: None)
* TRUSTS_ROOT_TITLE -- The title of the root trust object. (default:
  "In Trust We Trust")
* TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS -- Opt-in for registered
  callable permission conditions on ``has_perm`` (default: False). See
  the migration record.

.. admonition:: Verified — custom user; not custom Group or Permission

   ``AUTH_USER_MODEL`` is the only supported principal swap. Group and
   Permission stay ``auth.Group`` / ``auth.Permission``.
   ``TRUSTS_GROUP_MODEL`` and ``TRUSTS_PERMISSION_MODEL`` are deprecated
   in ``1.0`` and will be removed in ``1.1.0``. They do not select a
   model. Leave them unset.

   An experiment that treated those settings as swappable Django
   Group/Permission replacements was attempted and **rejected**. Django's
   permission framework is not swappable there. A private parallel
   contract would silently diverge from ``User.groups`` /
   ``ModelBackend``. That is a negative architectural result, not
   supported behavior, and not a future feature.

   The isolated suite ``python -m tests.runtests_custom`` migrates a
   fresh database with a custom ``AUTH_USER_MODEL`` (and matching
   ``TRUSTS_ENTITY_MODEL``) selected **before** migrations. Group and
   Permission remain ``auth.Group`` / ``auth.Permission``. Mismatched
   model instances fail closed; a foreign instance's primary key is not
   used to select a row on the expected table. Ordinary Django
   ``ModelBackend`` behavior without an object remains a separate backend
   path.

   Example — custom user, standard Group and Permission (no group or
   permission settings)::

      AUTH_USER_MODEL = 'accounts.User'
      TRUSTS_ENTITY_MODEL = 'accounts.User'
      # Do not set TRUSTS_GROUP_MODEL or TRUSTS_PERMISSION_MODEL.

What remains a map, not a road
------------------------------

These ideas stay on the sketch and are not 1.0 behavior:

* Parent/child Trust permission ceilings, explicit deny, and Windows-style
  ACL ordering
* Per-Trust group membership (membership is still global ``Group.user_set``)
* Trust-scoped Role assignment (`#34 <https://github.com/django-trusts/django-trusts/issues/34>`_)
* Closing `#4 <https://github.com/django-trusts/django-trusts/issues/4>`_
  for arbitrary callbacks, serialization, or a policy service
* Removal of the deprecated ``TRUSTS_GROUP_MODEL`` /
  ``TRUSTS_PERMISSION_MODEL`` settings (scheduled for ``1.1.0``)
* Measured throughput claims for the database-side design
* A published PyPI ``1.0.0`` (the package version stays ``1.0.0.dev0``)

Further documentation
---------------------

* `Migration record <https://github.com/django-trusts/django-trusts/blob/master/migrates.md>`_
* `Supported Python and Django versions <https://github.com/django-trusts/django-trusts/blob/master/docs/support-matrix.md>`_
* `Runnable example application <https://github.com/django-trusts/django-trusts-example>`_
* `Development version <https://github.com/django-trusts/django-trusts/blob/master/docs/development-version.md>`_
