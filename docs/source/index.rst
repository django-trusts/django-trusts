.. django-trusts documentation master file, created by
   sphinx-quickstart on Fri Jan 29 22:11:11 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to django-trusts's documentation!
=========================================

Django authorization add-on for multiple organizations and object-level permission settings

Introduction
------------

``django-trusts`` is an add-on to Django's built-in [1]_ authorization. It strives to be a **minimal** implementation, adding only a single concept, ``trust``, to enable maintainable per-object permission settings for a Django project that hosts users from multiple organizations [2]_ in a single user namespace.

A ``trust`` associates content with a ``settlor`` and grants permissions to specific users (``trustees``) or groups. The settlor identifies the entity under whose trust the content is held; django-trusts does not require the settlor to be the content's creator and does not automatically grant the settlor permissions. Content can be an instance of a ``Content`` subclass or an existing model connected through a junction table. A single trust can cover multiple content objects so their permission settings can be maintained together. Django's built-in ``Group`` model is supported and can define reusable permissions for groups of users.

``django-trusts`` also strives to be a **scalable** solution. Trust and grant resolution uses database queries, and the implementation minimizes database hits. Permission checks can be made against an individual content object or a ``QuerySet``.

.. warning::

   The documented ``_trust_perm_cache`` attribute is not automatically invalidated when grants, group membership, local TrustGroup permissions, or roles change. Reload the user object, or explicitly remove its ``_trust_perm_cache`` attribute, before making further permission checks with the same user instance. Registered terminals authorize from the compiler; do not treat the cache as a second authorization source.

``django-trusts`` supports Django's built-in user permission methods, ``has_perm()`` and ``has_perms()``.


.. [1]  See: `Django Object Permissions <https://github.com/djangoadvent/djangoadvent-articles/blob/master/1.2/06_object-permissions.rst>`_.
.. [2]  Although ``django-trusts`` was created to support multiple organizations in one project, it does not define or restrict the organization model. One approach is to model an organization as a special user that can be the settlor of trusts. Another is to create a separate organization model. In that arrangement, a trust's settlor may be the creating user, who may or may not have every permission on the organization's content.

Usages
------

Installation
~~~~~~~~~~~~

Steps:

1. Install django-trusts::

     python -m pip install django-trusts

2. Set ``AUTHENTICATION_BACKENDS`` in ``settings.py``. Trusts answers
   object and QuerySet permission checks. It contributes ``False`` /
   empty permissions when ``obj is None``. Hosts that also want ordinary
   global Django permissions must list ``ModelBackend`` (or another
   global backend) separately::

   AUTHENTICATION_BACKENDS = (
     'django.contrib.auth.backends.ModelBackend',
     'trusts.backends.TrustModelBackend',
   )

   ``TrustModelBackend`` still subclasses ``ModelBackend`` for
   ``authenticate`` / ``get_user`` only. That inheritance does not
   confer global permission authority.

3. Add ``trusts`` to ``INSTALLED_APPS`` in ``settings.py``. After the
   C2 kernel extraction the kernel app label is ``trusts_core``.
   Hosts that need the historical 0.x schema (``Trust``, content types,
   permissions, migrations ``trusts.0001_initial`` /
   ``trusts.0002_trustgroup``) must also install ``django-trusts-zero``
   and add the explicit class path::

     INSTALLED_APPS = [
       ...,
       'trusts',  # kernel: name=trusts, label=trusts_core
       'trusts.zero.apps.ZeroConfig',  # schema: name=trusts.zero, label=trusts
     ]

   Bare ``'trusts'`` alone is the kernel with no concrete models.
   Bare ``'trusts.zero'`` is forbidden; use ``ZeroConfig``.
   ``from trusts.models import Trust`` still resolves when Zero is
   installed (PEP 562 shim). Without Zero that import raises
   ``ImportError`` naming ``django-trusts-zero``. Canonical imports are
   ``trusts.zero.models``.

4. Apply migrations::

     python manage.py migrate

5. Run Django system checks in CI and before deploy::

     python manage.py check

Implementation
~~~~~~~~~~~~~~

Alternative 1
++++++++++++++

Use ``Content`` ::

   # app/models.py

   from django.db import models
   from trusts.models import Content

   class Receipt(Content, models.Model):
       account = models.ForeignKey(Account, null=True, on_delete=models.CASCADE)
       merchant = models.ForeignKey(Merchant, null=True, on_delete=models.CASCADE)
       # ... other field

Alternative 2
+++++++++++++

Use ``Junction`` ::

   # app/models.py

   from django.db import models
   from django.contrib.auth.models import Group
   from trusts.models import Junction

   # New Junction to model that is not under your control
   class GroupJunction(Junction, models.Model):
       # field name must be named as `content` and unique=True, null=False, blank=False
       content = models.ForeignKey(django.contrib.auth.models.Group, unique=True, null=False, blank=False, on_delete=models.CASCADE)

Permission Assignments
~~~~~~~~~~~~~~~~~~~~~~

Example::

   from django.contrib.auth.models import User, Group, Permission
   from trusts.models import Trust

   # Helper function
   def grant_user_group_permission_to_model(user, group_name, model_name, code='change', app='app'):
       # Django's auth permission mechanism, nothing specific to `django-trust`

       # get perm by name
       perm = Permission.objects.get_by_natural_key('change_%s' % model_name, app, model_name)
       group = Group.objects.get(name=group_name)

       # connect them
       user.groups.add(group)
       perm.group_set.add(group)

       # user.has_perm('%s.change_%s' % (app, model_name)) ==> True
       # user.has_perm('%s.change_%s' % (app, model_name), obj) ==> False

   # View
   def create_receipt_object_for_user(request, title, details):
       trust = Trust.objects.get_or_create_settlor_default(settlor=request.user)

       content = Receipt(trust=trust, title=title, details=details)
       content.save()

       model_name = receipt.__class__.__name__.lower()
       perm = Permission.objects.get_by_natural_key('%_%' % ('change', model_name), 'app', model_name)

       tup = TrustUserPermission(trust=trust, entity=request.user, permission=perm)
       tup.save()

       # request.user.has_perm('%s.change_%s' % ('app', model_name), content) ==> True

   # View
   def give_user_change_permission_on_existing_group(request, user, group_name):
       grant_user_permssion_to_model(request.user, group_name, code='change', app='auth')

       group = Group.objects.get(name=group_name)
       junction = GroupJunction(trust=trust, content=group)
       junction.save()

       # request.user.has_perm('auth.change_group', group) ==> True

Inheritance
~~~~~~~~~~~

A dependent model can inherit authorization from a related ``Content``
row. Both documented levels — ``ReceiptImage`` and ``ReceiptImageMeta``
— must be declared explicitly from the host ``AppConfig`` using the
bounded ``Ref`` grammar. Trusts does not import or discover host models,
and it does not infer a field lookup from a static content map.

Consider ``ReceiptImage`` as a dependent of ``Receipt``, and
``ReceiptImageMeta`` as a dependent of ``ReceiptImage``, with the
related-name ``image`` at each hop::

   # app/models.py
   class Receipt(Content):
       title = models.CharField(max_length=40)

   class ReceiptImage(models.Model):
       receipt = models.ForeignKey(Receipt, related_name='image', on_delete=models.CASCADE)

   class ReceiptImageMeta(models.Model):
       image = models.ForeignKey(ReceiptImage, related_name='image', on_delete=models.CASCADE)

   # app/apps.py
   from django.apps import AppConfig
   from trusts.apps import kernel_config
   from trusts.core import Ref
   from trusts.models import TrustUserPermission

   class ReceiptsConfig(AppConfig):
       name = 'app'

       def ready(self):
           try:
               registry = kernel_config(self.apps).configured_backend().registry
           except LookupError:
               return
           from app.models import Receipt
           j = Ref(TrustUserPermission)
           rev = Receipt._meta.get_field('trust').remote_field.get_accessor_name()
           if getattr(self, '_trusts_tup_receipt_image_registry_id', None) is not registry:
               registry.register(
                   content=getattr(j.trust, rev).image,
                   user=j.entity,
                   permission=j.permission,
               )
               self._trusts_tup_receipt_image_registry_id = registry
           if getattr(self, '_trusts_tup_receipt_image_meta_registry_id', None) is not registry:
               registry.register(
                   content=getattr(j.trust, rev).image.image,
                   user=j.entity,
                   permission=j.permission,
               )
               self._trusts_tup_receipt_image_meta_registry_id = registry

Name the exact Trusts path in ``configured_backend(path)`` when more
than one Trusts backend is listed. An undeclared dependent fails closed
(object checks false, enumeration empty, QuerySet authorization
none/false). Conditions remain overlays on an existing relational grant;
they never create a grant.

Role
~~~~

``Role`` can be specified in a ``Content`` model's ``Meta`` class. The management command ``python manage.py update_roles_permissions`` updates the corresponding database entries.

Here is an example of how roles can be specified::

   class Receipt(Content):

       name = models.CharField(max_length=40, null=False, blank=False)

       class Meta:
           abstract = True
           default_permissions = ('add', 'read', 'change', 'delete')
           permissions = (
               ('ask_question_about_receipt', 'Ask question about a receipt'),
           )
           roles = (
               ('user', ('read_receipt', 'ask_question_about_receipt')),
               ('manager', ('read_receipt', 'change_receipt', 'ask_question_about_receipt')),
               ('accounting', ('read_receipt', 'add_receipt', 'change_receipt', 'ask_question_about_receipt')),
           )

Roles specified in different models with the same role name are merged. Once
the database entries are created, those role permissions become part of the
group's **global capability ceiling**. Associating a group with a trust
(``trust.groups.add``) does not grant access by itself. A group permission
applies to Trust-controlled content only when the user is a member, a
``TrustGroup`` row exists, the permission is enabled locally on that
``TrustGroup``, and the permission is in the group's ceiling
(``Group.permissions`` or a role assigned to the group).

Add a role to a group, associate the group, then enable the local subset::

   from trusts.models import TrustGroup

   accountants = Group.objects.get(name='accountants')
   accountants.roles.add(Role.objects.get(name='accounting'))

   trust.groups.add(accountants)
   tg = TrustGroup.objects.get(trust=trust, group=accountants)
   tg.grant_permission(change_receipt)
   r = Receipt(trust=trust, ...)
   r.save()


Permissions Checking
~~~~~~~~~~~~~~~~~~~~

To check permission, simply use Django builtin API::

   def check_permission_to_a_specific_receipt(request, receipt_id):
     return request.user.has_perm('app.change_receipt', Receipt.objects.get(id=receipt_id))

   def check_permission_to_a_specific_group(request, group_id):
     return request.user.has_perm('app.change_group', Group.objects.get(id=group_id))


Generic instance authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Hosts that already hold a permission **instance** (not a Django codename
string) can filter candidate rows with the generic queryset API::

   from trusts.query import AuthorizedManager, AuthorizedQuerySet

   class Repository(models.Model):
       objects = AuthorizedManager()

   Repository.objects.authorized(account, operation)

``AuthorizedQuerySet.authorized(user, permission, extra_q=None)`` requires
``permission`` to be a model instance. Strings and auth.Permission
codenames raise ``TrustsConfigurationError`` with no SQL. The method does
not parse ``:condition``, does not call ``is_active_principal``, and does
not call ``get_permission``. ``extra_q`` is an AND overlay on an existing
grant; it never creates one. There is no ``.permitted`` and no
``.get_permission`` on this class. Django-permission list filtering
(``ContentQuerySet.permitted``) stays the documented codec for Trust
content and is unchanged.

Create-under-scope (filter rows of an **intermediate** model that appears
on a registered content path) uses ``filter_authorized_scopes`` from
``trusts.core``::

   from trusts.core import filter_authorized_scopes

   filter_authorized_scopes(
       Scope.objects.all(), user, permission_instance,
       content=Payload,
   )

The queryset model must be a proper prefix node of some applicable
record's ``content_path`` whose content terminal is ``content``. The
content terminal itself returns ``none()`` (use ``.authorized()``).
Unknown terminals, empty handles, and scope models that are not on the
path return ``none()``. ``permission`` must be an instance. Prefix
correlation uses the hop's resolved target field (including non-PK
``to_field`` identities), not an assumed primary key.

``ConditionLookup`` is a tiny protocol bound with
``TrustsRegistry.set_condition_lookup(lookup)``. Both ``record_for`` and
``compile_q`` must be present or bind raises ``TrustsConfigurationError``
(no partial bind). Callables compile to
``PermissionConditionNotQueryable`` and are never invoked. An unbound
lookup is the C1 default (instance-only callers; historical ``Content``
conditions stay in place until a later Zero bind).

``trusts.apps.kernel_config()`` returns the kernel ``trusts.apps.AppConfig``
by class identity. The kernel label is ``trusts_core``. After Zero is
installed, ``apps.get_app_config('trusts')`` is ``ZeroConfig`` (models,
not registries). Callers of the kernel store must use ``kernel_config()``
rather than the string label ``'trusts'``.

Closed registry predicates
~~~~~~~~~~~~~~~~~~~~~~~~~~

``TrustsRegistry.register`` accepts an optional closed predicate tree
from ``trusts.core``. This is not the historical ``Expr`` /
``:condition`` codec and is not a general ``Q`` dialect::

   from trusts.core import All, Equal, Ref, permission_in

   t = Ref(TeamRepoGrant)
   registry.register(
       content=t.repository,
       user=t.team.members,
       permission=t.operation,
       condition=All(
           permission_in(t.team.permission_bundles.operations),
           Equal(t.team.organization, t.repository.organization),
       ),
   )

A requester path may be one forward single-valued hop, or zero or more
forward single-valued hops followed by exactly one terminal many-to-many
membership hop. Reverse one-to-many requester paths stay rejected.
``All``, ``Equal``, and ``permission_in`` are AND-correlated through the
same permission-bearing row. ``Equal`` sides must share one resolved
comparison field; distinct unique fields on the same model are
rejected. Object authorization, authorized querysets / managers, and
permission enumeration share that plan. Malformed arity, types, or
paths raise ``TrustsConfigurationError`` at registration with zero SQL.

Decorators
~~~~~~~~~~

Trusts provides a decorator that checks permissions at the object level::

   from trusts.decorators import permission_required
   from app.models import Xyz

   @permission_required('app.change_xyz', fieldlookups_kwargs={'pk': 'xyz_id'})
   def edit_xyz_view(request, xyz_id):
     # ...
     pass

The argument `fieldlookups_kwargs` specifies the mapping between permissible object's field and view's arguments list.

The mapping is used to load the permissible object for permission check.


K(), G(), O() Lookups
+++++++++++++++++++++

Alternatively, `fieldlookups_kwargs` can be expressed with K() lookup::

   from trusts.decorators import permission_required, K, G, O
   from app.models import Xyz

   @permission_required('app.change_xyz', pk=K('xyz_id'))
   def edit_xyz_view(request, xyz_id):
     # ...
     pass

Similar to K() lookup, G() and O() can also be used.

``G()`` maps a permissible object's field to the request's ``GET`` dictionary.

``O()`` maps a permissible object's field to the request's ``POST`` dictionary.


Permission Conditions
+++++++++++++++++++++

In addition to ``Group`` and ``Permission`` based checks, an object-level permission condition can be used.

For example, a user may modify a ``Receipt`` only if the user owns it. In this case, register a condition code::

   Content.register_permission_condition(Receipt, 'own', lambda u, p, o: u == o.user)

Callables stay object-only (``has_perm``); they are never invoked with
symbolic references. They require
``TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS = True`` (see the migration
record). Register an ``Expr`` from ``condition_refs()`` to compile a V1
expression for ``.permitted()`` (see below).

To check ``own`` permission, a colon and the condition name should be added after the condition name::

   def check_permission_to_a_specific_receipt(request, receipt_id):
     return request.user.has_perm('app.change_receipt:own', Receipt.objects.get(id=receipt_id))

A condition can also be used with the decorator::

   @permission_required('app.change_receipt:own', pk=K('pk'))
   def edit_receipt_view(request, pk):
     # ...
     pass

.. warning::

   A permission condition is an additional constraint; it does not grant the underlying permission. For example, ``change_receipt:own`` requires both ``change_receipt`` and a successful ``own`` condition.

   V1 declarative conditions are **registered expression objects** (``==``, ``!=``, ``&``, ``|`` over principal and object fields), not probed lambdas. ``has_perm`` and ``.permitted()`` consume the same tree: object checks evaluate it in Python, and queryset filtering is ``base relational grant AND compiled condition`` before pagination.

   Callables remain object-only. They are a system-check error
   (``trusts.E002``) unless ``TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`` is
   True. ``ContentQuerySet.permitted`` and ``filter_by_user_content_perm``
   raise ``PermissionConditionNotQueryable`` for those callbacks so they
   cannot silently return the underlying grant. Invalid registered
   expressions fail closed on both paths.

   Run ``python manage.py check`` in CI and before deploy so invalid
   ``Expr`` registrations (``trusts.E001``) are reported before requests
   are served. Silencing a check ID does not make the policy executable.


Queryable permission conditions
+++++++++++++++++++++++++++++++

Build an ``Expr`` from symbolic ``u``, ``p``, ``o`` and register that tree.
Django ``Q`` is a compiler target, not the canonical form. Dispatch is by
type: an ``Expr`` is queryable policy data; a callable is never probed::

   from trusts.conditions import condition_refs
   from trusts.models import Content

   u, p, o = condition_refs()
   Content.register_permission_condition(
       Receipt, 'editable',
       (u == o.owner) |
       ((u == o.organization.manager) & (o.status != "locked")),
   )

   request.user.has_perm('app.change_receipt:editable', receipt)
   Receipt.objects.permitted('app.change_receipt:editable', request.user)

``django_trusts.Query`` / ``TQ`` is the reserved namespace for later
Django-style lookups (not a ``QuerySet``). V1 does not implement extra
lookups; equality uses ``==`` / ``!=`` on the refs.

Supported in this experiment:

* Principal and object field references, including ``ForeignKey`` / ``OneToOneField`` traversal (``o.organization.manager``)
* Literal constants (``None``, booleans, numbers, strings) whose Python type matches the field; relations compare to model instances, not raw primary keys
* ``==`` and ``!=``
* Nested ``&`` and ``|`` (grouping is preserved)

Unsupported (fail closed; do not drop the condition):

* Python ``and`` / ``or`` / ``not`` (they cannot be overloaded). Symbolic truth testing raises ``PermissionConditionBooleanError`` directing callers to ``&`` / ``|``.
* Chained comparisons such as ``0 < o.amount < 100`` (they truth-test the first comparison). Ordering comparisons are not in V1.
* Function or method calls, loops, indexing, I/O, arithmetic, assignment to symbolic fields
* Source or bytecode inspection; automatic probing of callables
* Permission attribute traversal (``p.codename``); ``p`` is unused in V1 except as a ref
* Terminal ``ManyToManyField`` and reverse one-to-many refs (``o.owner.groups``) until membership is defined
* Django field coercion (``Q(status=1)`` becoming ``"1"`` on a ``CharField``, or a ``ForeignKey`` accepting a raw PK). Incompatible ``Eq`` / ``Ne`` operands raise ``PermissionConditionError`` on both ``has_perm`` and ``.permitted()``.

Object and principal field paths are resolved against the target model and
``TRUSTS_ENTITY_MODEL`` / ``AUTH_USER_MODEL`` respectively (``_meta`` fields
and ``ForeignKey`` / ``OneToOneField`` traversal). Unknown or misspelled
names raise ``PermissionConditionError`` on both ``has_perm`` and
``.permitted()``; they are not treated as SQL/Python ``NULL``. Legitimate
nullable relations may still compare as ``None``. Python ``@property``
values are not V1 field paths. Operand types are checked without Django
``get_prep_value`` coercion: ``o.status == 1`` and ``o.owner == "1"``
raise ``PermissionConditionError`` on both ``has_perm`` and
``.permitted()``. ``filter_by_user_content_perm`` still rejects
every ``:condition`` suffix: that API filters Trust rows, not the content
model the condition is registered on. Field names, relation traversal, and
operand types are also reported by ``python manage.py check``
(``trusts.E001``) after models load.


P() Expressions
+++++++++++++++

Trusts' decorator supports P() expression, permitting the construction of compound permission using | (OR) and & (AND) operators;
In particular, it is not otherwise possible to use OR in permission::

   from trusts.decorators import permission_required, P, K, G, O
   from app.models import Xyz

   @permission_required(P('app.change_project:own', pk=K('project_id')) | P('app.move_receipt', pk=O('receipt_id')))
   def move_xyz_to_project_view(request, project_id):
     # ...
     pass


Customization
~~~~~~~~~~~~~

The following Django settings allow customization and adaptation.


Initial Options
+++++++++++++++

.. warning::

   Set ``TRUSTS_ENTITY_MODEL``, ``TRUSTS_GROUP_MODEL``, ``TRUSTS_PERMISSION_MODEL``, ``TRUSTS_ALLOW_NULL_SETTLOR``, and ``TRUSTS_DEFAULT_SETTLOR`` before creating migrations or running ``manage.py migrate`` for the first time. These settings affect model fields and relationships. Changing them after tables exist is not handled automatically by ``makemigrations`` and requires an explicit schema and data migration.

   The root settings control initial root creation. Changing ``TRUSTS_CREATE_ROOT``, ``TRUSTS_ROOT_PK``, ``TRUSTS_ROOT_SETTLOR``, or ``TRUSTS_ROOT_TITLE`` after the root exists does not update that row automatically. In particular, changing ``TRUSTS_ROOT_PK`` can invalidate existing references and defaults and requires a deliberate data migration.

* TRUSTS_ENTITY_MODEL -- The model name for `settlors` and `trustees` field. Must be specified in contenttypes format, ie, 'app_label.model_name'. (default: `settings.AUTH_USER_MODEL`.)
* TRUSTS_GROUP_MODEL -- The model name for `groups` field. (default: `auth.Group`)
* TRUSTS_PERMISSION_MODEL -- The model name for `Permission`. (default: `auth.Permission`)
* TRUSTS_CREATE_ROOT -- A boolean set to True indicates root Trust model object to be created during the initial migration. (default: True)
* TRUSTS_ROOT_PK -- The `pk` of the root trust model object. (default: 1)
* TRUSTS_ROOT_SETTLOR -- The `pk` of settlor of the root trust object. (default: None)
* TRUSTS_ALLOW_NULL_SETTLOR -- A boolean set to True indicates Trust.settlor field can be null. (default: TRUSTS_DEFAULT_SETTLOR == None)
* TRUSTS_DEFAULT_SETTLOR -- The default value for `settlor` field on Trust model. (default: None)
* TRUSTS_ROOT_TITLE -- The title of the root trust object. (default: "In Trust We Trust")
* TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS -- Opt-in for registered callable permission conditions on ``has_perm`` (default: False). See the migration record.


Further Documentation
~~~~~~~~~~~~~~~~~~~~~

* `Migration record <https://github.com/django-trusts/django-trusts/blob/master/migrates.md>`_
* `Supported Python and Django versions <https://github.com/django-trusts/django-trusts/blob/master/docs/support-matrix.md>`_
* `Runnable example application <https://github.com/django-trusts/django-trusts-example>`_
