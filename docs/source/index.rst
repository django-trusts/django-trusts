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

``django-trusts`` also strives to be a **scalable** solution. Trust and grant resolution uses database queries, and the implementation minimizes database hits. Permissions are cached per ``trust`` on the user object. Permission checks can be made against an individual content object or a ``QuerySet``.

.. warning::

   The per-trust permission cache is not automatically invalidated when grants, group membership, local TrustGroup permissions, or roles change. Reload the user object, or explicitly remove its ``_trust_perm_cache`` attribute, before making further permission checks with the same user instance.

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

2. Set ``AUTHENTICATION_BACKENDS`` in ``settings.py``::

   AUTHENTICATION_BACKENDS = (
     'trusts.backends.TrustModelBackend',
   )

3. Add ``trusts`` to ``INSTALLED_APPS`` in ``settings.py``.

4. Apply migrations::

     python manage.py migrate

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

Dependent model can inherit Trust from a related model. Such class need to be registered manually
with ``fieldlookup`` specified.

Consider ReceiptImage as a dependent model of Receipt, and ReceiptImageMeta as a dependent
model of ReceiptImage. The following code makes both model available for permission checking::

   Content.register_content(ReceiptImage, '%s__image' % Content.get_content_fieldlookup('app.Receipt'))
   Content.register_content(ReceiptImageMeta, '%s__image' % Content.get_content_fieldlookup(ReceiptImage))

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
symbolic references. Register an ``Expr`` from ``condition_refs()`` to
compile a V1 expression for ``.permitted()`` (see below).

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

   Callables remain object-only. ``ContentQuerySet.permitted`` and ``filter_by_user_content_perm`` raise ``PermissionConditionNotQueryable`` for those callbacks so they cannot silently return the underlying grant. Invalid registered expressions fail closed on both paths.


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
raise on both paths. ``filter_by_user_content_perm`` still rejects
every ``:condition`` suffix: that API filters Trust rows, not the content
model the condition is registered on.


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


Further Documentation
~~~~~~~~~~~~~~~~~~~~~

* `Migration record <https://github.com/django-trusts/django-trusts/blob/master/migrates.md>`_
* `Supported Python and Django versions <https://github.com/django-trusts/django-trusts/blob/master/docs/support-matrix.md>`_
* `Runnable example application <https://github.com/django-trusts/django-trusts-example>`_
