.. django-trusts documentation master file, created by
   sphinx-quickstart on Fri Jan 29 22:11:11 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to django-trusts's documentation!
=========================================

Django authorization add-on for multiple organizations and object-level permission settings

Introduction
------------

``django-trusts`` is a add-on to Django's builtin [1]_ authorization. It strives to be a **minimal** implementation, adding only a single concept, ``trust``, to enable maintainable per-object permission settings for a django project that hosts users of multiple organizations [2]_ with a single user namespace.

A ``trust`` is a relationship whereby content access is permitted by the creator [``settlor``] to specific user(s) [``trustee`` (s)] or ``group`` (s). Content can be an instance of a `Content` subclass, or of an existing model via a junction table. Access to multiple content can be permitted by a single ``trust`` for maintainable permssion settings. Django's builtin model, `group`, is supported and can be used to define reusuable permissions for a ``group`` of ``user``'s.

``django-trusts`` also strives to be a **scalable** solution. Permissions checking is offloaded to the database by design, and the implementation minimizes database hits. Permissions are cached per ``trust`` for the lifecycle of ``request user``. If a project's request lifecycle resolves most checked content to one or few ``trusts``, which should be very typically the case, this design should be a winner in term of performance. Permissions checking is done against an individual content or a ``QuerySet``.

``django-trusts`` supports Django's builtins User models ``has_perms()`` / ``has_perms()`` and does not provides any in-addition.


.. [1]  See: `Django Object Permissions <https://github.com/djangoadvent/djangoadvent-articles/blob/master/1.2/06_object-permissions.rst>`_.
.. [2]  Even ``django-trusts`` is incepted to support multiple organizations in a single project, it does not define or restrict oraganization model design. One natural approach is to model an organization as a special user. With this arrangment, an organization can be the `settlor` of `trusts`. Alternative approach is to create another model for organization. With this arrangment, the `settlor` of `trust`s can simple be the creating user and one might or might not have all permissions of organization's content.

Usages
----- 

Installation
~~~~~~~~~~~~

Steps:

1. pip install django-trusts

2. Replace ``AUTHENTICATION_BACKENDS`` in ``settings.py`` ::

   AUTHENTICATION_BACKENDS = (
     'trusts.backends.TrustModelBackend',
   )

3. Add ``trusts`` to INSTALLED_APPS in your settings.py

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
   def grant_user_group_permssion_to_model(user, group_name, model_name, code='change', app='app'):
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

``Role`` can be specified in Content's Meta class. The management command ``update_roles_permissions.py`` will update corresponding entries in the database.

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

Roles specified in different models with the same role name are merged. Once the database entries is created, all user in groups that links to a role will automatically inherits all permissions specified for that roles for all models.

Add a role to a group to instead of adding each permissions one-by-one::

   accountants = Group.objects.get(name='accountants')
   accountants.roles.add(Role.objects.get(name='accounting')

   trust.groups.add(accountants)
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

Trusts provides a decorator that check permission on object level. (in contrast to builtin one only verify permission at model level)::

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

G() lookup maps permissible object's field and request's GET dict.

G() lookup maps permissible object's field and request's POST dict.


Permission Conditions
+++++++++++++++++++++

In additional ``Group`` and ``Permission`` based check, object level permission condition can be used.

For example, a user should be let to modify a ``Receipt`` if he was the creation owner. In
this case, a condition code should be registered::

   Content.register_permission_condition(Receipt, 'own', lambda u, p, o: u == o.user)

To check ``own`` permission, a colon and the condition name should be added after the condition name::

   def check_permission_to_a_specific_receipt(request, receipt_id):
     return request.user.has_perm('app.change_receipt:own', Receipt.objects.get(id=receipt_id))

Condition can also be used with decorator as follow::

   @permission_required('app.change_receipt:own', pk=K('pk'))
   def edit_receipt_view(request, pk):
     # ...
     pass


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

The folllowing settings (django.conf) allow for customization and adaptation.


Initial Options
+++++++++++++++

..  Warning:: Changing the options below affects the construction of foreign keys and many-to-many
    relationships. If you intend to set these options, you should set it before creating any
    migrations or running `manage.py migrate` for the first time, and should not be changed afterward.

    Changing this setting after you have tables created is not supported by `makemigrations` and
    will result in you having to manually fix your schema, port your data from the old user table,
    and possibly manually reapply some migrations.

* TRUSTS_ENTITY_MODEL -- The model name for `settlors` and `trustees` field. Must be specified in contenttypes format, ie, 'app_label.model_name'. (default: `settings.AUTH_USER_MODEL`.)
* TRUSTS_GROUP_MODEL -- The model name for `groups` field. (default: `auth.Group`)
* TRUSTS_PERMISSION_MODEL -- The model name for `Permission`. (default: `auth.Permission`)
* TRUSTS_CREATE_ROOT -- A boolean set to True indicates root Trust model object to be created during the initial migration. (default: True)
* TRUSTS_ROOT_PK -- The `pk` of the root trust model object. (default: 1)
* TRUSTS_ROOT_SETTLOR -- The `pk` of settlor of the root trust object. (default: None)
* TRUSTS_ALLOW_NULL_SETTLOR -- A boolean set to True indicates Trust.settlor field can be null. (default: TRUSTS_DEFAULT_SETTLOR == None)
* TRUSTS_DEFAULT_SETTLOR -- The default value for `settlor` field on Trust model. (default: None)
* TRUSTS_ROOT_TITLE -- The title of root rust object. (default: "In Trust We Trust")
