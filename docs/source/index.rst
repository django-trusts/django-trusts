django-trusts
=============

.. image:: _static/django-trusts-mascot.png
   :alt: django-trusts badger mascot holding a green key
   :align: center
   :width: 220px

Declarative object permissions for Django
-----------------------------------------

A permission is a persisted relationship between a user, an operation, and
protected content. Your application owns those models; django-trusts compiles
the registered relationships into permission queries.

This example gives a user permission to change a document.

Installation
------------

The development line supports Python 3.12--3.14 and Django 6.1.

.. code-block:: console

   python -m pip install "Django>=6.1,<6.2"
   python -m pip install "django-trusts @ git+https://github.com/django-trusts/django-trusts@dev"

Define the models
-----------------

The **trust model**, ``DocumentPermission``, connects the user, permission,
and document:

.. code-block:: python

   # documents/models.py
   from django.conf import settings
   from django.contrib.auth.models import Permission
   from django.db import models
   from trusts.query import PermittedQuerySetMixin, PermittedUsersMixin


   class DocumentQuerySet(PermittedQuerySetMixin, models.QuerySet):
       pass


   class Document(PermittedUsersMixin, models.Model):
       title = models.CharField(max_length=200)
       objects = DocumentQuerySet.as_manager()


   class DocumentPermission(models.Model):
       user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
       permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
       document = models.ForeignKey(Document, on_delete=models.CASCADE)

Define the backend
------------------

.. code-block:: python

   # documents/backends.py
   from django.contrib.auth.backends import ModelBackend
   from trusts.backends import TrustModelBackendMixin


   class DocumentBackend(TrustModelBackendMixin, ModelBackend):
       pass

Register the trust
------------------

.. code-block:: python

   # documents/apps.py
   from trusts.apps import TrustsImplementationConfig


   class DocumentsConfig(TrustsImplementationConfig):
       name = "documents"
       trusts_backend_paths = ("documents.backends.DocumentBackend",)

       def ready(self):
           super().ready()
           from .models import DocumentPermission

           backend = self.configured_backend()
           backend.register(
               trust=DocumentPermission,
               user=lambda t: t.user,
               permission=lambda t: t.permission,
               content=lambda t: t.document,
           )

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

Create and apply your application's migrations, then run Django's checks:

.. code-block:: console

   python manage.py makemigrations documents
   python manage.py migrate
   python manage.py check

Grant a permission
------------------

Granting and revoking permission are ordinary application data writes:

.. code-block:: python

   from django.contrib.auth.models import Permission
   from documents.models import DocumentPermission

   change_document = Permission.objects.get(
       content_type__app_label="documents",
       content_type__model="document",
       codename="change_document",
   )
   grant = DocumentPermission.objects.create(
       user=user, permission=change_document, document=document,
   )
   # grant.delete() revokes this grant.

Ask permission questions
------------------------

.. code-block:: python

   user.has_perm("documents.change_document", document)
   user.get_all_permissions(document)
   documents = Document.objects.filter(title__startswith="Report").permitted(
       "documents.change_document", user,
   )
   users = document.get_permitted_users("documents.change_document")

For other manager attachments, permission forms, and inquiry signatures,
see the `permission inquiry reference
<https://github.com/django-trusts/django-trusts/blob/dev/docs/dev/permission-inquiries.md>`_.

Protect a view
--------------

.. code-block:: python

   # documents/views.py
   from django.http import HttpResponse
   from trusts.decorators import authorization_required
   from .models import Document


   @authorization_required(Document, "documents.change_document")
   def edit_document(request, pk):
       return HttpResponse("Permitted")

The guard uses the URL keyword ``pk``; see its `lookup and denial behavior
<https://github.com/django-trusts/django-trusts/blob/dev/docs/dev/permission-inquiries.md#protect-a-view>`_.

.. _user-is-active-checks:
.. _user-conditions-and-overrides:

User conditions and overrides
-----------------------------

A user condition must hold for every grant. A user override grants the
checked user without an ordinary grant. The only default condition is
``is_active``, if the field exists; no override is registered by default.

Set user conditions and overrides in ``AppConfig.ready()``, before
registering permissions or delegations:

.. code-block:: python

   registry = backend.registry
   registry.set_user_condition("is_active", lambda u: u.is_active)

Setting the same name replaces that condition; pass ``None`` to remove it.
Condition names are unique Python identifiers and lambdas return Boolean
expressions. ``set_user_override()`` sets one override slot; setting another
replaces it, and passing its current name with ``None`` removes it.

To audit an inactive user's grants, skip the condition for that inquiry:

.. code-block:: python

   documents = Document.objects.permitted(
       "documents.change_document", user, skip_is_active=True,
   )

Django allows active superusers before asking backends; see the `Django auth boundary
<https://github.com/django-trusts/django-trusts/blob/dev/SECURITY_AUDIT.md#django-auths-checks-before-calling-backends>`_.

Next steps
----------

* `Security audit <https://github.com/django-trusts/django-trusts/blob/dev/SECURITY_AUDIT.md>`_: policy boundaries, delegation, named filters, ``along=``, and SQL lockfiles.
* `Migrations <https://github.com/django-trusts/django-trusts/blob/dev/migrates.md>`_: required upgrade actions.
* `What's new <https://github.com/django-trusts/django-trusts/blob/dev/docs/whats-new.md>`_: release changes.

Reference implementations
-------------------------

* `GH permissions <https://github.com/django-trusts/django-trusts-gh-permissions>`_: organization, team, and repository permissions.
* `OrderedFold <https://github.com/django-trusts/django-trusts-ordered-fold>`_: provisional ordered allow/deny policies.
* `Windows ACL <https://github.com/django-trusts/django-trusts-windows-acl>`_: an OrderedFold example.
* `Zero <https://github.com/django-trusts/django-trusts-zero>`_ and its `runnable example <https://github.com/django-trusts/django-trusts-zero-example>`_: the 0.x implementation.
