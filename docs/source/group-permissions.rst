Membership and group permissions
================================

Authorization through membership
--------------------------------

A trust may reach a user through a team, role, organization, or another
membership relationship. Register that relationship as the ``user`` path:

.. code-block:: python

   backend.register(
       trust=TeamDocumentPermission,
       user=lambda t: t.team.members,
       permission=lambda t: t.permission,
       content=lambda t: t.document,
   )

This path can authorize ordinary object-permission inquiries:

.. code-block:: python

   user.has_perm("documents.change_document", document)
   user.get_all_permissions(document)
   Document.objects.authorized(user, change_document)

The model name does not give the relationship special meaning.
``django-trusts`` evaluates the registered relationship, whether the
application calls it a team, group, role, or something else.

Django group-permission enumeration
-----------------------------------

Django's ``user.get_group_permissions(obj)`` asks a narrower question: which
permissions did an authentication backend classify as permissions obtained
through groups?

Core ``django-trusts`` does not infer that classification from relationship
shape. In particular, a many-to-many membership path is not automatically a
Django group-permission path. A membership-derived trust may therefore make
``has_perm()`` true and appear in ``get_all_permissions()`` while Core
``get_group_permissions()`` remains empty.

Use ``has_perm()`` to answer whether the user may perform an operation,
``get_all_permissions()`` to enumerate all permissions supplied for an object,
and ``QuerySet.authorized()`` to select authorized objects. Use
``get_group_permissions()`` only when the distinction between group-derived
and other permissions is itself part of the application's supported
permission model.

Global Django permissions
-------------------------

This object-level behavior does not replace Django's global permission
backends. Applications that need Django's model and group permissions normally
list ``django.contrib.auth.backends.ModelBackend`` alongside their
``django-trusts`` backend. Django combines the permissions returned by the
configured backends.

django-trusts-zero compatibility
--------------------------------

``django-trusts-zero`` preserves the 0.x user-by-group-by-content permission
model. Its compatibility backend continues to answer
``get_group_permissions(obj)`` for those persisted group memberships.

That compatibility behavior does not make every Core membership path a group
permission. Applications using their own Core trust models should rely on the
ordinary authorization inquiries above unless their chosen permission
implementation explicitly documents group-permission enumeration.
