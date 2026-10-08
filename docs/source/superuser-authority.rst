Superuser Authority Across Permission Surfaces
==============================================

This document is the implementation contract for `issue #273
<https://github.com/django-trusts/django-trusts/issues/273>`_. It is being
reviewed before the runtime change so that the security boundary can be
approved independently of its implementation.

Contract and implementation status
----------------------------------

The contract is:

   ``is_superuser`` is not, by itself, a django-trusts grant.

A Trusts-owned inquiry grants only through a complete registered path, with
all selected conditions applied. This rule covers direct and delegated
branches. A superuser is an ordinary principal inside the Trusts policy unless
the application registers a path that grants that principal authority.

At the time this contract was written, ``dev`` still has two known
implementation differences:

* ``authorization_required()`` lets an active superuser bypass grants and
  selected conditions after structural preflight; and
* the reverse user inquiry adds an active-superuser predicate outside its
  registered backend branches.

Those are implementation work for issue #273. Merging this document approves
the target behavior; it does not claim that the runtime work has landed.

The Django boundary
-------------------

Django's ``PermissionsMixin.has_perm()`` returns ``True`` for an active
superuser before it asks any authentication backend. django-trusts cannot
revoke that result. Therefore these two questions deliberately have different
boundaries:

.. code-block:: python

   user.has_perm("documents.change_document", document)
   # Django-facing question. PermissionsMixin may answer True first.

   Document.objects.permitted(
       "documents.change_document",
       user,
   )
   # Trusts-owned question. Requires a complete registered path.

Applications may intentionally use Django's outer rule for Django admin or
another application-owned policy. That choice does not enter a Trusts query,
a delegated sponsor's ordinary-authority union, or policy-lock SQL.

Surface matrix
--------------

The same principal can therefore receive different answers from APIs that ask
different questions:

.. list-table::
   :header-rows: 1
   :widths: 28 34 38

   * - Surface
     - Authority source
     - Superuser behavior
   * - ``user.has_perm(code, obj)``
     - Django's outer principal rule, then configured backend OR
     - Active ``PermissionsMixin`` superuser remains globally authorized
   * - Direct call to a Trusts backend object check
     - That backend's complete registered paths
     - No implicit shortcut
   * - Trusts permission enumeration
     - Permission strings produced by complete registered paths
     - No permission is added merely because ``is_superuser`` is true
   * - ``QuerySet.authorized()``
     - Complete registered relationship paths
     - No implicit shortcut
   * - ``QuerySet.permitted()``
     - Complete registered relationship paths and selected conditions
     - No implicit shortcut
   * - ``authorization_required()``
     - Complete registered relationship paths and selected conditions
     - No implicit shortcut; this is pending runtime work in #273
   * - ``get_permitted_users()`` and ``User.objects.permitted()``
     - OR of supported backend contributions, each containing its complete
       grant and eligibility predicates
     - Core adds no outer active-superuser branch; this is pending runtime
       work in #273
   * - Policy SQL and lockfile
     - Backend-local complete registered paths
     - No Django outer shortcut

``authorization_required()`` keeps its existing HTTP distinction: a missing
candidate is 404 and an existing unauthorized candidate is 403. An active
superuser receives those same results from the same registered-path decision
as any other principal.

The reverse inquiry remains a union of supported backend contributions.
Removing Core's outer superuser predicate does not turn one backend's rejection
into a global deny, and it does not remove a grant explicitly contributed by a
supported backend. It means only that Core does not manufacture an additional
grant from the user model's ``is_superuser`` value.

User-model requirements
-----------------------

A Trusts-owned inquiry must not require an ``is_superuser`` field merely to
reproduce Django's outer shortcut. In particular, the reverse inquiry must
accept a custom user model without a concrete ``is_superuser`` field when the
model otherwise satisfies the inquiry's persisted-principal and registered
path requirements.

This does not weaken requirements that belong to a particular surface. For
example, a public content-list inquiry still denies an anonymous or inactive
acting principal, and a reverse backend contribution may still require fields
needed by that backend's own eligibility predicate.

Delegation
----------

Delegation does not create a second superuser rule. Its sponsor-side ordinary
authority is the union of complete registered ordinary paths, not the result
of calling ``PermissionsMixin.has_perm()``:

.. code-block:: text

   actor ordinary authority
   OR
   (
       matching delegation relationship
       AND
       sponsor live ordinary authority from registered paths
   )

Consequently, setting ``is_superuser`` on either the actor or sponsor does not
complete a missing branch. An application that wants a root, break-glass, or
administrator path inside Trusts must model and register that path explicitly.

Implementation acceptance
-------------------------

The implementation following this contract must demonstrate all of the
following:

1. An active superuser without a matching registered grant is denied or
   absent on every Trusts-owned surface in the matrix: the direct backend
   object check, permission enumeration, ``.authorized()``, ``.permitted()``,
   the view guard, and the reverse inquiry.
2. A matching registered grant authorizes a superuser under the same
   conditions as another active principal.
3. Selected conditions can deny a superuser.
4. Direct and delegated branches both use registered-path-only authority.
5. Removing a sponsor's last applicable ordinary path removes the delegated
   result even when that sponsor is a superuser.
6. An inactive superuser with a registered grant is denied by the view guard
   and ``.permitted()``. The reverse inquiry includes that principal only
   when a supported backend's own eligibility rule would include the same
   inactive user.
7. An inactive sponsor contributes no delegated authority.
8. A custom user model without a concrete ``is_superuser`` field can use the
   reverse inquiry when its registered paths are otherwise supported.
9. ``PermissionsMixin.has_perm()`` retains Django's active-superuser result,
   and the stock Django admin index and changelist still return HTTP 200 for
   an active superuser without application-specific admin changes.
10. Backend-local policy-lock bytes do not change solely because Core removes
    its outer runtime shortcut.

Downstream applications must update expectations for Trusts-owned reverse
queries when they repin Core. Application code that intentionally implements
Django's outer superuser policy remains application-owned and is not rewritten
as part of #273.
