Activity checks in permission inquiries
=======================================

An owner reviewing permissions needs to see authority held by a temporarily
suspended user. Otherwise, a permission may appear absent during suspension
and become usable again when that suspension ends. Normal inquiries should
deny inactive principals; an explicit audit inquiry should include their
otherwise valid grants.

Activity eligibility
--------------------

Trusts-owned inquiries accept a keyword-only ``allow_inactive=False``.
The value must be a boolean. Input and configuration validation still run
before an eligibility shortcut; an inactive user does not conceal an invalid
permission or unsupported configuration.

With the default, a queried user or delegate must satisfy the existing
principal-eligibility rule. Every sponsor used to supply delegated authority
must satisfy it too. With ``allow_inactive=True``, only the built-in
``is_active`` test is skipped for those principals. Anonymous and
unauthenticated principals remain ineligible. Required model-instance,
permission-identity, and relationship validation remains unchanged.

The mode is passed through every grant branch in an inquiry. It is not
implemented by modifying a user object's attributes, loading and modifying a
sponsor, or temporarily changing global settings. Persisted principal
eligibility remains a SQL predicate, and a queryset inquiry remains lazy.

The flag does not waive stored policy. Tenant restrictions, delegation scope,
grant revocation, approval, expiry, and named conditions still apply. An
explicit condition on ``is_active`` is still evaluated. A sponsor still needs
an applicable ordinary grant for the same content and permission; auditing
does not make delegated authority into sponsor authority.

Public signatures
-----------------

.. code-block:: text

   queryset.permitted(permission, user, conditions=(), *, allow_inactive=False)
   queryset.authorized(user, permission, extra_q=None, *, allow_inactive=False)
   content.get_permitted_users(perm, *, allow_inactive=False)
   User.objects.permitted(content, perm, *, allow_inactive=False)

   backend.has_perm(user_obj, permext, obj=None, *, allow_inactive=False)
   backend.get_all_permissions(user_obj, obj=None, *, allow_inactive=False)
   backend.get_group_permissions(user_obj, obj=None, *, allow_inactive=False)

Manager adapters forward the keyword without changing positional arguments.
Registry inquiries ``permissions_for``, ``has_permission``, and
``filter_authorized``, and ``filter_authorized_scopes``, use the same explicit
mode. The mode applies only to grant shapes that the inquiry already supports.
It does not add delegated scope listing or change permission codecs.

Both reverse adapters return the same users when they start from the same
candidate queryset. Under the same mode, the Trusts contribution to a reverse
result must agree with the corresponding forward/object inquiry. Existing
differences in permission codecs, backend composition, and superuser
shortcuts are not removed by this flag.

Inspecting suspended accounts
-----------------------------

An audit call includes an inactive user or sponsor only when a matching grant
and every remaining restriction allow the operation:

.. code-block:: python

   documents = Document.objects.permitted(
       "documents.change_document", suspended_user, allow_inactive=True,
   )
   users = document.get_permitted_users(
       "documents.change_document", allow_inactive=True,
   )

With the flag omitted, an inactive principal produces no permitted rows, no
permissions in enumeration, and a false object check. The same default gate
applies to ordinary and delegated grants. In reverse inquiries it applies to
the candidate users across the combined backend contributions.

Candidate querysets and other backends
--------------------------------------

The original candidate queryset remains the upper bound. If an application's
user manager excludes inactive users, audit mode does not recover them by
replacing that manager. Applications needing a complete audit must provide a
candidate source that includes the rows they want to inspect. Explicit
``filter(is_active=True)`` restrictions likewise remain effective.

Stock Django ``user.has_perm``, ``has_perms``, permission enumeration, and
``has_module_perms`` do not forward this keyword. Audit callers use the
explicit Trusts inquiry adapters. A backend call describes that backend's
contribution, not Django's aggregate answer. No Django monkey patch or
mandatory user-model replacement is part of this contract.

A custom compiler or third-party backend that participates in an audit
inquiry must explicitly support the mode. If its audit contribution cannot
be expressed, the inquiry raises ``TrustsConfigurationError`` before SQL.
It must not silently omit that backend, retry without the flag, or return a
partial result described as complete. Existing default-mode backend
composition is retained, with activity eligibility applied to
the aggregate candidate users. Unsupported reverse shapes remain errors.

Enforcement and superusers
--------------------------

View guards and login/authentication flows keep their existing enforcement
behavior. ``authorization_required`` has no audit-mode argument. The flag does
not authorize the caller to inspect another user's permissions; the
application protects its audit interface separately.

``allow_inactive`` grants no superuser privilege and does not relax Django's
outer active-superuser rule. An inactive superuser can be included through
actual grants in an audit inquiry, but does not acquire the automatic
superuser shortcut through this flag.

Migrating existing inquiries
----------------------------

``.authorized()`` and ordinary registry/scope inquiries deny inactive users by
default. Code that previously used their ungated ordinary projections to
inspect a suspended user's stored grants supplies ``allow_inactive=True``.
See the `migration guide
<https://github.com/django-trusts/django-trusts/blob/dev/migrates.md#activity-checks-in-permission-inquiries-284>`_
for the affected calls and before/after examples.

Audit results are not reused for normal enforcement. If an application caches
permission results, its cache identity includes the inquiry's activity mode
and its invalidation accounts for changed principal activity and grant state.
