Activity checks in permission inquiries
=======================================

.. note::

   This is the proposed contract for `issue #284
   <https://github.com/django-trusts/django-trusts/issues/284>`_.
   ``allow_inactive`` is not implemented. The signatures below require
   implementation and agreement tests before applications can use them.

An owner reviewing permissions needs to see authority held by a temporarily
suspended user. Otherwise, a permission may appear absent during suspension
and become usable again when that suspension ends. Normal inquiries should
deny inactive principals; an explicit audit inquiry should include their
otherwise valid grants.

Current behavior
----------------

The existing entry points do not all impose the same activity rule:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Entry point
     - Current activity behavior
   * - Content queryset ``.permitted(...)``
     - Anonymous, unauthenticated, and inactive users receive no rows.
   * - Trusts backend ``has_perm``, ``get_all_permissions``, and
       ``get_group_permissions``
     - Reject the same ineligible principals before the grant inquiry.
   * - ``.authorized(...)`` and ordinary registry/plan projections
     - Ordinary grants have no equivalent principal shortcut. They can
       produce results for an inactive user.
   * - Delegated grant compilation
     - The delegate and sponsor must satisfy principal eligibility.
       Sponsor eligibility is compiled into the delegation predicate.
   * - Reverse user inquiries
     - Trusts branches apply principal eligibility. The aggregate also
       includes Django's active-superuser rule and participating backend
       predicates; it has no global activity filter over those branches.
   * - ``authorization_required``
     - An enforcement guard with its existing principal checks and
       active-superuser behavior. It has no audit-mode option.

Stock Django user methods keep Django's signatures and backend composition.
They must not be described as having an ``allow_inactive`` argument.

Proposed contract
-----------------

Trusts-owned inquiries gain a keyword-only ``allow_inactive=False``.
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

Proposed public signatures
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following are proposed extensions of the existing Trusts adapters,
not examples of currently runnable code:

.. code-block:: text

   queryset.permitted(permission, user, conditions=(), *, allow_inactive=False)
   queryset.authorized(user, permission, extra_q=None, *, allow_inactive=False)
   content.get_permitted_users(perm, *, allow_inactive=False)
   User.objects.permitted(content, perm, *, allow_inactive=False)

   backend.has_perm(user_obj, permext, obj=None, *, allow_inactive=False)
   backend.get_all_permissions(user_obj, obj=None, *, allow_inactive=False)
   backend.get_group_permissions(user_obj, obj=None, *, allow_inactive=False)

Manager adapters forward the keyword without changing positional arguments.
The lower-level registry inquiry methods ``permissions_for``,
``has_permission``, and ``filter_authorized``, and the scope inquiry
``filter_authorized_scopes``, need the same explicit mode. Plan and compiler
helpers must propagate that mode into both ordinary and delegated proofs.
Their exact signatures and companion overrides require review before the
runtime change; raw correlated-predicate builders must not mistake an
``OuterRef`` for a concrete user instance.

Both reverse adapters return the same users when they start from the same
candidate queryset. Under the same mode, the Trusts contribution to a reverse
result must agree with the corresponding forward/object inquiry. Existing
differences in permission codecs, backend composition, and superuser
shortcuts are not removed by this flag.

Candidate querysets and other backends
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
composition is retained, with the proposed activity eligibility applied to
the aggregate candidate users. Unsupported reverse shapes remain errors.

Enforcement and superusers
~~~~~~~~~~~~~~~~~~~~~~~~~~

View guards and login/authentication flows keep their existing enforcement
behavior. This proposal adds no audit option to ``authorization_required``.
An application choosing audit mode must do so explicitly; the flag does not
authorize the caller to inspect another user's permissions.

This flag grants no superuser privilege and does not relax Django's outer
active-superuser rule. A future Trusts superuser feature would give no special
treatment by default and require explicit opt-in. Its scope and API are a
separate decision under `issue #273
<https://github.com/django-trusts/django-trusts/issues/273>`_. They are not
implemented or settled by this activity contract.

Implementation and migration requirements
-----------------------------------------

Changing ``.authorized()`` and ordinary registry inquiries to deny inactive
users by default changes existing results. The implementation PR must add a
``migrates.md`` entry with old/new behavior, the explicit audit replacement,
affected companion APIs, and a migration-bot checklist. This documentation
proposal is not a release claim and supplies no executable migration yet.

Audit and normal results must not share a permission-cache entry. Existing
activity/revocation cache behavior must also be reviewed; an audit result
must never be reused to grant normal access.

Policy SQL must describe the selected eligibility mode without silently
relabeling the current default statement as audit SQL. The default and audit
representation, parameter roles, and lockfile compatibility must be agreed
before runtime implementation. No schema-version change is assumed here.

Acceptance includes forward, reverse, object, enumeration, and scope results
under both modes; inactive delegates and sponsors independently and together;
ordinary grants alongside delegation; revocation and expiry; explicit
activity conditions; anonymous and unauthenticated denial; restricted
candidate managers; mode-separated caches; and unsupported backend errors.
The docs, runtime, companion behavior, and policy SQL must agree before this
contract is described as implemented.
