Authorization policy in SQL
===========================

django-trusts can render its registered authorization policy as parameterized
SQL for inspection. The same stable output can be committed as an authorization
policy lockfile, making changes to the policy and its SQL visible during normal
code review.

Inspecting the generated SQL
----------------------------

Render the finalized authorization policy without writing a lockfile:

.. code-block:: console

   python manage.py trusts_policy_sql

The command uses the database alias selected by ``TRUSTS_POLICY_DATABASE``, or
Django's ``default`` alias when that setting is unset. Select another configured
alias for one invocation with ``--database``:

.. code-block:: console

   python manage.py trusts_policy_sql --database policy_inspection

The command writes YAML using the installed PyYAML writer. The selected Django
database backend and driver determine SQL quoting, placeholders, operators, and
dialect. The alias is not stored; ``database.engine`` records its configured
engine.

Runtime user and permission roles remain symbolic ``bind`` parameters. For
candidate-object checks, the exporter compiles a type-correct sentinel primary
key and records it as ``const``. That value identifies the compiled comparison
position; it is not a primary key read from application data. Rendering compiles
the exported queries without executing them or reading application or
authorization rows.

Document shape
--------------

The document is organized by application meaning:

* each configured Trusts backend has one ``backends`` row,
  including ``contents: []`` when it has no declarations;
* each backend lists its ``contents`` models;
* a content with trusts lists them with their associated SQL for
  ``permitted``, ``has_perm``, ``get_all_permissions``, and
  ``get_permitted_users``, plus ``get_group_permissions`` when a trust
  uses ``group=``;
* a content with named filters lists those queries; and
* a filter-only content contains ``model`` and ``named_filters``.

The following abridged example shows the schema:

.. code-block:: yaml

   schema_version: 1
   database:
     engine: "django.db.backends.sqlite3"
   backends:
     - path: "documents.backends.DocumentBackend"
       contents:
         - model: "documents.Document"
           trusts:
             - id: "documents__DocumentPermission__document"
               root: "documents.DocumentPermission"
               user: {path: "user", model: "auth.User", target: "id"}
               permission: {path: "permission", model: "auth.Permission", target: "id"}
               content: {path: "document", model: "documents.Document", target: "id"}
           permitted:
             params: [{const: 1}, {bind: "permission.id"}, {const: "documents"}, {const: "document"}, {bind: "user.id"}]
             sql: |-
               SELECT DISTINCT ...
           has_perm:
             params: [{const: 1}, {const: 1}, {const: 1}, {bind: "permission.id"}, {const: "documents"}, {const: "document"}, {bind: "user.id"}]
             sql: |-
               SELECT ... WHERE candidate-primary-key AND grant-exists
           get_all_permissions:
             params: [{const: 1}, {const: 1}, {const: 1}, {const: 1}, {const: 1}, {const: "documents"}, {const: "document"}, {bind: "user.id"}]
             sql: |-
               SELECT DISTINCT ... FROM auth_permission ...
           get_permitted_users:
             params: [{const: true}, {const: 1}, {bind: "content.id"}, {bind: "permission.id"}, {const: "documents"}, {const: "document"}]
             sql: |-
               SELECT DISTINCT ... FROM auth_user ... WHERE grant-exists
           named_filters:
             - id: "documents__Document__non_confidential"
               params: [{const: true}]
               sql: |-
                 SELECT ... WHERE non-confidential-predicate

Trusts and OR composition
~~~~~~~~~~~~~~~~~~~~~~~~~

Each trust retains the registered root and the resolved ``user``,
``permission``, and ``content`` relationships. Relationship ``path`` values
use Django's ``__`` spelling for multiple steps; ``model`` and ``target``
identify the related concrete model and comparison field.

An explicit ``group=`` registration also records ``group``: the declared
path, which ends at ``auth.Group``. Its ``permission`` relation is the
compiler-owned step from that group to ``auth.Permission``. That content
includes ``get_group_permissions`` next to the other permission inquiries.
A ``permission=`` registration does not add either field. When
``permission=`` ends on a forward many-to-many collection, ``permission``
records that path (for example ``permissions`` or ``team__permissions``),
``auth.Permission``, and the permission primary key. The lock still omits
``group`` and ``get_group_permissions`` for that registration.

When the permission terminal's concrete model is ``auth.Permission``,
each inquiry's grant also requires that row's ``app_label`` and ``model``
to be the protected model's content identity. Those two values are
``const`` parameters in the same statement. A proxy model would use its
own identity. Any other permission terminal, including a custom model
with a ``content_type`` foreign key, does not gain the predicate and
stays a primary-key comparison. The codename is not parsed to choose the
model. Regenerating the lockfile after this predicate is present changes
the SQL bytes for every ``auth.Permission`` grant.

``get_permitted_users`` is the reverse of ``permitted``: one saved content
object and one permission, compiled to the users that backend can grant.
The locked statement is that backend branch only. It carries the backend's
eligibility predicate and the complete-grant ``EXISTS``. It does not include
Django's outer active-superuser rule, and it does not OR other
authentication backends. The content primary key is a ``content.<target>``
bind. The permission row is a ``permission.<target>`` bind. The candidate
user is the outer row. ``content.get_permitted_users(perm)`` and optional
``User.objects.permitted(content, perm)`` share this one policy entry
because they use the same reverse compiler; the document does not duplicate
their SQL. The lockfile key stays ``get_permitted_users``. An ``Along`` registration has no exact
reverse predicate, so rendering raises ``TrustsConfigurationError`` before a
partial document is returned.

A django-trusts backend issues one SQL statement for each permission inquiry.
When more than one trust in that backend authorizes the same content model, the
SQL combines those trusts with OR and each trust in the content row has
``or_group: true``. A sole trust omits ``or_group``.

A delegated trust exposes its normalized ``delegate``, ``sponsor``,
``content``, and condition relationships in the same content row. Its inquiry
SQL remains one statement: the actor's ordinary branch is ORed with a
correlated delegation ``EXISTS`` whose inner sponsor predicate is the complete
applicable ordinary-trust union for the same content and permission.
Reviewers should verify the delegate/sponsor direction, the
relationship-owned scope predicate, the delegate and sponsor eligibility
predicates, and the inner ordinary union in both the policy document and
generated SQL. A delegate or sponsor that fails the principal eligibility rule
equivalent to ``is_active_principal`` must contribute no delegated authority,
even while its grants and delegation rows remain stored.

Backends remain independent. When more than one Trusts backend targets the same
content model, the document records each backend separately.

Permission inquiries and named filters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every permission inquiry row contains one SQL statement and its ordered
parameters. Named filters are listed in ``add_named_filter()`` order.

Identifiers and ordering
~~~~~~~~~~~~~~~~~~~~~~~~

Artifact IDs use portable ``_`` and ``__`` segments. A trust ID folds model-name
dots to ``__`` and adds the content field, for example
``documents__DocumentPermission__document``. Conditions append ``__cond``;
``Along`` adds ``__along_{shape}_{bound}``. For repeated bases, the first ID
keeps the unsuffixed base and the second and later IDs add ``__2``, ``__3``, and
so on. Named-filter IDs combine the content-model label and filter code. Filter
codes must match ``[A-Za-z0-9_]+`` or export fails.

Backend rows are sorted by backend path, independent of
``AUTHENTICATION_BACKENDS`` order. Content rows follow first-seen trust content,
followed by filter-only contents. Trusts preserve ``register()`` order, named
filters preserve ``add_named_filter()`` order, and parameters preserve compiler
order.

Constants and generated YAML
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``bind`` entries name runtime values without storing them. Constants are
mapped between Python and SQL types so their values and type information are
available for inspection. These mappings are data, not YAML object tags.

The writer uses the installed supported ``PyYAML`` release. Output is UTF-8
without a byte-order mark, uses LF endings, fixed key order, double-quoted
string values, ``|-`` SQL blocks, does not emit YAML tags or aliases, and ends
with one trailing newline. ``trusts.E009`` compares raw bytes; it does not
parse the document.

Creating the lockfile
---------------------

After application registration is complete, write the lockfile:

.. code-block:: console

   python manage.py trusts_policy_sql --lock

The command writes the same bytes produced on stdout.
``TRUSTS_POLICY_LOCKFILE`` selects the destination when configured and must be
absolute. A relative explicit path is not joined to ``BASE_DIR`` or the process
working directory and produces ``trusts.E009``. Otherwise, django-trusts uses
``BASE_DIR / "trusts-policy.lock.yaml"`` when ``BASE_DIR`` is absolute. If
``BASE_DIR`` is missing or relative, ``--lock`` fails and the conventional-file
check remains inactive. Parent directories must already exist.

Commit the lockfile with the application code that declares the policy. When a
policy change is intentional, regenerate the file and review the declaration,
permission-inquiry SQL, parameter roles, and lockfile diff together. A PyYAML or other
dependency upgrade may change the generated bytes; rerun
``python manage.py trusts_policy_sql --lock`` and review and commit any
intentional lockfile diff with the dependency change.

Checking the lockfile
---------------------

The Django model check ``trusts.E009`` enforces the lockfile when the
conventional file exists or ``TRUSTS_POLICY_LOCKFILE`` is configured. It renders
with ``TRUSTS_POLICY_DATABASE``, or ``default`` when unset, and compares the
generated bytes with the committed file.

When the conventional file does not exist and ``TRUSTS_POLICY_LOCKFILE`` is not
configured, the check returns no error without resolving the database alias or
rendering SQL. A configured path is explicit: a missing, unreadable, or
byte-different file produces an error.

Run the check in CI and before deployment:

.. code-block:: console

   python manage.py check

``trusts.E009`` is the lockfile's enforcement point. It is not a request-time
authorization gate.

One renderer per lockfile
-------------------------

A lockfile belongs to one selected Django database renderer. SQL emitted for
SQLite and MySQL may differ even when the application declarations are
identical. Schema version 1 exports only supported trust registrations. An unsupported
registration shape makes rendering fail rather than emitting a partial row.

CI that executes runtime tests against several engines may still review one
lockfile. Configure a dedicated inspection alias, set
``TRUSTS_POLICY_DATABASE`` to that alias in application settings, and keep the
same value in every CI job that renders or runs E009. For example, a MySQL
``default`` runtime database and a SQLite ``policy`` inspection alias can share
one committed SQLite lockfile: E009 follows ``policy``, not ``default``.
Repeated renders through the selected alias must match the committed bytes.
The runtime test database and the lockfile renderer are separate choices. If
an application intentionally reviews several deployment dialects, it may
instead configure separate lockfile paths and renderer aliases per job.

Rendering compiles statements without executing them, but a Django backend or
driver may still connect for initialization, server-version discovery, or
capability checks. A separate inspection alias can limit production exposure;
the resulting artifact describes that alias's renderer, not production by
implication.

Reviewing changes
-----------------

Review changes to backend paths, content grouping, trust relationships,
``or_group``, permission-inquiry SQL, named filters, parameter roles, identifiers, and
``database.engine`` as changes to the authorization surface.

Byte equality proves only that the current declarations and selected renderer
produce the reviewed bytes. It does not prove compiler correctness, omitted
runtime compositions, trustworthy grant data, the absence of application
bypasses, the behavior of other authentication backends, or the safety of a
code-and-lockfile change merely because they match.

Recommended workflow
--------------------

#. Declare or change the application's authorization policy.
#. Run ``python manage.py trusts_policy_sql`` and inspect the SQL.
#. Run ``python manage.py trusts_policy_sql --lock``.
#. Review the application and lockfile changes together.
#. Commit both.
#. Run ``python manage.py check`` in CI and before deployment.

Lockfile equality is a change-control mechanism, not a security proof.
