Authorization policy in SQL
===========================

django-trusts can render its registered authorization policy as parameterized
SQL for inspection. The same deterministic YAML can be committed as an
authorization policy lockfile so policy and compiler changes appear in normal
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

The command writes deterministic YAML using the pinned writer. The selected Django database
backend and driver determine SQL quoting, placeholders, operators, and dialect.
The alias is not stored; ``database.engine`` records its configured engine.

Runtime user and permission roles remain symbolic ``bind`` parameters. For
candidate-object checks, the exporter compiles a type-correct sentinel primary
key and records it as ``const``. That value identifies the compiled comparison
position; it is not a primary key read from application data. Rendering compiles
the exported queries without executing them or reading application or
authorization rows.

Document shape
--------------

The document is organized by application meaning rather than compiler
fragments:

* each configured relationship-family Trusts backend has one ``backends`` row,
  including ``contents: []`` when it has no declarations;
* each backend groups its declarations under ``contents`` by protected model;
* a content with trusts lists its trust legs and complete compiler SQL for
  ``permitted``, ``has_perm``, and ``get_all_permissions``;
* a content with named filters lists those standalone queries; and
* a filter-only content contains ``model`` and ``named_filters`` without trust
  or operation keys.

``permitted`` is the artifact label for one backend's list query. It matches
``QuerySet.authorized()`` when that backend is the only relationship-family
contributor. The runtime API is not renamed.

The following abridged example shows the schema. The committed artifact contains
the complete SQL where the example uses shortened text:

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
             params: [{const: 1}, {bind: "permission.id"}, {bind: "user.id"}]
             sql: |-
               SELECT DISTINCT ...
           has_perm:
             params: [{const: 1}, {const: 1}, {const: 1}, {bind: "permission.id"}, {bind: "user.id"}]
             sql: |-
               SELECT ... WHERE candidate-primary-key AND grant-exists
           get_all_permissions:
             params: [{const: 1}, {const: 1}, {const: 1}, {const: 1}, {const: 1}, {bind: "user.id"}]
             sql: |-
               SELECT DISTINCT ... FROM auth_permission ...
           named_filters:
             - id: "documents__Document__non_confidential"
               params: [{const: true}]
               sql: |-
                 SELECT ... WHERE non-confidential-predicate

Trust legs and OR composition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each trust leg retains the registered root and the resolved ``user``,
``permission``, and ``content`` relationships. Relationship ``path`` values use
Django's ``__`` spelling for multiple hops; ``model`` and ``target`` identify
the related concrete model and comparison field.

When more than one trust in the same backend authorizes the same content model,
every leg in that content row has ``or_group: true``. The nesting identifies the
group. The complete SQL for the three operations contains the actual OR
compiled by Django. A sole trust omits ``or_group``.

Backends remain independent. Two backends that target the same content model do
not share an ``or_group`` or an artifact SQL statement. Django combines
``user.has_perm()`` and ``user.get_all_permissions()`` backend answers at the
authentication layer. ``QuerySet.authorized()`` instead compiles one
relationship-family SQL expression across all applicable Trusts backends; that
cross-backend list query is not recorded in schema version 1.

Operations and named filters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every operation row contains one complete compiler statement and its parameters
in compiler order. SQL parameter placeholders such as ``%s`` remain paired with
the ``params`` list. The artifact does not use fragment-reference placeholders,
reconstructed SQL, or a public reverse mapping. Repeated SQL is intentional
when separate public operations compile similarly.

Named filters are standalone content-query statements in
``add_named_filter()`` order. A named filter cannot grant access by itself. The
artifact does not add a combined grant-plus-filter statement.

Schema version 1 does not record separate rows for:

* permission-code variants of ``has_perm``;
* QuerySet-valued ``has_perm``;
* ``get_group_permissions``;
* a grant AND named-filter query;
* the relationship-family OR that ``QuerySet.authorized()`` compiles across
  multiple Trusts backends; or
* the OR or set union that Django performs across authentication backends for
  object checks and permission enumeration.

Those paths remain runtime and test concerns. They are not silently reconstructed
from the recorded rows.

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

``bind`` entries name runtime values without storing them. JSON-compatible
constants that preserve their type use ``const`` directly: ``null``, booleans,
strings, integers, and finite floats, including ``-0.0``. Other supported values
use tagged data mappings under ``const``:

* non-finite floats use ``type: "float"`` and a ``value`` of ``NaN``,
  ``Infinity``, or ``-Infinity``;
* bytes use ``type: "bytes"`` and hexadecimal data under ``hex``;
* decimals, UUIDs, dates, times, and datetimes use their type and a string under
  ``value``;
* timedeltas store ``days``, ``seconds``, and ``microseconds``; and
* model identities store ``app_label``, ``model``, and a recursively encoded
  ``pk``.

These mappings are data, not YAML object tags, and do not enable object
construction.

The writer uses the exact supported ``PyYAML==6.0.3`` release. Output is UTF-8
without a byte-order mark, uses LF endings, fixed key order, double-quoted string
values, one-line ``params``, ``|-`` SQL blocks, does not emit YAML tags or aliases, and ends with one
trailing newline. ``trusts.E009`` compares raw bytes; it does not parse the
document. Private loader and inverse helpers exist only for implementation tests
and are not a supported YAML-to-registration API.

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
operation SQL, parameter roles, and lockfile diff together.

Checking the lockfile
---------------------

The untagged Django system check ``trusts.E009`` is always registered. Lockfile
enforcement applies when the conventional file exists or
``TRUSTS_POLICY_LOCKFILE`` is configured. The check renders with
``TRUSTS_POLICY_DATABASE``, or ``default`` when unset, and byte-compares the
result with the committed file.

When the conventional file is absent, the check returns no error and does not
resolve the database alias or render SQL. A configured path is explicit intent:
a missing, unreadable, or byte-different file produces an error.

Run the check in CI and before deployment:

.. code-block:: console

   python manage.py check

``trusts.E009`` is the lockfile's enforcement point. It is not a request-time
authorization gate. Silencing it with ``SILENCED_SYSTEM_CHECKS`` or running only
tags that omit untagged checks removes that enforcement.

One renderer per lockfile
-------------------------

A lockfile belongs to one selected Django database renderer. It is not a
database-neutral policy IR. SQL emitted for SQLite and MySQL may differ even
when the application declarations are identical. Schema version 1 exports the
relationship family; configuring a non-relationship family makes the complete
render fail rather than emitting a partial row.

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
``or_group``, operation SQL, named filters, parameter roles, identifiers, and
``database.engine`` as changes to the authorization surface.

Byte equality proves only that the current declarations and selected renderer
produce the reviewed bytes. It does not prove compiler correctness, omitted
runtime compositions, trustworthy grant data, the absence of application
bypasses, the behavior of other authentication backends, or the safety of a
code-and-lockfile change merely because they match.

Recommended workflow
--------------------

#. Declare or change the application's authorization policy.
#. Run ``python manage.py trusts_policy_sql`` and inspect the complete SQL.
#. Run ``python manage.py trusts_policy_sql --lock``.
#. Review the application and lockfile changes together.
#. Commit both.
#. Run ``python manage.py check`` in CI and before deployment.

Lockfile equality is a change-control mechanism, not a security proof.
