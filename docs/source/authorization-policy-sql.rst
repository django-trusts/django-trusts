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

The command writes canonical YAML to stdout. The selected Django database
backend and driver determine SQL quoting, placeholders, operators, and dialect.
The alias is not stored; ``database.engine`` records its configured engine.

Runtime user, permission, and candidate-object values remain symbolic
parameters. Rendering compiles the exported queries without executing them or
reading application or authorization rows.

Document shape
--------------

The document is organized by application meaning rather than compiler
fragments:

* each configured Trusts backend has one ``backends`` row;
* each backend groups its declarations under ``contents`` by protected model;
* each content row lists the trust legs that can authorize that model;
* a content with trusts records complete compiler SQL for ``permitted``,
  ``has_perm``, and ``get_all_permissions``; and
* named filters appear under the content model they constrain.

``permitted`` is the artifact label for the list query currently exposed by
``QuerySet.authorized()``. The runtime API is not renamed.

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
not share an ``or_group`` or a SQL statement; Django combines backend results at
the authentication layer.

Operations and named filters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every operation row contains one complete compiler statement and its parameters
in compiler order. The artifact does not use fragments, references,
placeholders, reconstructed SQL, or a public reverse mapping. Repeated SQL is
intentional when separate public operations compile similarly.

Named filters are standalone content-query statements in
``add_named_filter()`` order. A named filter cannot grant access by itself. The
artifact does not add a combined grant-plus-filter statement.

Schema version 1 does not record separate rows for:

* permission-code variants of ``has_perm``;
* QuerySet-valued ``has_perm``;
* ``get_group_permissions``;
* a grant AND named-filter query; or
* the OR that Django performs across authentication backends.

Those paths remain runtime and test concerns. They are not silently reconstructed
from the recorded rows.

Identifiers and ordering
~~~~~~~~~~~~~~~~~~~~~~~~

Artifact IDs use portable ``_`` and ``__`` segments. A trust ID folds model-name
dots to ``__`` and adds the content field, for example
``documents__DocumentPermission__document``. Conditions append ``__cond``;
``Along`` adds ``__along_{shape}_{bound}``; repeated bases add ``__2``, ``__3``,
and so on. Named-filter IDs combine the content-model label and filter code.
Filter codes must match ``[A-Za-z0-9_]+`` or export fails.

Backend rows follow configured backend order. Content rows follow first-seen
trust content, followed by filter-only contents. Trusts preserve
``register()`` order, named filters preserve ``add_named_filter()`` order, and
parameters preserve compiler order.

Constants and canonical YAML
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``bind`` entries name runtime values without storing them. JSON-compatible
constants that preserve their type use ``const`` directly: ``null``, booleans,
strings, integers, and finite floats, including ``-0.0``. Other supported values
use tagged data mappings under ``const``:

* non-finite floats use ``type: "float"`` and ``NaN``, ``Infinity``, or
  ``-Infinity``;
* bytes use ``type: "bytes"`` and hexadecimal data;
* decimals, UUIDs, dates, times, and datetimes use their type and a string value;
* timedeltas store days, seconds, and microseconds; and
* model identities store app label, model, and a recursively encoded primary
  key.

These mappings are data, not YAML object tags, and do not enable object
construction.

The writer uses the exact supported ``PyYAML==6.0.3`` release. Output is UTF-8
without a byte-order mark, uses LF endings, fixed key order, double-quoted string
values, one-line ``params``, ``|-`` SQL blocks, no YAML tags or aliases, and one
trailing newline. ``trusts.E009`` compares raw bytes; it does not parse the
document. Private loader and inverse helpers exist only for implementation tests
and are not a supported YAML-to-registration API.

Creating the lockfile
---------------------

After application registration is complete, write the lockfile:

.. code-block:: console

   python manage.py trusts_policy_sql --lock

The command writes the same bytes produced on stdout.
``TRUSTS_POLICY_LOCKFILE`` selects the destination when configured. Otherwise,
django-trusts uses ``BASE_DIR / "trusts-policy.lock.yaml"`` when ``BASE_DIR`` is
absolute. Parent directories must already exist.

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
a missing, unreadable, noncanonical, or different file produces an error.

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
when the application declarations are identical.

CI that executes runtime tests against several engines may still review one
lockfile. Configure a dedicated inspection alias and set
``TRUSTS_POLICY_DATABASE`` to that same alias in every job that runs E009. The
runtime test database and the lockfile renderer are separate choices. If an
application intentionally reviews several deployment dialects, it may instead
configure separate lockfile paths and renderer aliases per job.

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
