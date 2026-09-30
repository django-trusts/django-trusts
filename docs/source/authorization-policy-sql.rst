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

The command writes canonical YAML to stdout. The selected database backend and
driver determine SQL quoting, placeholders, operators, and dialect. The alias
is not stored in the document. ``database.engine`` records the configured
engine, and two aliases that render the same document produce the same bytes.
``schema_version`` stays ``1``. The JSON spelling of this document never
shipped in a release, so there is no second format and no migration.

Runtime values remain symbolic parameters. Rendering compiles the exported
queries without executing them.

What is recorded
----------------

The first format records one ``.authorized()`` query for each registered trust.
Each trust includes readable ``user``, ``permission``, and ``content``
relationships. Their ``path`` values use Django's ``__`` spelling for multiple
hops, while ``model`` and ``target`` identify the related model and comparison
field.

When two or more trusts on the same backend authorize the same content model,
django-trusts combines them with OR at runtime. Their rows share an
``or_group`` value so reviewers can see the relationship while inspecting each
trust's SQL separately. A trust that is the only path to its content model has
no ``or_group`` field.

Named filters are recorded separately, in ``add_named_filter()`` order, with
their own SQL and parameters. The export does not combine a named filter with a
grant query. That AND composition, other authorization operations, short
circuits that issue no SQL, and combinations across authentication backends
remain covered by library tests rather than lockfile rows.

For the ``DocumentPermission`` registration and ``non_confidential`` named
filter in the main guide, SQLite produces this document:

.. code-block:: yaml

   schema_version: 1
   database:
     engine: "django.db.backends.sqlite3"
   backends:
     - path: "documents.backends.DocumentBackend"
       trusts:
         - id: "documents.DocumentPermission:document"
           root: "documents.DocumentPermission"
           user:
             path: "user"
             model: "auth.User"
             target: "id"
           permission:
             path: "permission"
             model: "auth.Permission"
             target: "id"
           content:
             path: "document"
             model: "documents.Document"
             target: "id"
           sql: |-
             SELECT DISTINCT "documents_document"."id", "documents_document"."title", "documents_document"."confidential" FROM "documents_document" WHERE EXISTS(SELECT %s AS "a" FROM "documents_documentpermission" "U0" WHERE ("U0"."permission_id" = %s AND "U0"."user_id" = %s AND "U0"."document_id" = ("documents_document"."id")) LIMIT 1)
           params:
             - const: 1
             - bind: "permission.id"
             - bind: "user.id"
       named_filters:
         - model: "documents.Document"
           code: "non_confidential"
           sql: |-
             SELECT "documents_document"."id", "documents_document"."title", "documents_document"."confidential" FROM "documents_document" WHERE ("documents_document"."confidential" IS NULL OR NOT ("documents_document"."confidential" = %s))
           params:
             - const: true

``const: 1`` is Django's ``EXISTS`` probe. ``const: true``
is the declared constant in ``o.confidential != True``. ``bind`` entries name
runtime values without storing them. SQL is a ``|-`` literal block. Other
strings are double-quoted. Keys are plain identifiers.

The document uses UTF-8 without a byte-order mark, LF line endings, two-space
indentation, fixed key order, and one trailing newline. It has no anchors,
aliases, comments, or YAML tags. Backend rows are ordered by path. Trust rows
preserve ``register()`` order, named-filter rows preserve
``add_named_filter()`` order, and parameters preserve compiler order.

The writer is pinned to ``PyYAML==6.0.3``. PyYAML does not promise stable
emitter bytes across releases, so a later 6.0 patch is not a supported
dependency. CI compares the committed goldens on Python 3.12, 3.13, and
3.14.

Constant spelling
-----------------

Bare scalars are only ``null``, ``true``, ``false``, canonical integers, and
canonical finite floats. Every other string is double-quoted. Values that
YAML 1.1 would mistype (dates, decimals, bytes, non-finite numbers) stay
ordinary mappings. The codec does not use custom YAML tags, ``yes``/``no``/
``on``/``off``, or implicit timestamps.

* ``None`` is plain ``null``. ``~`` and an empty scalar are not null.
* ``True`` and ``False`` are plain ``true`` and ``false``.
* Strings, including ones that look like bools, null, numbers, or dates
  (``"true"``, ``"null"``, ``"1"``, ``"yes"``, ``"2024-03-04"``), are
  double-quoted.
* Integers are plain decimals: ``1``, ``-2``. No ``+`` prefix, no leading
  zeros, no hex or octal.
* Finite floats always include a decimal point, so ``1.0`` is not ``1``.
  ``-0.0`` keeps its sign. Scientific form keeps a dot before ``e``, as in
  ``1.0e+16`` and ``1.0e-07``. ``.nan``, ``.inf``, and ``!!float`` are not
  used.
* Non-finite floats use ``type: "float"`` and a quoted ``value`` of
  ``"NaN"``, ``"Infinity"``, or ``"-Infinity"``.
* Bytes use ``type: "bytes"`` and quoted lowercase ``hex`` (``"00ff"``).
* ``Decimal``, including non-finite values, uses ``type: "decimal"`` and
  quoted ``value`` taken from ``str(decimal)`` (``"12.50"``, ``"NaN"``,
  ``"Infinity"``, ``"-Infinity"``).
* ``UUID`` uses ``type: "uuid"`` and a quoted canonical string.
* ``date``, ``time``, and ``datetime`` use ``type`` plus quoted
  ``isoformat()`` text. A bare ``2024-03-04`` is not a date.
* ``timedelta`` uses ``type: "timedelta"`` with integer ``days``,
  ``seconds``, and ``microseconds``.
* ``ModelIdentity`` uses ``type: "model"``, quoted ``app_label`` and
  ``model``, and ``pk`` encoded with these same rules, including a nested
  mapping.

Diagnostic reader
-----------------

``load_policy_yaml`` and ``load_policy_sql_document`` are not used by
``trusts.E009``. They accept a document only when its bytes are exactly
what the canonical writer emits. The reader parses the input, writes it
again with that writer, and rejects the payload unless the bytes match.
Flow mappings (``a: {b: 1}``), flow sequences, folded blocks, keep or
clip chomping, and any other spelling the writer does not emit are
rejected. Hand-edited YAML should be regenerated with
``trusts_policy_sql`` rather than normalized by this reader.

Composition evidence stays in tests
-----------------------------------

Schema 1 records each trust's ``.authorized()`` statement and each named
filter's statement. Instance ``has_perm``, permission-code ``has_perm``,
filter-to-grant AND, multi-trust OR, and queryset ``all_match`` compile to
different statements. ``trusts.E009`` does not compare those statements.
The lockfile command does not emit them. There is no public composition
API.

Tests under ``tests/core/test_issue147/`` compile those statements and,
where a lockfile fragment is an exact substring with a contiguous
parameter span, record a template that names the fragment. Permission-code
``has_perm`` is full SQL: the permission subquery already uses alias
``U0``, so the grant table is ``V0`` and the permission predicate is not
``permission.id``. Instance ``has_perm`` with a permission instance keeps
the grant ``EXISTS`` text and adds a candidate primary-key predicate. It
is not ``IN`` (the ``.authorized()`` statement). Named-filter composition
references the filter's ``WHERE`` predicate, not the named-filter
``SELECT``. The evidence file is
``tests/core/test_issue147/golden_composition_sqlite.yaml``. It is not the
lockfile.

Creating the lockfile
---------------------

After the application's Trusts registrations are complete, write the lockfile:

.. code-block:: console

   python manage.py trusts_policy_sql --lock

The command writes the same bytes produced on stdout. ``TRUSTS_POLICY_LOCKFILE``
selects the destination when configured. Otherwise, django-trusts uses
``BASE_DIR / "trusts-policy.lock.yaml"`` when ``BASE_DIR`` is absolute. For an
ad hoc destination, redirect stdout. Parent directories must already exist.

Commit the lockfile with the application code that declares the policy. When a
policy change is intentional, regenerate it and review the application change
and lockfile diff together.

Checking the lockfile
---------------------

Lockfile enforcement through the untagged Django system check
``trusts.E009`` applies when a conventional lockfile exists or
``TRUSTS_POLICY_LOCKFILE`` is configured. The check uses
``TRUSTS_POLICY_DATABASE``, or ``default`` when that setting is unset, and
compares the generated bytes directly with the committed file. It does not
choose a connection from the document.

When the conventional file is absent, the registered check returns no error and
does not resolve the database alias or render SQL. A configured
``TRUSTS_POLICY_LOCKFILE`` path is explicit: a missing or unreadable file
produces an error.

Run the check in CI and before deployment:

.. code-block:: console

   python manage.py check

``trusts.E009`` is the lockfile's enforcement point. It is not a request-time
authorization gate. Silencing the check with ``SILENCED_SYSTEM_CHECKS`` or
running only tags that omit untagged checks also omits lockfile enforcement.

Database access during rendering
--------------------------------

django-trusts compiles the authorization statements in the export without
executing them or reading application and authorization rows. A selected
Django backend or driver may still connect for initialization, server-version
discovery, or capability checks.

Use a separate configured database alias when production connectivity is not
appropriate for inspection or CI. The resulting lockfile describes that
renderer. See the `security audit guide
<../../SECURITY_AUDIT.md#authorization-policy-sql-and-lockfile>`_ for the
connection and enforcement boundaries.

Reviewing changes
-----------------

Review a changed backend path, trust relationship, ``or_group``, named filter,
parameter role, or SQL statement as a change to the authorization surface.
Database-backend or driver changes can also change the generated SQL.

Byte equality proves that the current declarations and selected renderer
produce the reviewed artifact. It does not prove compiler correctness,
filter-to-grant AND composition, other authorization operations, combination
across authentication backends, trustworthy grant data, the absence of
application bypasses, or the safety of a code and lockfile change merely
because they match.

Recommended workflow
--------------------

#. Declare or change the application's authorization policy.
#. Run ``python manage.py trusts_policy_sql`` and inspect the generated SQL.
#. Run ``python manage.py trusts_policy_sql --lock``.
#. Review the application and lockfile changes together.
#. Commit both.
#. Run ``python manage.py check`` in CI and before deployment.

Lockfile equality is a change-control mechanism, not a security proof.
