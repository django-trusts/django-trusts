Permission policy in SQL
========================

.. note::

   Historical development record. Last source update: 2026-10-15.
   This reorganization has not been reviewed by a human for current accuracy.

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

Call inputs remain symbolic ``$role.field`` parameters, for example
``$user.id``, ``$permission.id``, and ``$content.id``. Bound constants use
``source=value`` tokens, for example ``user.is_active=True`` and
``$content.model="document"``. Rendering compiles the exported queries without
executing them or reading application or authorization rows.

Document shape
--------------

The document is organized by application meaning:

* each configured Trusts backend has one ``backends`` row,
  including ``contents: []`` when it has no declarations;
* each backend lists its ``contents`` models;
* a content with trusts lists them with their associated SQL for
  ``permitted``, ``has_perm``, ``get_all_permissions``, and
  ``get_permitted_users``, plus ``get_group_permissions`` when a trust
  uses ``group=``, plus ``filter_by_permitted_content`` when the content
  path has a proper prefix;
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
             params: ["$user.id", "$permission.id", "user.is_active=True", "$content.app_label=\"documents\"", "$content.model=\"document\"", "skip_is_active=False"]
             sql: |-
               SELECT DISTINCT ...
           has_perm:
             params: ["$user.id", "$permission.id", "$content.id", "user.is_active=True", "$content.app_label=\"documents\"", "$content.model=\"document\"", "skip_is_active=False"]
             sql: |-
               SELECT ... WHERE candidate-primary-key AND grant-exists
           get_all_permissions:
             params: ["$user.id", "$content.id", "user.is_active=True", "$content.app_label=\"documents\"", "$content.model=\"document\"", "skip_is_active=False"]
             sql: |-
               SELECT DISTINCT ... FROM auth_permission ...
           get_permitted_users:
             params: ["$permission.id", "$content.id", "user.is_active=True", "$content.app_label=\"documents\"", "$content.model=\"document\"", "skip_is_active=False"]
             sql: |-
               SELECT DISTINCT ... FROM auth_user ... WHERE grant-exists
           named_filters:
             - id: "documents__Document__non_confidential"
               params: ["confidential=True"]
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
to be the protected model's content identity. Those two values stay
bound parameters, written ``$content.app_label="..."`` and
``$content.model="..."``. A proxy model would use its
own identity. Any other permission terminal, including a custom model
with a ``content_type`` foreign key, does not gain the condition and
stays a primary-key comparison. The codename is not parsed to choose the
model. Regenerating the lockfile after this condition is present changes
the SQL bytes for every ``auth.Permission`` grant.

``get_permitted_users`` is the reverse of ``permitted``: one saved content
object and one permission, compiled to the users that backend can grant.
The locked statement is that backend branch only. It carries the backend's
registered user conditions, any user override, and the grant
``EXISTS``. It does not OR other authentication backends. The content primary
key is the call input ``$content.<target>``. The permission row is the call
input ``$permission.<target>``. The candidate
user is the outer row. ``content.get_permitted_users(perm)`` and optional
``User.objects.permitted(content, perm)`` share this one policy entry
because they use the same compiler for users from content; the document does not duplicate
their SQL. The lockfile key stays ``get_permitted_users``. For an ``Along``
registration, the recursive query walks the inverse graph from the supplied
content without the outer candidate user, then joins eligible grants and users.
The same terminal ``condition=`` overlay and user eligibility check apply
outside the recursive query. The locked reverse statement must therefore agree
with the object check. An unsupported renderer or unrenderable
recursive condition raises before a partial document is returned.

A django-trusts backend issues one SQL statement for each permission inquiry.
When more than one trust in that backend authorizes the same content model, the
SQL combines those trusts with OR and each trust in the content row has
``or_group: true``. A sole trust omits ``or_group``.

A delegated trust exposes its normalized ``delegate``, ``sponsor``,
``content``, and condition relationships in the same content row.
``delegate`` and ``sponsor`` are one-line flow maps, the same spelling
``user`` and ``permission`` already use:
``{path: "...", model: "...", target: "..."}``. Its inquiry
SQL remains one statement: the actor's ordinary branch is ORed with a
correlated delegation ``EXISTS``. Inside that ``EXISTS``, the sponsor-grant query
combines all applicable ordinary sponsor grants with OR. Reviewers should
verify the delegate/sponsor direction, the relationship's explicit conditions,
and the ordinary sponsor-grant query in the document and generated
SQL.
A delegated row records the same ``along`` path, shape, and bound, and the
same ``__along_{path}_{shape}_{bound}`` id suffix, when that registration
used ``along=``. The depth cap is the bound constant ``$along_bound=<n>``.
The delegate is allowed only where the delegation walk and the ordinary sponsor-grant query both reach the requested object. Each contributing
ordinary grant's ``along=`` walk or exact match must reach that object.

Backends remain independent. When more than one Trusts backend targets the same
content model, the document records each backend separately.

Permission inquiries and named filters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every permission inquiry row contains one SQL statement and its ordered
parameters. Named filters are listed in ``add_named_filter()`` order.

User conditions and overrides
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Registered user conditions appear in inquiry SQL and ordered ``params``.
The optional override participates in permission inquiries;
``get_group_permissions`` uses conditions and group grants without it. The lockfile does not add a
parallel user-rule expression or a second statement for skipped rules. Every
registered rule must compile completely to SQL over concrete user fields; a
Python property such as ``is_authenticated`` or ``is_anonymous`` is rejected.

Each registered rule adds its default bound skip value, for example
``skip_is_active=False`` or ``skip_superuser=False``. User Boolean comparisons
are labeled ``user.<field>=True``, for example ``user.is_superuser=True``.
At runtime a caller may
bind ``True`` for a valid ``skip_<name>`` keyword without changing the
statement shape. A condition is compiled as ``skip_<name> OR condition``. An
override is compiled as ``NOT skip_<name> AND override`` and ORed with the
ordinary grant proof. Review that Boolean grouping directly in the SQL.

Permitted content
~~~~~~~~~~~~~~~~~

When the registered content path passes through another model before the
protected object, the lockfile lists that model under
``filter_by_permitted_content``. Each entry names the model and holds one
SQL statement and its ordered parameters. A cabinet that holds sheets
produces one entry for the cabinet. The statement keeps a cabinet when a
permitted sheet sits under it.

The statement is the queryset ``filter_by_permitted_content`` compiles for
that model. The parameter values are the values in that statement. An
``along=`` walk uses the same bounded ``WITH RECURSIVE`` query as the
object check. The depth cap is the bound constant ``$along_bound=<n>``. A
prefix at the walk site is compared with the walk. An ancestor of the walk
site stays the value stored on the grant. A one-level delegation keeps a
row only where the delegation and the sponsor's authority both reach it. By
default that authority comes from ordinary sponsor grants, which may come from
another backend in the same document as they do for ``has_perm``. A content
path with no proper prefix omits the key. A prefix whose queryset is empty
also omits that model, because that call runs no SQL. Schema version stays 1.

Identifiers and ordering
~~~~~~~~~~~~~~~~~~~~~~~~

Artifact IDs use portable ``_`` and ``__`` segments. A trust ID folds model-name
dots to ``__`` and adds the content field, for example
``documents__DocumentPermission__document``. Conditions append ``__cond``
because the registration stored a condition (``record.condition`` is not
``None``). That entry then includes the condition as one double-quoted
Python-like line. Field paths stay bare. Membership uses the same
token as the permission parameter: ``$permission.<target> in <collection>``
(``$permission.id in permissions``, ``$permission.id in
team__allowed_operations``, ``$permission.code in caps`` when the
permission identity is ``code``). The grant's permission-role column
equals that call input. ``==`` compares two
columns. ``and`` joins them, with parentheses only around a nested group.
A registration without a condition omits that key.

``Along`` adds ``__along_{path}_{shape}_{bound}``, where ``path`` uses the
registered Django relationship segments. Each recursive trust row also records
``along`` with the registered ``path``, resolved ``shape``, and
integer ``bound``. The recursive SQL records the bound as
``$along_bound=<n>``, not a call input. For repeated bases, the first ID keeps the unsuffixed
base and the second and later IDs add ``__2``, ``__3``, and so on. Named-filter
IDs combine the content-model label and filter code. Filter codes must match
``[A-Za-z0-9_]+`` or export fails.

For example, ``along=("folder__parent", 8)`` records:

.. code-block:: yaml

   id: "documents__FolderGrant__folder__along_folder__parent_S_8"
   along: {path: "folder__parent", shape: "S", bound: 8}

The public path is preserved even when two paths resolve to the same shape and
bound, so their reviewed identifiers and metadata remain distinct.

Backend rows are sorted by backend path, independent of
``AUTHENTICATION_BACKENDS`` order. Content rows follow first-seen trust content,
followed by filter-only contents. Trusts preserve ``register()`` order, named
filters preserve ``add_named_filter()`` order. Each ``params`` line
lists one string per ``%s``, in that order. ``trusts_bind`` columns are
ordered user, permission, then content, skipping a role the statement
does not use. Remaining columns keep registration order.

Constants and generated YAML
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``params`` is one flow line. There is no parallel hint line. A call
input is a bare token: ``$user.id``, ``$permission.id``, ``$content.id``.
A non-id target stays dotted (``$user.code``, ``$content.ident``,
``$content.pk_value``). A bound constant is ``source=value``:
``$content.app_label="documents"``, ``$content.model="document"``,
``user.is_active=True`` (no ``$`` on the field), ``$along_bound=2``,
``$along_match=True``, or the compared field (``confidential=True``,
``amount=1.5``). A content primary key is the call input
``$content.<target>``, sorted with content. The whole token is one
double-quoted YAML string.

Bools spell ``True`` / ``False``. Strings use JSON quoting. Integers
are decimal. Finite floats use the canonical float spelling, so
``-0.0`` keeps its sign. Bytes, decimals, UUIDs, dates, times,
datetimes, timedeltas, non-finite floats, and model identities are the
JSON form of a tagged mapping inside that same token. These mappings
are data, not YAML object tags. The only literal in the SQL is the
``EXISTS`` marker ``SELECT 1``; it is not a parameter. Every other
value stays a bound ``%s``.

The writer uses the installed supported ``PyYAML`` release. Output is UTF-8
without a byte-order mark, uses LF endings, fixed key order, double-quoted
string values, ``|-`` SQL blocks, does not emit YAML tags or aliases, and ends
with one trailing newline. ``trusts.E009`` compares raw bytes; it does not
parse the document.

Each SQL block is broken between tokens onto predictable lines: before
``FROM``, ``JOIN`` (including ``LEFT OUTER JOIN`` and ``INNER JOIN``),
``WHERE``, ``AND``, ``OR``, ``UNION``, ``UNION ALL``, ``EXISTS``, and the
other clause keywords (``ORDER BY``, ``GROUP BY``, ``HAVING``, ``LIMIT``,
``OFFSET``, ``CYCLE``, and a ``SELECT`` or ``WITH`` that continues the
statement). ``AND`` and ``OR`` use that same break. A comparison stays
on the connective's line (``AND "t"."id" = %s``), indented two spaces
past the group that contains it. An ``EXISTS`` operand stays on that
line too, including ``EXISTS (``, ``NOT EXISTS (``, and ``( EXISTS (``,
at the same indent as the sibling operand::

    AND ( EXISTS (
      ...
    )
    OR EXISTS (
      ...
    ) )

``EXISTS (`` always has that space. ``NOT EXISTS`` stays one unit, so
``AND NOT ( EXISTS (`` is one line as well. A run of closing parens that
finishes the group shares one line (``) )``). The seed and recursive
member of ``WITH RECURSIVE``, and
the subqueries inside them, are indented. A break never falls inside a
quoted identifier or a plain single-quoted string.

The formatter accepts only tokens it fully understands: identifiers quoted
the way SQLite, PostgreSQL, and MySQL quote them, plain single-quoted
strings, numbers, ``%s`` and ``?`` placeholders, parentheses, commas, dots,
and an explicit allowlist of operators and keywords those compilers and
``along=`` SQL emit. A line comment, a block comment, a MySQL ``#`` comment,
a dollar-quoted string, an ``E''`` string, a backslash escape, adjacent
string literals (including a newline between two ``'...'`` literals), an
unknown operator, or any other unrecognized token raises
``TrustsConfigurationError``. The error names the query and the token.
Formatting does not strip comments, guess, or return the original text.
After formatting, the token stream must match the original stream, or
formatting raises. The formatted text is that same statement.

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
