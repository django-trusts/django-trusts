Policy SQL artifact format
==========================

.. note::

   Historical development record. Last source update: 2026-10-15.
   Reorganized 2026-10-16; this revision has not been reviewed by a human
   for current accuracy.

Commands, renderer selection, and enforcement live in the
`security audit <../../SECURITY_AUDIT.md#authorization-policy-sql-and-lockfile>`_.

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

Relationship metadata
~~~~~~~~~~~~~~~~~~~~~

Relationship flow maps use ``{path: "...", model: "...", target: "..."}``.
``path`` uses Django's ``__`` spelling; ``model`` and ``target`` identify the
resolved concrete model and comparison field. An explicit group row adds
``group`` and its compiler-owned ``permission`` path. A permission collection
uses its declared collection path without a ``group`` key.

A delegated row has ``delegate``, ``sponsor``, ``content``, and ``condition``
instead of the ordinary user/permission pair. Walk metadata has the same
shape on either kind of row. Multiple trusts in one content row each carry
``or_group: true``; a sole trust omits that key.

``filter_by_permitted_content`` is a list of proper-prefix models, each with
one ``sql`` and ordered ``params`` entry. A terminal-only path omits the key;
a prefix whose queryset compiles to no SQL is omitted as well.

User rules have no parallel expression field or alternate skipped statement.
Their parameters include default ``skip_<name>=False`` bindings and comparisons
labeled ``user.<field>=True``. Runtime skip values change bindings, not this
artifact's statement shape.

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
``along`` with the complete registered ``path``, resolved ``shape``, and
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
with one trailing newline. The enforcement lifecycle belongs in the audit linked above.

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

