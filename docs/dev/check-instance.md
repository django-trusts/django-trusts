# Instance-side user-rule evaluation

Status: unresolved design option for [issue #313](https://github.com/django-trusts/django-trusts/issues/313).

This is a development note, not implemented behavior. django-trusts currently
compiles user conditions and the optional user override into permission SQL.
There is no public `check_instance` argument.

## Candidate behavior

A possible `check_instance=True` option would evaluate selected rules against
the supplied user object before the permission query. Those terms would be
omitted from that query. The existing SQL behavior would remain the default.

The candidate could make the result reflect unsaved field changes and
Python-only attributes on the supplied object. It could also deny a user who
fails a rule without executing the grant query.

## Boundaries that must be resolved

- `get_permitted_users()` has no single supplied user. By contrast,
  `filter_by_permitted_content()` receives one user while filtering many
  content rows; those two shapes cannot share the same instance shortcut.
- A delegation sponsor is not the checked-user instance. Evaluating sponsor
  rules would require a separate load or a return to SQL.
- A Python evaluator and SQL compiler would need identical grouping, skip
  handling, and `on=` targeting.
- A rule omitted from SQL is no longer visible in the executed statement.
  Policy output would need to record where and how it is evaluated.
- An instance early return must not bypass permission parsing, content-type
  validation, candidate existence, required conditions, or other fail-closed
  checks.
- A supplied object can disagree with persisted state. The contract must say
  which value each permission inquiry uses.
- The performance benefit is unmeasured. Trusts still needs a query for the
  underlying grants.

## Projection questions

A decision must cover every permission surface, not only `has_perm()`:

| Surface | Instance available? | Question |
| --- | --- | --- |
| Object check | Yes | Which checks run before SQL, and in what order? |
| Permission enumeration | Yes | Must it use the same instance rules as the object check? |
| Permitted-content queryset | Yes | Are instance rules fixed when the queryset is built or evaluated? |
| Permitted users | No single user | Is instance evaluation rejected or replaced by SQL? |
| Rows with permitted content | Yes, one checked user | Does the user rule run once while content restrictions remain in SQL? |
| Delegated sponsor ceiling | Sponsor is not supplied | Is the sponsor loaded or always checked in SQL? |
| Policy SQL and lockfile | n/a | How are non-SQL terms represented for audit? |

## Decision gate

Do not add the option until there is:

1. a concrete use case that SQL cannot reasonably serve;
2. one rule for every projection above;
3. a lockfile representation for terms evaluated outside SQL;
4. explicit sponsor and unsaved-user semantics;
5. proof that validation and authorization ordering remain fail closed; and
6. a test and query-budget matrix covering conditions, overrides, targets, and
   skips.

If these requirements cannot be met without two drifting authorization
engines, keep all user rules in SQL.
