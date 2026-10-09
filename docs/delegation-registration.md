# Delegation registration contract

Status: proposed feature contract for [issue #266][issue-266]. This API is not
implemented in django-trusts 1.0 or 1.1. Approval of this document defines the
target for a later implementation PR; it does not make the feature available.

The public `register()` API has two different authorization modes. They must
remain visibly different because an ordinary registration is a grant, while a
delegated registration is only one side of a conditional grant.

## Registration modes

An ordinary permission registration identifies the principal receiving a
grant and the permission granted:

```python
backend.register(
    trust=RepositoryGrant,
    user=lambda grant: grant.user,
    permission=lambda grant: grant.permission,
    content=lambda grant: grant.repository,
    condition=lambda grant: ...,
)
```

A delegated registration instead identifies the acting principal and the
principal whose live ordinary authority sponsors that action:

```python
backend.register(
    trust=RepositoryDelegation,
    delegate=lambda relationship: relationship.delegate,
    sponsor=lambda relationship: relationship.sponsor,
    content=lambda relationship: relationship.repository,
    condition=lambda relationship: ...,
)
```

The mode switch is therefore:

| Mode | Principal arguments | Meaning |
| --- | --- | --- |
| Ordinary permission | `user=` and `permission=` | The matching row is an ordinary grant. |
| Delegated | `delegate=` and `sponsor=` | The matching row is a relationship that requires the sponsor's live ordinary authority. |

`delegate=` binds the principal who is acting. It takes the place of `user=`
for the delegated mode. `sponsor=` binds the principal whose ordinary
permission paths provide the live ceiling.

The delegated row does not carry an ordinary `permission=` grant. The
permission being checked comes from the inquiry and must be satisfied by the
sponsor's ordinary authority union on the same content. A relationship may
narrow allowed operations through its registered condition and related scope
rows, but it cannot grant an operation merely by storing it.

`content=` identifies the meeting point of the two sides. `condition=` applies
relationship-owned restrictions such as selected scope, approval,
organization eligibility, revocation, and expiry. Those arguments are
available in both modes, subject to their existing validation rules.

The existing explicit `group=` form remains an ordinary-authority
registration. It continues to use `user=` and is mutually exclusive with
`permission=`. It is not a third delegation spelling and cannot be combined
with `delegate=` or `sponsor=`.

## Validation

Registration must reject incomplete or crossed modes before invoking a public
condition builder or mutating registry state:

- `permission=` requires `user=` and forbids `delegate=` and `sponsor=`;
- `group=` requires `user=` and forbids `delegate=` and `sponsor=`;
- delegated mode requires both `delegate=` and `sponsor=` and forbids
  `user=`, `permission=`, and `group=`;
- either member of the delegated pair without the other is invalid; and
- supplying none of the complete modes is invalid.

The first implementation should require `delegate=` and `sponsor=` to resolve
to the same persisted principal model used by applicable ordinary authority
registrations. Heterogeneous principal models remain a separate design
question.

## Authorization rule

For actor `u`, content `c`, and permission `p`, the compiled result is:

```text
ordinary(u, c, p)
OR
EXISTS relationship d:
    d.delegate = u
    AND d.content = c
    AND relationship_condition(d, p)
    AND ordinary(d.sponsor, c, p)
```

The exact relationship row binds the sponsor. A matching relationship from
one installation cannot borrow the sponsor, approval, content, or condition
state of another relationship.

`ordinary(d.sponsor, c, p)` is the complete live OR-union of applicable
ordinary registrations, including registrations under other configured
handles. It is not one selected permission path. Delegated registrations are
excluded from that inner union, establishing the initial one-hop bound.

The actor's independent ordinary authority remains the existing outer OR
branch. Adding delegation neither converts an ordinary grant into a delegated
one nor forces an independently permitted actor through a relationship.

## Shared compiler surfaces

The same correlated rule must drive:

- point permission checks;
- permitted-content querysets;
- permission enumeration;
- reverse permitted-user inquiry; and
- authorization-policy SQL and lockfiles.

An application helper that loads a sponsor and calls `sponsor.has_perm()` is
not an implementation of this contract. It bypasses the shared declarative
plan, can import an outer permission shortcut, and cannot provide equivalent
queryset, reverse-inquiry, or policy-SQL behavior.

## Separate prerequisites and policy decisions

This feature contract does not settle whether active-superuser status supplies
direct or sponsor-side authority. [Issue #273][issue-273] owns that decision.
The compiler must represent the chosen policy at the direct-actor and
sponsor-authority composition points rather than inheriting it accidentally
from a nested `has_perm()` call.

Real expiry and revocation rules also require the existing registration
condition language to express null tests and ordered comparison against a
database-side query clock. That condition-language work remains a separate
prerequisite and should not be hidden inside the correlated-plan patch.

## Implementation split

After this contract is approved, implementation should remain in a separate
code PR. At minimum, that work must include:

1. public and internal registration validation for the two modes;
2. a stored non-ordinary relationship record shape;
3. aggregate correlated compilation across applicable handles;
4. exclusion of delegated records from both ordinary unions;
5. forward, reverse, enumeration, queryset, and policy-SQL agreement tests;
6. backend, content-model, permission-model, chain, and cycle fail-closed
   tests; and
7. user documentation and What's New entries describing only behavior that
   actually ships.

## Related design record

The framework-independent requirements and reasoning live in
[Considerations in Permission Delegation][considerations]. Core
[issues #265][issue-265] and [#266][issue-266] contain the original problem
statement, concrete cases, and candidate scorecard.

[considerations]: https://github.com/django-trusts/django-trusts/pull/278
[issue-265]: https://github.com/django-trusts/django-trusts/issues/265
[issue-266]: https://github.com/django-trusts/django-trusts/issues/266
[issue-273]: https://github.com/django-trusts/django-trusts/issues/273
