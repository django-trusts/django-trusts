# Delegation registration contract

Status: proposed implementation-driver contract for [issue #266][issue-266].

- Release train: 1.1
- Last updated: 2026-10-09
- Documentation PR: [#279][docs-pr]
- Implementation PR: not opened

This document records the contract used to drive implementation. The public
guide, security audit, and What's New describe the intended 1.1 behavior. The
implementation PR and its tests determine when that behavior becomes
available.

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
    condition=lambda relationship, permission: ...,
)
```

The mode switch is therefore:

| Mode | Principal arguments | Meaning |
| --- | --- | --- |
| Ordinary permission | `user=` and `permission=` | The matching row is an ordinary grant. |
| Delegated | `delegate=` and `sponsor=` | The matching row is a relationship that requires the sponsor's live ordinary authority. |

`delegate=` binds the current principal who is acting and receiving delegated
access. It takes the place of `user=` for the delegated mode. `sponsor=` binds
the principal who delegated the authority and whose live ordinary permission
paths provide the ceiling.

The delegated row does not carry an ordinary `permission=` grant. The
permission being checked comes from the inquiry and must be satisfied by the
sponsor's ordinary authority union on the same content. A delegated condition
may compare that requested permission with relationship-owned scope data, but
it cannot grant an operation that the sponsor does not currently hold.

`content=` identifies the meeting point of the two sides. In ordinary mode,
`condition=` keeps its existing one-argument builder. In delegated mode, it
may take either the relationship row alone or that row plus the requested
permission. The one-argument form applies row-only restrictions. The
two-argument form additionally supports permission-dependent scope such as
allowed operations. Either form may apply relationship-owned restrictions
such as selected scope, approval, organization eligibility, revocation, and
expiry.

A delegated content path uses the same bounded dependent-content grammar as
an ordinary registration. One or more reverse one-to-one relations may be
chained as single-valued prefix hops before the one reverse one-to-many
content gateway. This allows a relationship with no direct content foreign
key to cover a bounded set, for example:

```python
backend.register(
    trust=AllPersonalRepositoriesDelegation,
    delegate="delegate",
    sponsor="sponsor",
    content="sponsor__personal_organization__repositories",
    condition=lambda d, p: d.allowed_permissions.contains(p),
)
```

Here `personal_organization` is reverse one-to-one from the sponsor and
`repositories` is the reverse one-to-many gateway. A reverse one-to-one may
be a prefix hop, including one hop in a chain, but is not itself a supported
content terminal or gateway.

The initial delegated mode does not accept `along=` on the delegated
registration itself. Such a registration fails closed as unsupported pending
the hierarchy design in [issue #282][issue-282]. This is a temporary feature
boundary, not a decision that delegated hierarchical reach should be rejected
permanently. An ordinary registration may still use `along=`, and the
sponsor-side ordinary-authority union must honor that effective bounded reach.

For example, a delegation row with an `allowed_permissions` relation may
narrow the sponsor ceiling without adding another public registration
argument:

```python
backend.register(
    trust=RepositoryDelegation,
    delegate=lambda d: d.delegate,
    sponsor=lambda d: d.sponsor,
    content=lambda d: d.repository,
    condition=lambda d, p: d.allowed_permissions.contains(p),
)
```

The permission argument is symbolic registration-time input. It does not turn
the condition into a runtime callback.

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
- supplying none of the complete modes is invalid;
- an ordinary condition builder must take one argument; and
- a delegated condition builder may take one or two arguments, while any
  other arity is invalid.

The first implementation should require `delegate=` and `sponsor=` to resolve
to the same persisted principal model used by applicable ordinary authority
registrations. Heterogeneous principal models remain a separate design
question.

## Authorization rule

For actor `u`, content `c`, and permission `p`, the compiled result is:

```text
is_active_principal(u)
AND (
    ordinary(u, c, p)
    OR
    EXISTS relationship d:
        d.delegate = u
        AND d.content = c
        AND delegated_condition(d, p)
        AND is_active_principal(d.sponsor)
        AND ordinary(d.sponsor, c, p)
)
```

`is_active_principal(x)` is expressed as its equivalent eligibility predicate
where the inquiry projects persisted principals. A delegate or sponsor that
fails that rule cannot
authorize through delegation, even while its ordinary grants and delegation
rows remain stored. The delegate gate applies to both the actor's ordinary
branch and delegated branch. This eligibility rule does not decide whether
active-superuser status supplies authority.

The exact relationship row binds the sponsor. A matching relationship from
one installation cannot borrow the sponsor, approval, content, or condition
state of another relationship.

More than one delegated relationship model may target the same content model.
Those registrations are ORed only after each branch is complete:

```text
ordinary(u, c, p)
OR EXISTS d1: left1(d1, u, c, p) AND ordinary(d1.sponsor, c, p)
OR EXISTS d2: left2(d2, u, c, p) AND ordinary(d2.sponsor, c, p)
```

They are not flattened into
`(left1 OR left2) AND (ordinary(sponsor1) OR ordinary(sponsor2))`. Approval,
scope, and the sponsor-authority ceiling stay correlated to the exact row from
the same relationship branch.

`ordinary(d.sponsor, c, p)` is the complete live OR-union of applicable
ordinary registrations, including registrations under other configured
handles. It is not one selected permission path. Delegated registrations are
excluded from that inner union.

The current proposal supports exactly one level of delegation. The sponsor's
authority must come from ordinary registrations; one delegated relationship
cannot sponsor another. Multi-level and recursive delegation are out of scope.

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

The implementation compiles the actor's direct branch and every correlated
delegation branch into one queryset statement for each inquiry. An
application helper that loads a sponsor and calls `sponsor.has_perm()` is
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
2. delegated one- and two-argument condition parsing and validation;
3. a stored non-ordinary relationship record shape;
4. aggregate correlated compilation across applicable handles;
5. exclusion of delegated records from both ordinary unions;
6. forward, reverse, enumeration, queryset, and policy-SQL agreement tests;
7. a lockfile representation that exposes delegate, sponsor, content,
   condition, and correlated ordinary-authority composition;
8. backend, content-model, permission-model, inactive delegate, inactive
   sponsor, chain, and cycle fail-closed tests; and
9. user documentation and What's New entries describing only behavior that
   actually ships.

## Related design record

The framework-independent requirements and reasoning live in
[Considerations in Permission Delegation][considerations]. Core
[issues #265][issue-265] and [#266][issue-266] contain the original problem
statement, concrete cases, and candidate scorecard.

[considerations]: https://github.com/django-trusts/django-trusts/pull/278
[docs-pr]: https://github.com/django-trusts/django-trusts/pull/279
[issue-265]: https://github.com/django-trusts/django-trusts/issues/265
[issue-266]: https://github.com/django-trusts/django-trusts/issues/266
[issue-273]: https://github.com/django-trusts/django-trusts/issues/273
[issue-282]: https://github.com/django-trusts/django-trusts/issues/282
