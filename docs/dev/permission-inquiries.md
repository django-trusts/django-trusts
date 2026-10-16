# Permission inquiries: implementation reference

Historical development record, consolidated 2026-10-16 from the queryset,
content-to-users, and registry projection contracts. Last source updates:
2026-10-16. This consolidation has not been reviewed by a human for current
accuracy. The [usage guide](../source/index.rst) is the application entry point;
the [security audit](../../SECURITY_AUDIT.md) owns policy semantics.

## Inquiry map

`flags` below means named `skip_<name>` keyword arguments, not a positional
dictionary. Shapes describe relationship-family Trusts paths unless stated
otherwise.

| Surface | Inputs and result |
| --- | --- |
| `backend.has_perm(user, perm, obj, **flags)` | One content instance, or a supported content queryset with all-match semantics; returns a Boolean |
| `backend.get_all_permissions(user, obj, **flags)` | Bare Django permission codes common to the supplied content |
| `backend.get_group_permissions(user, obj, **flags)` | The group-derived subset selected by explicit `group=` registrations |
| `queryset.permitted(permission, user, conditions=(), **flags)` | Lazy distinct permitted rows of the same content model |
| `queryset.authorized(user, permission, extra_q=None, **flags)` | Lower-level instance-bound projection; `permission` is a model instance |
| `content.get_permitted_users(perm, **flags)` | Lazy distinct queryset of configured user-model candidates for one saved content instance |
| `User.objects.permitted(content, perm, **flags)` | Optional manager spelling of the preceding inquiry, using that manager's queryset |
| `filter_by_permitted_content(queryset, user, permission, *, content, handles=None, **flags)` | Lazy rows of an intermediate model with permitted protected content below them |
| `authorization_required(Model, permission, conditions=(), **flags)` | View guard using the URL keyword `pk` |

Native `user` methods call Django's backend dispatch rather than exposing all
of these keyword forms; their boundary is documented in the
[audit](../../SECURITY_AUDIT.md#django-auths-checks-before-calling-backends).

## Permission inputs

| Surface | Permission representation | Named-filter selection |
| --- | --- | --- |
| Trusts backend object check | Django `app_label.codename` parsed by `parse_perm_code`; an instance requires matching singular-backend capability | Existing `:name` suffix |
| Content `.permitted()` | Full `app_label.codename`, bound exactly to the protected model's content type, or a saved exact `auth.Permission` instance | Exact tuple `conditions=("name",)` |
| View guard | Full `app_label.codename` string, with matching application label | Exact tuple `conditions=("name",)` |
| `.authorized()`, intermediate-content filter, and registry projections | Saved permission model instance, including supported custom terminals | An explicit `extra_q` overlay where offered, not a string suffix parser |
| Users from content | Django string, `auth.Permission`, or another permission-instance type explicitly accepted by the backend's singular object check | Supported string `:name` suffix |

The first string codec infers a model from the codename suffix; the exact
codec does not. They agree for `action_modelname` but may diverge for other
codenames. This unresolved difference is [#268](https://github.com/django-trusts/django-trusts/issues/268).
An accepted permission string is bound inside the eventual SQL, without a
construction-time permission lookup. For agreement checks, Django 6.1's
`Permission.user_perm_str` supplies its string identity; custom permission
models get no invented codec. Content-type enforcement is specified only in
the [audit](../../SECURITY_AUDIT.md#permission-identity-and-failure-behavior).

Content `.permitted()` rejects a bare codename, a `:name` suffix, unsaved or
proxy permission instances, and other permission model classes. `conditions`
must be an exact tuple of distinct, non-blank, unpadded names without `:`.
Names select already-registered queryable filters; they do not invoke callbacks.

## Queryset and manager attachment

The getting-started example uses `PermittedQuerySetMixin` with `as_manager()`.
An existing manager instead uses Django's `from_queryset`:

```python
class DocumentManager(models.Manager.from_queryset(DocumentQuerySet)):
    pass
```

`PermittedQuerySet` and `PermittedManager` are concrete alternatives when no
custom queryset methods are needed. A manager-only permission method would be
lost after `filter()`, so there is no `PermittedManagerMixin`.

`PermittedUsersMixin` attaches the content-to-users method independently of
the content manager. For the optional user-manager spelling, mix
`PermittedUsersManagerMixin` into the application's existing user manager:

```python
class UserManager(PermittedUsersManagerMixin, ExistingUserManager):
    pass
```

Install that manager on the user model before using its method. Stock
`auth.User` does not grow `objects.permitted`. The content spelling works
without changing the user manager. Both adapters preserve the queryset type,
existing filters, and database alias of their starting manager; they have
the same candidate universe when installed on the default user manager.

## Participating backends and query budgets

User-rule and delegation grouping belongs in the
[audit](../../SECURITY_AUDIT.md#user-rule-validation-and-composition).

### Permitted content queryset

A backend participates only if it has an applicable exact `auth.Permission`
plan and owns every selected name as a queryable condition. Non-owning
backends add nothing, including their unconditioned grants. If no backend
owns the whole selection, construction raises `TrustsConfigurationError`.
Backend order does not change the OR-union. Zero's separate
`ContentQuerySet.permitted` keeps its own permission codec.

Construction performs no SQL. Evaluation filters before pagination,
aggregation, or application ordering in one distinct content query. No
preliminary `Permission.objects.get()` or Python object loop is needed.

### Users from content

Both content and permission arguments are scalar; queryset inputs and
unsaved content are rejected. The content adapter starts with
`get_user_model()._default_manager.get_queryset()`. The optional manager
adapter starts with its own manager queryset. A registration with a different
user-terminal model cannot silently change the content adapter's candidate
model.

Every configured authentication backend must be accounted for at construction:

| Backend capability | Contribution |
| --- | --- |
| `permitted_users_predicate(content, perm)` | A `Q` over candidate users, or `None` when the backend does not apply |
| `trusts_object_permissions = False` | No object grant |
| Exact built-in object-blind backend class | No object grant |
| Potential object-granting backend without a SQL contribution | Raises `TrustsConfigurationError` |

The recognized exact classes are `ModelBackend`, `AllowAllUsersModelBackend`,
`RemoteUserBackend`, and `AllowAllUsersRemoteUserBackend`; subclasses are not
assumed safe from their ancestry. `singular_permission_accepted(perm)` declares
custom permission-instance compatibility. The mixin default accepts only
`auth.Permission` instances.

Construction performs no SQL; evaluation ORs the supported backend branches
in one distinct user query. Each branch uses the same permission identity,
selected filter, and skip inputs as that backend's singular object check.
No claim is made about native `user.has_perm()` before backend dispatch.
The policy-lock key `get_permitted_users` records one Trusts backend branch,
not the aggregate backend union or a duplicate manager entry.

A saved content instance supplies its database alias when available;
otherwise Django's router selects the read alias. All correlated tables must
be queryable there. Cross-database authorization raises rather than merging
results in Python or issuing an unnoticed second query.

### Lower-level and intermediate-content projections

`AuthorizedQuerySet`, `AuthorizedManagerMixin`, and `AuthorizedManager` remain
exported. `.authorized()` does not call `.permitted()` or parse its inputs;
it selects relationship-family handles only. It raises for a non-instance
permission instead of comparing its raw value with an unrelated terminal.

`filter_by_permitted_content` matches a proper prefix of a registered content
path. It correlates that prefix's resolved target field, including non-PK
`to_field`, to each candidate row. A self-referential path may have a proper
prefix of the same model as its terminal. Terminal-only paths, unknown
terminals, empty handle lists, and models absent from the path yield `none()`.
Default and explicit handle selections omit non-relationship backends.

An `along=` prefix at the walk site is retained by reachability. A later
prefix must hang from a reached walk-site row; an earlier prefix stays the
row on the grant. The additional delegated/sponsor suffix limit is in the
[bounded-walk contract](../../SECURITY_AUDIT.md#bounded-inherited-relationships).

## Protect a view

The guard coerces only `view_kwargs["pk"]` through the protected model's
primary-key field. It validates declared backend/filter ownership before
candidate lookup. For an eligible user, an absent candidate gives 404 and
an existing denied candidate gives 403; an ineligible user is denied before
that lookup. A mismatched permission application label is rejected
by guard preflight rather than treated as a content queryset's empty result.

Selected names and skip values are fixed when the decorator is constructed;
request data cannot select them. `trusts.E008` diagnoses declared guard
ownership problems. It does not register runtime `.permitted()` calls;
those perform their own construction-time validation, even if E008 is silenced.

## Internal projection seams

`TrustsRegistry.permissions_for(user, content)`,
`has_permission(user, content, permission)`, and
`filter_authorized(queryset, user, permission)` use model-instance bindings.
Their shared `RelationPlan` supplies `content_exists`, `permissions`,
`common_permissions`, and `has_permission`; an object decision uses SQL
`EXISTS`, not materialized enumeration.

`granted` combines applicable handle branches. `instance_match` checks one
candidate; `all_match` requires every candidate and treats an empty candidate
queryset as false. `common_permissions` returns permission rows shared by all
candidates. Explicit `extra_q` overlays are ANDed with the selected result.
Root/lookup resolution is recorded in [core-registry.md](core-registry.md).

Async dispatch is tracked separately in [#247](https://github.com/django-trusts/django-trusts/issues/247);
this record does not promise that unresolved async paths match the sync methods.

## Failure classification

Malformed permission shapes, unsupported instance types, invalid condition
selections, incompatible models, and incomplete backend coverage raise during
construction. Well-formed but unknown permissions, revoked grants, and ordinary
non-matches produce false or empty results on applicable inquiry paths.
The guard's special lookup behavior is described above rather than inferred
from queryset behavior. Required user-rule denials follow the audit contract.

Construction/evaluation bounds describe Trusts' permission statements, not
authentication middleware, arbitrary application builders, or subsequent
operations performed by the caller on the returned queryset.
