"""Names downstream packages still import from ``trusts.core``.

In-repo modules import the defining modules directly. This file
defines nothing.

django-trusts-zero production on the same-named branch ``4d33fe3``
(the pair job still pins ``8d7c729``):

- ``TrustsConfigurationError`` — ``trusts/zero/apps.py``,
  ``trusts/zero/query.py``
- ``PlanQueryCompiler`` — ``trusts/zero/backends.py``
- ``BackendHandle`` — ``trusts/zero/registration.py``
- ``granted`` — ``trusts/zero/query.py``
- ``filter_authorized_scopes`` and ``any_plan_records`` — still
  imported by the pair pin ``8d7c729`` (``trusts/zero/query.py``).
  Same-branch Zero ``4d33fe3`` does not import either name from
  production code. ``filter_authorized_scopes`` remains a Zero test
  import (``tests/legacy/test_issue54.py``). The re-exports stay
  until that pin moves.

django-trusts-gh-permissions production:

- ``BackendHandle`` — ``gh_permissions/policy.py``

Test-only movers, one follow-up rather than a name at a time:
``compiler_for_class`` (Zero ``tests/apps.py`` and
``tests/legacy/test_issue75.py``) and ``common_permissions`` (Zero
``tests/legacy/test_issue77.py``, ``tests/legacy/test_issue87.py``,
and the aggregate tests that assert this Core name). Retarget that
batch together.

Zero and gh-permissions tests also import ``TrustsRegistry``, ``Ref``,
``All``, ``Equal``, ``PermissionIn``, ``RelationPlan``,
``ConditionLookup``, and ``TrustsCompilerError``. Those stay until
those tests move. Deleting this module waits on that downstream set.

``_FrozenRegistry`` stays because ``test_registry_spike`` asserts this
alias. ``permission_in`` stays because ``test_issue98`` asserts that
export. ``plan.registry`` does not import ``compile``.
"""

from trusts.compile.factory import TrustsRegistry
from trusts.compile.nodes import All, Equal, PermissionIn, Ref, permission_in
from trusts.errors import TrustsCompilerError, TrustsConfigurationError
from trusts.plan.aggregates import (
    any_plan_records,
    common_permissions,
    compiler_for_class,
)
from trusts.plan.contents import filter_authorized_scopes, granted
from trusts.plan.handles import BackendHandle
from trusts.plan.registry import FrozenRegistry as _FrozenRegistry
from trusts.plan.relations import (
    ConditionLookup,
    PlanQueryCompiler,
    RelationPlan,
)
