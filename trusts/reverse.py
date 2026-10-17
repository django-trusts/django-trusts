"""Re-export of the object-to-users compiler.

The implementation lives in ``trusts.plan.users``. This module remains
so existing imports such as ``from trusts.reverse import
compile_permitted_users`` keep working.
"""

from trusts.plan.users import (
    _trusts_eligibility_q,
    compile_permitted_users,
    lock_permitted_users_queryset,
    trusts_mixin_predicate,
)

__all__ = []
