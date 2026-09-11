from django.db.models import Q
from django.contrib.auth.backends import ModelBackend

from trusts.core_backends import TrustModelBackendMixin  # deprecated alias
from trusts.query import (
    historical_group_grant_exists,
)


class HistoricalGroupQueryCompiler(object):
    """Complete proof: registered plan OR historical TrustGroup.

    #69 S6 registers Group as protected content through Junction. It does
    not register group membership as a trustee route for Category/Ticket.
    This compiler remains through S7 until a separately designed
    group-as-trustee relation replaces it.

    ``historical_fallback`` identifies this concrete compiler for mixin
    isolation. It does not reopen a static content map. Unknown or
    undeclared terminals fail closed. Declared Category / Ticket / Trust
    / Group use the registered plan plus this compiler's TrustGroup OR.
    """

    historical_fallback = True

    def complete_exists(self, plan, candidates, user, permission):
        if getattr(plan, 'strategy', None) is not None:
            return plan.content_exists(user, permission)
        if not plan.records:
            return None
        return Q(plan.content_exists(user, permission)) | Q(
            historical_group_grant_exists(plan, user, permission)
        )

    def group_exists(self, plan, candidates, user, permission):
        if getattr(plan, 'strategy', None) is not None:
            return None
        if not plan.records:
            return None
        return Q(historical_group_grant_exists(plan, user, permission))


class TrustModelBackend(TrustModelBackendMixin, ModelBackend):
    query_compiler = HistoricalGroupQueryCompiler()
