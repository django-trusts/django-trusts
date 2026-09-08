from django.db.models import Q, QuerySet
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission

from trusts.models import Trust, Content, legacy_permission_callbacks_allowed
from trusts.query import permission_granted_via_group_exists
from trusts.conditions import PermissionConditionError, evaluate_registered_expression
from trusts import (
    supported_entity_contract,
    supported_group_contract,
    supported_permission_contract,
    utils,
)


class TrustModelBackendMixin(object):
    @staticmethod
    def _get_perm_code(perm):
        return '%s.%s' % (
            perm.content_type.app_label, perm.codename
        )

    @staticmethod
    def _get_trusts(obj):
        if not Content.is_content(obj):
            return []

        trusts = Trust.objects.filter_by_content(obj)
        if trusts is None:
            return []

        if not hasattr(trusts, '__iter__'):
            trusts = [trusts]

        return trusts

    @staticmethod
    def _get_class(obj):
        if isinstance(obj, QuerySet):
            klass = obj.model
        else:
            klass = obj.__class__
        return klass

    def get_group_permissions(self, user_obj, obj=None):
        """
        Returns a set of permission strings that this user has through his/her
        groups.
        """

        if user_obj.is_anonymous or obj is None:
            return super(TrustModelBackendMixin, self).get_group_permissions(user_obj, obj)

        if not _group_permission_queries_allowed():
            return set()

        if Content.is_content(obj):
            trusts = self._get_trusts(obj)
            if not trusts:
                return Permission.objects.none()
            return Permission.objects.filter(
                permission_granted_via_group_exists(user_obj, trusts)
            )

        return []

    def get_all_permissions(self, user_obj, obj=None):
        if user_obj.is_anonymous or obj is None:
            return super(TrustModelBackendMixin, self).get_all_permissions(user_obj, obj)

        if not supported_permission_contract():
            return []

        if not hasattr(user_obj, '_trust_perm_cache'):
            setattr(user_obj, '_trust_perm_cache', dict())
        perm_cache = getattr(user_obj, '_trust_perm_cache')

        trusts = self._get_trusts(obj)
        if len(trusts):
            all_perms = []
            for trust in trusts:
                if trust.pk not in perm_cache.keys():
                    grant_q = _trust_permission_grant_q(user_obj, trust)
                    if grant_q is None:
                        trust_perm = set()
                    else:
                        trust_perm = set([self._get_perm_code(p) for p in
                            Permission.objects.filter(grant_q)
                        ])

                    perm_cache[trust.pk] = trust_perm
                else:
                    trust_perm = perm_cache[trust.pk]

                all_perms.append(trust_perm)
            return set.intersection(*all_perms)
        return []

    def permission_condition_met(self, record, user_obj, perm, obj):
        if isinstance(obj, QuerySet):
            objs = obj.all()
            model = obj.model
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            objs = obj
            model = None
        else:
            objs = [obj]
            model = obj.__class__

        if record.expr is not None:
            return all([
                evaluate_registered_expression(
                    record.expr, user_obj, perm, o, model=model or o.__class__
                )
                for o in objs
            ])
        if not legacy_permission_callbacks_allowed():
            raise PermissionConditionError(
                'Callable permission conditions are disabled. Set '
                'TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS = True to use '
                'the object-only has_perm path, or register an Expr from '
                'condition_refs(). Silencing trusts.E002 does not enable '
                'the callback.'
            )
        return all([record.func(user_obj, perm, o) for o in objs])

    def has_perm(self, user_obj, permext, obj=None):
        applabel, modelname, action, cond = utils.parse_perm_code(permext)
        record = None
        if len(cond) != 0:
            record = Content.get_permission_condition_record(self._get_class(obj), cond)
            if record is None:
                raise AttributeError('Permission condition code "%s" is not associate with model "%s_%s"' % (cond, applabel, modelname))

        perm = '%s.%s_%s' % (applabel, action, modelname)
        positive = super(TrustModelBackendMixin, self).has_perm(user_obj=user_obj, perm=perm, obj=obj)
        if positive:
            if len(cond) == 0:
                return True

            if self.permission_condition_met(record, user_obj, perm, obj):
                return True
        return False


def _group_permission_queries_allowed():
    return supported_group_contract() and supported_permission_contract()


def _trust_permission_grant_q(user_obj, trust):
    parts = []
    if supported_entity_contract():
        parts.append(Q(trustentities__trust=trust, trustentities__entity=user_obj))
    if _group_permission_queries_allowed():
        parts.append(permission_granted_via_group_exists(user_obj, trust))
    if not parts:
        return None
    grant_q = parts[0]
    for part in parts[1:]:
        grant_q |= part
    return grant_q


class TrustModelBackend(TrustModelBackendMixin, ModelBackend):
    pass
