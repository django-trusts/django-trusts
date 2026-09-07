from django.db.models import Q, QuerySet
from django.contrib.auth.backends import ModelBackend

from trusts.models import Trust, Content
from trusts import get_permission_model, utils


class TrustModelBackendMixin(object):
    perm_model = get_permission_model()

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

        if Content.is_content(obj):
            filter = self.perm_model.objects.filter
            return filter(group__trusts__in=self._get_trusts(obj), group__user=user_obj)

        return []

    def get_all_permissions(self, user_obj, obj=None):
        if user_obj.is_anonymous or obj is None:
            return super(TrustModelBackendMixin, self).get_all_permissions(user_obj, obj)

        if not hasattr(user_obj, '_trust_perm_cache'):
            setattr(user_obj, '_trust_perm_cache', dict())
        perm_cache = getattr(user_obj, '_trust_perm_cache')

        trusts = self._get_trusts(obj)
        if len(trusts):
            all_perms = []
            for trust in trusts:
                if trust.pk not in perm_cache.keys():
                    trust_perm = set([self._get_perm_code(p) for p in
                        self.perm_model.objects.filter(
                            Q(group__trusts=trust, group__user=user_obj) |
                            Q(roles__groups__trusts=trust, roles__groups__user=user_obj) |
                            Q(trustentities__trust=trust, trustentities__entity=user_obj)
                        )
                        .order_by('group__trusts', 'trustentities__entity')
                    ])

                    perm_cache[trust.pk] = trust_perm
                else:
                    trust_perm = perm_cache[trust.pk]

                all_perms.append(trust_perm)
            return set.intersection(*all_perms)
        return []

    def permission_condition_met(self, func, user_obj, perm, obj):
        if isinstance(obj, QuerySet):
            objs = obj.all()
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            objs = obj
        else:
            objs = [obj]

        return all([func(user_obj, perm, o) for o in objs])

    def has_perm(self, user_obj, permext, obj=None):
        applabel, modelname, action, cond = utils.parse_perm_code(permext)
        if len(cond) != 0:
            func = Content.get_permission_condition_func(self._get_class(obj), cond)
            if func is None:
                raise AttributeError('Permission condition code "%s" is not associate with model "%s_%s"' % (cond, applabel, modelname))

        perm = '%s.%s_%s' % (applabel, action, modelname)
        positive = super(TrustModelBackendMixin, self).has_perm(user_obj=user_obj, perm=perm, obj=obj)
        if positive:
            if len(cond) == 0:
                return True

            if self.permission_condition_met(func, user_obj, perm, obj):
                return True
        return False


class TrustModelBackend(TrustModelBackendMixin, ModelBackend):
    pass
