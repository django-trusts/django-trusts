from django.apps import apps as django_apps
from django.db.models import Q, QuerySet, Subquery
from django.contrib.auth.backends import ModelBackend

from trusts.models import (
    Content,
    Trust,
    compile_registered_condition_q,
    legacy_permission_callbacks_allowed,
    permission_has_condition,
)
from trusts.query import (
    group_local_grant_exists,
    is_active_principal,
    permission_granted_via_group_exists,
)
from trusts.conditions import PermissionConditionError, evaluate_registered_expression
from trusts.core import (
    PlanQueryCompiler,
    all_match,
    common_permissions,
    instance_match,
)
from trusts import get_permission_model, utils


class HistoricalGroupQueryCompiler(object):
    """Transitional complete proof: registered plan OR historical TrustGroup.

    #69 S6 registers Group as protected content through Junction. It does
    not register group membership as a trustee route for Category/Ticket.
    This compiler remains through S6/S7 until a separately designed
    group-as-trustee relation replaces it.
    """

    def complete_exists(self, plan, candidates, user, permission):
        if not plan.records:
            return None
        return Q(plan.content_exists(user, permission)) | Q(
            group_local_grant_exists(user, permission, 'trust_id')
        )

    def group_exists(self, plan, candidates, user, permission):
        if not plan.records:
            return None
        return Q(group_local_grant_exists(user, permission, 'trust_id'))


def _permission_binding(perm, model):
    """Unevaluated Permission pk for ``perm`` (instance or dotted code).

    Unknown codes become an empty subquery and match nothing. This is
    permission identity in SQL, not a second authorization source.
    """
    Permission = get_permission_model()
    if isinstance(perm, Permission):
        return perm
    applabel, modelname, action, _cond = utils.parse_perm_code(perm)
    return Subquery(
        Permission.objects.filter(
            codename='%s_%s' % (action, modelname),
            content_type__app_label=applabel.lower(),
            content_type__model=modelname,
        ).values('pk')[:1]
    )


def _perm_codes(permission_qs):
    return set(
        '%s.%s' % (app, code)
        for app, code in permission_qs.values_list(
            'content_type__app_label', 'codename',
        )
    )


class TrustModelBackendMixin(object):
    query_compiler = PlanQueryCompiler()
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

    def _trusts_config(self):
        return django_apps.get_app_config('trusts')

    def _own_handle(self):
        config = self._trusts_config()
        return config.configured_backend(config.path_for_backend(self))

    def _is_collection_coordinator(self):
        """First configured Trusts path (de-duped) is the sole coordinator."""
        config = self._trusts_config()
        paths = config._configured_trusts_paths()
        if not paths:
            return False
        return config.path_for_backend(self) == paths[0]

    def _ensure_perm_cache(self, user_obj):
        """Documented ``_trust_perm_cache`` attribute; not an auth source."""
        if not hasattr(user_obj, '_trust_perm_cache'):
            setattr(user_obj, '_trust_perm_cache', dict())
        return getattr(user_obj, '_trust_perm_cache')

    def _historical_group_permissions(self, user_obj, obj):
        if not Content.is_content(obj):
            return set()
        trusts = self._get_trusts(obj)
        if not trusts:
            return set()
        return _perm_codes(
            self.perm_model.objects.filter(
                permission_granted_via_group_exists(user_obj, trusts)
            )
        )

    def _historical_all_permissions(self, user_obj, obj):
        self._ensure_perm_cache(user_obj)
        perm_cache = getattr(user_obj, '_trust_perm_cache')

        trusts = self._get_trusts(obj)
        if len(trusts):
            all_perms = []
            for trust in trusts:
                if trust.pk not in perm_cache.keys():
                    trust_perm = set([self._get_perm_code(p) for p in
                        self.perm_model.objects.filter(
                            Q(trustentities__trust=trust, trustentities__entity=user_obj) |
                            permission_granted_via_group_exists(user_obj, trust)
                        )
                    ])

                    perm_cache[trust.pk] = trust_perm
                else:
                    trust_perm = perm_cache[trust.pk]

                all_perms.append(trust_perm)
            return set.intersection(*all_perms)
        return set()

    def _collection_permissions(self, user_obj, obj, *, kind):
        handles = self._trusts_config().configured_handles()
        qs = common_permissions(handles, obj, user_obj, kind=kind)
        if qs is None:
            if kind == 'group':
                return self._historical_group_permissions(user_obj, obj)
            return self._historical_all_permissions(user_obj, obj)
        return _perm_codes(qs)

    def _instance_permissions(self, user_obj, obj, *, kind):
        handle = self._own_handle()
        qs = common_permissions((handle,), obj, user_obj, kind=kind)
        if qs is None:
            if kind == 'group':
                return self._historical_group_permissions(user_obj, obj)
            return self._historical_all_permissions(user_obj, obj)
        return _perm_codes(qs)

    def get_group_permissions(self, user_obj, obj=None):
        """
        Returns a set of permission strings that this user has through his/her
        groups.
        """
        if obj is None or not is_active_principal(user_obj):
            return set()

        if isinstance(obj, QuerySet):
            if not self._is_collection_coordinator():
                return set()
            return self._collection_permissions(user_obj, obj, kind='group')

        if Content.is_content(obj):
            return self._instance_permissions(user_obj, obj, kind='group')
        return set()

    def get_all_permissions(self, user_obj, obj=None):
        if obj is None or not is_active_principal(user_obj):
            return set()

        self._ensure_perm_cache(user_obj)

        if isinstance(obj, QuerySet):
            if not self._is_collection_coordinator():
                return set()
            return self._collection_permissions(user_obj, obj, kind='complete')

        if Content.is_content(obj):
            return self._instance_permissions(user_obj, obj, kind='complete')
        return set()

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

    def _condition_overlay(self, permext, obj, user_obj):
        """Return (record, extra_q) for a ``:condition`` suffix.

        An ``Expr`` on a QuerySet compiles to SQL (AND overlay). Callables
        stay on the documented object-only path. Unregistered codes raise
        the same ``AttributeError`` as before.
        """
        if not permission_has_condition(permext):
            return None, None
        applabel, modelname, action, cond = utils.parse_perm_code(permext)
        record = Content.get_permission_condition_record(self._get_class(obj), cond)
        if record is None:
            raise AttributeError(
                'Permission condition code "%s" is not associate with model "%s_%s"'
                % (cond, applabel, modelname)
            )
        extra_q = None
        if record.expr is not None and isinstance(obj, QuerySet):
            extra_q = compile_registered_condition_q(
                obj.model, permext, user_obj,
            )
        return record, extra_q

    def _collection_has_perm(self, user_obj, perm, obj, extra_q=None):
        handles = self._trusts_config().configured_handles()
        binding = _permission_binding(perm, obj.model)
        matched = all_match(
            handles, obj, user_obj, binding, kind='complete', extra_q=extra_q,
        )
        if matched is None:
            return perm in self._historical_all_permissions(user_obj, obj)
        return matched

    def _instance_has_perm(self, user_obj, perm, obj, extra_q=None):
        handle = self._own_handle()
        binding = _permission_binding(perm, obj.__class__)
        matched = instance_match(
            handle, obj, user_obj, binding, kind='complete', extra_q=extra_q,
        )
        if matched is None:
            return perm in self._historical_all_permissions(user_obj, obj)
        return matched

    def has_perm(self, user_obj, permext, obj=None):
        if obj is None or not is_active_principal(user_obj):
            return False

        if isinstance(obj, QuerySet) and not self._is_collection_coordinator():
            return False

        if not isinstance(obj, QuerySet) and not Content.is_content(obj):
            return False

        record, extra_q = self._condition_overlay(permext, obj, user_obj)
        applabel, modelname, action, _cond = utils.parse_perm_code(permext)
        perm = '%s.%s_%s' % (applabel, action, modelname)

        if isinstance(obj, QuerySet):
            positive = self._collection_has_perm(
                user_obj, perm, obj, extra_q=extra_q,
            )
        else:
            positive = self._instance_has_perm(
                user_obj, perm, obj, extra_q=extra_q,
            )
        if not positive:
            return False
        if record is None or extra_q is not None:
            return True
        return self.permission_condition_met(record, user_obj, perm, obj)


class TrustModelBackend(TrustModelBackendMixin, ModelBackend):
    query_compiler = HistoricalGroupQueryCompiler()
