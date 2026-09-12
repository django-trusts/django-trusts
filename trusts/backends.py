"""Generic Trusts backend mixin.

``TrustModelBackendMixin`` lives only here. Core does not ship
``TrustModelBackend`` or ``HistoricalGroupQueryCompiler``; those names
are ``trusts.zero.backends``. ``trusts.core_backends`` is gone.
"""

from django.contrib.auth.models import Permission
from django.db.models import Model, QuerySet, Subquery

from trusts.conditions import (
    PermissionConditionError,
    evaluate_registered_expression,
    permission_has_condition,
)
from trusts.query import (
    is_active_principal,
)
from trusts.core import (
    PlanQueryCompiler,
    all_match,
    common_permissions,
    instance_match,
)
from trusts import utils


def _permission_binding(perm, model):
    """Unevaluated Permission pk for ``perm`` (instance or dotted code).

    Unknown codes become an empty subquery and match nothing. This is
    permission identity in SQL, not a second authorization source.
    """
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

    @staticmethod
    def _get_class(obj):
        if isinstance(obj, QuerySet):
            klass = obj.model
        else:
            klass = obj.__class__
        return klass

    def _trusts_config(self):
        from trusts.apps import implementation_for_class

        return implementation_for_class(type(self), required=True)

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

    def _collection_permissions(self, user_obj, obj, *, kind):
        handles = self._trusts_config().configured_handles()
        qs = common_permissions(handles, obj, user_obj, kind=kind)
        if qs is None:
            return set()
        return _perm_codes(qs)

    def _instance_permissions(self, user_obj, obj, *, kind):
        handle = self._own_handle()
        qs = common_permissions((handle,), obj, user_obj, kind=kind)
        if qs is None:
            return set()
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

        if not isinstance(obj, Model):
            return set()
        return self._instance_permissions(user_obj, obj, kind='group')

    def get_all_permissions(self, user_obj, obj=None):
        if obj is None or not is_active_principal(user_obj):
            return set()

        self._ensure_perm_cache(user_obj)

        if isinstance(obj, QuerySet):
            if not self._is_collection_coordinator():
                return set()
            return self._collection_permissions(user_obj, obj, kind='complete')

        if not isinstance(obj, Model):
            return set()
        return self._instance_permissions(user_obj, obj, kind='complete')

    def permission_condition_met(self, record, user_obj, perm, obj):
        if record.expr is None:
            model = obj.model if isinstance(obj, QuerySet) else getattr(obj, '__class__', obj)
            raise PermissionConditionError(
                'Permission condition on %s is unbound.'
                % getattr(getattr(model, '_meta', None), 'label', model)
            )
        if isinstance(obj, QuerySet):
            objs = obj.all()
            model = obj.model
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            objs = obj
            model = None
        else:
            objs = [obj]
            model = obj.__class__

        return all([
            evaluate_registered_expression(
                record.expr, user_obj, perm, o, model=model or o.__class__
            )
            for o in objs
        ])

    def _bound_condition_lookup(self, obj):
        """Bound ``ConditionLookup`` on the coordinating / own registry.

        Unbound (the C1 default) is ``None``. Unknown ``:condition``
        codes then raise ``AttributeError``.
        """
        if isinstance(obj, QuerySet):
            handles = self._trusts_config().configured_handles()
            if not handles:
                return None
            return handles[0].registry.condition_lookup
        return self._own_handle().registry.condition_lookup

    def _condition_overlay(self, permext, obj, user_obj):
        """Return (record, extra_q) for a ``:condition`` suffix.

        Stored IR on a QuerySet compiles to SQL (AND overlay).
        Unregistered codes raise the same ``AttributeError`` as before.

        A bound ``ConditionLookup`` is the only condition path. Unknown
        codes raise ``AttributeError``. Core does not import Zero modules
        or discover helpers from a model ``__module__``.
        """
        if not permission_has_condition(permext):
            return None, None
        applabel, modelname, action, cond = utils.parse_perm_code(permext)
        model = self._get_class(obj)
        lookup = self._bound_condition_lookup(obj)
        if lookup is None:
            raise AttributeError(
                'Permission condition code "%s" is not associate with model "%s_%s"'
                % (cond, applabel, modelname)
            )
        record = lookup.record_for(model, cond)
        if record is None:
            raise AttributeError(
                'Permission condition code "%s" is not associate with model "%s_%s"'
                % (cond, applabel, modelname)
            )
        extra_q = None
        if isinstance(obj, QuerySet):
            extra_q = lookup.compile_q(obj.model, permext, user_obj)
        return record, extra_q

    def _collection_has_perm(self, user_obj, perm, obj, extra_q=None):
        handles = self._trusts_config().configured_handles()
        binding = _permission_binding(perm, obj.model)
        matched = all_match(
            handles, obj, user_obj, binding, kind='complete', extra_q=extra_q,
        )
        if matched is None:
            return False
        return matched

    def _instance_has_perm(self, user_obj, perm, obj, extra_q=None):
        handle = self._own_handle()
        binding = _permission_binding(perm, obj.__class__)
        matched = instance_match(
            handle, obj, user_obj, binding, kind='complete', extra_q=extra_q,
        )
        if matched is None:
            return False
        return matched

    def has_perm(self, user_obj, permext, obj=None):
        if obj is None or not is_active_principal(user_obj):
            return False

        if isinstance(obj, QuerySet) and not self._is_collection_coordinator():
            return False

        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
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
