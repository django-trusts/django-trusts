from django.apps import apps as django_apps
from django.db.models import Model, Q, QuerySet, Subquery
from django.contrib.auth.backends import ModelBackend

from trusts.conditions import (
    PermissionConditionError,
    PermissionConditionNotQueryable as KernelPermissionConditionNotQueryable,
    evaluate_registered_expression,
    legacy_permission_callbacks_allowed,
    permission_has_condition,
)
from trusts.query import (
    historical_group_grant_exists,
    is_active_principal,
)
from trusts.core import (
    PlanQueryCompiler,
    all_match,
    common_permissions,
    instance_match,
)
from trusts import get_permission_model, utils


def _permission_condition_not_queryable():
    """Zero's class when Trust is installed; otherwise the kernel copy."""
    try:
        Trust = django_apps.get_model('trusts', 'Trust')
    except LookupError:
        return KernelPermissionConditionNotQueryable
    import sys
    cls = getattr(
        sys.modules.get(Trust.__module__),
        'PermissionConditionNotQueryable',
        None,
    )
    if cls is None:
        return KernelPermissionConditionNotQueryable
    return cls


def _historical_content_class():
    """Abstract Zero ``Content`` via Trust's MRO. Does not import the shim."""
    try:
        Trust = django_apps.get_model('trusts', 'Trust')
    except LookupError:
        return None
    for base in Trust.__mro__:
        meta = getattr(base, '_meta', None)
        if (
            meta is not None
            and meta.abstract
            and base.__name__ == 'Content'
            and meta.app_label == 'trusts'
        ):
            return base
    return None


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
        if not plan.records:
            return None
        return Q(plan.content_exists(user, permission)) | Q(
            historical_group_grant_exists(plan, user, permission)
        )

    def group_exists(self, plan, candidates, user, permission):
        if not plan.records:
            return None
        return Q(historical_group_grant_exists(plan, user, permission))


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
    def _get_class(obj):
        if isinstance(obj, QuerySet):
            klass = obj.model
        else:
            klass = obj.__class__
        return klass

    def _trusts_config(self):
        from trusts.apps import kernel_config
        return kernel_config()

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
        if isinstance(obj, QuerySet) and record.expr is None:
            raise _permission_condition_not_queryable()(
                'ContentQuerySet.permitted does not support permission '
                'condition on %s. Register an Expr from condition_refs() '
                'to compile a V1 declarative expression. Callables remain '
                'object-only via has_perm; this queryset API refuses them so '
                'the underlying grant cannot be returned without the '
                'condition.' % obj.model._meta.label
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

    def _bound_condition_lookup(self, obj):
        """Bound ``ConditionLookup`` on the coordinating / own registry.

        Unbound (the C1 default) is ``None`` so instance-only callers and
        the historical ``Content`` condition store keep current behavior.
        """
        if isinstance(obj, QuerySet):
            handles = self._trusts_config().configured_handles()
            if not handles:
                return None
            return handles[0].registry.condition_lookup
        return self._own_handle().registry.condition_lookup

    def _condition_overlay(self, permext, obj, user_obj):
        """Return (record, extra_q) for a ``:condition`` suffix.

        An ``Expr`` on a QuerySet compiles to SQL (AND overlay). Callables
        on a QuerySet raise ``PermissionConditionNotQueryable`` before
        any candidate SQL or callback. Unregistered codes raise the same
        ``AttributeError`` as before.

        A bound ``ConditionLookup`` is preferred when present. Unbound
        preserves the historical ``Content`` condition registry when Zero
        is installed (discovered from Trust's MRO; the shim is not
        imported). Core does not import Zero models for this overlay.
        """
        if not permission_has_condition(permext):
            return None, None
        applabel, modelname, action, cond = utils.parse_perm_code(permext)
        model = self._get_class(obj)
        lookup = self._bound_condition_lookup(obj)
        if lookup is not None:
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
        Content = _historical_content_class()
        if Content is None:
            raise AttributeError(
                'Permission condition code "%s" is not associate with model "%s_%s"'
                % (cond, applabel, modelname)
            )
        record = Content.get_permission_condition_record(model, cond)
        if record is None:
            raise AttributeError(
                'Permission condition code "%s" is not associate with model "%s_%s"'
                % (cond, applabel, modelname)
            )
        extra_q = None
        if isinstance(obj, QuerySet):
            import sys
            compile_registered_condition_q = getattr(
                sys.modules[Content.__module__],
                'compile_registered_condition_q',
            )
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


class TrustModelBackend(TrustModelBackendMixin, ModelBackend):
    query_compiler = HistoricalGroupQueryCompiler()
