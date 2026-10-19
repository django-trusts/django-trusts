"""Front over one factory and the registry it builds. Not a second store."""

from django.contrib.auth.models import Permission
from django.db.models import QuerySet, Subquery

from trusts.compile.factory import RegistryFactory
from trusts.errors import PermissionConditionError
from trusts.plan.conditions import (
    evaluate_registered_expression,
    permission_has_condition,
)
from trusts.utils import parse_perm_code
_NO_PRESET = object()  # not None: False and empty answers are real

class PreparedInquiry(object):
    def __init__(self, model, result=_NO_PRESET, qs=None):
        self.model = model
        self.result = result
        self.qs = qs

    def execute(self):
        if self.result is not _NO_PRESET:
            return self.result
        return bool(self.qs.exists())

class Catalog(object):
    def __init__(self, *, cls, path, family, compiler, factory=None,
                 registry=None):
        self.cls = cls
        self.path = path
        self.family = family
        self._replay = factory is None
        self.factory = factory if factory is not None else RegistryFactory(
            compiler=compiler, path=path, family=family,
        )
        self._registry = registry

    @property
    def registry(self):
        return self._registry

    def build(self, recorder):
        if self._registry is not None:
            return self._registry
        recorder.freeze()
        if self._replay:
            recorder.play(self.get_record_adapter())
        self._registry = self.factory.build_registry()
        return self._registry

    def get_record_adapter(self):
        return self.factory.get_record_adapter()

    def prepare_has_perm(self, user_obj, permext, obj, *, skipped, sponsors):
        registry = self.registry
        model = _content_model(obj)
        if not registry.applies(registry.plan_for(obj, user=user_obj)):
            return PreparedInquiry(model, result=False)
        record, extra_q = self._condition_overlay(permext, obj, user_obj)
        applabel, modelname, action, _cond = parse_perm_code(permext)
        perm = '%s.%s_%s' % (applabel, action, modelname)
        if permission_has_condition(permext) and record is None:
            return PreparedInquiry(model, result=False)
        held = registry.has_permission(
            user_obj, obj, _permission_binding(perm, model),
            extra_q=extra_q, sponsors=_registries(sponsors),
            permission_model=Permission,
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )
        if not held:
            return PreparedInquiry(model, result=False)
        if record is None or extra_q is not None:
            return PreparedInquiry(model, result=True)
        return self.permission_condition_met(record, user_obj, perm, obj)

    def permission_condition_met(self, record, user_obj, perm, obj):
        model = _content_model(obj)
        if record.expr is None:
            label = getattr(getattr(model, '_meta', None), 'label', model)
            raise PermissionConditionError(
                'Permission condition on %s is unbound.' % label
            )
        if isinstance(obj, QuerySet):
            objs, model = obj.all(), obj.model
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            objs, model = obj, None
        else:
            objs = [obj]
        met = all(
            evaluate_registered_expression(
                record.expr, user_obj, perm, item,
                model=model or item.__class__,
            )
            for item in objs
        )
        return PreparedInquiry(model, result=bool(met))

    def _condition_overlay(self, permext, obj, user_obj):
        if not permission_has_condition(permext):
            return None, None
        applabel, modelname, _action, cond = parse_perm_code(permext)
        model = _content_model(obj)
        lookup = getattr(self.registry, 'condition_lookup', None)
        if lookup is None:
            if isinstance(obj, QuerySet):
                return None, None
            raise AttributeError(
                'Permission condition code "%s" is not associate with model "%s_%s"'
                % (cond, applabel, modelname)
            )
        record = lookup.record_for(model, cond)
        if record is None or not isinstance(obj, QuerySet):
            return record, None
        return record, lookup.compile_q(obj.model, permext, user_obj)

def _content_model(obj):
    return obj.model if isinstance(obj, QuerySet) else obj.__class__

def _registries(sponsors):
    return tuple(
        sponsor.registry for sponsor in sponsors if sponsor.registry is not None
    )

def _permission_binding(perm, model):
    if isinstance(perm, Permission):
        return perm
    applabel, modelname, action, _cond = parse_perm_code(perm)
    return Subquery(
        Permission.objects.filter(
            codename='%s_%s' % (action, modelname),
            content_type__app_label=applabel.lower(),
            content_type__model=modelname,
        ).values('pk')[:1]
    )
