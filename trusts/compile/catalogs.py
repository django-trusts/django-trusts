from trusts.compile.factory import RegistryFactory
from trusts.plan.conditions import (
    evaluate_registered_expression,
    permission_has_condition,
)

"""
    Catalog is an instance created for a backend class.
    Every object created inside / under trace back to a single backend class.
    So, getting a handle is not needed.
"""
class Catalog(object):
    query_compiler = PlanQueryCompiler()

    def __init__(path=path, family=family, cls=cls):
        self.cls = cls # backend's class
        self.path = path
        self.family = family
        self.factory = RegistryFactory()

    def build():
        _get_or_create_registry()

    def get_record_adapter(self):
        """Adapter ``Recorder.play`` calls. Methods forward to this factory."""
        return _RecordAdapter(self.factory)

    def prepare_has_perm_entry(self, user_obj, permext, obj=None, **skip_flags) -> CatalogEntry:
        # @TODO: convert to return CatalogEntry

        registry = self._get_or_create_registry()
        if not registry.applies(registry.plan_for(obj, user=user_obj)):
            return False
        record, extra_q = self._condition_overlay(
            permext, obj, user_obj, registry=registry,
        )
        applabel, modelname, action, _cond = utils.parse_perm_code(permext)
        perm = '%s.%s_%s' % (applabel, action, modelname)
        if permission_has_condition(permext) and record is None:
            return False
        if isinstance(obj, QuerySet):
            positive = self._collection_has_perm(
                user_obj, perm, obj, extra_q=extra_q,
                skipped=inquiry.values, registry=registry,
            )
        else:
            positive = self._instance_has_perm(
                user_obj, perm, obj, extra_q=extra_q,
                skipped=inquiry.values, registry=registry,
            )
        if not positive:
            return False
        if record is None or extra_q is not None:
            return True
        return self.permission_condition_met(record, user_obj, perm, obj)

        # @TODO: Implement the rest of prepare_xyz() -> CatalogEntry for other 4 permission inquiries
        # there should be only two shape of permission inqury, eg,
        #   has_perm() -> get_qs from Catalog -> execute it and return result
        #   User.with_perm() -> get_qs from Catalog -> return qs
        # So, return CatalogEntry() for all 4, and let backend choose what to do.
        # If non-qs result is known without executing the qs, or fail-safe == False, then set result.
        # caller's responsiblity to check qs first.
        #
        # move all code that need /compile /plan into here

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

        # @TODO: implement me
        return CatalogEntry(model=model, result=None, qs= ...)
        """
        all([
            evaluate_registered_expression(
                record.expr, user_obj, perm, o, model=model or o.__class__
            )
            for o in objs
        ])
        """

    def _get_or_create_registry():
        if self.registry == None:
            self.registry = factory.build_registry()
        return self.registry


class CatalogEntry(object):
    def __init__(model=model, result=result, qs=qs):
        self.model = model
        self.result = result
        self.qs = qs
        ## qs and result is mutual exclusive. One of them is none

    def get_qs():
        return self.qs

    def get_model():
        return self.model

    def execute():
        if (result != None):
            return result
        return self.qs.execute()


class _RecordAdapter(object):
    """Visitor ``Recorder.play`` drives. Forwards to this factory's public API."""

    def __init__(self, factory):
        self.factory = factory

    def register_principal(self, **kwargs):
        return self.factory.register(**kwargs)

    def register_delegate(self, **kwargs):
        return self.factory.register_delegation(**kwargs)

    def add_named_filter(self, model, code, predicate):
        return self.factory.register_permission_condition(model, code, predicate)

    def set_user_condition(self, name, expr, on='*'):
        return self.factory.set_user_condition(name, expr, on=on)

    def set_user_override(self, name, expr, on='user'):
        return self.factory.set_user_override(name, expr, on=on)

