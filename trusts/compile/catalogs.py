from trusts.compile.factory import RegistryFactory
from trusts.plan.conditions import (
    evaluate_registered_expression,
    permission_has_condition,
)

"""
    Catalog is an instance created for a backend class.
    Every object created inside / under trace back to a single backend class.
    So, getting a handle is not needed.

    CLARITY (sketch, not implementation) -- what this class is meant to be:

    (a) Owner, not a second store: ``Catalog`` is the per-backend-class
        owner of the encapsulated compile/plan step, living in
        ``trusts/compile/``. It holds the ``RegistryFactory``, builds and
        caches the lowered registry as private data (``catalog.registry``),
        and owns the query compiler. It does NOT invent a second store;
        nothing lowered lives directly on the Catalog except via that
        built registry.
    (b) What is inside, via its built registry: ``records`` (tuple of
        ``RegisteredRelation``), ``delegations`` (tuple of
        ``RegisteredDelegation``), ``conditions`` (``ConditionRegistry``),
        and ``user_conditions`` / ``user_override``. ``RelationPlan``s are
        built on demand from the records; they are not stored.
    (c) Two modes only -- Catalog constructs, it never executes for the
        caller: ``has_perm()`` -> get_qs from Catalog -> execute it
        (``qs.exists()`` -> ``bool``) and return the result; and
        ``User.with_perm()`` -> get_qs from Catalog -> return the qs
        unevaluated. Execution/return is the caller's choice.
    (d) Vocabulary: "entries" means those lowered records/delegations a
        Catalog holds. The answer to one inquiry is NOT an entry; it is
        a ``PreparedInquiry`` (see below).

    Compiler ownership: the compiler arrives at construction -- passed
    from the backend class's ``query_compiler`` into the Catalog /
    ``RegistryFactory`` constructor (and on to the built registry).
    A ``Catalog`` class attribute is NOT the customization surface; the
    class attribute in this sketch is a placeholder only.
"""
class Catalog(object):
    # Placeholder only -- see module note on compiler ownership above.
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

    def prepare_has_perm(self, user_obj, permext, obj=None, **skip_flags) -> PreparedInquiry:
        # @TODO: convert to return PreparedInquiry (inquiry answer, not a stored entry)

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

        # @TODO: Implement prepare_* -> PreparedInquiry for the inquiries,
        # in this order (stage 1 is has_perm only; the rest migrate later
        # by the same prepare pattern, not in the same run):
        #   1. has_perm (this method)
        #   2. permissions_for / get_all_permissions + get_group_permissions
        #   3. permitted_users / permitted_users_predicate
        #   4. filter_authorized / permitted content
        # there should be only two shape of permission inqury, eg,
        #   has_perm() -> get_qs from Catalog -> execute it and return result
        #   User.with_perm() -> get_qs from Catalog -> return qs
        # So, return PreparedInquiry() for all of them, and let backend choose what to do.
        # If non-qs result is known without executing the qs, or fail-safe == False, then set result.
        # caller's responsiblity to check qs first.
        #
        # OPEN execute() shape question: the inquiries do not share one
        # result shape -- has_perm wants a bool (qs.exists()), the
        # permissions_for family materializes a set of codes, and the
        # permitted-users predicate returns a Q or None. PreparedInquiry
        # .execute() as sketched only fits the bool shape; the other
        # shapes must be resolved explicitly, not folded into execute().
        # A preset result also needs a sentinel distinct from None:
        # None cannot mean "no preset", because False / an empty set
        # are legitimate preset answers.
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
        return PreparedInquiry(model=model, result=None, qs= ...)
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


class PreparedInquiry(object):
    """One inquiry's answer envelope: (model, result, qs).

    Not a stored registration -- do not confuse with the Catalog's
    entries (its lowered records/delegations).
    """

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
        # Sketch only: a QuerySet has no .execute(); the bool mode is
        # qs.exists(). See the OPEN execute() shape note in Catalog.
        if (result != None):
            return result
        return self.qs.execute()


# CLARITY: this _RecordAdapter duplicates the adapter already in
# trusts/compile/factory.py. Implementation must reuse factory's
# adapter and delete this duplicate; do not keep two adapters.
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

