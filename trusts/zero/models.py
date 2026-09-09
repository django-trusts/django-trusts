from django.apps import apps
from django.core.exceptions import AppRegistryNotReady, FieldDoesNotExist, ValidationError
from django.db import models, transaction
from django.db.models import signals, Q, options
from django.conf import settings as django_settings
from django.utils.translation import gettext_lazy as _

from trusts import utils
from trusts.zero import (
    ENTITY_MODEL_NAME, PERMISSION_MODEL_NAME, GROUP_MODEL_NAME,
    DEFAULT_SETTLOR, ALLOW_NULL_SETTLOR, ROOT_PK,
    supported_entity_contract, supported_group_contract,
    supported_permission_contract,
)
from trusts.context import (
    KIND_DIRECT,
    KIND_RELATED,
    Context,
    ContextRegistrationError,
    ContextRegistryFrozen,
    check_registration,
)
from trusts.trustee import Trustee, TrusteeMixin
from trusts.zero.query import compose_zero_path, is_active_principal, trust_grant_q
from trusts.conditions import (
    Expr,
    PermissionConditionError,
    condition_refs,
    compile_expression_q,
    is_predicate,
)


DIRECT_TRUSTEE = 'direct'
GROUP_TRUSTEE = 'group'


def prepare_context_registry():
    """Finalize pending Content conveniences, then freeze before queries.

    ``KernelConfig.ready`` / ``ZeroConfig.ready`` run before later
    ``INSTALLED_APPS`` have registered. Authorization queries and
    ``manage.py check`` share ``Context.ensure_frozen()``, which runs
    registered finalizers (including
    ``Content.sync_pending_context_registrations``) before freeze. After
    freeze, public registration is idempotent-only or rejected.
    """
    Context.ensure_frozen()


def prepare_trustee_registry():
    """Finalize django-trusts Trustee conveniences, then freeze.

    ``KernelConfig.ready`` / ``ZeroConfig.ready`` run before later
    ``INSTALLED_APPS`` have registered. Authorization queries and
    ``manage.py check`` share ``Trustee.ensure_frozen()``, which runs
    registered finalizers (including ``sync_default_trustee_adapters``)
    before freeze. After freeze, public registration is idempotent-only
    or rejected.
    """
    Trustee.ensure_frozen()


options.DEFAULT_NAMES += ('roles', 'permission_conditions',
                          'content_roles', 'content_permission_conditions',
                          'auto_modeladmin',
    )


class ContentLookupNotReady(ValueError):
    """A Trust→content lookup cannot be fully resolved until models are loaded."""


class InvalidContentFieldlookup(ValueError):
    """A Trust→content lookup is not a relation path to the registered model.

    Raised for scalar hops, missing relations, and paths whose terminal
    model is not the model passed to ``register_content``. Invalid
    registrations must raise rather than query.
    """


class PermissionConditionNotQueryable(ValueError):
    """Raised when a SQL list/create filter cannot compile a ``:condition``.

    Only a registered ``Expr`` compiles into the tree ``has_perm``
    evaluates. Callables stay object-only: ``permitted`` and
    ``filter_by_user_content_perm`` refuse them so they cannot silently
    over-grant the underlying permission.
    """


def permission_has_condition(perm):
    """True when ``perm`` is a string with a ``:condition`` suffix."""
    return isinstance(perm, str) and ':' in perm


def reject_queryable_condition(perm, api_name):
    if permission_has_condition(perm):
        raise PermissionConditionNotQueryable(
            '%s does not support permission conditions (%r). '
            'Create-under-trust filters Trust rows, not the content '
            'model the condition is registered on. Use the unconditioned '
            'permission for this queryset, or ContentQuerySet.permitted '
            'for V1 declarative conditions on content rows.' % (api_name, perm)
        )


def _condition_code(perm):
    if not isinstance(perm, str) or ':' not in perm:
        return ''
    if '.' in perm:
        try:
            return utils.parse_perm_code(perm)[3]
        except ValueError:
            pass
    return perm.split(':', 1)[1]


def legacy_permission_callbacks_allowed():
    """True only when ``TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`` is set.

    Read at call time so ``override_settings`` works. Missing or False
    means registered callables are a system-check error and runtime
    fail-closed (the callback is never invoked).
    """
    return bool(getattr(
        django_settings, 'TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS', False
    ))


class _ConditionRecord(object):
    """Registered condition: an ``Expr`` tree or a legacy callable.

    ``model`` is retained so a ``class_prepared`` registration can be
    validated by the system check after all apps have loaded.
    """

    __slots__ = ('expr', 'func', 'model')

    def __init__(self, expr=None, func=None, model=None):
        self.expr = expr
        self.func = func
        self.model = model


_u, _p, _o = condition_refs()


def compile_registered_condition_q(model, perm, user):
    """Compile a ``:condition`` suffix to ``Q``, or raise fail-closed.

    Unregistered codes raise ``AttributeError`` (same as ``has_perm``).
    Callables raise ``PermissionConditionNotQueryable`` without being
    invoked. Registered ``Expr`` trees that are not valid V1 fail closed.
    """
    cond = _condition_code(perm)
    record = Content.get_permission_condition_record(model, cond)
    if record is None:
        raise AttributeError(
            'Permission condition code "%s" is not associate with model "%s_%s"' % (
                cond, model._meta.app_label, model._meta.model_name
            )
        )
    if record.expr is None:
        raise PermissionConditionNotQueryable(
            'ContentQuerySet.permitted does not support permission '
            'condition %r on %s. Register an Expr from condition_refs() '
            'to compile a V1 declarative expression. Callables remain '
            'object-only via has_perm; this queryset API refuses them so '
            'the underlying grant cannot be returned without the '
            'condition.' % (perm, model._meta.label)
        )
    return compile_expression_q(
        record.expr, model, user, perm.split(':', 1)[0]
    )


def resolve_content_permission(model, perm):
    """Resolve ``perm`` on ``auth.Permission``.

    Accepts a permission instance, a codename (``read_category``), a bare
    action (``read`` → ``read_<model>``), or a dotted code
    (``app.read_category``).

    Queryset list APIs must reject or compile ``:condition`` suffixes
    before using this helper to resolve the grant. This helper may still
    strip a leftover ``:condition`` when resolving a grant/revoke target;
    it must not be used alone to filter lists.
    """
    if not supported_permission_contract():
        raise ValidationError(
            'TRUSTS_PERMISSION_MODEL must be auth.Permission. '
            'Silencing trusts.E005 does not enable a non-auth permission model.',
            code='unsupported_permission_model',
        )
    from django.contrib.auth.models import Permission
    if isinstance(perm, Permission):
        return perm

    app_label = model._meta.app_label
    model_name = model._meta.model_name
    perm = str(perm)
    if '.' in perm:
        try:
            applabel, modelname, action, _cond = utils.parse_perm_code(perm)
            perm = '%s_%s' % (action, modelname)
            app_label = applabel
            model_name = modelname
        except ValueError:
            app_label, perm = perm.split('.', 1)
    if ':' in perm:
        perm = perm.split(':', 1)[0]
    if not perm.endswith('_' + model_name) and '_' not in perm:
        perm = '%s_%s' % (perm, model_name)

    return Permission.objects.get_by_natural_key(
        perm, app_label.lower(), model_name,
    )


class ContentQuerySet(models.QuerySet):
    def permitted(self, perm, user):
        """Content the user may access via trustee or group local/global grants.

        SQL-filtered (paginate the returned QuerySet). Empty for inactive
        or anonymous principals. Group-derived access requires the
        TrustGroup local/global intersection; role-derived permissions
        participate only as the group's global ceiling. List results match
        ``has_perm`` on the supported relational paths. Superuser
        short-circuit is not duplicated (Django ModelBackend).

        A ``:condition`` suffix compiles only when the registered value
        is an ``Expr``. Filtering is ``base relational grant AND
        condition`` in SQL (paginate the returned QuerySet). Callables
        raise ``PermissionConditionNotQueryable`` so they cannot
        over-grant.

        The relational grant is the composed ``AuthorizationPath``
        predicate (same seam as object-level ``has_perm``). Anonymous
        principals stay empty; other non-requester values fail closed.
        """
        from trusts.zero.query import require_configured_requester

        condition_q = None
        if permission_has_condition(perm):
            condition_q = compile_registered_condition_q(self.model, perm, user)
        if user is None or getattr(user, 'is_anonymous', False):
            return self.none()
        require_configured_requester(user)
        if not is_active_principal(user):
            return self.none()
        if not supported_entity_contract() or not supported_permission_contract():
            return self.none()
        permission = resolve_content_permission(self.model, perm)
        path = compose_zero_path(self.model, permission)
        if path is None:
            return self.none()
        granted = path.grant_q(user, permission)
        if condition_q is None:
            return self.filter(granted).distinct()
        return self.filter(granted & condition_q).distinct()


class ContentManager(models.Manager):
    def get_queryset(self):
        return ContentQuerySet(self.model, using=self._db)

    def get_permission(self, perm):
        return resolve_content_permission(self.model, perm)

    def permitted(self, perm, user):
        return self.get_queryset().permitted(perm, user)


class TrustManager(ContentManager):
    def get_or_create_settlor_default(self, settlor, defaults={}, **kwargs):
        if 'trust' in kwargs:
            raise TypeError('"%s" are invalid keyword arguments' % 'trust')
        if settlor is None:
            raise ValueError('"settlor" must has a value.')
        if settlor.is_anonymous:
            # @TODO -- Handle anonymous settings
            raise ValueError('Anonymous is not yet supported.')

        try:
            return self.get(settlor=settlor, title='', **kwargs), False
        except Trust.DoesNotExist:
            params = {k: v for k, v in kwargs.items() if '__' not in k}
            params.update(defaults)
            params.update({'title': '', 'trust_id': ROOT_PK})
            trust = self.model(**params)
            trust.save()
            return trust, True

    def get_root(self):
        return self.get(pk=ROOT_PK)

    def filter_by_content(self, obj):
        if isinstance(obj, models.QuerySet):
            klass = obj.model
            is_qs = True
        else:
            klass = obj.__class__
            is_qs = False

        if not Content.is_content_model(klass):
            return self.none()

        prepare_context_registry()
        fieldlookup = Content.get_content_fieldlookup(klass)
        if not fieldlookup:
            return self.none()

        Content.require_valid_content_fieldlookup(klass, fieldlookup)

        filters = {}
        if is_qs:
            filters['%s__in' % fieldlookup] = obj
        else:
            filters[fieldlookup] = obj
        return self.filter(**filters).distinct()

    def filter_by_user_perm(self, user, **kwargs):
        if 'group__user' in kwargs:
            raise TypeError('"%s" are invalid keyword arguments' % 'group__user')

        if not supported_entity_contract():
            return self.none()
        parts = [Q(trustees__entity=user)]
        if supported_group_contract():
            parts.append(Q(groups__user=user))
        grant_q = parts[0]
        for part in parts[1:]:
            grant_q |= part
        return self.filter(grant_q, **kwargs)

    def filter_by_user_content_perm(self, user, content, perm_name, exclude_root=True, **kwargs):
        """Return Trusts under which ``user`` may exercise ``perm_name``.

        Create-under-trust semantics (verified, not inherited from #9):

        - A Trust is included when ``user`` has ``perm_name`` for ``content``
          via trustee grants or the TrustGroup local/global intersection
          **on that Trust row**. Role-derived permissions are the global
          ceiling, not a local assignment.
        - Parent-trust relations (``trust__trustees`` / ``trust__groups``)
          are not queried. ``#9`` did that accidentally.
        - Settlor identity is not a grant. Use ``has_perm(..., :own)`` for
          settlor-only operations (not this queryset).
        - ``fieldlookup`` from ``Content.get_content_fieldlookup`` is unused:
          this API filters Trust rows by grants, not by existing content
          rows. A Trust with no content yet can still be a create target.
        - Inactive / anonymous principals yield an empty queryset.
        - ``exclude_root=True`` drops ``TRUSTS_ROOT_PK`` (typical for
          organization content).
        - ``filter_by_user_perm`` is unchanged (membership/trustee, no
          permission name).
        - A ``:condition`` suffix raises ``PermissionConditionNotQueryable``.
          This API filters Trust rows, not content rows, so it does not
          compile V1 conditions (unlike ``ContentQuerySet.permitted``).
        """
        if 'group__user' in kwargs:
            raise TypeError('"%s" are invalid keyword arguments' % 'group__user')

        from trusts.zero.query import require_configured_requester

        reject_queryable_condition(
            perm_name, 'Trust.objects.filter_by_user_content_perm'
        )
        if user is None or getattr(user, 'is_anonymous', False):
            return self.none()
        require_configured_requester(user)
        if not is_active_principal(user):
            return self.none()
        if not supported_entity_contract() or not supported_permission_contract():
            return self.none()

        if not isinstance(content, type):
            content = content.__class__

        if not Content.is_content_model(content):
            return self.none()

        permission = resolve_content_permission(content, perm_name)
        qs = self.filter(trust_grant_q(user, permission), **kwargs)
        if exclude_root and ROOT_PK is not None:
            qs = qs.exclude(pk=ROOT_PK)
        return qs.distinct()


class ReadonlyFieldsMixin(object):
    def _readonly_attname(self, field_name):
        try:
            return self._meta.get_field(field_name).attname
        except Exception:
            return field_name

    def __init__(self, *args, **kwargs):
        super(ReadonlyFieldsMixin, self).__init__(*args, **kwargs)

        if hasattr(self, '_readonly_fields'):
            # Snapshot column values from __dict__. getattr() on a ForeignKey
            # in Django 6.1 fetch-mode would load the related object and recurse
            # on Trust.trust (the self-referential root).
            self._state.init_fields = {}
            for field in self._readonly_fields:
                attname = self._readonly_attname(field)
                if attname in self.__dict__:
                    self._state.init_fields[field] = self.__dict__[attname]

    def clean(self):
        super(ReadonlyFieldsMixin, self).clean()

        if hasattr(self, '_readonly_fields') and hasattr(self._state, 'init_fields'):
            for field in self._readonly_fields:
                if field in self._state.init_fields:
                    saved_value = self._state.init_fields[field]
                    attname = self._readonly_attname(field)
                    if saved_value != self.__dict__.get(attname, getattr(self, attname)):
                        raise ValidationError('Field "%s" is readonly.' % 'trust')


class Content(ReadonlyFieldsMixin, models.Model):
    trust = models.ForeignKey('trusts.Trust', related_name='%(app_label)s_%(class)s_content',
                default=ROOT_PK, null=False, blank=False, on_delete=models.CASCADE)
    objects = ContentManager()
    _contents = {}
    _conditions = {}
    _pending_related = []

    class Meta:
        abstract = True
        default_permissions = ('add', 'change', 'delete', 'read',)
        permission_conditions = ()
        auto_modeladmin = False

    def grant(self, perm, user):
        """Create a TrustUserPermission on this content's authorizing trust."""
        user = _require_configured_entity(user)
        permission = type(self).objects.get_permission(perm)
        TrustUserPermission.objects.get_or_create(
            trust=self.trust, entity=user, permission=permission
        )

    def revoke(self, perm, user):
        """Remove TrustUserPermission rows on this content's trust.

        ``perm=None`` removes every trustee grant for ``user`` on this trust.
        """
        user = _require_configured_entity(user)
        qs = TrustUserPermission.objects.filter(trust=self.trust, entity=user)
        if perm is not None:
            qs = qs.filter(permission=type(self).objects.get_permission(perm))
        qs.delete()

    @staticmethod
    def register_permission_condition(klass, cond_code, condition):
        """Register a ``:cond_code`` condition on ``klass``.

        Pass an ``Expr`` built from ``condition_refs()`` to opt into V1
        compile/evaluate. Pass a callable to keep the historical
        object-only ``has_perm`` path. Dispatch is by type: callables are
        never invoked with symbolic ``Ref`` arguments.

        Construction-time shape errors (bare non-predicate ``Expr``, a
        value that is neither ``Expr`` nor callable) still raise here.
        Model-aware semantic validation is reported by the registered
        Django system check as ``CheckMessage``s, not raised from this
        method, so ``SILENCED_SYSTEM_CHECKS`` can filter the diagnostic.
        """
        if isinstance(condition, Expr):
            if not is_predicate(condition):
                raise PermissionConditionError(
                    'Registered expression must be a V1 comparison '
                    '(==, != combined with & / |), not %r.' % (condition,)
                )
            record = _ConditionRecord(expr=condition, model=klass)
        elif callable(condition):
            record = _ConditionRecord(func=condition, model=klass)
        else:
            raise TypeError(
                'register_permission_condition expected an Expr or a '
                'callable, got %r.' % (type(condition).__name__,)
            )
        short_name = utils.get_short_model_name(klass)
        if short_name not in Content._conditions:
            Content._conditions[short_name] = {}
        Content._conditions[short_name][cond_code] = record

    @staticmethod
    def direct_content_fieldlookup(klass):
        """Return the Trust → Content-subclass ORM path.

        This is the reverse related name of ``Content.trust``
        (``%(app_label)s_%(class)s_content``). It is a composable lookup
        prefix, never ``None``.
        """
        return '%s_content' % utils.get_short_model_name_lower(klass).replace('.', '_')

    @staticmethod
    def _validate_content_fieldlookup(fieldlookup):
        if not isinstance(fieldlookup, str) or not fieldlookup:
            raise InvalidContentFieldlookup(
                'fieldlookup must be a non-empty string, not %r.' % (fieldlookup,)
            )
        parts = fieldlookup.split('__')
        if any(part == '' or part == 'None' for part in parts):
            raise InvalidContentFieldlookup(
                'fieldlookup %r is not a composable Trust-to-content path. '
                'Content.get_content_fieldlookup returns a resolved lookup '
                'for registered models. Use compose_content_fieldlookup for '
                'dependent hops; do not interpolate None.' % (fieldlookup,)
            )
        return fieldlookup

    @staticmethod
    def _trust_model():
        try:
            return apps.get_model('trusts', 'Trust', require_ready=False)
        except (LookupError, AppRegistryNotReady):
            raise ContentLookupNotReady('trusts.Trust')

    @staticmethod
    def _related_model(field):
        related = field.related_model
        if related is None:
            raise InvalidContentFieldlookup(
                'Relation %r has no related model.' % (field,)
            )
        if isinstance(related, str):
            try:
                related = apps.get_model(related, require_ready=False)
            except (LookupError, AppRegistryNotReady):
                raise ContentLookupNotReady(related)
        return related

    @staticmethod
    def resolve_trust_content_lookup(fieldlookup, missing_as_unready=False):
        """Walk ``fieldlookup`` from Trust and return the terminal model.

        Each hop must be a relation. A named scalar field always raises
        ``InvalidContentFieldlookup``. A missing hop raises
        ``ContentLookupNotReady`` when ``missing_as_unready`` is True or
        ``apps.models_ready`` is False (reverse relations may still be
        contributing during ``class_prepared``), and
        ``InvalidContentFieldlookup`` afterward.
        """
        fieldlookup = Content._validate_content_fieldlookup(fieldlookup)
        model = Content._trust_model()
        for part in fieldlookup.split('__'):
            try:
                field = model._meta.get_field(part)
            except FieldDoesNotExist:
                if missing_as_unready or not apps.models_ready:
                    raise ContentLookupNotReady(fieldlookup)
                raise InvalidContentFieldlookup(
                    'fieldlookup %r: %r is not a field or relation on %s.' % (
                        fieldlookup, part, model._meta.label,
                    )
                )
            if not field.is_relation:
                raise InvalidContentFieldlookup(
                    'fieldlookup %r: %r on %s is not a relation. '
                    'Dependent hops must be relations, not scalar fields.' % (
                        fieldlookup, part, model._meta.label,
                    )
                )
            model = Content._related_model(field)
        return model

    @staticmethod
    def _same_content_model(left, right):
        return left._meta.concrete_model == right._meta.concrete_model

    @staticmethod
    def validate_content_fieldlookup_target(klass, fieldlookup, defer_if_unready=False):
        """Ensure ``fieldlookup`` is a Trust-origin relation path to ``klass``.

        Returns True when validated. Returns False only when validation is
        deferred because the app registry is not ready. Runtime callers
        must use ``require_valid_content_fieldlookup``.
        """
        try:
            target = Content.resolve_trust_content_lookup(
                fieldlookup, missing_as_unready=defer_if_unready,
            )
        except (ContentLookupNotReady, AppRegistryNotReady):
            if defer_if_unready:
                return False
            raise InvalidContentFieldlookup(
                'fieldlookup %r cannot be resolved from Trust.' % (fieldlookup,)
            )
        if not Content._same_content_model(target, klass):
            raise InvalidContentFieldlookup(
                'fieldlookup %r resolves to %s, not registered model %s.' % (
                    fieldlookup, target._meta.label, klass._meta.label,
                )
            )
        return True

    @staticmethod
    def require_valid_content_fieldlookup(klass, fieldlookup):
        """Runtime check: raise rather than query an invalid registration."""
        Content.validate_content_fieldlookup_target(
            klass, fieldlookup, defer_if_unready=False,
        )

    @staticmethod
    def compose_content_fieldlookup(klass, related_name):
        """Join a registered content lookup with one reverse-relation hop.

        ``related_name`` is the related query name on the parent model
        (for example ``Receipt.image`` or ``ReceiptImage.meta``), not a
        field on Trust. Raises ``AttributeError`` if ``klass`` is not a
        registered content model so callers cannot build ``None__…`` paths.
        A named scalar field is always rejected, even before
        ``apps.models_ready``.
        """
        parent = Content.get_content_fieldlookup(klass)
        if parent is None:
            raise AttributeError(
                'Cannot compose a content fieldlookup for %r: the model is '
                'not registered. Register the parent with '
                'Content.register_content before adding a dependent hop.' % (
                    utils.get_short_model_name(klass),
                )
            )
        if not isinstance(related_name, str) or not related_name:
            raise ValueError('related_name must be a non-empty string.')
        if '__' in related_name:
            raise ValueError(
                'related_name must be a single hop, not %r. Call '
                'compose_content_fieldlookup once per reverse relation.' % (
                    related_name,
                )
            )
        parent_model = klass
        if isinstance(parent_model, str):
            try:
                parent_model = apps.get_model(parent_model)
            except (LookupError, ValueError):
                parent_model = None
        if parent_model is not None:
            try:
                hop = parent_model._meta.get_field(related_name)
            except FieldDoesNotExist:
                hop = None
            else:
                if not hop.is_relation:
                    raise InvalidContentFieldlookup(
                        'related_name %r on %s is not a relation. '
                        'Dependent hops must be relations, not scalar fields.' % (
                            related_name, parent_model._meta.label,
                        )
                    )
        composed = Content._validate_content_fieldlookup(
            '%s__%s' % (parent, related_name)
        )
        try:
            Content.resolve_trust_content_lookup(composed)
        except ContentLookupNotReady:
            return composed
        return composed

    @staticmethod
    def _through_from_trust_origin_lookup(klass, fieldlookup):
        """Invert a Trust-origin lookup to a resource-origin ``through`` path.

        ``fieldlookup`` walks Trust → … → ``klass``. The last hop is the
        reverse name on an already registered parent. The forward field
        on ``klass`` is the related-Context ``through`` value.
        """
        parts = fieldlookup.split('__')
        if len(parts) < 2:
            raise InvalidContentFieldlookup(
                'Related registration %r must include a hop from a '
                'registered parent to %s.' % (fieldlookup, klass._meta.label)
            )
        parent_lookup = '__'.join(parts[:-1])
        parent = Content.resolve_trust_content_lookup(parent_lookup)
        if not Context.is_registered(parent):
            raise InvalidContentFieldlookup(
                'fieldlookup %r: parent %s is not a registered Context '
                'resource. Register the parent before the dependent hop.' % (
                    fieldlookup, parent._meta.label,
                )
            )
        try:
            hop = parent._meta.get_field(parts[-1])
        except FieldDoesNotExist:
            raise InvalidContentFieldlookup(
                'fieldlookup %r: %r is not a relation on %s.' % (
                    fieldlookup, parts[-1], parent._meta.label,
                )
            )
        if hop.concrete:
            raise InvalidContentFieldlookup(
                'fieldlookup %r: %r on %s is not a reverse relation to %s.' % (
                    fieldlookup, parts[-1], parent._meta.label, klass._meta.label,
                )
            )
        return hop.remote_field.name

    @staticmethod
    def register_content(klass, fieldlookup=None):
        short_name = utils.get_short_model_name(klass)
        related_through = None
        if fieldlookup is None:
            content_model_fields = [f for f in klass._meta.fields if f.remote_field is not None and f.name == 'trust']
            if len(content_model_fields) != 1:
                raise AttributeError('Expect "trust" field in model %s.' % short_name)
            fieldlookup = Content.direct_content_fieldlookup(klass)
            # class_prepared fires before Trust has the reverse relation.
            defer = True
        else:
            fieldlookup = Content._validate_content_fieldlookup(fieldlookup)
            defer = not apps.models_ready
        Content.validate_content_fieldlookup_target(
            klass, fieldlookup, defer_if_unready=defer,
        )
        if fieldlookup == Content.direct_content_fieldlookup(klass):
            try:
                Context.register_direct(klass, scope_field='trust')
            except ContextRegistryFrozen:
                raise
            except ContextRegistrationError as exc:
                raise InvalidContentFieldlookup(str(exc)) from exc
        else:
            try:
                related_through = Content._through_from_trust_origin_lookup(
                    klass, fieldlookup,
                )
                Context.register_related(klass, through=related_through)
            except ContextRegistryFrozen:
                raise
            except (ContentLookupNotReady, AppRegistryNotReady):
                if not defer:
                    raise InvalidContentFieldlookup(
                        'fieldlookup %r cannot be resolved from Trust.' % (
                            fieldlookup,
                        )
                    )
            except ContextRegistrationError as exc:
                raise InvalidContentFieldlookup(str(exc)) from exc
        if Context.is_registered(klass):
            Content._contents[short_name] = Context.resource_path(klass)
        else:
            Content._contents[short_name] = fieldlookup

        if hasattr(klass._meta, 'permission_conditions'):
            for permcond, condition in klass._meta.permission_conditions:
                Content.register_permission_condition(klass, permcond, condition)

    @staticmethod
    def compatibility_context_error(model, fieldlookup):
        """Return a ``ContextRegistrationError`` if a deferred lookup is invalid.

        Used by sync (so ``prepare_context_registry`` does not abort
        ``manage.py check``) and by ``trusts.E006``. Does not execute
        getters or properties.
        """
        try:
            if (
                fieldlookup is None
                or fieldlookup == Content.direct_content_fieldlookup(model)
            ):
                return check_registration(model, KIND_DIRECT, 'trust')
            through = Content._through_from_trust_origin_lookup(
                model, fieldlookup,
            )
            return check_registration(model, KIND_RELATED, through)
        except (
            InvalidContentFieldlookup,
            ContentLookupNotReady,
            AppRegistryNotReady,
            ContextRegistrationError,
        ) as exc:
            if isinstance(exc, ContextRegistrationError):
                return exc
            return ContextRegistrationError(str(exc))

    @staticmethod
    def iter_unresolved_content_registrations():
        """Yield ``(model, fieldlookup)`` leftovers that have no Context adapter."""
        for short_name, fieldlookup in Content._contents.items():
            try:
                model = apps.get_model(short_name)
            except (LookupError, ValueError):
                continue
            if Context.is_registered(model):
                continue
            yield model, fieldlookup

    @staticmethod
    def sync_pending_context_registrations():
        """Register Content conveniences that deferred Context until ready.

        Registered as a ``Context`` finalizer so every freeze path
        (including ``filter_by_scope`` / ``resolves_to_scope``) mirrors
        ``_contents`` and deferred Junction related hops before the map
        becomes static. Invalid leftovers stay in ``_contents`` so
        ``trusts.E006`` can report them; they are not raised out of
        prepare.
        """
        if Context.is_frozen():
            return
        pending = list(Content._pending_related)
        contents = dict(Content._contents)
        Content._pending_related = []
        try:
            Content._sync_pending_context_registrations(pending)
        except Exception:
            Content._pending_related = pending
            Content._contents.clear()
            Content._contents.update(contents)
            raise

    @staticmethod
    def _sync_pending_context_registrations(pending):
        for model, through in pending:
            if Context.is_registered(model):
                continue
            try:
                Context.register_related(model, through=through)
            except (
                ContextRegistrationError,
                ContentLookupNotReady,
                AppRegistryNotReady,
            ):
                continue
            Content._contents[utils.get_short_model_name(model)] = (
                Context.resource_path(model)
            )
        for short_name, fieldlookup in list(Content._contents.items()):
            try:
                model = apps.get_model(short_name)
            except (LookupError, ValueError):
                continue
            if Context.is_registered(model):
                continue
            try:
                if (
                    fieldlookup is None
                    or fieldlookup == Content.direct_content_fieldlookup(model)
                ):
                    Context.register_direct(model, scope_field='trust')
                else:
                    through = Content._through_from_trust_origin_lookup(
                        model, fieldlookup,
                    )
                    Context.register_related(model, through=through)
            except (
                ContextRegistrationError,
                ContentLookupNotReady,
                AppRegistryNotReady,
                InvalidContentFieldlookup,
            ):
                continue
            Content._contents[short_name] = Context.resource_path(model)

    @staticmethod
    def is_content_model(klass):
        short_name = utils.get_short_model_name(klass)
        if short_name in Content._contents.keys():
            return True
        return False

    @staticmethod
    def get_content_fieldlookup(klass):
        """Return the Trust → content ORM lookup, or None if unregistered.

        Direct ``Content`` subclasses resolve to
        ``direct_content_fieldlookup`` (a composable string). Dependent
        models return the lookup they were registered with. Never returns
        a value that string-formats to ``None__…``.
        """
        short_name = utils.get_short_model_name(klass)
        if short_name not in Content._contents:
            return None
        fieldlookup = Content._contents[short_name]
        if fieldlookup is None:
            return Content.direct_content_fieldlookup(klass)
        return fieldlookup

    @staticmethod
    def is_content(obj):
        if isinstance(obj, models.QuerySet):
            klass = obj.model
            is_qs = True
        else:
            klass = obj.__class__
            is_qs = False
        return Content.is_content_model(klass)

    @staticmethod
    def get_permission_condition_record(klass, cond_code):
        short_name = utils.get_short_model_name(klass)
        if short_name in Content._conditions:
            if cond_code in Content._conditions[short_name]:
                return Content._conditions[short_name][cond_code]
        return None

    @staticmethod
    def get_permission_condition_func(klass, cond_code):
        record = Content.get_permission_condition_record(klass, cond_code)
        if record is None:
            return None
        return record.func

    @staticmethod
    def iter_permission_conditions():
        """Yield ``(model, cond_code, record)`` for every registration.

        Used by the system check after model loading. Identity comes from
        the record so ``class_prepared`` registrations remain validatable
        without importing extra application modules.
        """
        for codes in Content._conditions.values():
            for cond_code, record in codes.items():
                yield record.model, cond_code, record


Context.add_finalizer(Content.sync_pending_context_registrations)


class Trust(Content):
    title = models.CharField(max_length=40, null=False, blank=False, verbose_name=_('title'))
    settlor = models.ForeignKey(ENTITY_MODEL_NAME, default=DEFAULT_SETTLOR, null=ALLOW_NULL_SETTLOR, blank=False,
                on_delete=models.CASCADE)
    groups = models.ManyToManyField(GROUP_MODEL_NAME, related_name='trusts',
                through='trusts.TrustGroup',
                verbose_name=_('groups'),
                help_text=_('Groups associated with this trust. Association '
                            'alone grants nothing; a permission applies only '
                            'when it is in both the group\'s global ceiling '
                            'and this trust\'s local TrustGroup grants.'),
    )
    _readonly_fields = ('trust', 'settlor',)

    objects = TrustManager()

    def associate_group(self, group):
        """Create or return the TrustGroup association. Grants nothing."""
        return TrustGroup.objects.associate(self, group)

    @transaction.atomic
    def grant_group_permission(self, group, permission):
        """Enable ``permission`` locally on this trust for ``group``.

        Associates the group only after ``permission`` is accepted as
        inside the group's global ceiling. A rejected grant does not
        create a TrustGroup row.
        """
        permission = _resolve_configured_permission(permission)
        require_permissions_in_global_ceiling(group, [permission])
        return self.associate_group(group).grant_permission(permission)

    def revoke_group_permission(self, group, permission):
        """Remove a local TrustGroup grant. Association is left in place."""
        group = _require_configured_group(group)
        permission = _resolve_configured_permission(permission)
        try:
            tg = TrustGroup.objects.get(trust=self, group=group)
        except TrustGroup.DoesNotExist:
            return 0
        return tg.revoke_permission(permission)

    @transaction.atomic
    def set_group_permissions(self, group, permissions):
        """Replace this trust's local grants for ``group``.

        Associates the group only after every permission is accepted as
        inside the group's global ceiling. A rejected set does not create
        a TrustGroup row.
        """
        resolved = [_resolve_configured_permission(p) for p in permissions]
        require_permissions_in_global_ceiling(group, resolved)
        return self.associate_group(group).set_permissions(resolved)

    class Meta:
        unique_together = ('settlor', 'title')
        default_permissions = ('add', 'change', 'delete', 'read',)
        permission_conditions = (('own', _u == _o.settlor), )

    def __str__(self):
        settlor_str = ' of %s' % str(self.settlor) if self.settlor is not None else ''
        return 'Trust[%s]: "%s"' % (self.id, self.title)
Content.register_content(Trust)


class Role(TrusteeMixin, models.Model):
    name = models.CharField(max_length=80, null=False, blank=False, unique=True,
                help_text=_('The name of the role. Corresponds to the key of model\'s trusts option.'))
    groups = models.ManyToManyField(GROUP_MODEL_NAME, related_name='roles', blank=False,
                verbose_name=_('groups')
            )
    permissions = models.ManyToManyField(PERMISSION_MODEL_NAME,
                through='trusts.RolePermission',
                related_name='roles', blank=False,
                verbose_name=_('permissions')
            )

    class Meta:
        pass


class RolePermission(models.Model):
    role = models.ForeignKey('trusts.Role', related_name='rolepermissions', null=False, blank=False,
                on_delete=models.CASCADE)
    permission = models.ForeignKey(PERMISSION_MODEL_NAME, related_name='rolepermissions', null=False, blank=False,
                on_delete=models.CASCADE)
    managed = models.BooleanField(null=False, blank=False, default=False)

    class Meta:
        unique_together = ('role', 'permission')


class TrustUserPermission(models.Model):
    trust = models.ForeignKey('trusts.Trust', related_name='trustees', null=False, blank=False,
                on_delete=models.CASCADE)
    entity = models.ForeignKey(ENTITY_MODEL_NAME, related_name='trustpermissions', null=False, blank=False,
                on_delete=models.CASCADE)
    permission = models.ForeignKey(PERMISSION_MODEL_NAME, related_name='trustentities', null=False, blank=False,
                on_delete=models.CASCADE)

    class Meta:
        unique_together = ('trust', 'entity', 'permission')


def _require_supported_entity_contract():
    if not supported_entity_contract():
        raise ValidationError(
            'TRUSTS_ENTITY_MODEL must be AUTH_USER_MODEL. '
            'Silencing trusts.E003 does not enable a non-user entity.',
            code='unsupported_entity_model',
        )


def _require_supported_group_contract():
    if not supported_group_contract():
        raise ValidationError(
            'TRUSTS_GROUP_MODEL must be auth.Group. '
            'Silencing trusts.E004 does not enable a non-auth group model.',
            code='unsupported_group_model',
        )


def _require_supported_permission_contract():
    if not supported_permission_contract():
        raise ValidationError(
            'TRUSTS_PERMISSION_MODEL must be auth.Permission. '
            'Silencing trusts.E005 does not enable a non-auth permission model.',
            code='unsupported_permission_model',
        )


def _require_configured_entity(entity):
    from django.contrib.auth import get_user_model

    _require_supported_entity_contract()
    User = get_user_model()
    if isinstance(entity, User):
        return entity
    raise ValidationError(
        'Trustee grants require a %s instance.' % User.__name__,
        code='mismatched_entity_model',
    )


def _require_configured_group(group):
    from django.contrib.auth.models import Group

    _require_supported_group_contract()
    if isinstance(group, Group):
        return group
    raise ValidationError(
        'TrustGroup operations require a %s instance.' % Group.__name__,
        code='mismatched_group_model',
    )


def get_group_global_ceiling(group):
    """Permissions the group may exercise anywhere: Group.permissions ∪ roles.

    Role assignments are global ceiling only. They are not per-Trust grants.
    Uses Django ``auth.Group`` / ``auth.Permission``.
    """
    from django.contrib.auth.models import Permission

    group = _require_configured_group(group)
    _require_supported_permission_contract()
    return Permission.objects.filter(
        Q(group=group) | Q(roles__groups=group)
    ).distinct()


def permission_in_global_ceiling(group, permission):
    if group is None or permission is None:
        return False
    return get_group_global_ceiling(group).filter(pk=permission.pk).exists()


def require_permissions_in_global_ceiling(group, permissions):
    """Raise ``ValidationError`` if any permission is outside the ceiling.

    Call this before creating a TrustGroup so a rejected grant/set cannot
    leave an empty association behind.
    """
    for permission in permissions:
        if not permission_in_global_ceiling(group, permission):
            raise ValidationError(
                'Permission "%s" is outside the global ceiling of group "%s".' % (
                    permission, group
                ),
                code='local_grant_outside_ceiling',
            )


def _resolve_configured_permission(permission):
    """Accept ``auth.Permission`` or an integer PK.

    Other model instances fail closed. Primary keys are not taken from a
    mismatched instance. A silenced ``trusts.E005`` does not authorize a
    non-``auth.Permission`` setting.
    """
    from django.contrib.auth.models import Permission

    _require_supported_permission_contract()
    if isinstance(permission, Permission):
        return permission
    if isinstance(permission, models.Model):
        raise ValidationError(
            'Local TrustGroup grants require a %s instance.' % Permission.__name__,
            code='mismatched_permission_model',
        )
    if isinstance(permission, int) and not isinstance(permission, bool):
        try:
            return Permission.objects.get(pk=permission)
        except (Permission.DoesNotExist, TypeError, ValueError):
            pass
    raise ValidationError(
        'Local TrustGroup grants require a %s instance.' % Permission.__name__,
        code='mismatched_permission_model',
    )


class TrustGroupManager(models.Manager):
    def associate(self, trust, group):
        group = _require_configured_group(group)
        obj, _created = self.get_or_create(trust=trust, group=group)
        return obj


class TrustGroup(models.Model):
    """Through model for ``Trust.groups`` plus per-trust local grants.

    Association without local permissions grants nothing. Effective access
    still requires group membership and the group's global ceiling.
    """
    trust = models.ForeignKey('trusts.Trust', related_name='trustgroups', null=False, blank=False,
                on_delete=models.CASCADE)
    group = models.ForeignKey(GROUP_MODEL_NAME, related_name='trustgroups', null=False, blank=False,
                on_delete=models.CASCADE)
    permissions = models.ManyToManyField(PERMISSION_MODEL_NAME,
                through='trusts.TrustGroupPermission',
                related_name='granted_trustgroups', blank=True,
                verbose_name=_('permissions'))

    objects = TrustGroupManager()

    class Meta:
        db_table = 'trusts_trust_groups'
        unique_together = ('trust', 'group')

    def __str__(self):
        return 'TrustGroup[%s]: trust=%s group=%s' % (self.pk, self.trust_id, self.group_id)

    def grant_permission(self, permission):
        """Add a local grant. Rejected when the permission is outside the ceiling."""
        permission = _resolve_configured_permission(permission)
        require_permissions_in_global_ceiling(self.group, [permission])
        obj, _created = TrustGroupPermission.objects.get_or_create(
            trustgroup=self, permission=permission
        )
        return obj

    def revoke_permission(self, permission):
        permission = _resolve_configured_permission(permission)
        deleted, _ = TrustGroupPermission.objects.filter(
            trustgroup=self, permission=permission
        ).delete()
        return deleted

    @transaction.atomic
    def set_permissions(self, permissions):
        """Replace local grants. Every permission must be in the global ceiling."""
        resolved = [_resolve_configured_permission(p) for p in permissions]
        require_permissions_in_global_ceiling(self.group, resolved)
        wanted = {p.pk for p in resolved}
        existing = set(self.permissions.values_list('pk', flat=True))
        TrustGroupPermission.objects.filter(
            trustgroup=self, permission_id__in=(existing - wanted)
        ).delete()
        for permission in resolved:
            if permission.pk not in existing:
                TrustGroupPermission.objects.create(
                    trustgroup=self, permission=permission
                )
        return list(self.permissions.all())


class TrustGroupPermissionQuerySet(models.QuerySet):
    def bulk_create(self, objs, **kwargs):
        for obj in objs:
            obj.full_clean()
        return super(TrustGroupPermissionQuerySet, self).bulk_create(objs, **kwargs)


class TrustGroupPermission(models.Model):
    """Local permission tuple on a TrustGroup. Must stay inside the ceiling."""
    trustgroup = models.ForeignKey('trusts.TrustGroup', related_name='trustgrouppermissions',
                null=False, blank=False, on_delete=models.CASCADE)
    permission = models.ForeignKey(PERMISSION_MODEL_NAME, related_name='trustgrouppermissions',
                null=False, blank=False, on_delete=models.CASCADE)

    objects = TrustGroupPermissionQuerySet.as_manager()

    class Meta:
        unique_together = ('trustgroup', 'permission')

    def __str__(self):
        return 'TrustGroupPermission[%s]: trustgroup=%s permission=%s' % (
            self.pk, self.trustgroup_id, self.permission_id
        )

    def clean(self):
        super(TrustGroupPermission, self).clean()
        if not self.trustgroup_id or not self.permission_id:
            raise ValidationError(
                'TrustGroupPermission requires trustgroup and permission.',
                code='incomplete_trustgroup_permission',
            )
        if not permission_in_global_ceiling(self.trustgroup.group, self.permission):
            raise ValidationError(
                'Permission "%s" is outside the global ceiling of group "%s".' % (
                    self.permission, self.trustgroup.group
                ),
                code='local_grant_outside_ceiling',
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        super(TrustGroupPermission, self).save(*args, **kwargs)


def sync_default_trustee_adapters():
    """Register the 1.x requester, Group, and Role-ceiling adapters.

    Role inherits ``TrusteeMixin`` as declaration convenience. Its current
    behavior is the second Group constraint path (global ceiling), not a
    third OR-composed grant branch. No new grant table is introduced.
    """
    Trustee.configure(
        requester_model=ENTITY_MODEL_NAME,
        scope_model='trusts.Trust',
        operation_model=PERMISSION_MODEL_NAME,
    )
    Trustee.register(
        name=DIRECT_TRUSTEE,
        trustee_model=ENTITY_MODEL_NAME,
        grant_model=TrustUserPermission,
        trustee_path='entity',
        scope_path='trust',
        operation_path='permission',
        membership_path='',
    )
    Trustee.register(
        name=GROUP_TRUSTEE,
        trustee_model=GROUP_MODEL_NAME,
        grant_model=TrustGroupPermission,
        trustee_path='trustgroup__group',
        scope_path='trustgroup__trust',
        operation_path='permission',
        membership_path='user',
        constraint_paths=(
            'trustgroup__group__permissions',
            'trustgroup__group__roles__permissions',
        ),
    )


Trustee.add_finalizer(sync_default_trustee_adapters)


class Junction(ReadonlyFieldsMixin, models.Model):
    trust = models.ForeignKey('trusts.Trust', related_name='%(app_label)s_%(class)s',
                default=ROOT_PK, null=False, blank=False, on_delete=models.CASCADE)
    _readonly_fields = ('trust',)

    class Meta:
        abstract = True
        default_permissions = ()
        content_permission_conditions = ()
        unique_together = ('content', )

    @staticmethod
    def register_junction(klass, content_model=None):
        """Compatibility wrapper: register via the Context related form.

        The junction table is a direct Context (it owns ``trust``). The
        wrapped model is a related Context that reaches that table. The
        wrapped model remains the public content registration
        (``from trusts.zero.models import Junction`` keeps working; existing
        concrete junction tables are unchanged).
        """
        content = content_model or klass.get_content_model()
        if isinstance(content, str):
            try:
                content = apps.get_model(content, require_ready=False)
            except (LookupError, AppRegistryNotReady, ValueError):
                Content.register_content(content, klass.get_fieldlookup())
                Junction._register_junction_conditions(klass)
                return
        content_fields = [
            f for f in klass._meta.fields
            if f.remote_field is not None and f.name != 'trust'
        ]
        if len(content_fields) != 1:
            Content.register_content(content, klass.get_fieldlookup())
            Junction._register_junction_conditions(klass)
            return
        through = content_fields[0].related_query_name()
        if Junction._junction_identity_matches(klass, content, through):
            Junction._register_junction_conditions(klass)
            return
        Junction._raise_if_junction_conflicts(klass, content, through)
        if Context.is_frozen():
            raise ContextRegistryFrozen(
                'Context registry is frozen; cannot register %s.' % (
                    klass._meta.label,
                )
            )
        try:
            Context.register_direct(klass, scope_field='trust')
        except ContextRegistryFrozen:
            raise
        except ContextRegistrationError as exc:
            raise InvalidContentFieldlookup(str(exc)) from exc
        # Reverse accessors on the wrapped model are not visible during
        # class_prepared. Defer the related hop until models are ready.
        Content._pending_related.append((content, through))
        Content._contents[utils.get_short_model_name(content)] = (
            klass.get_fieldlookup()
        )
        Junction._register_junction_conditions(klass)

    @staticmethod
    def _junction_identity_matches(klass, content, through):
        """True when both adapters are exactly this junction declaration."""
        if not Context.is_registered(klass) or not Context.is_registered(content):
            return False
        direct = Context.get(klass)
        related = Context.get(content)
        return (
            direct.kind == KIND_DIRECT
            and direct.decl == 'trust'
            and related.kind == KIND_RELATED
            and related.decl == through
        )

    @staticmethod
    def _raise_if_junction_conflicts(klass, content, through):
        """Raise when an existing adapter is not this junction declaration."""
        if Context.is_registered(klass):
            existing = Context.get(klass)
            if existing.kind != KIND_DIRECT or existing.decl != 'trust':
                raise ContextRegistrationError(
                    '%s is already registered as %s %r; cannot register '
                    'as direct %r.' % (
                        klass._meta.label, existing.kind, existing.decl, 'trust',
                    )
                )
        if Context.is_registered(content):
            existing = Context.get(content)
            if existing.kind != KIND_RELATED or existing.decl != through:
                raise ContextRegistrationError(
                    '%s is already registered as %s %r; cannot register '
                    'as related %r via %s.' % (
                        content._meta.label, existing.kind, existing.decl,
                        through, klass._meta.label,
                    )
                )

    @staticmethod
    def _register_junction_conditions(klass):
        if hasattr(klass._meta, 'content_permission_conditions'):
            for permcond, condition in klass._meta.content_permission_conditions:
                Content.register_permission_condition(klass, permcond, condition)

    @classmethod
    def get_content_model(cls):
        # introspect for the content model class with the easy case
        content_model_fields = [f for f in cls._meta.fields if f.remote_field is not None and f.name != 'trust']
        if len(content_model_fields) == 1:
            return content_model_fields[0].remote_field.model
        raise NotImplementedError('Juctnion\'s classmethod "get_content_model" is not implemented.')

    @classmethod
    def get_fieldlookup(cls):
        return '%s__content' % utils.get_short_model_name_lower(cls).replace('.', '_')


def register_content_junction(sender, **kwargs):
    # Proxy subclasses share the concrete table and must not overwrite the
    # content/junction fieldlookup registered for that table.
    if sender._meta.proxy or sender._meta.abstract:
        return
    if Context.is_frozen():
        # Late class_prepared must not mutate the frozen map. Permission
        # conditions still register so Meta on ephemeral models remains
        # checkable. Explicit register_content / register_junction raise.
        if issubclass(sender, Junction):
            Junction._register_junction_conditions(sender)
        elif issubclass(sender, Content):
            if hasattr(sender._meta, 'permission_conditions'):
                for permcond, condition in sender._meta.permission_conditions:
                    Content.register_permission_condition(
                        sender, permcond, condition,
                    )
        return
    if issubclass(sender, Junction):
        Junction.register_junction(sender)
    elif issubclass(sender, Content):
        Content.register_content(sender)
signals.class_prepared.connect(register_content_junction)
