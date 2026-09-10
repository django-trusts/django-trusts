from django.apps import apps as django_apps
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import signals, Q, options
from django.conf import settings as django_settings
from django.utils.translation import gettext_lazy as _

from trusts import ENTITY_MODEL_NAME, PERMISSION_MODEL_NAME, GROUP_MODEL_NAME, \
                    DEFAULT_SETTLOR, ALLOW_NULL_SETTLOR, ROOT_PK, \
                    get_permission_model, utils
from trusts.query import (
    group_local_grant_exists,
    is_active_principal,
    trust_grant_q,
)
from trusts.conditions import (
    Expr,
    PermissionConditionError,
    condition_refs,
    compile_expression_q,
    is_predicate,
)


options.DEFAULT_NAMES += ('roles', 'permission_conditions',
                          'content_roles', 'content_permission_conditions',
                          'auto_modeladmin',
    )


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
    """Resolve ``perm`` via ``TRUSTS_PERMISSION_MODEL``, not hardcoded auth.Permission.

    Accepts a permission instance, a codename (``read_category``), a bare
    action (``read`` → ``read_<model>``), or a dotted code
    (``app.read_category``).

    Queryset list APIs must reject or compile ``:condition`` suffixes
    before using this helper to resolve the grant. This helper may still
    strip a leftover ``:condition`` when resolving a grant/revoke target;
    it must not be used alone to filter lists.
    """
    Permission = get_permission_model()
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

    manager = Permission.objects
    if hasattr(manager, 'get_by_natural_key'):
        return manager.get_by_natural_key(perm, app_label.lower(), model_name)
    return manager.get(
        codename=perm,
        content_type__app_label=app_label.lower(),
        content_type__model=model_name,
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
        """
        condition_q = None
        if permission_has_condition(perm):
            condition_q = compile_registered_condition_q(self.model, perm, user)
        if not is_active_principal(user):
            return self.none()
        permission = resolve_content_permission(self.model, perm)
        # Child H: registered Category trustee half from the package registry.
        # Group stays in this reader and is OR-ed on the original candidate
        # queryset. Do not filter_authorized(...) then OR group — filtered-out
        # group-only rows cannot be restored. Unregistered models keep the
        # old trust_grant_q path.
        registry = django_apps.get_app_config('trusts').registry
        plan = registry.plan_for(self, user=user, permission=permission)
        if plan.records:
            trustee = plan.content_exists(user=user, permission=permission)
            granted = Q(trustee) | Q(
                group_local_grant_exists(user, permission, 'trust_id')
            )
        else:
            granted = trust_grant_q(user, permission, trust_fk='trust')
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

        if Content.is_content_model(klass):
            fieldlookup = Content.get_content_fieldlookup(klass)
            if fieldlookup is None:
                fieldlookup = '%s_content' % utils.get_short_model_name_lower(klass).replace('.', '_')

            filters = {}
            if is_qs:
                filters['%s__in' % fieldlookup] = obj
            else:
                filters[fieldlookup] = obj
            return self.filter(**filters).distinct()

        return self.none()

    def filter_by_user_perm(self, user, **kwargs):
        if 'group__user' in kwargs:
            raise TypeError('"%s" are invalid keyword arguments' % 'group__user')

        return self.filter(Q(groups__user=user) | Q(trustees__entity=user), **kwargs)

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

        reject_queryable_condition(
            perm_name, 'Trust.objects.filter_by_user_content_perm'
        )
        if not is_active_principal(user):
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

    class Meta:
        abstract = True
        default_permissions = ('add', 'change', 'delete', 'read',)
        permission_conditions = ()
        auto_modeladmin = False

    def grant(self, perm, user):
        """Create a TrustUserPermission on this content's authorizing trust."""
        permission = type(self).objects.get_permission(perm)
        TrustUserPermission.objects.get_or_create(
            trust=self.trust, entity=user, permission=permission
        )

    def revoke(self, perm, user):
        """Remove TrustUserPermission rows on this content's trust.

        ``perm=None`` removes every trustee grant for ``user`` on this trust.
        """
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
    def register_content(klass, fieldlookup=None):
        short_name = utils.get_short_model_name(klass)
        if fieldlookup is None:
            content_model_fields = [f for f in klass._meta.fields if f.remote_field is not None and f.name == 'trust']
            if len(content_model_fields) != 1:
                raise AttributeError('Expect "trust" field in model %s.' % short_name)
        Content._contents[short_name] = fieldlookup

        if hasattr(klass._meta, 'permission_conditions'):
            for permcond, condition in klass._meta.permission_conditions:
                Content.register_permission_condition(klass, permcond, condition)

    @staticmethod
    def is_content_model(klass):
        short_name = utils.get_short_model_name(klass)
        if short_name in Content._contents.keys():
            return True
        return False

    @staticmethod
    def get_content_fieldlookup(klass):
        short_name = utils.get_short_model_name(klass)
        if short_name in Content._contents.keys():
            return Content._contents[short_name]
        return None

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


class Role(models.Model):
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


def get_group_global_ceiling(group):
    """Permissions the group may exercise anywhere: Group.permissions ∪ roles.

    Role assignments are global ceiling only. They are not per-Trust grants.
    Custom group models must expose a ``permissions`` M2M to
    ``TRUSTS_PERMISSION_MODEL`` and a ``user`` related-query name for
    membership (the same conventions as ``auth.Group``).
    """
    Permission = get_permission_model()
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
    Permission = get_permission_model()
    if isinstance(permission, Permission):
        return permission
    if isinstance(permission, int) or getattr(permission, 'pk', None) is not None \
            and not isinstance(permission, (str, bytes)):
        try:
            return Permission.objects.get(pk=getattr(permission, 'pk', permission))
        except (Permission.DoesNotExist, TypeError, ValueError):
            pass
    raise ValidationError(
        'Local TrustGroup grants require a %s instance.' % Permission.__name__
    )


class TrustGroupManager(models.Manager):
    def associate(self, trust, group):
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
        Content.register_content(klass.get_content_model(), klass.get_fieldlookup())
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
    if issubclass(sender, Junction):
        Junction.register_junction(sender)
    elif issubclass(sender, Content):
        Content.register_content(sender)
signals.class_prepared.connect(register_content_junction)
