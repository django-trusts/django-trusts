from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import signals, Q, options
from django.utils.translation import gettext_lazy as _

from trusts import ENTITY_MODEL_NAME, PERMISSION_MODEL_NAME, GROUP_MODEL_NAME, \
                    DEFAULT_SETTLOR, ALLOW_NULL_SETTLOR, ROOT_PK, \
                    get_permission_model, utils
from trusts.query import is_active_principal, trust_grant_q


options.DEFAULT_NAMES += ('roles', 'permission_conditions',
                          'content_roles', 'content_permission_conditions',
                          'auto_modeladmin',
    )


class PermissionConditionNotQueryable(ValueError):
    """Raised when a SQL list/create filter is given a ``:condition`` suffix.

    Conditions (``:own`` and custom ``permission_conditions``) are Python
    predicates evaluated by ``User.has_perm``. They are not compiled into
    SQL. ``permitted`` and ``filter_by_user_content_perm`` refuse them so
    they cannot silently over-grant the underlying permission.
    """


def permission_has_condition(perm):
    """True when ``perm`` is a string with a ``:condition`` suffix."""
    return isinstance(perm, str) and ':' in perm


def reject_queryable_condition(perm, api_name):
    if permission_has_condition(perm):
        raise PermissionConditionNotQueryable(
            '%s does not support permission conditions (%r). '
            'Conditions are evaluated by has_perm, not SQL. Use the '
            'unconditioned permission for the queryset and apply '
            'has_perm(..., obj) per object until conditions are '
            'SQL-queryable.' % (api_name, perm)
        )


def resolve_content_permission(model, perm):
    """Resolve ``perm`` via ``TRUSTS_PERMISSION_MODEL``, not hardcoded auth.Permission.

    Accepts a permission instance, a codename (``read_category``), a bare
    action (``read`` → ``read_<model>``), or a dotted code
    (``app.read_category``).

    Queryset APIs must call ``reject_queryable_condition`` first. This
    helper may still strip a leftover ``:condition`` when resolving a
    grant/revoke target; it must not be used alone to filter lists.
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
        """Content the user may access via trustee, group, or role grants.

        SQL-filtered (paginate the returned QuerySet). Empty for inactive
        or anonymous principals. Role-derived grants are included so list
        results match ``has_perm`` on the supported relational paths.
        Superuser short-circuit is not duplicated (Django ModelBackend).

        A ``:condition`` suffix raises ``PermissionConditionNotQueryable``.
        Conditions are not SQL-queryable; refusing them avoids over-granting
        the underlying permission.
        """
        reject_queryable_condition(perm, 'ContentQuerySet.permitted')
        if not is_active_principal(user):
            return self.none()
        permission = resolve_content_permission(self.model, perm)
        return self.filter(trust_grant_q(user, permission, trust_fk='trust')).distinct()


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
          via trustee, ``Group.permissions``, or role grants **on that Trust
          row**.
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
        - A ``:condition`` suffix raises ``PermissionConditionNotQueryable``
          (same fail-closed rule as ``permitted``).
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
    def register_permission_condition(klass, cond_code, func):
        short_name = utils.get_short_model_name(klass)
        if short_name not in Content._conditions:
            Content._conditions[short_name] = {}
        Content._conditions[short_name][cond_code] = func

    @staticmethod
    def register_content(klass, fieldlookup=None):
        short_name = utils.get_short_model_name(klass)
        if fieldlookup is None:
            content_model_fields = [f for f in klass._meta.fields if f.remote_field is not None and f.name == 'trust']
            if len(content_model_fields) != 1:
                raise AttributeError('Expect "trust" field in model %s.' % short_name)
        Content._contents[short_name] = fieldlookup

        if hasattr(klass._meta, 'permission_conditions'):
            for permcond, func in klass._meta.permission_conditions:
                Content.register_permission_condition(klass, permcond, func)

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
    def get_permission_condition_func(klass, cond_code):
        short_name = utils.get_short_model_name(klass)
        if short_name in Content._conditions:
            if cond_code in Content._conditions[short_name]:
                return Content._conditions[short_name][cond_code]
        return None


class Trust(Content):
    title = models.CharField(max_length=40, null=False, blank=False, verbose_name=_('title'))
    settlor = models.ForeignKey(ENTITY_MODEL_NAME, default=DEFAULT_SETTLOR, null=ALLOW_NULL_SETTLOR, blank=False,
                on_delete=models.CASCADE)
    groups = models.ManyToManyField(GROUP_MODEL_NAME, related_name='trusts',
                verbose_name=_('groups'),
                help_text=_('The groups this trust grants permissions to. A user will'
                            'get all permissions granted to each of his/her group.'),
    )
    _readonly_fields = ('trust', 'settlor',)

    objects = TrustManager()

    class Meta:
        unique_together = ('settlor', 'title')
        default_permissions = ('add', 'change', 'delete', 'read',)
        permission_conditions = (('own', lambda u, p, o: u == o.settlor), )

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
            for permcond, func in klass._meta.content_permission_conditions:
                Content.register_permission_condition(klass, permcond, func)

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
