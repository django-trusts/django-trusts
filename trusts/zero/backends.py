from django.db.models import QuerySet
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission

from trusts.zero.models import (
    GROUP_TRUSTEE, Trust, Content, legacy_permission_callbacks_allowed,
    prepare_trustee_registry, resolve_content_permission,
)
from trusts.zero.query import (
    compose_zero_path,
    enabled_trustee_adapter_names,
    is_active_principal,
    queryset_is_zero_granted,
    require_configured_requester,
    row_is_zero_granted,
    scope_pks_from_resource,
)
from trusts.trustee import Trustee
from trusts.conditions import PermissionConditionError, evaluate_registered_expression
from trusts import (
    utils,
)
from trusts.zero import (
    supported_entity_contract,
    supported_group_contract,
    supported_permission_contract,
)


class TrustModelBackendMixin(object):
    @staticmethod
    def _get_perm_code(perm):
        return '%s.%s' % (
            perm.content_type.app_label, perm.codename
        )

    @staticmethod
    def _get_class(obj):
        if isinstance(obj, QuerySet):
            klass = obj.model
        else:
            klass = obj.__class__
        return klass

    def _scopes_for_content(self, obj):
        """Trust rows reached by the composed resource→scope hop.

        Zero public-content gate stays ``Content.is_content`` so Junction
        table rows do not enter ``User.has_perm``. Scope identity comes
        from ``AuthorizationPath.resource_to_scope``, not a Trust-origin
        reverse lookup.
        """
        from trusts.path import AuthorizationPathError

        if not Content.is_content(obj):
            return Trust.objects.none()
        klass = self._get_class(obj)
        fieldlookup = Content.get_content_fieldlookup(klass)
        if fieldlookup:
            Content.require_valid_content_fieldlookup(klass, fieldlookup)
        try:
            path = compose_zero_path(klass, None)
        except AuthorizationPathError:
            return Trust.objects.none()
        if path is None:
            return Trust.objects.none()
        pks = scope_pks_from_resource(obj, path)
        if not pks:
            return Trust.objects.none()
        return Trust.objects.filter(pk__in=pks)

    def get_group_permissions(self, user_obj, obj=None):
        """
        Returns a set of permission strings that this user has through his/her
        groups.
        """

        if user_obj.is_anonymous or obj is None:
            return super(TrustModelBackendMixin, self).get_group_permissions(user_obj, obj)

        if not _group_permission_queries_allowed():
            return set()

        require_configured_requester(user_obj)

        if Content.is_content(obj):
            trusts = self._scopes_for_content(obj)
            if not trusts.exists():
                return Permission.objects.none()
            prepare_trustee_registry()
            return Permission.objects.filter(
                Trustee.get(GROUP_TRUSTEE).operation_exists_q(user_obj, trusts)
            )

        return []

    def get_all_permissions(self, user_obj, obj=None):
        if user_obj.is_anonymous or obj is None:
            return super(TrustModelBackendMixin, self).get_all_permissions(user_obj, obj)

        if not supported_entity_contract() or not supported_permission_contract():
            return []

        require_configured_requester(user_obj)

        if not hasattr(user_obj, '_trust_perm_cache'):
            setattr(user_obj, '_trust_perm_cache', dict())
        perm_cache = getattr(user_obj, '_trust_perm_cache')

        trusts = list(self._scopes_for_content(obj))
        if len(trusts):
            all_perms = []
            names = enabled_trustee_adapter_names()
            for trust in trusts:
                if trust.pk not in perm_cache.keys():
                    if not names:
                        trust_perm = set()
                    else:
                        grant_q = Trustee.operation_grant_q(
                            user_obj, trust, names=names,
                        )
                        trust_perm = set([self._get_perm_code(p) for p in
                            Permission.objects.filter(grant_q)
                        ])

                    perm_cache[trust.pk] = trust_perm
                else:
                    trust_perm = perm_cache[trust.pk]

                all_perms.append(trust_perm)
            return set.intersection(*all_perms)
        return []

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

    def _object_perm_granted(self, user_obj, perm, obj):
        """Object-level grant via compose, not ``get_all_permissions``."""
        from django.contrib.contenttypes.models import ContentType
        from django.core.exceptions import ValidationError
        from trusts.context import Context
        from trusts.path import AuthorizationPathError

        if not supported_entity_contract() or not supported_permission_contract():
            return False
        if not is_active_principal(user_obj):
            return False
        if not Content.is_content(obj):
            return False
        klass = self._get_class(obj)
        fieldlookup = Content.get_content_fieldlookup(klass)
        if fieldlookup:
            Content.require_valid_content_fieldlookup(klass, fieldlookup)
        if not Context.is_registered(klass):
            return False
        try:
            permission = resolve_content_permission(klass, perm)
        except (Permission.DoesNotExist, ContentType.DoesNotExist, ValidationError, ValueError):
            return False
        try:
            if isinstance(obj, QuerySet):
                return queryset_is_zero_granted(obj, user_obj, permission)
            return row_is_zero_granted(obj, user_obj, permission)
        except AuthorizationPathError as exc:
            if 'not a registered' in str(exc):
                return False
            raise

    def has_perm(self, user_obj, permext, obj=None):
        applabel, modelname, action, cond = utils.parse_perm_code(permext)
        record = None
        if len(cond) != 0:
            record = Content.get_permission_condition_record(self._get_class(obj), cond)
            if record is None:
                raise AttributeError('Permission condition code "%s" is not associate with model "%s_%s"' % (cond, applabel, modelname))

        perm = '%s.%s_%s' % (applabel, action, modelname)
        if obj is None or getattr(user_obj, 'is_anonymous', False):
            # ``obj=None`` keeps Django's model-level path (including
            # PermissionsMixin's superuser shortcut on ``User.has_perm``).
            # Object-level checks do not: they use the composed grant, as
            # pre-PR ``get_all_permissions(obj)`` did.
            positive = super(TrustModelBackendMixin, self).has_perm(
                user_obj=user_obj, perm=perm, obj=obj,
            )
        else:
            require_configured_requester(user_obj)
            positive = self._object_perm_granted(user_obj, perm, obj)
        if positive:
            if len(cond) == 0:
                return True

            if self.permission_condition_met(record, user_obj, perm, obj):
                return True
        return False


def _group_permission_queries_allowed():
    return (
        supported_entity_contract()
        and supported_group_contract()
        and supported_permission_contract()
    )


class TrustModelBackend(TrustModelBackendMixin, ModelBackend):
    pass
