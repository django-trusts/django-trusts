from django.core.management.base import BaseCommand
from django.db import DEFAULT_DB_ALIAS, router
from django.db.models import Q


def _process_roles(Permission, model_roles, content_klass, roles, using):
    for rolename, perm_names in roles:
        if rolename not in model_roles:
            model_roles[rolename] = set()

        # Force looking up the content types in the current database
        # before creating foreign keys to them.
        from django.contrib.contenttypes.models import ContentType
        ctype = ContentType.objects.db_manager(using).get_for_model(content_klass)

        model_roles[rolename].update([Permission.objects.get(content_type=ctype, codename=perm_name)
                for perm_name in perm_names
        ])


def update_roles_permissions(Role, Permission, RolePermission, app_config, verbosity=2, interactive=True, using=DEFAULT_DB_ALIAS, **kwargs):
    if not router.allow_migrate_model(using, Role):
        return

    try:
        Role = app_config.get_model('trusts', 'Role')
    except LookupError:
        return

    # This will hold the roles we're looking for as
    # (rolename (permissions))
    model_roles = {}
    for klass in app_config.get_models():
        if hasattr(klass._meta, 'roles'):
            _process_roles(Permission, model_roles, klass, klass._meta.roles, using)
        elif hasattr(klass._meta, 'content_roles'):
            if hasattr(klass, 'get_content_model'):
                content_klass = klass.get_content_model()
                _process_roles(Permission, model_roles, content_klass, klass._meta.content_roles, using)

    # Find all the Roles and its Permission
    db_roles = {}
    for r in Role.objects.using(using).all():
        db_roles[r.name] = set(r.permissions.all())

    # Get all the diff between sets
    model_rolenames = set(model_roles.keys())
    db_rolenames = set(db_roles.keys())
    added_rolenames = model_rolenames - db_rolenames
    deleted_rolenames = db_rolenames - model_rolenames
    existing_rolenames = model_rolenames.intersection(db_rolenames)

    # Prepare rolepermissions for bulk op at the end
    bulk_add_rolepermissions = []
    q_del_rolepermissions = []
    deleted_role_ids = []
    # Process added roles
    for rolename in added_rolenames:
        r = Role(name=rolename)
        r.save()
        for p in model_roles[rolename]:
            bulk_add_rolepermissions.append(RolePermission(managed=True, permission=p, role=r))

    # Process existing roles
    for rolename in existing_rolenames:
        r = Role.objects.get(name=rolename)
        db_permissions = db_roles[rolename]
        model_permissions = model_roles[rolename]

        added_permissions = set(model_permissions) - set(db_permissions)
        for p in added_permissions:
            bulk_add_rolepermissions.append(RolePermission(managed=True, permission=p, role=r))

        deleted_permissions = set(db_permissions) - set(model_permissions)
        if len(deleted_permissions):
            q_del_rolepermissions.append((r, Q(managed=True, role=r, permission__in=deleted_permissions)))

    # Process deleted roles
    for rolename in deleted_rolenames:
        r = Role.objects.get(name=rolename)
        q_del_rolepermissions.append((r, Q(managed=True, role=r)))
        deleted_role_ids.append(r.pk)

    # Create the added role permissions
    RolePermission.objects.using(using).bulk_create(bulk_add_rolepermissions)
    if verbosity >= 2:
        for rolepermission in bulk_add_rolepermissions:
            print('Adding role(%s).rolepermission "%s"' % (rolepermission.role.name, rolepermission))

    # Remove the deleted role permissions
    for r, q in q_del_rolepermissions:
        qs = RolePermission.objects.filter(q)
        if verbosity >= 2:
            if qs.count() > 0:
                for rolepermission in qs.all():
                    print('Removing role(%s).rolepermission "%s"' % (rolepermission.role.name, rolepermission))
        qs.delete()

    # Remove the deleted role
    qs = Role.objects.filter(pk__in=deleted_role_ids, permissions__isnull=True)
    if verbosity >= 2:
        if qs.count() > 0:
            for role in qs.all():
                print('Removing role "%s"' % (role.name))
    qs.delete()


class Command(BaseCommand):
    help = 'Create Role objects linking to permission defined in models\'s meta class.'

    def handle(self, **options):
        self.verbosity = int(options.get('verbosity', 1))

        if 'apps' in options:
            apps = options['apps']
            Permission = apps.get_model('auth', 'Permission')
            Role = apps.get_model('trusts', 'role')
            RolePermission = apps.get_model('trusts', 'rolepermission')
            app_config = options['apps']
        else:
            from trusts.zero.models import Role, RolePermission
            from django.contrib.auth.models import Permission
            from django.apps import apps as app_config

        update_roles_permissions(Role, Permission, RolePermission, app_config, **options)
