"""Populate empty TrustGroup local grants from the current global ceiling.

Schema migration 0002 preserves Trust.groups associations but does not
infer authorization policy. Operators who deliberately want the former
implicit group-derived Trust access can run this command.

Default mode is ``--dry-run`` (report tuples, write nothing). Pass
``--apply`` to insert ``TrustGroupPermission`` rows.
"""

from django.core.management.base import BaseCommand, CommandError

from trusts.zero.models import TrustGroup, TrustGroupPermission, get_group_global_ceiling


def _perm_code(permission):
    content_type = getattr(permission, 'content_type', None)
    app_label = getattr(content_type, 'app_label', None)
    codename = getattr(permission, 'codename', None)
    if app_label and codename:
        return '%s.%s' % (app_label, codename)
    return str(permission)


def iter_grandfather_tuples():
    """Yield (trust, group, permission) for missing local ceiling copies."""
    for trustgroup in TrustGroup.objects.select_related('trust', 'group').order_by('pk'):
        ceiling = get_group_global_ceiling(trustgroup.group)
        existing = set(
            TrustGroupPermission.objects.filter(
                trustgroup=trustgroup
            ).values_list('permission_id', flat=True)
        )
        for permission in ceiling.order_by('pk'):
            if permission.pk in existing:
                continue
            yield trustgroup.trust, trustgroup.group, permission


def format_tuple(trust, group, permission):
    return (
        'trust_id=%s group_id=%s permission_id=%s %s (trust=%r group=%r)' % (
            trust.pk,
            group.pk,
            permission.pk,
            _perm_code(permission),
            getattr(trust, 'title', trust.pk),
            getattr(group, 'name', group.pk),
        )
    )


class Command(BaseCommand):
    help = (
        'Copy each TrustGroup\'s current global ceiling into local '
        'TrustGroupPermission rows. Default is --dry-run (no writes).'
    )

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument(
            '--dry-run',
            action='store_true',
            help='Report Trust/group/permission tuples without writing (default).',
        )
        mode.add_argument(
            '--apply',
            action='store_true',
            help='Insert the reported TrustGroupPermission rows.',
        )

    def handle(self, *args, **options):
        apply = bool(options.get('apply'))
        dry_run = (not apply) or bool(options.get('dry_run'))
        if apply and options.get('dry_run'):
            raise CommandError('Pass only one of --dry-run or --apply.')

        tuples = list(iter_grandfather_tuples())
        mode_label = 'dry-run' if (dry_run and not apply) else 'apply'
        self.stdout.write(
            'grandfather_trust_group_permissions mode=%s tuples=%s' % (
                mode_label, len(tuples)
            )
        )
        for trust, group, permission in tuples:
            self.stdout.write(format_tuple(trust, group, permission))
            if apply:
                TrustGroupPermission.objects.get_or_create(
                    trustgroup=TrustGroup.objects.get(trust=trust, group=group),
                    permission=permission,
                )
        if not apply:
            self.stdout.write(
                'No rows written. Re-run with --apply to insert these tuples.'
            )
        else:
            self.stdout.write('Inserted %s TrustGroupPermission row(s).' % len(tuples))
