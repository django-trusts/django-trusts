"""Management command for the authorization policy SQL document.

A host app gets the command by adding
``management/commands/trusts_policy_sql.py`` containing
``from trusts.inspect.commands import PolicySqlCommand as Command``.

The command prints the schema-1 canonical YAML document and, with
``--lock``, writes those same bytes. It does not authorize and it does
not execute the exported statements.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from trusts.errors import TrustsConfigurationError
from trusts.inspect.snapshot import (
    render_policy_sql_bytes,
    resolve_policy_database,
    write_policy_lock,
)

__all__ = ['PolicySqlCommand']


class PolicySqlCommand(BaseCommand):
    """Print the policy SQL document. ``--lock`` writes the same bytes."""

    help = (
        'Print the canonical YAML authorization policy for the database '
        'alias selected by TRUSTS_POLICY_DATABASE, or Django\'s default '
        'alias when that setting is unset. Each content lists its trust '
        'legs and the compiled SQL for permitted, has_perm, '
        'get_all_permissions, and get_permitted_users. --database selects '
        'another configured alias for this process only. --lock writes '
        'the same bytes to the lockfile path.'
    )
    requires_system_checks = []
    requires_migrations_checks = False

    def add_arguments(self, parser):
        parser.add_argument(
            '--database',
            default=None,
            help=(
                'Database alias for this process. Overrides '
                'TRUSTS_POLICY_DATABASE and is not written into the file.'
            ),
        )
        parser.add_argument(
            '--lock',
            action='store_true',
            help=(
                'Write the same bytes to the lockfile path. Does not '
                'create missing parent directories.'
            ),
        )

    def handle(self, *args, **options):
        try:
            alias = resolve_policy_database(options.get('database'))
            payload = render_policy_sql_bytes(alias=alias)
            if options.get('lock'):
                write_policy_lock(payload)
        except TrustsConfigurationError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(payload.decode('utf-8'), ending='')
