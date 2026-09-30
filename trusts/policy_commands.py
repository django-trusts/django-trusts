"""Management command for the authorization policy SQL document.

Core is not an installed Django app and does not ship
``trusts/management``. ``TrustsImplementationConfig.ready`` calls
:func:`install_policy_commands` so ``trusts_policy_sql`` is
discoverable after ``django.setup()``.

The command prints the schema-1 document and, with ``--lock``, writes
those same bytes. It does not authorize and it does not execute the
exported statements.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from trusts.core import TrustsConfigurationError
from trusts.policy_lock import (
    render_policy_sql_bytes,
    resolve_policy_database,
    write_policy_lock,
)

_POLICY_COMMAND_APP = 'trusts.policy_commands'
_INSTALLED = False


class PolicySqlCommand(BaseCommand):
    """Print the policy SQL document. ``--lock`` writes the same bytes."""

    help = (
        'Print the authorization policy SQL document for the database '
        'alias selected by TRUSTS_POLICY_DATABASE, or Django\'s default '
        'alias when that setting is unset. --database selects another '
        'configured alias for this process only. --lock writes the same '
        'bytes to the lockfile path.'
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


_POLICY_COMMANDS = {
    'trusts_policy_sql': PolicySqlCommand,
}


def install_policy_commands():
    """Register ``trusts_policy_sql`` on Django's command loader.

    Idempotent. Does not override a command of the same name already
    provided by an installed application. Safe to call from every
    implementation ``ready()``.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    import django.core.management as management

    original_get = management.get_commands
    original_load = management.load_command_class

    def get_commands():
        commands = original_get()
        for name in _POLICY_COMMANDS:
            commands.setdefault(name, _POLICY_COMMAND_APP)
        return commands

    def cache_clear():
        original_get.cache_clear()

    get_commands.cache_clear = cache_clear

    def load_command_class(app_name, name):
        command_cls = _POLICY_COMMANDS.get(name)
        if app_name == _POLICY_COMMAND_APP and command_cls is not None:
            return command_cls()
        return original_load(app_name, name)

    management.get_commands = get_commands
    management.load_command_class = load_command_class
    _INSTALLED = True
