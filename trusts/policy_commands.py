"""Management commands for the authorization policy lockfile (#147 C3).

Core is not an installed Django app and does not ship
``trusts/management`` (#129). ``TrustsImplementationConfig.ready`` calls
:func:`install_policy_commands` so ``trusts_policy_generate`` and
``trusts_policy_check`` are discoverable after ``django.setup()``.

Neither command calls ``ensure_policy_lockfile_verified`` or returns an
authorization result. Both stay at zero SQL.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from trusts.core import TrustsConfigurationError
from trusts.policy_lock import (
    PolicyLockDrift,
    check_policy_lockfile,
    generate_policy_lockfile,
)

_POLICY_COMMAND_APP = 'trusts.policy_commands'
_INSTALLED = False


class GenerateCommand(BaseCommand):
    """Write the canonical ``trusts-policy.lock.json`` document."""

    help = (
        'Create or replace the canonical authorization policy lockfile. '
        'Uses BASE_DIR / trusts-policy.lock.json unless '
        'TRUSTS_POLICY_LOCKFILE or --lockfile sets an absolute path. '
        'Does not search the process working directory.'
    )
    requires_system_checks = []
    requires_migrations_checks = False

    def add_arguments(self, parser):
        parser.add_argument(
            '--lockfile',
            default=None,
            help=(
                'Absolute lockfile path. Overrides TRUSTS_POLICY_LOCKFILE. '
                'Relative paths are rejected and are not resolved against '
                'the process working directory.'
            ),
        )

    def handle(self, *args, **options):
        try:
            path = generate_policy_lockfile(override=options.get('lockfile'))
        except TrustsConfigurationError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write('wrote %s' % path)


class CheckCommand(BaseCommand):
    """Compare the live policy to the lockfile, or report inactive."""

    help = (
        'Compare the live authorization policy to the lockfile. '
        'Conventional absence is inactive. An explicit missing path, a '
        'malformed document, and semantic drift fail closed. '
        'Does not search the process working directory.'
    )
    requires_system_checks = []
    requires_migrations_checks = False

    def add_arguments(self, parser):
        parser.add_argument(
            '--lockfile',
            default=None,
            help=(
                'Absolute lockfile path. Overrides TRUSTS_POLICY_LOCKFILE. '
                'Relative paths are rejected and are not resolved against '
                'the process working directory.'
            ),
        )

    def handle(self, *args, **options):
        try:
            result = check_policy_lockfile(override=options.get('lockfile'))
        except PolicyLockDrift as exc:
            self.stdout.write(exc.diff, ending='')
            if options.get('verbosity', 1) >= 2 and exc.raw_diff:
                self.stdout.write(exc.raw_diff, ending='')
            raise CommandError('Policy lock drift: %s' % exc.path) from exc
        except TrustsConfigurationError as exc:
            raise CommandError(str(exc)) from exc
        if result.status == 'inactive':
            self.stdout.write('policy lock inactive: %s' % result.path)
            return
        self.stdout.write('policy lock ok: %s' % result.path)


_POLICY_COMMANDS = {
    'trusts_policy_generate': GenerateCommand,
    'trusts_policy_check': CheckCommand,
}


def install_policy_commands():
    """Register the two policy commands on Django's command loader.

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
