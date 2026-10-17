"""Re-export of the policy SQL management command.

The implementation lives in ``trusts.inspect.commands``. This module
remains so existing imports such as ``from trusts.policy_commands
import install_policy_commands`` keep working. The Django command
loader key stays ``trusts.policy_commands``.
"""

from trusts.inspect.commands import PolicySqlCommand, install_policy_commands

__all__ = []
