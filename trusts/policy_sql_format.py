"""Re-export of the policy SQL line breaker.

The implementation lives in ``trusts.inspect.format``. This module
remains so existing imports such as ``from trusts.policy_sql_format
import _format_policy_sql`` keep working.
"""

from trusts.inspect.format import (
    _emit,
    _format_policy_sql,
    _tokenize_policy_sql,
)

__all__ = []
