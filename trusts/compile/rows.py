"""Stateless registration checks shared by the recorder and the factory.

The recorder calls these with the new row and the rows already stored.
``RegistryFactory.register`` / ``register_delegation`` call the same
functions, so the rules exist once.
"""

from trusts.compile.factory import (
    build_delegation,
    build_public_registration,
    build_relation,
    validate_delegation,
    validate_named_filter,
    validate_principal,
)

__all__ = [
    'build_delegation',
    'build_public_registration',
    'build_relation',
    'validate_delegation',
    'validate_named_filter',
    'validate_principal',
]
