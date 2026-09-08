"""Isolated custom AUTH_USER_MODEL for the issue #26 custom-user install.

Selected via AUTH_USER_MODEL / TRUSTS_ENTITY_MODEL **before** migrations.
Does not import ``trusts.models`` (that would cycle trusts.0001 →
custom_auth → trusts). Group and Permission stay Django's ``auth`` models.
"""

from django.contrib.auth.models import AbstractUser


class CustomUser(AbstractUser):
    """Custom user. Django Group / Permission remain auth.Group / auth.Permission."""
