"""Isolated auth models for the issue #26 custom-model install.

These models are selected via AUTH_USER_MODEL / TRUSTS_*_MODEL **before**
migrations. They do not import ``trusts.models`` (that would cycle
trusts.0001 → custom_auth → trusts).
"""

from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.models import ContentType
from django.db import models


class CustomPermissionManager(models.Manager):
    def get_by_natural_key(self, codename, app_label, model):
        return self.get(
            codename=codename,
            content_type=ContentType.objects.db_manager(self.db).get_by_natural_key(
                app_label, model
            ),
        )


class CustomPermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        related_name='custom_permissions',
    )
    codename = models.CharField(max_length=100)
    objects = CustomPermissionManager()

    class Meta:
        unique_together = ('content_type', 'codename')

    def __str__(self):
        return '%s | %s' % (self.content_type, self.codename)

    def natural_key(self):
        return (self.codename,) + self.content_type.natural_key()


class CustomGroup(models.Model):
    name = models.CharField(max_length=150, unique=True)
    permissions = models.ManyToManyField(
        CustomPermission,
        blank=True,
        related_name='group_set',
        related_query_name='group',
    )

    def __str__(self):
        return self.name


class CustomUser(AbstractUser):
    """Custom user plus Trusts group membership (Django User.groups stays auth.Group)."""

    trust_groups = models.ManyToManyField(
        CustomGroup,
        blank=True,
        related_name='user_set',
        related_query_name='user',
        help_text='Trusts group membership. Django User.groups remains auth.Group.',
    )
