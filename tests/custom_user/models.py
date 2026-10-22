from trusts.query import PermittedUsersManagerMixin
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import UserManager as DjangoUserManager


class UserManager(PermittedUsersManagerMixin, DjangoUserManager):
    pass


class User(AbstractUser):
    objects = UserManager()
