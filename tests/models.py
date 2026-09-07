from django.db import models
from django.contrib.auth.models import Group

from trusts.models import Content, Junction


class Category(Content):
    name = models.CharField(max_length=40, null=False, blank=False)

    class Meta:
        default_permissions = ('add', 'read', 'change', 'delete')
        permissions = (
            ('add_topic_to_category', 'Add topic to a category'),
        )
        roles = (
            ('public', ('read_category', 'add_topic_to_category')),
            ('admin', ('read_category', 'add_category', 'change_category', 'add_topic_to_category')),
            ('write', ('read_category', 'change_category', 'add_topic_to_category')),
        )


class TestGroupJunction(Junction):
    content = models.ForeignKey(Group, unique=True, null=False, blank=False, on_delete=models.CASCADE)
    name = models.CharField(max_length=40, null=False, blank=False)

    class Meta:
        content_roles = (
            ('public', ('read_group', 'add_topic_to_group')),
            ('admin', ('read_group', 'add_group', 'change_group', 'add_topic_to_group')),
            ('write', ('read_group', 'change_group', 'add_topic_to_group')),
        )
