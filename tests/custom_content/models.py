from django.db import models

from trusts.zero.models import Content


class Item(Content):
    name = models.CharField(max_length=40, null=False, blank=False)

    class Meta:
        default_permissions = ('add', 'read', 'change', 'delete')
        permissions = (
            ('add_topic_to_item', 'Add topic to an item'),
        )
        roles = (
            ('public', ('read_item', 'add_topic_to_item')),
            ('admin', ('read_item', 'add_item', 'change_item', 'add_topic_to_item')),
        )
