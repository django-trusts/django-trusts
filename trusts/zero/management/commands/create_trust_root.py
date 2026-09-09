from django.core.management.base import BaseCommand
from django.conf import settings


def create_root_trust(Trust, pk, settlor, title):
    if Trust.objects.filter(pk=pk).exists():
        return Trust.objects.get(pk=pk)

    kwargs = {'id': pk, 'title': title}
    if settlor is not None:
        kwargs.update({'settlor_id': settlor})

    trust = Trust(**kwargs)
    trust.trust = trust
    trust.save()
    return trust


class Command(BaseCommand):
    help = "Create a self-referencing trust as the root of all trust."

    def handle(self, **options):
        self.verbosity = int(options.get('verbosity', 1))

        pk = getattr(settings, 'TRUSTS_ROOT_PK', 1)
        settlor = getattr(settings, 'TRUSTS_ROOT_SETTLOR', None)
        title = getattr(settings, 'TRUSTS_ROOT_TITLE', 'In Trust We Trust')

        from trusts.zero.models import Trust
        create_root_trust(Trust, pk, settlor, title)
