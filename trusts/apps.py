from django.apps import AppConfig as DjangoAppConfig


class KernelConfig(DjangoAppConfig):
    """Kernel Django app: package ``trusts``, distinct label, no migrations."""

    name = 'trusts'
    label = 'trusts_kernel'
    verbose_name = 'Django Trusts kernel'
    default = False

    def ready(self):
        # Register kernel system checks (E006 adapter re-walk, E007).
        from trusts import checks as _trusts_checks  # noqa: F401
