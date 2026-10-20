import trusts.apps as trusts_apps


HOST_BACKEND = 'tests.kernel_host.backends.HostTrustModelBackend'


class KernelHostConfig(trusts_apps.TrustsConfigMixin):
    """Kernel-only test app. The host backend lives in this package."""

    name = 'tests.kernel_host'
    label = 'trusts_kernel_host'
    default = False
    default_auto_field = 'django.db.models.AutoField'
