from django.apps import AppConfig


HOST_BACKEND = 'tests.backends.HostTrustModelBackend'


class KernelHostConfig(AppConfig):
    """Kernel-only test app. The host backend is listed in settings.

    Pair settings omit this app. The ready-time sweep builds whatever
    ``AUTHENTICATION_BACKENDS`` lists.
    """

    name = 'tests.kernel_host'
    label = 'trusts_kernel_host'
    default = False
    default_auto_field = 'django.db.models.AutoField'
