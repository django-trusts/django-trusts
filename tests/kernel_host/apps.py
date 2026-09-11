from trusts.apps import TrustsImplementationConfig


HOST_BACKEND = 'tests.backends.HostTrustModelBackend'


class KernelHostConfig(TrustsImplementationConfig):
    """Kernel-only test implementation owner.

    Owns the mixin host backend so KERNEL_SUITE never calls the
    ``kernel_config()`` tombstone. Pair settings omit this app; Zero IIa
    is the sole owner there.
    """

    name = 'tests.kernel_host'
    label = 'trusts_kernel_host'
    default = False
    default_auto_field = 'django.db.models.AutoField'
    trusts_backend_paths = (HOST_BACKEND,)
