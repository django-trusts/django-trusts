from trusts.apps import TrustsImplementationConfig


HOST_BACKEND = 'tests.backends.HostTrustModelBackend'


class KernelHostConfig(TrustsImplementationConfig):
    """Kernel-only test implementation owner.

    Owns the mixin host backend for the library-only suite. Pair
    settings omit this app; supported Zero is the sole owner there.
    """

    name = 'tests.kernel_host'
    label = 'trusts_kernel_host'
    default = False
    default_auto_field = 'django.db.models.AutoField'
    trusts_backend_paths = (HOST_BACKEND,)
