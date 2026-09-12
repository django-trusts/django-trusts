# Library-only suite. Not part of the installable trusts package.


def kernel_host_listed():
    from django.conf import settings

    return 'tests.backends.HostTrustModelBackend' in (
        getattr(settings, 'AUTHENTICATION_BACKENDS', ()) or ()
    )


class KernelHostRequiredMixin(object):
    def setUp(self):
        if not kernel_host_listed():
            self.skipTest('kernel-only host path is not listed on the pair')
        super().setUp()
