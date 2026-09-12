# Library-only suite. Not part of the installable trusts package.

import unittest


def kernel_host_listed():
    from django.conf import settings

    return 'tests.backends.HostTrustModelBackend' in (
        getattr(settings, 'AUTHENTICATION_BACKENDS', ()) or ()
    )


class KernelHostRequiredMixin(object):
    """Skip live KernelHost / Document tests when pair settings omit them.

    ``setUpClass`` skips before subclass ``setUp`` runs, so host-only
    fixtures that forget ``super().setUp()`` cannot fail the pair job.
    """

    @classmethod
    def setUpClass(cls):
        if not kernel_host_listed():
            raise unittest.SkipTest(
                'kernel-only host path is not listed on the pair'
            )
        super().setUpClass()

    def setUp(self):
        if not kernel_host_listed():
            self.skipTest('kernel-only host path is not listed on the pair')
        super().setUp()
