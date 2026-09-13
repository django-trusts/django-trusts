from pkgutil import extend_path
__path__ = extend_path(__path__, __name__)


def __getattr__(name):
    if name == 'check':
        from trusts.core import check
        return check
    raise AttributeError('module %r has no attribute %r' % (__name__, name))
