"""Process state written by ``TrustsImplementationConfig.ready``."""

recorders = {}
catalogs = {}
_user_model = None
_object_blind_backends = frozenset()


def user_model():
    """User model stored by ``TrustsImplementationConfig.ready``."""
    return _user_model


def store_user_model(model):
    global _user_model
    _user_model = model


def store_object_blind_backends(classes):
    global _object_blind_backends
    _object_blind_backends = frozenset(classes)


def installed_object_blind_backends():
    """Object-blind backend classes stored by ``ready``."""
    return _object_blind_backends
