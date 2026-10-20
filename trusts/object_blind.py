"""Stock Django backends that ignore the object argument.

Imported by ``trusts.apps`` when the sweep runs. Not on the query path.
"""

from django.contrib.auth.backends import (
    AllowAllUsersModelBackend,
    AllowAllUsersRemoteUserBackend,
    ModelBackend,
    RemoteUserBackend,
)

OBJECT_BLIND_BACKENDS = (
    ModelBackend,
    AllowAllUsersModelBackend,
    RemoteUserBackend,
    AllowAllUsersRemoteUserBackend,
)
