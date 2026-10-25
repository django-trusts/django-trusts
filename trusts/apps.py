"""The app config relays ``ready`` to backend state. It has no catalog."""

from typing import Callable, TypeVar

from django.apps import AppConfig

T = TypeVar('T')


class TrustsConfigMixin(AppConfig):
    """Stores backend state and relays ``ready`` to each key.

    ``get_or_create_config`` creates that state the first time a backend
    asks and keeps the ``on_ready`` callable passed with it. ``ready``
    calls ``on_ready(self, state)`` for every key that already exists.
    The config does not build a catalog.
    """

    def __init__(self, app_name, app_module):
        super().__init__(app_name, app_module)
        self._states = {}

    def get_or_create_config(
        self, key, factory: Callable[[], T],
        on_ready: Callable[[AppConfig, T], None],
    ) -> T:
        entry = self._states.get(key)
        if entry is None:
            state = factory()
            self._states[key] = (state, on_ready)
            return state
        return entry[0]

    def get_config(self, key):
        """State stored for ``key``, or ``None``."""
        entry = self._states.get(key)
        if entry is None:
            return None
        return entry[0]

    def ready(self):
        super().ready()
        for state, on_ready in tuple(self._states.values()):
            on_ready(self, state)
