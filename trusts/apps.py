"""The app config relays ``ready`` to backend state. It has no catalog."""

import abc
from typing import Callable

import django.apps


class AppLifecycle(abc.ABC):
    """Per-key state that receives the app config's ``ready``."""

    @abc.abstractmethod
    def app_ready(self, app_config):
        """Called after ``AppConfig.ready``."""


class TrustsConfigMixin(django.apps.AppConfig):
    """Stores backend state and relays ``ready`` to each key.

    ``get_or_create_config`` creates that state the first time a backend
    asks. ``ready`` notifies every key that already exists. The config
    does not build a catalog.
    """

    def __init__(self, app_name, app_module):
        super().__init__(app_name, app_module)
        self._states = {}

    def get_or_create_config(self, key, factory: Callable[[], AppLifecycle]):
        state = self._states.get(key)
        if state is None:
            state = factory()
            self._states[key] = state
        return state

    def ready(self):
        super().ready()
        for state in tuple(self._states.values()):
            state.app_ready(self)
