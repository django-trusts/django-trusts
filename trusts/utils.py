"""Public helpers that are not a Django app, a model, or a backend."""


def parse_perm_code(perm):
    """Split ``app.action_model`` plus an optional ``:condition`` suffix.

    The condition is partitioned first so condition codes may contain
    underscores (``app.change_ticket:own_item``). Returns
    ``(applabel, modelname, action, cond)``. ``cond`` is ``''`` when
    the permission has no suffix.
    """
    applabel, rest = perm.split('.', 1)
    rest, _sep, cond = rest.partition(':')
    action, modelname = rest.rsplit('_', 1)
    return applabel, modelname, action, cond
