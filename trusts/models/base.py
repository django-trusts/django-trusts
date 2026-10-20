class PermittedUsersMixin:
    """Content-instance adapter for the reverse permission inquiry.

    ``content.get_permitted_users(perm)`` is the path that exists on
    every protected model that mixes this in. It is not a content-manager
    method: ``Content.objects`` keeps returning content rows.
    """

    def get_permitted_users(self, perm, **skip_flags):
        # Catalog import stays in the method so model import needs no registry.
        from trusts.compile.catalogs import compile_permitted_users

        return compile_permitted_users(self, perm, **skip_flags)
