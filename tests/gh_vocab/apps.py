from django.apps import AppConfig


class GhVocabConfig(AppConfig):
    """Private GH-shaped vocabulary for the noun-independent kernel proof.

    Not a public package. Terminology is GH, not the full external service
    name. No affiliation, endorsement, or official compatibility.
    """

    name = 'tests.gh_vocab'
    label = 'gh_vocab'
    verbose_name = 'GH vocabulary proof'
    default_auto_field = 'django.db.models.AutoField'
