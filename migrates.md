# Migrating to django-trusts 1.0

django-trusts 1.0 is a step change from django-trusts 0.x. It is not API,
model, or schema compatible with the 0.x package. Version 1.0 is a
schema-neutral authorization library and does not provide a direct migration
path for applications using the historical Trust and Content implementation.

The compatibility layer for django-trusts 0.x is
[django-trusts-zero](https://github.com/django-trusts/django-trusts-zero).
Existing 0.x applications should install that package and follow its
[migration guide](https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md).
That is the supported 0.x migration path.

Applications adopting schema-neutral django-trusts 1.0 as a new integration
should follow the
[usage guide](https://django-trusts.readthedocs.io/en/dev/).
