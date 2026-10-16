# Runtime selection history

Historical development record. Last source update: 2026-10-11. Reorganized
2026-10-16; this revision has not been reviewed by a human for current accuracy.

The [usage guide](../source/index.rst#installation) owns supported runtime
versions; CI and package metadata are the executable evidence.

The following sources were consulted on 2026-09-07 for #14/#15. The statements
below describe that dated decision, not today's upstream release status.

## Sources checked at implementation time

| Source | What it established | URL |
| --- | --- | --- |
| Django download page | Latest official Django is **6.1.1**. 6.1 mainstream support ends April 2027. Django 5.2 is the current LTS (extended support through April 2028). Django 4.2 LTS ended 2026-04-07. | https://www.djangoproject.com/download/ |
| Django install FAQ (stable) | Django **6.1** officially supports **Python 3.12, 3.13, and 3.14** only. | https://docs.djangoproject.com/en/stable/faq/install/ |
| Django 6.1 release notes | Same Python list; only the latest micro of each series is officially supported. | https://docs.djangoproject.com/en/6.1/releases/6.1/ |
| CPython Developer's Guide | Supported CPython on 2026-09-07: 3.14 and 3.13 (bugfix), 3.12 / 3.11 / 3.10 (security). 3.15 is prerelease (first release scheduled 2026-10-01). 3.9 ended 2025-10-31. | https://devguide.python.org/versions/ |

## Scope of that decision

The first modernization targeted the intersection of Django's supported
CPython versions, rather than adding a Django LTS or an intermediate Python-only
port. See the [legacy baseline](legacy-baseline.md) for the earlier stack and
the [audit](../../SECURITY_AUDIT.md#bounded-inherited-relationships) for database
limits on recursive permission queries.
