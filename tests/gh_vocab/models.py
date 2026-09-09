"""Private GH-shaped models for the noun-independent kernel proof (#43).

Public relations used to authorize:

    account.teams
    team.permission_bundles
    repository.policy

``organization.teams`` is owner containment and is not the requester
path. These models never inherit Content and never register on the
process-wide Context / Trustee maps. Isolated tests compose
AuthorizationPath from explicit frozen registries.

Use GH in symbols, fixtures, and headings. Do not imply affiliation,
endorsement, or official compatibility with any external service.
"""

from django.db import models


class Account(models.Model):
    """Requester / person. Never the organization."""

    name = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.name


class Organization(models.Model):
    """Owner / containment only. Not a requester."""

    name = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.name


class Team(models.Model):
    """Collective subject. Membership reverse is ``account.teams``."""

    organization = models.ForeignKey(
        Organization, related_name='teams', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    name = models.CharField(max_length=40, null=False, blank=False)
    members = models.ManyToManyField(
        Account, related_name='teams', blank=True,
    )

    def __str__(self):
        return self.name


class Operation(models.Model):
    """Kernel operation. Not auth.Permission."""

    code = models.CharField(max_length=40, null=False, blank=False, unique=True)

    def __str__(self):
        return self.code


class PermissionBundle(models.Model):
    """Operation ceiling for a team. Constraints never create a grant."""

    team = models.ForeignKey(
        Team, related_name='permission_bundles', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    name = models.CharField(max_length=40, null=False, blank=False)
    operations = models.ManyToManyField(
        Operation, related_name='bundles', blank=True,
    )

    def __str__(self):
        return self.name


class Policy(models.Model):
    """Policy scope. Not a Trusts convenience."""

    title = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.title


class Repository(models.Model):
    """Protected resource. Scope is ``repository.policy``."""

    policy = models.ForeignKey(
        Policy, related_name='repositories', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    title = models.CharField(max_length=40, null=False, blank=False)

    def __str__(self):
        return self.title


class TeamPolicyGrant(models.Model):
    """Grant row: team + policy + operation."""

    policy = models.ForeignKey(
        Policy, related_name='team_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    team = models.ForeignKey(
        Team, related_name='policy_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    operation = models.ForeignKey(
        Operation, related_name='team_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ('policy', 'team', 'operation')


class GhTrapGrant(models.Model):
    """Grant whose Python getters must never run during resolution."""

    policy = models.ForeignKey(
        Policy, related_name='trap_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    team = models.ForeignKey(
        Team, related_name='trap_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    operation = models.ForeignKey(
        Operation, related_name='trap_grants', null=False, blank=False,
        on_delete=models.CASCADE,
    )

    @property
    def forbidden(self):
        raise AssertionError('AuthorizationPath must not execute properties')

    def get_team(self):
        raise AssertionError('AuthorizationPath must not execute getters')


class UnregisteredGhNote(models.Model):
    """Must stay unregistered so missing compose fails closed."""

    repository = models.ForeignKey(
        Repository, related_name='notes', null=False, blank=False,
        on_delete=models.CASCADE,
    )
    text = models.CharField(max_length=80, null=False, blank=False, default='')
