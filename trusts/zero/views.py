"""Team management views.

These recover the historical People / create-team pages from #9 with the
authorization holes closed. ``read`` or mere membership cannot add members.
Submitted user IDs are resolved through ``authorization`` (unknown IDs do
not mutate). Creating a team requires ``change`` on a specified trust.

The issue #8 screenshots are not in the current issue body. Templates
match the historical group_detail / group_form evidence. A separate
"Team's Team" chrome page and project-settings UI live in the example
app and are not invented here.
"""

from django import forms
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.views.generic import CreateView, DetailView

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from trusts.zero import supported_entity_contract
from trusts.zero.authorization import (
    AuthorizationDenied,
    add_group_member,
    can_administer_trust,
    can_manage_group_membership,
    create_team,
)
from trusts.zero.models import Trust


def _entity_queryset():
    Entity = get_user_model()
    if not supported_entity_contract():
        return Entity._default_manager.none()
    qs = Entity._default_manager.all()
    if hasattr(Entity, 'is_active'):
        qs = qs.filter(is_active=True)
    return qs


class SelectUserForm(forms.Form):
    user = forms.ModelChoiceField(queryset=_entity_queryset())


class NewTeamForm(forms.ModelForm):
    trust = forms.ModelChoiceField(queryset=Trust.objects.none())

    class Meta:
        model = Group
        fields = ('name',)

    def __init__(self, user=None, *args, **kwargs):
        super(NewTeamForm, self).__init__(*args, **kwargs)
        self.user = user
        if user is not None:
            self.fields['trust'].queryset = Trust.objects.filter_by_user_content_perm(
                user, Trust, 'change', exclude_root=True
            )


class NewTeamView(CreateView):
    """Create a team attached to a trust the actor administers."""
    form_class = NewTeamForm
    template_name = 'auth/group_form.html'
    model = Group

    def get_form_kwargs(self):
        kwargs = super(NewTeamView, self).get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def get_success_url(self):
        return '/teams/%s/' % self.object.pk

    def form_valid(self, form):
        trust = form.cleaned_data['trust']
        try:
            self.object = create_team(self.request.user, trust, form.cleaned_data['name'])
        except AuthorizationDenied:
            return HttpResponseForbidden()
        return redirect(self.get_success_url())


newteam = login_required(NewTeamView.as_view())


class TeamView(DetailView):
    """Team People page: view members; add only with administrative change."""
    model = Group
    template_name = 'auth/group_detail.html'

    def get_context_data(self, **kwargs):
        ctx = super(TeamView, self).get_context_data(**kwargs)
        ctx['adduserform'] = self.adduserform
        ctx['can_manage_members'] = can_manage_group_membership(
            self.request.user, self.object
        )
        return ctx

    def dispatch(self, request, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.adduserform = SelectUserForm(request.POST or None)
        group = self.get_object()
        # Management page: membership or read-only group access is not enough
        # to open the editor. Any associated trust the user administers, or
        # full membership-management authority, is required to GET.
        administers_any = any(
            can_administer_trust(request.user, trust)
            for trust in Trust.objects.filter(groups=group)
        )
        if not administers_any and not can_manage_group_membership(request.user, group):
            return HttpResponseForbidden()

        if request.method == 'POST':
            if not can_manage_group_membership(request.user, group):
                return HttpResponseForbidden()
            if self.adduserform.is_valid():
                try:
                    add_group_member(request.user, group, self.adduserform.cleaned_data['user'])
                except AuthorizationDenied:
                    return HttpResponseForbidden()
                return redirect('.')
        return super(TeamView, self).dispatch(request, *args, **kwargs)


team = login_required(TeamView.as_view())
