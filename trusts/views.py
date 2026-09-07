from django import forms
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.views.generic import CreateView, DetailView

from trusts import get_entity_model, get_group_model
from trusts.query import user_can_manage_group, user_can_view_group


class SelectUserForm(forms.Form):
    user = forms.ModelChoiceField(queryset=None)

    def __init__(self, *args, **kwargs):
        super(SelectUserForm, self).__init__(*args, **kwargs)
        self.fields['user'].queryset = get_entity_model().objects.all()


@method_decorator(login_required, name='dispatch')
class NewTeamView(CreateView):
    """Create a team (Django Group). Creator becomes a member; membership is not manage."""

    fields = ('name',)
    template_name = 'auth/group_form.html'

    def get_queryset(self):
        return get_group_model().objects.all()

    def get_form_class(self):
        return forms.modelform_factory(get_group_model(), fields=self.fields)

    def get_success_url(self):
        return '/teams/%s/' % self.object.pk

    def form_valid(self, form):
        response = super(NewTeamView, self).form_valid(form)
        self.request.user.groups.add(self.object)
        return response


newteam = NewTeamView.as_view()


@method_decorator(login_required, name='dispatch')
class TeamView(DetailView):
    """View team members. Adding members requires trustee change_trust on an attached trust."""

    template_name = 'auth/group_detail.html'

    def get_queryset(self):
        return get_group_model().objects.all()

    def dispatch(self, request, *args, **kwargs):
        self.object = self.get_object()
        if not user_can_view_group(request.user, self.object):
            return HttpResponseForbidden()
        return super(TeamView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(TeamView, self).get_context_data(**kwargs)
        context['adduserform'] = SelectUserForm()
        context['can_manage'] = user_can_manage_group(self.request.user, self.object)
        return context

    def post(self, request, *args, **kwargs):
        if not user_can_manage_group(request.user, self.object):
            return HttpResponseForbidden()
        form = SelectUserForm(request.POST)
        if form.is_valid():
            form.cleaned_data['user'].groups.add(self.object)
            return redirect(request.path)
        context = self.get_context_data()
        context['adduserform'] = form
        return self.render_to_response(context)


team = TeamView.as_view()
