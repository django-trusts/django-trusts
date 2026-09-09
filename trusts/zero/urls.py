from django.urls import path

from trusts.zero import views

app_name = 'trusts'

urlpatterns = [
    path('teams/new/', views.newteam, name='team_create'),
    path('teams/<int:pk>/', views.team, name='team_detail'),
]
