from django.urls import path

from trusts import views

urlpatterns = [
    path('teams/new/', views.newteam, name='trusts_team_create'),
    path('teams/<int:pk>/', views.team, name='trusts_team_detail'),
]
