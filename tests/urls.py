from django.urls import include, path

urlpatterns = [
    path('', include('trusts.urls')),
]
