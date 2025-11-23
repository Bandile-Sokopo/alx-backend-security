from django.urls import path
from .views import sensitive_view

urlpatterns = [
    path('sensitive/', sensitive_view, name='sensitive'),
]
