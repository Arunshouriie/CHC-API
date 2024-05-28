from django.urls import path, include, re_path
from rest_framework import routers, permissions
from .views import TrialAPIView

router = routers.DefaultRouter()
router.register(r"trial", TrialAPIView)

urlpatterns = [
    
    path("", include(router.urls)),
]