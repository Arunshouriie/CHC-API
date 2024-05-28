from django.shortcuts import render
from .models import trial
from .serializers import trial_serializer
from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework import status, viewsets



# Create your views here.
class TrialAPIView(viewsets.ModelViewSet):
    permission_classes = [permissions.AllowAny,]
    serializer_class = trial_serializer
    queryset = trial.objects.all()