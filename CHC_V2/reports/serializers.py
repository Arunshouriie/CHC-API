from .models import trial
from rest_framework import generics, permissions
from rest_framework import serializers



class trial_serializer(serializers.ModelSerializer):

    class Meta:
        model = trial
        fields = '__all__'