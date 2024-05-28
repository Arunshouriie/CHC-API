from rest_framework import generics, permissions
from rest_framework import serializers
from django.contrib.auth.models import User

from .models import  Reminderschedulegroups, DispenseInfo, Medicines, ReminderSchedule_audit, SideEffect, Points, AlarmAudit, Provisioning, Dispense_Log, userinfo, Captureevent, Trackerdata

# User Serializer
# class UserSerializer(serializers.ModelSerializer):
    # class Meta:
        # model = User
        # fields = ('id', 'username', 'email')

# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'])

        return user

# User Serializer
class UserSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ('id', 'username', 'email')

# Change Password
from rest_framework import serializers
from django.contrib.auth.models import User

class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

# class user_profile_serializer(serializers.Serializer):
#     user_profile = serializers.ModelSerializer
#     class Meta:
#         model = user_profile
#         fields = '__all__'

class medicine_schedule_serializer(serializers.ModelSerializer):

    class Meta:
        model = Reminderschedulegroups
        fields = '__all__'

class provisionserializer(serializers.ModelSerializer):
    class Meta:
        model = Provisioning
        fields = ('user_id', 'mac_id', 'public_ip')

class dispense_serializer(serializers.ModelSerializer):

    class Meta:
        model = DispenseInfo
        fields = '__all__'

class schedule_audit_serializer(serializers.ModelSerializer):

    class Meta:
        model = ReminderSchedule_audit
        fields = '__all__'

class alarm_audit_serializer(serializers.ModelSerializer):

    class Meta:
        model = AlarmAudit
        fields = '__all__'

class DispenseLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dispense_Log
        fields = '__all__'

class MedicineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Medicines
        fields = ['id', 'name', 'user']
class PointsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Points
        fields = '__all__'

class Capture_event_serializer(serializers.ModelSerializer):
    class Meta:
        model = Captureevent
        fields = '__all__'

class Tracker_data_serializer(serializers.ModelSerializer):

    class Meta:
        model = Trackerdata
        fields = '__all__'

class SideEffectSerializer(serializers.ModelSerializer):
    class Meta:
        model = SideEffect
        fields = '__all__'

class user_info_serializer(serializers.ModelSerializer):

    class Meta:

        model = userinfo

        fields = "__all__"

    # def create(self, validated_data):

        # user = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'])
        # return user