import http
from django.contrib.auth import login

from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from rest_framework import status, viewsets

from rest_framework import generics, permissions
from rest_framework.response import Response
# from .models import AuthToken
from .serializers import UserSerializer,provisionserializer,user_info_serializer, MedicineSerializer, PointsSerializer, RegisterSerializer, ChangePasswordSerializer, DispenseLogSerializer, medicine_schedule_serializer, dispense_serializer, schedule_audit_serializer, alarm_audit_serializer, Capture_event_serializer, Tracker_data_serializer
from django.views.decorators.debug import sensitive_post_parameters
from rest_framework.views import APIView
from rest_framework import generics, permissions
from .models import  Reminderschedulegroups, DispenseInfo, Medicines, ReminderSchedule_audit, Points, AlarmAudit, Provisioning, Dispense_Log, userinfo, Captureevent, Trackerdata
from django.utils import timezone
from datetime import timedelta
from rest_framework.decorators import action
# Change Password
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated   

# Register API
class RegisterAPI(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
        "user": UserSerializer(user, context=self.get_serializer_context()).data,
        # "token": AuthToken.objects.create(user)[1]
        })

# Login API
class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return super(LoginAPI, self).post(request, format=None)

# Get User API
class UserAPI(generics.RetrieveAPIView):
    permission_classes = [permissions.AllowAny,]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

class UserinfoView(viewsets.ModelViewSet):
    permission_classes = [permissions.AllowAny]
    queryset = userinfo.objects.all()
    serializer_class = user_info_serializer

class medicinescheduleView(viewsets.ModelViewSet):
    """
    """
    serializer_class = medicine_schedule_serializer
    permission_classes = [permissions.AllowAny]
    queryset = Reminderschedulegroups.objects.all()


class DispenseView(viewsets.ModelViewSet):
    """
    """
    serializer_class = dispense_serializer
    permission_classes = [permissions.AllowAny]
    queryset = DispenseInfo.objects.all()

class ScheduleAuditView(viewsets.ModelViewSet):
    """
    """
    serializer_class = schedule_audit_serializer
    permission_classes = [permissions.AllowAny]
    queryset = ReminderSchedule_audit.objects.all()

class AlarmAuditView(viewsets.ModelViewSet):
    """
    """
    serializer_class = alarm_audit_serializer
    permission_classes = [permissions.AllowAny]
    queryset = AlarmAudit.objects.all()

class provisionView(viewsets.ModelViewSet):
    """
    """
    serializer_class = provisionserializer
    permission_classes = [permissions.AllowAny]
    queryset = Provisioning.objects.all()

# class MedicinedispenseView(viewsets.ModelViewSet):
#     permission_classes = [permissions.AllowAny]
#     queryset = medicine_dispense_information.objects.all()
#     serializer_class = medicine_dispense_serializer

class DispenseLogViewSet(viewsets.ModelViewSet):
    queryset = Dispense_Log.objects.all()
    serializer_class = DispenseLogSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        self.award_points(response.data)
        return response

    def award_points(self, dispense_log_data):
        dispense_log = Dispense_Log.objects.get(id=dispense_log_data['id'])
        now = timezone.now()
        points = 0
        if dispense_log.taken_on_time:
            points += 3
            # Assume video is always reviewed successfully for simplicity
            points += 2
        else:
            time_difference = now - dispense_log.dispense_time
            if time_difference <= timedelta(minutes=20) and dispense_log.reason_not_taken:
                points += 2.5
        Points.objects.create(user=dispense_log.medicine.user, points=points, dispense_log=dispense_log)

class MedicineViewSet(viewsets.ModelViewSet):
    queryset = Medicines.objects.all()
    serializer_class = MedicineSerializer
class PointsViewSet(viewsets.ModelViewSet):
    queryset = Points.objects.all()
    serializer_class = PointsSerializer

class CaptureEventView(viewsets.ModelViewSet):
    permission_classes = [permissions.AllowAny]
    queryset = Captureevent.objects.all()
    serializer_class = Capture_event_serializer

class TrackerdataView(viewsets.ModelViewSet):
    permission_classes = [permissions.AllowAny]
    queryset = Trackerdata.objects.all()
    serializer_class = Tracker_data_serializer

from .models import SideEffect
from .serializers import SideEffectSerializer

class SideEffectViewSet(viewsets.ModelViewSet):
    queryset = SideEffect.objects.all()
    serializer_class = SideEffectSerializer


class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)