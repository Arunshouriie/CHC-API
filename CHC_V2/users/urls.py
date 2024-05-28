from knox import views as knox_views
from .views import RegisterAPI, UserAPI, UserinfoView, LoginAPI, SideEffectViewSet, ChangePasswordView,DispenseLogViewSet, PointsViewSet, MedicineViewSet, provisionView, medicinescheduleView, DispenseView, ScheduleAuditView, AlarmAuditView, CaptureEventView, TrackerdataView
from django.urls import path, include, re_path
from rest_framework import routers, permissions
from drf_yasg import openapi
from drf_yasg.views import get_schema_view


router = routers.DefaultRouter()
router.register(r"user/info", UserinfoView)
router.register(r"schedule", medicinescheduleView)
router.register(r"dispense", DispenseView)
router.register(r"rem/schedules/audit", ScheduleAuditView)
router.register(r"alarm/audit", AlarmAuditView)
router.register(r"device_provision", provisionView)
router.register(r"medicine/dispense/info", DispenseLogViewSet)
router.register(r"btn/event/info", CaptureEventView)
router.register(r"tracker/data", TrackerdataView)
router.register(r'medicines', MedicineViewSet)
# router.register(r'dispenselog', DispenseLogViewSet)
router.register(r'points', PointsViewSet)
router.register(r'side_effects', SideEffectViewSet)


urlpatterns = [
    path('api/register/', RegisterAPI.as_view(), name='register'),
    path('api/login/', LoginAPI.as_view(), name='login'),
    path('api/logout/', knox_views.LogoutView.as_view(), name='logout'),
    path('api/logoutall/', knox_views.LogoutAllView.as_view(), name='logoutall'),
    path('api/user/', UserAPI.as_view(), name='user'),
    path("", include(router.urls)),
    path('api/change-password/', ChangePasswordView.as_view(), name='change-password'),
    # path('api/user_profile/', UserProfileView.as_view(), name='user-profile')
]

schema_view = get_schema_view(
        openapi.Info(title="Coherence API",
        default_version="0.0.1",
        description="API for Device",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)
urlpatterns += [
    re_path(
        r"^swagger(?P<format>\.json|\.yaml)$",
        schema_view.without_ui(cache_timeout=0),
        name="schema-json",
    ),
    re_path(
        r"^swagger/$",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    re_path(
        r"^redoc/$",
        schema_view.with_ui("redoc", cache_timeout=0),
       name="schema-redoc"
    ),
]