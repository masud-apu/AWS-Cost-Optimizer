from django.urls import path, include
from .views import *
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)

urlpatterns = [
    path('v1/signup/', CustomUserCreateView.as_view(), name='signup'),
    path('v1/verify-otp/<str:username>/', OTPVerificationView.as_view(), name='otp_verification_view'),
    path('v1/resend-otp/<str:username>/', OTPResendView.as_view(), name='resend_otp'),
    path('v1/signin/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('v1/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('v1/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('v1/logout/', LogoutView.as_view(), name='auth_logout'),
    path('v1/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('v1/password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),

]
