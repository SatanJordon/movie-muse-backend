from django.urls import path
from .views import UserRegistrationView, CustomLoginView, VerifyOTPView, SendOTPView, ResetPasswordView,ResendOTPView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('register', UserRegistrationView.as_view({'post': 'create'}), name='user-registration'),
    path('token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('login', CustomLoginView.as_view(), name='login'),
    path('verify-otp', VerifyOTPView.as_view(), name='verify_otp'),
    path('resend-otp', ResendOTPView.as_view(), name='resend-otp'),
    path('password-reset', SendOTPView.as_view(), name='password-reset'),
    path('password-reset-confirm', ResetPasswordView.as_view(), name='password-reset-confirm'),
]
