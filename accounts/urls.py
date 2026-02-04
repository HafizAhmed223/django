from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    VerifyEmailRequestView,
    VerifyEmailConfirmView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
)
try:
    from rest_framework_simplejwt.views import TokenRefreshView
    from .views import JWTCreateView
    HAS_SIMPLEJWT = True
except Exception:
    HAS_SIMPLEJWT = False

urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="auth-register"),
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/verify/request/", VerifyEmailRequestView.as_view(), name="auth-verify-request"),
    path("auth/verify/confirm/", VerifyEmailConfirmView.as_view(), name="auth-verify-confirm"),
    path("auth/password-reset/request/", PasswordResetRequestView.as_view(), name="auth-password-reset-request"),
    path("auth/password-reset/confirm/", PasswordResetConfirmView.as_view(), name="auth-password-reset-confirm"),
]

if HAS_SIMPLEJWT:
    urlpatterns += [
        path("auth/jwt/create/", JWTCreateView.as_view(), name="jwt-create"),
        path("auth/jwt/refresh/", TokenRefreshView.as_view(), name="jwt-refresh"),
    ]
