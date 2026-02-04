from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
try:
    from rest_framework_simplejwt.views import TokenObtainPairView
    HAS_SIMPLEJWT = True
except Exception:
    TokenObtainPairView = None
    HAS_SIMPLEJWT = False
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    VerifyEmailRequestSerializer,
    VerifyEmailConfirmSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
)
if HAS_SIMPLEJWT:
    from .serializers import JWTTokenObtainPairSerializer

try:
    from drf_spectacular.utils import extend_schema
except Exception:
    def extend_schema(*args, **kwargs):
        def decorator(view):
            return view
        return decorator
from .tokens import email_verification_token, password_reset_token

User = get_user_model()


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    @extend_schema(request=RegisterSerializer, responses={201: RegisterSerializer})
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        user.is_email_verified = False
        user.save(update_fields=["is_email_verified"])
        self._send_verification_email(user)
        return Response(
            {
                "user_id": user.id,
                "username": user.username,
                "email_verified": user.is_email_verified,
            },
            status=status.HTTP_201_CREATED,
        )

    def _send_verification_email(self, user):
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = email_verification_token.make_token(user)
        self._send_templated_email(
            subject="Verify your account",
            to_email=user.email,
            text_template="emails/verify_email.txt",
            html_template="emails/verify_email.html",
            context={
                "username": user.username,
                "uid": uid,
                "token": token,
                "site_domain": settings.SITE_DOMAIN,
            },
        )

    def _send_templated_email(self, subject, to_email, text_template, html_template, context):
        text_body = render_to_string(text_template, context)
        html_body = render_to_string(html_template, context)
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[to_email],
        )
        email.attach_alternative(html_body, "text/html")
        email.send(fail_silently=True)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    @extend_schema(request=LoginSerializer)
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        if not user.is_email_verified:
            return Response(
                {"detail": "Email not verified."},
                status=status.HTTP_403_FORBIDDEN,
            )
        Token.objects.filter(user=user).delete()
        token = Token.objects.create(user=user)
        return Response(
            {"token": token.key, "user_id": user.id, "username": user.username},
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    @extend_schema(responses={200: None})
    def post(self, request):
        Token.objects.filter(user=request.user).delete()
        return Response({"detail": "Logged out."}, status=status.HTTP_200_OK)


class VerifyEmailRequestView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    @extend_schema(request=VerifyEmailRequestSerializer)
    def post(self, request):
        serializer = VerifyEmailRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"detail": "If the email exists, a link was sent."}, status=status.HTTP_200_OK)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = email_verification_token.make_token(user)
        self._send_templated_email(
            subject="Verify your account",
            to_email=user.email,
            text_template="emails/verify_email.txt",
            html_template="emails/verify_email.html",
            context={
                "username": user.username,
                "uid": uid,
                "token": token,
                "site_domain": settings.SITE_DOMAIN,
            },
        )
        return Response({"detail": "Verification sent."}, status=status.HTTP_200_OK)


class VerifyEmailConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    @extend_schema(request=VerifyEmailConfirmSerializer)
    def post(self, request):
        serializer = VerifyEmailConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        uid = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]
        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except (ValueError, User.DoesNotExist):
            return Response({"detail": "Invalid uid."}, status=status.HTTP_400_BAD_REQUEST)
        if not email_verification_token.check_token(user, token):
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        user.is_email_verified = True
        user.save(update_fields=["is_email_verified"])
        return Response({"detail": "Email verified."}, status=status.HTTP_200_OK)


class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    @extend_schema(request=PasswordResetRequestSerializer)
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"detail": "If the email exists, a link was sent."}, status=status.HTTP_200_OK)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = password_reset_token.make_token(user)
        self._send_templated_email(
            subject="Password reset",
            to_email=user.email,
            text_template="emails/password_reset.txt",
            html_template="emails/password_reset.html",
            context={
                "username": user.username,
                "uid": uid,
                "token": token,
                "site_domain": settings.SITE_DOMAIN,
            },
        )
        return Response({"detail": "Password reset sent."}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    @extend_schema(request=PasswordResetConfirmSerializer)
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        uid = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]
        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except (ValueError, User.DoesNotExist):
            return Response({"detail": "Invalid uid."}, status=status.HTTP_400_BAD_REQUEST)
        if not password_reset_token.check_token(user, token):
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save(update_fields=["password"])
        Token.objects.filter(user=user).delete()
        return Response({"detail": "Password updated."}, status=status.HTTP_200_OK)


if HAS_SIMPLEJWT:
    class JWTCreateView(TokenObtainPairView):
        serializer_class = JWTTokenObtainPairSerializer
        permission_classes = [permissions.AllowAny]
        throttle_classes = [ScopedRateThrottle]
        throttle_scope = "auth"

        @extend_schema(request=JWTTokenObtainPairSerializer)
        def post(self, request, *args, **kwargs):
            return super().post(request, *args, **kwargs)

# Create your views here.
