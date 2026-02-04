from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers
try:
    from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
    HAS_SIMPLEJWT = True
except Exception:
    TokenObtainPairSerializer = None
    HAS_SIMPLEJWT = False

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ["id", "username", "password", "email"]

    def create(self, validated_data):
        return User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email", ""),
            password=validated_data["password"],
        )

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already in use.")
        return value


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username = (attrs.get("username") or "").strip()
        email = (attrs.get("email") or "").strip()
        password = attrs.get("password")

        if not username and not email:
            raise serializers.ValidationError("username or email is required.")

        if email and not username:
            user = User.objects.filter(email=email).first()
            if not user or not user.check_password(password):
                raise serializers.ValidationError("Invalid credentials.")
        else:
            user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError("Invalid credentials.")
        attrs["user"] = user
        return attrs


class VerifyEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class VerifyEmailConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=6)


if HAS_SIMPLEJWT:
    class JWTTokenObtainPairSerializer(TokenObtainPairSerializer):
        def validate(self, attrs):
            data = super().validate(attrs)
            if not self.user.is_email_verified:
                raise serializers.ValidationError("Email not verified.")
            return data
