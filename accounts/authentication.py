from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed


class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        hours = getattr(settings, "TOKEN_EXPIRE_HOURS", 24)
        if hours is None:
            return user, token
        expiry_time = token.created + timedelta(hours=hours)
        if timezone.now() > expiry_time:
            token.delete()
            raise AuthenticationFailed("Token has expired.")
        return user, token
