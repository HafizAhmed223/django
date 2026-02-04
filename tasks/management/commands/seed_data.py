from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from rest_framework.authtoken.models import Token

from tasks.models import Task


class Command(BaseCommand):
    help = "Seed the database with a demo user and sample tasks."

    def handle(self, *args, **options):
        User = get_user_model()

        user, created = User.objects.get_or_create(
            username="demo_user",
            defaults={
                "email": "demo@example.com",
                "is_email_verified": True,
            },
        )
        if created:
            user.set_password("password123")
            user.save(update_fields=["password"])
            self.stdout.write(self.style.SUCCESS("Created demo user."))
        else:
            if not user.is_email_verified:
                user.is_email_verified = True
                user.save(update_fields=["is_email_verified"])
            self.stdout.write("Demo user already exists.")

        token, _ = Token.objects.get_or_create(user=user)

        Task.objects.get_or_create(
            title="Set up project",
            defaults={"description": "Initialize Django project", "is_completed": True},
        )
        Task.objects.get_or_create(
            title="Build tasks API",
            defaults={"description": "CRUD endpoints for tasks", "is_completed": False},
        )
        Task.objects.get_or_create(
            title="Test with Postman",
            defaults={"description": "Use collection to verify endpoints", "is_completed": False},
        )

        self.stdout.write(self.style.SUCCESS(f"Seeded tasks. Demo token: {token.key}"))
