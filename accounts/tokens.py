from django.contrib.auth.tokens import PasswordResetTokenGenerator


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    key_salt = "accounts.EmailVerificationTokenGenerator"


email_verification_token = EmailVerificationTokenGenerator()


class PasswordResetTokenGeneratorLocal(PasswordResetTokenGenerator):
    key_salt = "accounts.PasswordResetTokenGenerator"


password_reset_token = PasswordResetTokenGeneratorLocal()
