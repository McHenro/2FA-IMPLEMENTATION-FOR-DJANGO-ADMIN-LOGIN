from django.db import models
import random
import string
import uuid
import pyotp
from django.contrib.auth.models import AbstractUser, UserManager, Group, Permission
from django.utils.translation import gettext as _



class LowercaseEmailField(models.EmailField):
    """
    Override EmailField to convert emails to lowercase before saving.
    """
    def to_python(self, value):
        """
        Convert email to lowercase.
        """
        value = super(LowercaseEmailField, self).to_python(value)
        # Value can be None. Checks that it's a string before lowercasing.
        if isinstance(value, str):
            return value.lower()
        return value


class User(AbstractUser):
    username = models.CharField(
        _("Username"), unique=True, max_length=150, null=True, blank=True
    )
    email = LowercaseEmailField(_("Email"), unique=True, max_length=255)
    first_name = models.CharField(
        _("First name"), null=True, blank=True, max_length=255
    )
    last_name = models.CharField(_("Last name"), null=True, blank=True, max_length=255)
    is_verified = models.BooleanField(
        _("Verified"),
        default=False,
        help_text="Boolean field to check if user's email has been verified",
    )

    # Override default groups and permissions to prevent conflicts
    groups = models.ManyToManyField(
        Group,
        related_name="custom_user_groups",  # Avoid clash with auth.User
        blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="custom_user_permissions",  # Avoid clash with auth.User
        blank=True
    )
   
    objects = UserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = []
    def save(self, *args, **kwargs) -> None:
        if not self.pk:
            self.username = self.username if self.username else self.email
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.get_full_name()


class TwoFactorAuth(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    verified = models.BooleanField(default=False)
    totp_verified = models.BooleanField(default=False)
    totp_enabled = models.BooleanField(default=False)
    preferred_method = models.CharField(
        max_length=10,
        choices=[("sms", "SMS"), ("email", "Email"), ("call", "Phone Call")],
        default="email",
    )
    phone_number = models.CharField(max_length=15, null=True)
    backup_codes = models.JSONField(default=list)
    secret_key = models.CharField(max_length=32, default=pyotp.random_base32)

    def __str__(self):
        return self.user.username


class TrustedDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_id = models.UUIDField(default=uuid.uuid4)
    device_name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
