from authentication.models import TwoFactorAuth, User
from django.db.models.signals import post_save
from django.dispatch import receiver


@receiver(post_save, sender=User)
def create_two_factor(sender, instance, created, **kwargs):
    if created:
        TwoFactorAuth.objects.create(user=instance)
