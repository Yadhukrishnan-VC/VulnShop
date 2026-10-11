from django.apps import AppConfig

class AppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):
        try:
            from django.contrib.auth.models import User
            from app.models import UserProfile
            # Auto-create profile signal
            from django.db.models.signals import post_save
            def create_profile(sender, instance, created, **kwargs):
                if created:
                    UserProfile.objects.get_or_create(user=instance)
            post_save.connect(create_profile, sender=User)
        except Exception:
            pass
