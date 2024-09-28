from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import random
from datetime import timedelta, datetime

class OTPVerification(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return timezone.now() > self.expires_at
    
    @classmethod
    def generate_otp(cls, user):
        otp = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timedelta(minutes=10)
        return cls.objects.create(user=user, otp=otp, expires_at=expires_at)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_email_verified = models.BooleanField(default=False)

    def __str__(self) :
        return self.user.username
    
