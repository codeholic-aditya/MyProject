from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class User(AbstractUser):
    email_verified = models.BooleanField(default=False)
    password_reset_token = models.CharField(max_length=150)
    password_reset_expiry = models.CharField(max_length=150)
    last_password_reset_at = models.DateTimeField(auto_now=True)
    client_id = models.CharField(max_length=150, unique=True)

    def __str__(self):
        return f"User: {self.username})"
