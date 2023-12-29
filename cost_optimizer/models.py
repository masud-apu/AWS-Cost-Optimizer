from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils.translation import gettext_lazy as _

# Create your models here.

MONTHLY_CLOUD_SPEND_OPTIONS = [
    ('<$10,000', '<$10,000'),
    ('$10,000 to $100,000', '$10,000 to $100,000'),
    ('$100,001 to $250,000', '$100,001 to $250,000'),
    ('$250,001 to $500,000', '$250,001 to $500,000'),
    ('> $500,001', '> $500,001')
]


class CustomUser(AbstractUser):
    email = models.EmailField(_('email'), unique=True)
    email_verified = models.BooleanField(default=False)
    company_name = models.CharField(max_length=200)
    first_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200)
    hear_about_us = models.CharField(max_length=200)
    monthly_spend = models.CharField(max_length=200, choices=MONTHLY_CLOUD_SPEND_OPTIONS, default='<$10,000')

    groups = models.ManyToManyField(Group, blank=True, related_name='custom_users')
    user_permissions = models.ManyToManyField(Permission, blank=True, related_name='custom_users')
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.username


class OTP(models.Model):
    token = models.CharField(max_length=8)
    created_on = models.DateTimeField(auto_now_add=True)
    expire_time = models.DateTimeField(auto_now_add=False)
    reason = models.CharField(max_length=50, blank=True)

    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.user.username
