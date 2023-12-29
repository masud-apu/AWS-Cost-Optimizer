from rest_framework import serializers
from datetime import datetime, timedelta, date
import random
import string
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer as JwtTokenObtainPairSerializer
from .models import *
from django.contrib.auth import get_user_model
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'first_name', 'last_name', 'email', 'password', 'monthly_spend', 'hear_about_us')
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = CustomUser.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()

        # Generate and save OTP
        otp = self.generate_otp()
        self.save_otp(user, otp)

        # Send OTP via email (as shown in the previous response)
        self.send_otp_email(user, otp)  # New line to call the email sending function

        return user

    def generate_otp(self):
        digits = string.digits
        otp = ''.join(random.choice(digits) for i in range(5))
        return otp

    def save_otp(self, user, otp):
        otp_expiry = datetime.now() + timedelta(minutes=30)
        OTP.objects.create(token=otp, expire_time=otp_expiry, user=user)

    def send_otp_email(self, user, otp):
        context = {
            'first_name': user.first_name,
            'otp_verification_url': f"http://127.0.0.1:8000/api/v1/verify-otp/{user.email}?token={otp}"
        }
        email_html_message = render_to_string('email/verification_otp.html', context)
        email_plaintext_message = render_to_string('email/verification_otp.txt', context)
        msg = EmailMultiAlternatives(
            # title
            'Your Verification OTP Code',
            # message
            email_plaintext_message,
            # from
            settings.EMAIL_HOST_USER,
            # to
            [user.email]
        )
        msg.attach_alternative(email_html_message, "text/html")
        msg.send()


class OTPVerificationSerializer(serializers.Serializer):
    otp_token = serializers.CharField(max_length=8)


class OTPResendSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)


class CustomLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        email = data.get('email', '')
        password = data.get('password', '')
        user = get_adapter().authenticate(self.context.get('request'), email=email, password=password)
        if not user:
            raise serializers.ValidationError('Invalid email or password.')
        data['user'] = user
        return data

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['name'] = user.name
        token['email'] = user.email
        token['is_superuser'] = user.is_superuser
        token['is_staff'] = user.is_staff

        return token


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
