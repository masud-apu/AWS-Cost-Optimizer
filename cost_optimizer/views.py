import json

from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializer import *
from .models import *
from datetime import datetime, timedelta
import random
import string
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
import uuid
from rest_framework.parsers import JSONParser
from django.core.mail import send_mail
from django.contrib.auth.hashers import check_password
from django.db import IntegrityError
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


# Create your views here.

class CustomUserCreateView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = (AllowAny,)


class OTPVerificationView(generics.CreateAPIView):
    permission_classes = (AllowAny,)

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return OTPVerificationSerializer

    def post(self, request, *args, **kwargs):
        otp_token = request.data.get('otp_token')
        username = kwargs.get('username')  # Assuming you pass the user ID as a URL parameter

        try:
            otp = OTP.objects.get(user__username=username, token=otp_token, expire_time__gte=datetime.now())
        except OTP.DoesNotExist:
            return Response({"message": "Invalid OTP or OTP expired"}, status=status.HTTP_400_BAD_REQUEST)

        # If OTP is valid, activate the user or perform any other required action
        user = CustomUser.objects.get(username=username)
        user.is_active = True
        user.email_verified = True
        user.save()

        # Optionally, delete the OTP entry once it's verified and used
        otp.delete()

        return Response({"message": "Account activated successfully"}, status=status.HTTP_200_OK)


class OTPResendView(APIView):
    # serializer_class = OTPResendSerializer
    permission_classes = (AllowAny,)

    def generate_otp(self):
        digits = string.digits
        otp = ''.join(random.choice(digits) for i in range(5))
        return otp

    def save_otp(self, user, otp):
        otp_expiry = datetime.now() + timedelta(minutes=15)
        OTP.objects.create(token=otp, expire_time=otp_expiry, user=user)

    def send_otp_email(self, user, otp):
        context = {
            'first_name': user.first_name,
            'otp_verification_url': f"https://n-ops-demo.vercel.app/verify?email={user.email}?token={otp}"
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

    def get(self, request, username):
        # username = request.data.get('username')  # Get the username from the request data

        try:
            user = CustomUser.objects.get(email=username)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        if user.email_verified:
            return Response({"message": "Account is already activated"}, status=status.HTTP_200_OK)

        try:
            otp = OTP.objects.get(user=user)
            otp.delete()
        except OTP.DoesNotExist:
            pass

        # Generate and save new OTP
        otp = self.generate_otp()
        self.save_otp(user, otp)

        # Send new OTP via email
        self.send_otp_email(user, otp)

        return Response({"message": "New OTP sent successfully"}, status=status.HTTP_200_OK)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomLoginSerializer


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            old_password = serializer.data.get('old_password')
            new_password = serializer.data.get('new_password')

            # Check if the old password matches the current password
            if not check_password(old_password, request.user.password):
                return Response({"message": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

            # Change the password and save the user object
            request.user.set_password(new_password)
            request.user.save()
            return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        serializer = ProfileUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
