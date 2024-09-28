from django.contrib.auth.models import User 
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny
from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from .serializers import UserSerializer
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from django.core.mail import send_mail
from .models import OTPVerification, UserProfile  
from django.core.cache import cache
import time

class UserRegistrationView(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        email = request.data.get('email')
        username = request.data.get('username')
        
        existing_user = User.objects.filter(email=email).first()
        if existing_user:
            # If the user exists and is verified, restrict registration
            if existing_user.userprofile.is_email_verified:
                return Response({
                    'status': 'error',
                    'message': 'Email is already registered and verified.',
                    'code': status.HTTP_400_BAD_REQUEST,
                }, status=status.HTTP_400_BAD_REQUEST)
            # If the user exists but is not verified, resend the OTP
            else:
                if existing_user.username != username:
                    existing_user.username = username
                    existing_user.save()
                existing_otp = OTPVerification.objects.filter(user=existing_user).first()
                if existing_otp:
                    existing_otp.delete()  # Delete the old OTP
                otp_verification = OTPVerification.generate_otp(existing_user)

                try:
                    send_mail(
                        'Email Verification',
                        f'Your verification code is: {otp_verification.otp}',
                        'movie.muse.interactive@gmail.com',  # Replace with your email
                        [existing_user.email],
                        fail_silently=False,
                    )
                except Exception as e:
                    print(e)
                    user.delete()
                    return Response({
                        'status': 'error',
                        'message': 'Failed to resend verification email.',
                        'code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                return Response({
                    'status': 'success',
                    'message': 'A new verification code has been sent to your email.',
                    'code': status.HTTP_200_OK,
                }, status=status.HTTP_200_OK)


        serializer = UserSerializer(data = request.data)
        if serializer.is_valid():
            user = serializer.save()
            otp_verification = OTPVerification.generate_otp(user)
            UserProfile.objects.create(user=user)
            
            try:
                send_mail(
                    'Email Verification',
                    f'Your verification code is: {otp_verification.otp}',
                    'movie.muse.interactive@gmail.com',  # Replace with your email
                    [user.email],
                    fail_silently=False,
                )
            except Exception as e:
            # Roll back user creation if the email fails to send
                user.delete()  # Optionally delete the user if email sending fails
                print(e)
                return Response({
                    'status': 'error',
                    'message': 'User creation failed. Verification email could not be sent.',
                    'code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({
                'status': 'success',
                'message': 'User created successfully.',
                'code': status.HTTP_201_CREATED,
            }, status=status.HTTP_201_CREATED)
        return Response({
            'status': 'error',
            'message': 'Registration Failed',
            'code': status.HTTP_400_BAD_REQUEST,
            'errors': serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)

class CustomLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username_or_email = request.data.get("username_or_email")
        password = request.data.get("password")

        user = None

        if '@' in username_or_email:
            try:
                user = User.objects.get(email=username_or_email)
            except User.DoesNotExist:
                return Response({"error": "Invalid credentials"}, status=400)
        else:
            # It's a username
            user = authenticate(username=username_or_email, password=password)

        # If user is found by email or authenticated with username
        if user is not None and user.check_password(password):
            try:
                user_profile = UserProfile.objects.get(user=user)
                if not user_profile.is_email_verified:
                    return Response({"error": "Email not verified. Please verify your email first."}, status=400)
            except UserProfile.DoesNotExist:
                return Response({"error": "User profile not found."}, status=400)
            
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            })

        return Response({"error": "Invalid credentials"}, status=400)

class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        if not email or not otp:
            return Response({"error": "Email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)  # Fetch the user by email
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            print("a")
            otp_verification = OTPVerification.objects.get(user=user)
            print('b')
            print(f"Current time: {timezone.now()} (type: {type(timezone.now())})")
            print(f"OTP expires at: {otp_verification.expires_at} (type: {type(otp_verification.expires_at)})")
            if otp_verification.is_expired():
                return Response({"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)
            if otp_verification.otp == otp:
                user_profile =UserProfile.objects.get(user=user)
                user_profile.is_email_verified = True
                user_profile.save()
                otp_verification.delete()

                return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        except OTPVerification.DoesNotExist:
            return Response({"error": "No OTP found for this email."}, status=status.HTTP_400_BAD_REQUEST)
        
class ResendOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)  # Fetch the user by email
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        cache_key = f"otp_resend_{email}"
        last_request_time = cache.get(cache_key)
        current_time = time.time()
        cooldown_period = 60
        if last_request_time and (current_time - last_request_time) < cooldown_period:
            remaining_time = int(cooldown_period - (current_time - last_request_time))
            return Response({"error": f"Please wait {remaining_time} seconds before requesting another OTP."}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        try:
            otp_verification = OTPVerification.objects.get(user=user)
            
            # Delete the previous OTP regardless of whether it's expired
            otp_verification.delete()

            # Create a new OTP after deleting the previous one
            otp_verification =  OTPVerification.generate_otp(user)

            otp_verification.save()
            try:
                send_mail(
                    'Email Verification',
                    f'Your new verification code is: {otp_verification.otp}',
                    'movie.muse.interactive@gmail.com',  # Replace with your email
                    [user.email],
                    fail_silently=False,
                )
            except Exception as e:
                return Response({"error": "Failed to send email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"message": "A new OTP has been sent to your email."}, status=status.HTTP_200_OK)

        except OTPVerification.DoesNotExist:
            return Response({"error": "No OTP found for this email."}, status=status.HTTP_400_BAD_REQUEST)        

class SendOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        otp_verification = OTPVerification.generate_otp(user)

        # Send the password reset email
        try:
            send_mail(
                'Password Reset Request',
                f'Use the link below to reset your password: {otp_verification.otp}',
                'movie.muse.interactive@gmail.com',  
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
            return Response({"error": "Failed to send email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)
    
class ResetPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        new_password = request.data.get("new_password")

        if not email or not otp or not new_password:
            return Response({"error": "Email, OTP, and new password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            otp_verification = OTPVerification.objects.get(user=user)

            # Check if OTP is valid and not expired
            if otp_verification.otp != otp:
                return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
            if otp_verification.expires_at < timezone.now():
                return Response({"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

            # Update user's password
            user.set_password(new_password)
            user.save()

            # Optionally, delete the OTP record after successful password reset
            otp_verification.delete()

            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except OTPVerification.DoesNotExist:
            return Response({"error": "No OTP found for this user."}, status=status.HTTP_400_BAD_REQUEST)