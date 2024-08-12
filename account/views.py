from django.shortcuts import render
from django.contrib.auth import authenticate, login
import random
from datetime import timedelta
from django.utils import timezone
from .models import MyUser, IPAddress
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import MyUserSerializer
from .utils import get_ip, validate_phone_number
from rest_framework_simplejwt.tokens import RefreshToken

def send_sms(phone, otp):
    print(f"Sending SMS to {phone}: Your OTP is {otp}")

class InitialView(APIView):
    """
    User should enter phone number, and we check if the phone number exists in our DB or not.
    Proper format:
    {
        "phone": "09123456789"
    }
    """
    def post(self, request):
        phone = request.data.get('phone')
        if not validate_phone_number(phone):
            return Response({"error": "Invalid phone number format. Must start with 09 and be 11 digits long."}, status=status.HTTP_400_BAD_REQUEST)
        
        user = MyUser.objects.filter(phone=phone).first()
        ip_address = get_ip(request)
        ip_obj, created = IPAddress.objects.get_or_create(ip=ip_address)

        if ip_obj.is_blocked():
            return Response({"error": "Too many requests from this IP. Please try again later."}, status=status.HTTP_403_FORBIDDEN)

        if ip_obj.sms_request_count > 3 and ip_obj.last_sms_request and (timezone.now() - ip_obj.last_sms_request).total_seconds() < 3600:
            ip_obj.block_ip()
            return Response({"error": "Too many SMS requests. Your IP has been blocked for 1 hour."}, status=status.HTTP_403_FORBIDDEN)

            
        if user and user.otp_activate:
            return Response({"message": "User found, please enter your password in login page"}, status=status.HTTP_200_OK)
        else:
            otp = f"{random.randint(100000, 999999)}"
            expiration_time = timezone.now() + timedelta(minutes=10)

            if user:
                user.otp = otp
                user.otp_expiration = expiration_time
            else:
                user = MyUser.objects.create(phone=phone, otp=otp, otp_expiration=expiration_time)

            user.save()
            if ip_obj.sms_request_count < 3:
                send_sms(phone, otp)
            else:
                ip_obj.block_ip()
                return Response({"error": "Too many SMS requests. Your IP has been blocked for 1 hour."}, status=status.HTTP_403_FORBIDDEN)
                

            ip_obj.sms_request_count += 1
            ip_obj.last_sms_request = timezone.now()
            ip_obj.save()

            request.session['phone'] = phone
            request.session['otp'] = otp

            return Response({"message": "OTP sent successfully, please enter the OTP"}, status=status.HTTP_200_OK)
        

class ValidateOTPView(APIView):
    '''
    {
        "phone": "09123456789",
        "otp": "123456"
    }
    '''
    def post(self, request):
        phone = request.session.get('phone') 
        otp = request.data.get('otp')
        user = MyUser.objects.filter(phone=phone).first()
        ip_address = get_ip(request)
        ip_obj, created = IPAddress.objects.get_or_create(ip=ip_address)
        
        if user is None:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        
        if user.is_otp_blocked():
            return Response({"error": "Too many failed OTP attempts. Please try again later."}, status=status.HTTP_403_FORBIDDEN)
        
       
        if user.otp == otp and timezone.now() < user.otp_expiration:
            user.otp = None
            user.otp_expiration = None
            user.otp_activate = True
            user.failed_otp_attempts = 0
            ip_obj.sms_request_count = 0
            user.save()
            ip_obj.save()
            return Response(
                {
                    "message": "OTP validated successfully",
                    "phone_number": phone  
                },
                status=status.HTTP_200_OK
            )
        
       
        user.failed_otp_attempts += 1
        user.last_failed_otp_attempt = timezone.now()
        
        
        if user.failed_otp_attempts >= 3:
            user.block_otp()
            return Response({"error": "Too many failed OTP attempts. Your account is blocked for 1 hour."}, status=status.HTTP_403_FORBIDDEN)

        user.save()
        return Response({"error": "Invalid OTP or OTP expired"}, status=status.HTTP_400_BAD_REQUEST)
    
    
class SignupView(APIView):
    '''
    valid format:
    {
        "phone": "09123456789",
        "first_name": "nima",
        "last_name": "gol",
        "email": "nima@example.com",
        "password": "password123"
    }
    '''
    def post(self, request):
        ip_address = get_ip(request)
        ip_obj, created = IPAddress.objects.get_or_create(ip=ip_address)
        phone_number = request.session.get('phone')
        user = MyUser.objects.filter(phone=phone_number).first()
        if ip_obj.is_blocked():
            return Response({"error": "Too many failed attempts from this IP. Please try again later."}, status=status.HTTP_403_FORBIDDEN)

        if not user.otp_activate:
            return Response({"error": "you should activate your account by entering the sms that we send it to you in otp-validation page"}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = MyUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(phone=phone_number)
            password = serializer.validated_data.get('password')
            if password:
                user.set_password(password)
                user.save()
            ip_obj.failed_signup_attempts = 0
            ip_obj.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "User registered and logged in successfully",
                "refresh": str(refresh),
                "access": str(refresh.access_token)
            }, status=status.HTTP_201_CREATED)

        ip_obj.failed_signup_attempts += 1
        ip_obj.last_failed_attempt = timezone.now()
        ip_obj.save()
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    


class LoginView(APIView):
    def post(self, request):
        ip_address = get_ip(request)
        ip_obj, created = IPAddress.objects.get_or_create(ip=ip_address)

        if ip_obj.is_blocked():
            return Response({"error": "Too many failed attempts from this IP. Please try again later."}, status=status.HTTP_403_FORBIDDEN)

        phone = request.data.get('phone')
        password = request.data.get('password')
        user = authenticate(request, phone=phone, password=password)

        if user is not None:
            if user.failed_login_attempts >= 3 and (timezone.now() - user.last_failed_attempt).total_seconds() < 3600:
                return Response({"error": "Your account is blocked for 1 hour due to multiple failed attempts."}, status=status.HTTP_403_FORBIDDEN)

            
            user.failed_login_attempts = 0
            user.save()
            ip_obj.failed_login_attempts = 0
            ip_obj.save()

           
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            return Response({
                "message": "Login successful",
                "access_token": access_token,
                "refresh_token": refresh_token
            }, status=status.HTTP_200_OK)

        user = MyUser.objects.filter(phone=phone).first()
        if user:
            user.failed_login_attempts += 1
            user.last_failed_attempt = timezone.now()
            user.save()

        ip_obj.failed_login_attempts += 1
        ip_obj.last_failed_attempt = timezone.now()
        ip_obj.save()

        return Response({"error": "Invalid login credentials."}, status=status.HTTP_401_UNAUTHORIZED)

    