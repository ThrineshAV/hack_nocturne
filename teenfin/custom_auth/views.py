from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate
from .serializers import UserSerializer, LoginSerializer
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.urls import reverse
import json
from rest_framework.views import APIView
from .serializers import PasswordResetRequestSerializer, PasswordResetSerializer
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework import status
from django.conf import settings
User = get_user_model()



class RegisterView(generics.CreateAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        user = serializer.instance
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_id': user.pk,
            'email': user.email,
            'message': 'User registered successfully'
        }, status=status.HTTP_201_CREATED)

class LoginView(generics.GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(
            request,
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password']
        )
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user_id': user.pk,
                'email': user.email,
                'message': 'Login successful'
            })
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(generics.GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        try:
            # Blacklist the refresh token to invalidate the session
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
class RequestPasswordResetView(APIView):
    def post(self, request):
        print("Received data:", request.data)  # Debug line
        
        # Check if email is in the request data
        if 'email' not in request.data:
            return Response({"email": "Email field is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = get_object_or_404(User, email=email)
                
                # Generate token
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                
                # Create reset link
                reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"
                
                # Debug line
                print(f"Reset link generated: {reset_link}")
                
                try:
                    # Try to send email
                    send_mail(
                        subject="Password Reset Request",
                        message=f"Click the link to reset your password: {reset_link}",
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )
                    return Response({'message': 'Password reset link sent to email'}, status=status.HTTP_200_OK)
                except Exception as e:
                    print(f"Email sending error: {str(e)}")
                    # If email sending fails, still return success but log the error
                    # This is for testing purposes only - in production you should handle this differently
                    return Response({'message': 'Password reset link generated (email sending failed)'}, 
                                   status=status.HTTP_200_OK)
            except Exception as e:
                print(f"Error finding user: {str(e)}")
                return Response({"email": "Error processing request"}, status=status.HTTP_400_BAD_REQUEST)
        
        print("Validation errors:", serializer.errors)  # Debug line
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ResetPasswordView(APIView):
    def post(self, request, uid, token):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            new_password = serializer.validated_data['new_password']
            user_id = force_str(urlsafe_base64_decode(uid))
            user = get_object_or_404(User, pk=user_id)

            # Validate token
            if not default_token_generator.check_token(user, token):
                return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

            # Set new password
            user.set_password(new_password)
            user.save()

            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
