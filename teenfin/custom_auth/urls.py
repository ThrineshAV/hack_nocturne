from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import RegisterView, LoginView, LogoutView,RequestPasswordResetView, ResetPasswordView


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot-password/', RequestPasswordResetView.as_view(), name='forgot-password'),
    path('reset-password/<str:uid>/<str:token>/', ResetPasswordView.as_view(), name='reset-password'),

]