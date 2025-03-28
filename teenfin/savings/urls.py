from django.urls import path
from .views import *

urlpatterns = [
    # Month URLs
    path('months/', month_list_create, name='month_list_create'),
    path('months/<int:pk>/', month_detail, name='month_detail'),
    path('set-goals/', set_goal_list_create, name='set_goal_list_create'),
    path('set-goals/<int:pk>/', set_goal_detail, name='set_goal_detail'),
    
]
