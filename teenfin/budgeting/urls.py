from django.urls import path
from .views import expense_list_create, expense_detail

urlpatterns = [
    path('expenses/', expense_list_create, name='expense-list-create'),
    path('expenses/<int:pk>/', expense_detail, name='expense-detail'),
]
