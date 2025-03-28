from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from .models import *
from .serializers import *

# List all months or create a new month record
@api_view(['GET', 'POST'])
def month_list_create(request):
    if request.method == 'GET':
        months = Month.objects.all()
        serializer = MonthSerializer(months, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = MonthSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Retrieve, update, or delete a specific month record
@api_view(['GET', 'PUT', 'DELETE'])
def month_detail(request, pk):
    try:
        month = Month.objects.get(pk=pk)
    except Month.DoesNotExist:
        return Response({'error': 'Month record not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = MonthSerializer(month)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = MonthSerializer(month, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        month.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['GET', 'POST'])
def set_goal_list_create(request):
    if request.method == 'GET':
        goals = Set_Goal.objects.all()
        serializer = SetGoalSerializer(goals, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = SetGoalSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Retrieve, update, or delete a specific goal
@api_view(['GET', 'PUT', 'DELETE'])
def set_goal_detail(request, pk):
    try:
        goal = Set_Goal.objects.get(pk=pk)
    except Set_Goal.DoesNotExist:
        return Response({'error': 'Goal not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = SetGoalSerializer(goal)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = SetGoalSerializer(goal, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        goal.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
