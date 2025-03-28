from rest_framework import serializers
from .models import Month, Set_Goal

# Month Serializer
class MonthSerializer(serializers.ModelSerializer):
    class Meta:
        model = Month
        fields = '__all__'

# Set_Goal Serializer
class SetGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Set_Goal
        fields = '__all__'
