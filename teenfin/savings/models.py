from django.db import models
from teenfin import settings
from rest_framework.authtoken.models import Token

class Month(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    Month_name = models.CharField
    Expense = models.IntegerField

    def __str__(self):
        return "Month Data Record"
class Set_Goal(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=255, default="")
    amount = models.IntegerField(default=0)
    description = models.CharField(max_length=500, default="")

    def __str__(self):
        return self.title


# Create your models here.
